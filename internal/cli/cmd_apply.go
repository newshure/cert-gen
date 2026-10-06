package cli

// apply — openssl .cnf 블록들을 모아 적은 파일을 읽어 그대로 만든다.
//
// 한 파일에 CA 설정과 그 아래 발급할 leaf 설정들을 '---' 로 구분해 적는다. "이 PKI 를
// 이렇게 만들어라" 를 선언적으로 적고 한 번에 실행하는 흐름이다.
//
// 처리 순서는 파일에 적힌 순서다. CA 블록을 만나면 그 CA 를 만들고(또는 이미 있으면 재사용),
// 이후 leaf 블록은 **가장 최근 CA** 아래로 발급한다. CA 블록이 없으면 --ca 로 기존 CA 를
// 지정하거나, 등록된 CA 가 하나뿐이면 그것을 쓴다.
//
// 멈춤 원칙: 한 블록이 실패하면 거기서 멈춘다. 이미 만든 것은 되돌리지 않는다 — CA 와
// 인증서는 그 자체로 쓸 수 있는 산출물이고, 중간까지 만든 것을 지우는 편이 더 위험하다.
// 무엇까지 됐는지 분명히 보고한다.

import (
	"fmt"
	"strings"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/osslconf"
	"github.com/newshure/cert-gen/internal/store"
)

func (a *App) cmdApply(args []string) error {
	fs := flags("apply")
	var (
		caSlug    = fs.String("ca", "", "leaf 를 발급할 CA (파일에 CA 블록이 없을 때)")
		dryRun    = fs.Bool("dry-run", false, "읽고 계획만 보여 준다. 아무것도 만들지 않는다")
		outDir    = fs.String("o", "", "발급한 번들을 이 디렉터리에 풀어 놓는다")
		passStdin = fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
		noPass    = fs.Bool("no-passphrase", false, "새로 만드는 CA 키를 평문으로 둔다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) < 1 {
		return certerr.Validationf(
			"설정 파일을 하나 이상 지정하세요: cert-gen apply <파일>... " +
				"(한 파일에 --- 로 블록을 나누거나, CA·leaf 를 파일로 나누거나)")
	}

	// 파일을 명령행 순서대로, 각 파일 안의 블록도 순서대로 이어 붙인다.
	// 한 파일(블록 여럿)과 여러 파일(각 블록)을 같은 방식으로 처리하기 위해서다 —
	// CA 파일 다음에 leaf 파일을 주면 그 CA 아래로 발급된다.
	var specs []osslconf.Spec
	for _, path := range rest {
		fileSpecs, err := osslconf.ParseBlocksFile(path)
		if err != nil {
			return err
		}
		specs = append(specs, fileSpecs...)
	}

	// 계획을 먼저 보여 준다. 되돌릴 수 없는 일(CA 생성)을 하기 전에 무엇을 할지 알린다.
	a.renderPlan(specs)

	// 제약: apply 한 번은 CA 하나만 다룬다(1 CA / 1회). CA : 서버·클라이언트 = 1 : N.
	//
	// 한 번에 여러 CA 를 만들면 "어느 leaf 가 어느 CA 아래인가" 가 파일 순서에 숨어 헷갈리고,
	// CA 생성은 되돌리기 어려운 일이라 한 번에 하나씩 분명히 하는 편이 안전하다. CA 가
	// 여럿이면 CA 마다 따로 apply 를 돌린다.
	var (
		caSpecs   []osslconf.Spec
		leafSpecs []osslconf.Spec
	)
	for _, spec := range specs {
		if spec.IsCA {
			caSpecs = append(caSpecs, spec)
		} else {
			leafSpecs = append(leafSpecs, spec)
		}
	}
	if len(caSpecs) > 1 {
		names := make([]string, 0, len(caSpecs))
		for _, c := range caSpecs {
			names = append(names, c.Subject.CommonName)
		}
		return certerr.Validationf(
			"CA 블록이 %d개입니다(%s). apply 한 번은 CA 하나만 만듭니다(1 CA / 1회). "+
				"CA 마다 따로 실행하세요", len(caSpecs), strings.Join(names, ", "))
	}
	if len(caSpecs) == 1 && *caSlug != "" {
		// 파일이 CA 를 만들라는데 --ca 로 다른 CA 를 가리키면 의도가 충돌한다.
		return certerr.Validationf(
			"파일에 CA 블록이 있는데 --ca 도 지정했습니다. 둘 중 하나만 쓰세요")
	}
	if len(leafSpecs) == 0 {
		return certerr.Validationf("발급할 leaf 블록이 없습니다")
	}

	if *dryRun {
		a.Out.Printf("\n드라이런입니다. 아무것도 만들지 않았습니다.\n")
		return a.Out.Emit(map[string]any{
			"dry_run": true, "ca_blocks": len(caSpecs), "leaf_blocks": len(leafSpecs),
		})
	}

	if err := a.open(true); err != nil {
		return err
	}

	var (
		material  ca.Material
		results   []map[string]any
		madeCA    bool
		caSlugOut string
	)

	// 1. CA 를 정한다 — 파일의 CA 블록 하나, 또는 --ca, 또는 등록된 유일한 CA.
	switch {
	case len(caSpecs) == 1:
		rec, reused, err := a.applyCA(caSpecs[0], *noPass, *passStdin)
		if err != nil {
			return err
		}
		material, err = a.loadCA(rec.Slug, "", *passStdin)
		if err != nil {
			return err
		}
		madeCA = !reused
		caSlugOut = rec.Slug
		verb := "CA 생성"
		if reused {
			verb = "CA 재사용"
		}
		a.Out.Printf("%s: %s\n", verb, rec.Slug)
	case *caSlug != "":
		m, err := a.loadCA(*caSlug, "", *passStdin)
		if err != nil {
			return err
		}
		material = m
		caSlugOut = *caSlug
	default:
		m, err := a.defaultCA(*passStdin)
		if err != nil {
			return certerr.Validationf(
				"leaf 를 발급할 CA 가 없습니다. 파일에 CA 블록을 두거나 --ca <식별자> 를 "+
					"지정하세요 (%v)", err)
		}
		material = *m
		caSlugOut = m.Record.Slug
	}

	// 2. 모든 leaf 를 그 CA 아래로 발급한다. 한 건이 실패하면 멈추되 앞까지는 남긴다.
	madeCert := 0
	for i, spec := range leafSpecs {
		a.Out.Warnings(spec.Warnings)
		res, err := a.applyLeaf(spec, material, *outDir)
		if err != nil {
			return a.applyStopped(i, len(leafSpecs), results, err)
		}
		madeCert++
		a.Out.Printf("[%d/%d] 발급: #%d %s (%s)\n",
			i+1, len(leafSpecs), res.Record.ID, res.Record.CommonName, res.Record.Profile)
		results = append(results, map[string]any{
			"id": res.Record.ID, "common_name": res.Record.CommonName, "bundle": res.BundlePath,
		})
	}

	if err := a.Out.Emit(map[string]any{
		"ca": caSlugOut, "ca_created": madeCA, "issued": results, "certs_issued": madeCert,
	}); err != nil {
		return err
	}
	a.Out.Printf("\n완료: CA %s, 인증서 %d건 발급.\n", caVerb(madeCA, caSlugOut), madeCert)
	return nil
}

func caVerb(made bool, slug string) string {
	if made {
		return slug + " 생성"
	}
	return slug + " 사용"
}

// renderPlan 은 실행 전에
// renderPlan 은 실행 전에 무엇을 할지 보여 준다.
func (a *App) renderPlan(specs []osslconf.Spec) {
	if a.Out.JSON {
		return
	}
	a.Out.Printf("설정 블록 %d개:\n", len(specs))
	for i, spec := range specs {
		if spec.IsCA {
			pathlen := ""
			if spec.PathLen != nil {
				pathlen = fmt.Sprintf(", pathlen:%d", *spec.PathLen)
			}
			a.Out.Printf("  [%d] CA 생성   %s (%s%s)\n",
				i+1, spec.Subject.CommonName, orDefault(spec.KeyAlgo, "설정 기본"), pathlen)
		} else {
			a.Out.Printf("  [%d] 발급      %s [%s] SAN %s\n",
				i+1, spec.Subject.CommonName,
				orDefault(spec.Profile, "설정 기본"), osslSANSummary(spec.SANValues))
		}
	}
}

func osslSANSummary(sans []string) string {
	if len(sans) == 0 {
		return "(없음)"
	}
	return strings.Join(sans, ", ")
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func (a *App) applyCA(spec osslconf.Spec, noPass, passStdin bool) (store.CA, bool, error) {
	// 같은 지문·슬러그의 CA 가 이미 있으면 재사용한다. apply 를 다시 돌려도 CA 가 중복
	// 생성되지 않게 — 선언적 실행은 여러 번 돌려도 같은 결과여야 한다.
	slug := ca.UniqueSlug(a.store, spec.Subject.CommonName)
	if existing, ok := a.store.FindCA(slug); ok {
		return existing, true, nil
	}
	// CN 으로 만든 slug 가 그대로면 같은 CN 의 CA 가 이미 있을 수 있다. CN 으로도 확인한다.
	if list, err := a.store.ListCAs(""); err == nil {
		for _, rec := range list {
			if rec.CommonName == spec.Subject.CommonName {
				return rec, true, nil
			}
		}
	}

	require := a.cfg.CA.EncryptKey && !noPass
	var passphrase string
	if require {
		p, err := ReadSecret(SecretSource{
			Env: EnvCAPassphrase, FromStdin: passStdin,
			Prompt:  fmt.Sprintf("CA(%s) 개인키 패스프레이즈: ", spec.Subject.CommonName),
			Confirm: !passStdin,
		})
		if err != nil {
			return store.CA{}, false, err
		}
		if p == "" {
			return store.CA{}, false, certerr.Validationf(
				"패스프레이즈가 비어 있습니다. 평문으로 만들려면 --no-passphrase 를 쓰세요")
		}
		passphrase = p
	}
	requireFlag := require
	rec, err := ca.CreateRoot(a.cfg, a.store, ca.CreateOptions{
		Subject: spec.Subject, KeyAlgo: spec.KeyAlgo,
		Passphrase: passphrase, RequirePassphrase: &requireFlag,
	})
	if err != nil {
		return store.CA{}, false, err
	}
	return rec, false, nil
}

func (a *App) applyLeaf(spec osslconf.Spec, material ca.Material, outDir string) (issue.Result, error) {
	res, err := issue.Issue(a.cfg, a.store, issue.Options{
		Material:  material,
		Subject:   spec.Subject,
		SANValues: spec.SANValues,
		Profile:   spec.Profile,
		KeyAlgo:   spec.KeyAlgo,
		Frontend:  "cli",
	})
	if err != nil {
		return issue.Result{}, err
	}
	a.Out.Warnings(res.Warnings)
	if outDir != "" {
		if _, err := bundle.ExtractTo(res.BundlePath, outDir); err != nil {
			return issue.Result{}, err
		}
	}
	return res, nil
}

// defaultCA 는 등록된 CA 가 하나뿐이면 그것을 연다.
func (a *App) defaultCA(passStdin bool) (*ca.Material, error) {
	list, err := a.store.ListCAs("active")
	if err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, certerr.Validationf("CA 가 %d개입니다", len(list))
	}
	m, err := a.loadCA(list[0].Slug, "", passStdin)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (a *App) applyStopped(at, total int, done []map[string]any, cause error) error {
	a.Out.Printf("\n[%d/%d] 에서 멈췄습니다. 그 앞까지 만든 것은 그대로 남아 있습니다.\n",
		at+1, total)
	if len(done) > 0 {
		a.Out.Printf("만든 것: %d개\n", len(done))
	}
	return cause
}
