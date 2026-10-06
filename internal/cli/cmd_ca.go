package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

func (a *App) cmdInit(args []string) error {
	fs := flags("init")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.open(true); err != nil {
		return err
	}
	// 기존 디렉터리의 권한을 조인다. mkdir -p 는 우리가 준 모드를 umask 로 깎는다.
	for _, dir := range []string{a.cfg.DataDir, a.cfg.CADir(), a.cfg.KeyDir(),
		a.cfg.BundleDir(), a.cfg.CRLDir(), a.cfg.TmpDir()} {
		if err := fsops.EnsureDir(dir, fsops.ModeDir); err != nil {
			return err
		}
		if err := fsops.Chmod(dir, fsops.ModeDir); err != nil {
			return err
		}
	}
	version, err := a.store.SchemaVersionOf()
	if err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{
		"data_dir": a.cfg.DataDir, "db": a.cfg.DBPath(), "schema_version": version,
	}); err != nil {
		return err
	}
	a.Out.Line("상태 디렉터리를 준비했습니다: %s", a.cfg.DataDir)
	a.Out.Printf("  DB            %s (스키마 v%d)\n", a.cfg.DBPath(), version)
	a.Out.Printf("  설정          %s\n", a.cfg.ConfigPath())
	a.Out.Printf("\n다음: cert-gen ca create --cn \"<조직> Root CA\"\n")
	return nil
}

func (a *App) cmdWhere(args []string) error {
	fs := flags("where")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	dir, source := config.ResolveDataDir(a.dataFlag)
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DataDirSource = source
	exists := fsops.IsFile(cfg.DBPath())
	if err := a.Out.Emit(map[string]any{
		"data_dir": dir, "source": string(source), "initialized": exists,
	}); err != nil {
		return err
	}
	a.Out.Line("%s", cfg.Guide())
	if !exists {
		a.Out.Printf("아직 초기화되지 않았습니다. 'cert-gen init' 으로 만듭니다.\n")
	}
	return nil
}

// subjectFlags 는 DN 입력 플래그를 등록하고, 해석 후 값을 담을 구조체를 돌려준다.
// CA 생성·발급·CSR 생성이 같은 플래그 이름을 쓰게 한다.
func subjectFlags(fs *flag.FlagSet) *names.Subject {
	// 이름을 풀어 쓴다. Go 의 flag 는 -o 와 --o 를 같은 플래그로 보기 때문에, DN 의
	// Organization 을 "o" 로 두면 출력 디렉터리 -o 와 충돌해 **등록 시점에 panic** 한다.
	s := &names.Subject{}
	fs.StringVar(&s.CommonName, "cn", "", "Common Name (필수)")
	fs.StringVar(&s.Organization, "org", "", "Organization")
	fs.StringVar(&s.OrganizationalUnit, "ou", "", "Organizational Unit")
	fs.StringVar(&s.Country, "country", "", "Country (2자, 예: KR)")
	fs.StringVar(&s.State, "state", "", "State/Province")
	fs.StringVar(&s.Locality, "locality", "", "Locality")
	fs.StringVar(&s.Email, "email", "", "emailAddress")
	return s
}

func (a *App) caCreate(args []string) error {
	fs := flags("ca create")
	subj := subjectFlags(fs)
	var (
		slug         = fs.String("slug", "", "식별자 (기본: CN 에서 생성)")
		keyAlgo      = fs.String("key-algo", "", "키 알고리즘 ("+strings.Join(keys.Names(), ", ")+")")
		days         = fs.Int("days", 0, "유효기간(일)")
		noPassphrase = fs.Bool("no-passphrase", false, "패스프레이즈 없이 만든다 (비권장)")
		passStdin    = fs.Bool("passphrase-stdin", false, "패스프레이즈를 stdin 에서 읽는다")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if subj.CommonName == "" {
		return certerr.Validationf("--cn 이 필요합니다")
	}
	if err := a.open(true); err != nil {
		return err
	}

	require := a.cfg.CA.EncryptKey && !*noPassphrase
	var passphrase string
	if require {
		var err error
		passphrase, err = ReadSecret(SecretSource{
			Env: EnvCAPassphrase, FromStdin: *passStdin,
			Prompt: "CA 개인키 패스프레이즈: ", Confirm: !*passStdin,
		})
		if err != nil {
			return err
		}
		if passphrase == "" {
			return certerr.Validationf(
				"패스프레이즈가 비어 있습니다. 없이 만들려면 --no-passphrase 를 쓰세요")
		}
	}
	requireFlag := require
	rec, err := ca.CreateRoot(a.cfg, a.store, ca.CreateOptions{
		Subject: *subj, Slug: *slug, KeyAlgo: *keyAlgo, Days: *days,
		Passphrase: passphrase, RequirePassphrase: &requireFlag,
	})
	if err != nil {
		return err
	}
	if err := a.Out.Emit(caJSON(a.cfg, rec)); err != nil {
		return err
	}
	a.Out.Line("%s", rec.Slug)
	a.Out.Printf("Root CA 를 만들었습니다.\n")
	a.printCA(rec)
	if !require {
		a.Out.Warn("이 CA 의 개인키는 암호화되지 않았습니다. " +
			"상태 디렉터리를 읽을 수 있는 사람이 곧 이 CA 입니다")
	}
	a.Out.Printf("\n다음: cert-gen cert issue --ca %s --cn <호스트명>\n", rec.Slug)
	return nil
}

func (a *App) printCA(rec store.CA) {
	keyPath, certPath, _ := ca.ResolvePaths(a.cfg, rec)
	a.Out.Printf("  식별자        %s\n", rec.Slug)
	a.Out.Printf("  Subject       %s\n", rec.SubjectDN)
	a.Out.Printf("  키            %s%s\n", rec.KeyAlgo, encryptedNote(rec.KeyEncrypted))
	a.Out.Printf("  유효기간      %s ~ %s\n", shortDate(rec.NotBefore), shortDate(rec.NotAfter))
	a.Out.Printf("  지문(SHA256)  %s\n", rec.Fingerprint)
	a.Out.Printf("  인증서        %s\n", certPath)
	a.Out.Printf("  개인키        %s\n", keyPath)
	if rec.IsExternal {
		a.Out.Printf("  외부 CA       예 (원본: %s)\n", rec.SourceDir)
	}
}

func encryptedNote(encrypted bool) string {
	if encrypted {
		return " (암호화됨)"
	}
	return " (평문)"
}

func shortDate(iso string) string {
	if len(iso) >= 10 {
		return iso[:10]
	}
	return iso
}

func caJSON(cfg config.Config, rec store.CA) map[string]any {
	keyPath, certPath, chainPath := ca.ResolvePaths(cfg, rec)
	return map[string]any{
		"slug": rec.Slug, "common_name": rec.CommonName, "subject_dn": rec.SubjectDN,
		"key_algo": rec.KeyAlgo, "key_encrypted": rec.KeyEncrypted,
		"not_before": rec.NotBefore, "not_after": rec.NotAfter,
		"fingerprint_sha256": rec.Fingerprint, "serial_hex": rec.SerialHex,
		"is_external": rec.IsExternal, "source_dir": rec.SourceDir,
		"next_seq": rec.NextSeq, "crl_number": rec.CRLNumber, "status": rec.Status,
		"key_path": keyPath, "cert_path": certPath, "chain_path": chainPath,
	}
}

func (a *App) caList(args []string) error {
	fs := flags("ca list")
	status := fs.String("status", "", "상태 필터 (active|retired)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	list, err := a.store.ListCAs(*status)
	if err != nil {
		return err
	}
	if a.Out.JSON {
		out := make([]map[string]any, 0, len(list))
		for _, rec := range list {
			out = append(out, caJSON(a.cfg, rec))
		}
		return a.Out.Emit(out)
	}
	rows := make([][]string, 0, len(list))
	for _, rec := range list {
		kind := "로컬"
		if rec.IsExternal {
			kind = "외부"
		}
		rows = append(rows, []string{
			rec.Slug, Truncate(rec.CommonName, 28), rec.KeyAlgo,
			shortDate(rec.NotAfter), fmt.Sprintf("%d", rec.NextSeq-1), kind,
		})
	}
	a.Out.Table([]string{"식별자", "CN", "키", "만료", "발급", "구분"}, rows)
	if len(list) == 0 {
		a.Out.Printf("\nCA 가 없습니다. 'cert-gen ca create --cn \"<조직> Root CA\"' 로 만듭니다.\n")
	}
	return nil
}

func (a *App) caShow(args []string) error {
	fs := flags("ca show")
	showPEM := fs.Bool("pem", false, "인증서 PEM 을 출력한다")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("CA 식별자를 하나 지정하세요: cert-gen ca show SLUG")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.GetCA(rest[0])
	if err != nil {
		return err
	}
	if err := a.Out.Emit(caJSON(a.cfg, rec)); err != nil {
		return err
	}
	a.printCA(rec)
	certs, err := a.store.ListCerts(store.CertFilter{CAID: &rec.ID})
	if err != nil {
		return err
	}
	a.Out.Printf("  발급 건수     %d\n", len(certs))
	if *showPEM {
		_, certPath, _ := ca.ResolvePaths(a.cfg, rec)
		data, err := os.ReadFile(certPath)
		if err != nil {
			return certerr.WrapState(err, "인증서를 읽을 수 없습니다: %v", err)
		}
		fmt.Fprint(a.Out.W, string(data))
	}
	return nil
}

func (a *App) caExport(args []string) error {
	fs := flags("ca export")
	outDir := fs.String("o", ".", "출력 디렉터리")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("CA 식별자를 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.GetCA(rest[0])
	if err != nil {
		return err
	}
	_, certPath, chainPath := ca.ResolvePaths(a.cfg, rec)
	if err := fsops.EnsureDir(*outDir, fsops.ModeDir); err != nil {
		return err
	}
	written := []string{}
	for src, name := range map[string]string{certPath: "ca.crt", chainPath: "chain.pem"} {
		if src == "" {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		dst := filepath.Join(*outDir, name)
		// ca.crt 는 배포용 공개 파일이다.
		if err := fsops.WriteAtomic(dst, data, fsops.ModePublic); err != nil {
			return err
		}
		written = append(written, dst)
	}
	if err := a.Out.Emit(map[string]any{"files": written, "slug": rec.Slug}); err != nil {
		return err
	}
	for _, path := range written {
		a.Out.Line("%s", path)
	}
	a.Out.Printf("\n클라이언트에 신뢰 등록하려면 ca.crt 를 배포합니다.\n")
	return nil
}

func (a *App) caAdopt(args []string) error {
	fs := flags("ca adopt")
	var (
		dir      = fs.String("dir", "", "CA 가 있는 디렉터리 (필수)")
		keyFile  = fs.String("key", "", "개인키 파일명 (자동 탐색 실패 시)")
		certFile = fs.String("cert", "", "인증서 파일명 (자동 탐색 실패 시)")
		slug     = fs.String("slug", "", "식별자")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return certerr.Validationf("--dir 이 필요합니다")
	}
	if err := a.open(true); err != nil {
		return err
	}
	found, err := ca.DiscoverInDir(*dir, *keyFile, *certFile)
	if err != nil {
		return err
	}
	rec, reused, err := ca.AdoptExternal(a.cfg, a.store, found, *slug)
	if err != nil {
		return err
	}
	if err := a.Out.Emit(caJSON(a.cfg, rec)); err != nil {
		return err
	}
	a.Out.Line("%s", rec.Slug)
	if reused {
		a.Out.Printf("이미 등록된 CA 입니다(지문이 같습니다). 그 등록을 그대로 씁니다.\n")
	} else {
		a.Out.Printf("외부 CA 를 등록했습니다. 개인키는 복사하지 않고 원래 자리에서 씁니다.\n")
	}
	a.printCA(rec)
	return nil
}

func (a *App) caImport(args []string) error {
	fs := flags("ca import")
	var (
		keyPath   = fs.String("key", "", "개인키 파일 (필수)")
		certPath  = fs.String("cert", "", "인증서 파일 (필수)")
		chainPath = fs.String("chain", "", "상위 체인 파일")
		slug      = fs.String("slug", "", "식별자")
		passStdin = fs.Bool("passphrase-stdin", false, "개인키 패스프레이즈를 stdin 에서 읽는다")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *keyPath == "" || *certPath == "" {
		return certerr.Validationf("--key 와 --cert 가 모두 필요합니다")
	}
	if err := a.open(true); err != nil {
		return err
	}
	passphrase, err := ReadSecret(SecretSource{
		Env: EnvKeyPassphrase, FromStdin: *passStdin,
	})
	if err != nil {
		return err
	}
	rec, err := ca.ImportExisting(a.cfg, a.store, ca.ImportOptions{
		KeyFile: *keyPath, CertFile: *certPath, ChainFile: *chainPath,
		Slug: *slug, Passphrase: passphrase,
	})
	if err != nil {
		return err
	}
	if err := a.Out.Emit(caJSON(a.cfg, rec)); err != nil {
		return err
	}
	a.Out.Line("%s", rec.Slug)
	a.Out.Printf("CA 를 상태 디렉터리로 가져왔습니다.\n")
	a.printCA(rec)
	return nil
}

// loadCA 는 발급·폐기에 쓸 CA 재료를 연다.
//
// --ca(이력) 과 --ca-dir(외부 디렉터리) 두 입구를 한 곳에서 처리한다. 사용자 지정 메뉴의
// "① 이력 기반 / ② rootCA 디렉터리 입력" 분기가 여기다.
func (a *App) loadCA(slug, dir string, passStdin bool) (ca.Material, error) {
	if slug == "" && dir == "" {
		list, err := a.store.ListCAs("active")
		if err != nil {
			return ca.Material{}, err
		}
		if len(list) == 1 {
			// CA 가 하나뿐이면 그것을 쓴다. 매번 같은 값을 타이핑하게 할 이유가 없다.
			slug = list[0].Slug
		} else if len(list) == 0 {
			return ca.Material{}, certerr.NotFoundf(
				"CA 가 없습니다. 'cert-gen ca create --cn \"<조직> Root CA\"' 로 만드세요")
		} else {
			return ca.Material{}, certerr.Validationf(
				"CA 가 여러 개입니다. --ca <식별자> 로 지정하세요 ('cert-gen ca list' 로 확인)")
		}
	}

	var rec store.CA
	if dir != "" {
		found, err := ca.DiscoverInDir(dir, "", "")
		if err != nil {
			return ca.Material{}, err
		}
		adopted, _, err := ca.AdoptExternal(a.cfg, a.store, found, "")
		if err != nil {
			return ca.Material{}, err
		}
		rec = adopted
	} else {
		var err error
		rec, err = a.store.GetCA(slug)
		if err != nil {
			return ca.Material{}, err
		}
	}

	var passphrase string
	if rec.KeyEncrypted {
		var err error
		passphrase, err = ReadSecret(SecretSource{
			Env: EnvCAPassphrase, FromStdin: passStdin,
			Prompt: fmt.Sprintf("CA(%s) 패스프레이즈: ", rec.Slug),
		})
		if err != nil {
			return ca.Material{}, err
		}
	}
	return ca.LoadMaterial(a.cfg, a.store, rec, passphrase)
}
