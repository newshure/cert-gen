package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/csr"
	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/manifests"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
)

// --- csr ---------------------------------------------------------------------

func (a *App) csrCreate(args []string) error {
	fs := flags("csr create")
	subj := subjectFlags(fs)
	var sans repeatable
	fs.Var(&sans, "san", "SAN. 반복 지정")
	var (
		keyAlgo    = fs.String("key-algo", "rsa2048", "키 알고리즘")
		outDir     = fs.String("o", ".", "출력 디렉터리")
		encryptKey = fs.Bool("encrypt-key", false, "개인키를 암호화한다 (서버 기동 시 패스프레이즈를 묻게 된다)")
		passStdin  = fs.Bool("passphrase-stdin", false, "개인키 패스프레이즈를 stdin 에서 읽는다")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if subj.CommonName == "" {
		return certerr.Validationf("--cn 이 필요합니다")
	}
	var passphrase string
	if *encryptKey {
		var err error
		passphrase, err = ReadSecret(SecretSource{
			Env: EnvKeyPassphrase, FromStdin: *passStdin,
			Prompt: "개인키 패스프레이즈: ", Confirm: !*passStdin,
		})
		if err != nil {
			return err
		}
	}
	out, err := csr.Create(csr.CreateOptions{
		Subject: *subj, SANValues: sans, KeyAlgo: *keyAlgo, Passphrase: passphrase,
	})
	if err != nil {
		return err
	}
	if err := fsops.EnsureDir(*outDir, fsops.ModeDir); err != nil {
		return err
	}
	base := nameSlug(subj.CommonName)
	csrPath := filepath.Join(*outDir, base+".csr")
	keyPath := filepath.Join(*outDir, base+".key")
	if err := fsops.WriteAtomic(csrPath, out.CSRPEM, fsops.ModePublic); err != nil {
		return err
	}
	// 개인키는 0600 이다. CSR 만 외부로 나가고 이 파일은 나가지 않는다.
	if err := fsops.WriteAtomic(keyPath, out.KeyPEM, fsops.ModeSecret); err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{
		"csr": csrPath, "key": keyPath, "common_name": subj.CommonName,
		"key_algo": *keyAlgo, "key_encrypted": out.KeyEncrypted,
	}); err != nil {
		return err
	}
	a.Out.Line("%s", csrPath)
	a.Out.Printf("CSR 을 만들었습니다.\n")
	a.Out.Printf("  CSR           %s  ← 이것만 CA 에 제출합니다\n", csrPath)
	a.Out.Printf("  개인키        %s  ← 절대 외부로 보내지 않습니다\n", keyPath)
	a.Out.Printf("  SAN           %s\n", sanListText(out.SANs))
	return nil
}

func sanListText(sans []names.SAN) string {
	parts := make([]string, 0, len(sans))
	for _, s := range sans {
		parts = append(parts, s.Type+":"+s.Value)
	}
	if len(parts) == 0 {
		return "(없음)"
	}
	return strings.Join(parts, ", ")
}

func nameSlug(cn string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == '*':
			return -1
		default:
			return '-'
		}
	}, cn)
	slug = strings.Trim(strings.ReplaceAll(slug, "--", "-"), "-.")
	if slug == "" {
		return "cert"
	}
	return slug
}

func (a *App) csrSign(args []string) error {
	fs := flags("csr sign")
	var overrideSANs repeatable
	fs.Var(&overrideSANs, "override-san", "CSR 의 SAN 을 이것으로 대체. 반복 지정")
	var (
		csrPath   = fs.String("csr", "", "CSR 파일 (필수)")
		caSlug    = fs.String("ca", "", "CA 식별자")
		caDir     = fs.String("ca-dir", "", "CA 가 있는 디렉터리")
		profile   = fs.String("profile", "", "프로필 ("+strings.Join(profiles.Leaf, " | ")+")")
		days      = fs.Int("days", 0, "유효기간(일)")
		note      = fs.String("note", "", "메모")
		outDir    = fs.String("o", "", "번들을 이 디렉터리에 풀어 놓는다")
		passStdin = fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *csrPath == "" {
		return certerr.Validationf("--csr 이 필요합니다")
	}
	parsed, err := csr.ParseFile(*csrPath)
	if err != nil {
		return err
	}
	// CSR 이 확장을 요청했거나 키가 약하면 서명 전에 알린다.
	a.Out.Warnings(parsed.Warnings)

	if err := a.open(true); err != nil {
		return err
	}
	material, err := a.loadCA(*caSlug, *caDir, *passStdin)
	if err != nil {
		return err
	}
	res, err := issue.SignCSR(a.cfg, a.store, issue.SignCSROptions{
		Material: material, CSR: parsed.Request, Profile: *profile, Days: *days,
		OverrideSANs: overrideSANs, Note: *note, Frontend: "cli",
		CommonName: parsed.CommonName, SANs: parsed.SANs, CSRPEM: parsed.PEM,
	})
	if err != nil {
		return err
	}
	a.Out.Warnings(res.Warnings)

	var extracted []string
	if *outDir != "" {
		extracted, err = bundle.ExtractTo(res.BundlePath, *outDir)
		if err != nil {
			return err
		}
	}
	if err := a.Out.Emit(map[string]any{
		"id": res.Record.ID, "serial": res.Record.SerialHex,
		"common_name": res.Record.CommonName, "bundle": res.BundlePath,
		"extracted": extracted,
	}); err != nil {
		return err
	}
	a.Out.Line("%d", res.Record.ID)
	a.Out.Printf("CSR 을 서명했습니다. CSR 의 확장은 쓰지 않고 프로필(%s)을 적용했습니다.\n",
		res.Record.Profile)
	a.printCert(res.Record)
	a.Out.Printf("  번들          %s\n", res.BundlePath)
	a.Out.Printf("\n이 번들에는 개인키가 없습니다. 요청자가 가지고 있습니다.\n")
	return nil
}

// --- export ------------------------------------------------------------------

// convertInput 은 변환 대상을 해석한다.
//
// ① 발급 이력(ID|serial|CN) ② 외부 파일(--cert/--key). 사용자 지정 메뉴의 "인증서 변환"
// 분기가 여기다.
type convertFlags struct {
	certPath  string
	keyPath   string
	chainPath string
	caPath    string
	passStdin bool
}

func addConvertFlags(fs *flag.FlagSet, c *convertFlags) {
	fs.StringVar(&c.certPath, "cert", "", "외부 인증서 파일 (이력 대신)")
	fs.StringVar(&c.keyPath, "key", "", "외부 개인키 파일")
	fs.StringVar(&c.chainPath, "chain", "", "외부 체인 파일")
	fs.StringVar(&c.caPath, "ca-file", "", "외부 CA 인증서 파일")
	fs.BoolVar(&c.passStdin, "key-passphrase-stdin", false, "개인키 패스프레이즈를 stdin 에서 읽는다")
}

func (a *App) convertInput(rest []string, c convertFlags) (export.Input, *store.Cert, error) {
	if c.certPath != "" {
		passphrase, err := ReadSecret(SecretSource{Env: EnvKeyPassphrase, FromStdin: c.passStdin})
		if err != nil {
			return export.Input{}, nil, err
		}
		in, err := export.FromFiles(export.ExternalFiles{
			CertPath: c.certPath, KeyPath: c.keyPath,
			ChainPath: c.chainPath, CAPath: c.caPath, Passphrase: passphrase,
		})
		return in, nil, err
	}
	if len(rest) != 1 {
		return export.Input{}, nil, certerr.Validationf(
			"변환 대상이 필요합니다: 발급 이력(ID|serial|CN) 또는 --cert <파일>")
	}
	if err := a.open(false); err != nil {
		return export.Input{}, nil, err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return export.Input{}, nil, err
	}
	in, err := export.FromBundle(a.cfg, rec, "")
	if err != nil {
		return export.Input{}, nil, err
	}
	return in, &rec, nil
}

func (a *App) exportKeystore(name string, args []string, jks bool) error {
	fs := flags("export " + name)
	var conv convertFlags
	addConvertFlags(fs, &conv)
	var (
		alias     = fs.String("alias", "", "키스토어 별칭 (기본: CN)")
		outPath   = fs.String("o", "", "출력 파일")
		legacy    = fs.Bool("legacy", false, "구형 소비자용 약한 알고리즘 (Java 8, 옛 Windows)")
		passStdin = fs.Bool("password-stdin", false, "키스토어 비밀번호를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	in, _, err := a.convertInput(rest, conv)
	if err != nil {
		return err
	}
	prompt := "키스토어 비밀번호: "
	password, err := ReadSecret(SecretSource{
		Env: EnvExportPassword, FromStdin: *passStdin, Prompt: prompt, Confirm: !*passStdin,
	})
	if err != nil {
		return err
	}
	opts := export.Options{Password: password, Alias: *alias, Legacy: *legacy}
	var res export.Result
	if jks {
		res, err = export.JKS(in, opts)
	} else {
		res, err = export.P12(in, opts)
	}
	if err != nil {
		return err
	}
	return a.writeResult(res, *outPath)
}

func (a *App) exportP12(args []string) error { return a.exportKeystore("p12", args, false) }
func (a *App) exportJKS(args []string) error { return a.exportKeystore("jks", args, true) }

func (a *App) exportDER(args []string) error {
	fs := flags("export der")
	var conv convertFlags
	addConvertFlags(fs, &conv)
	outPath := fs.String("o", "", "출력 파일")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	in, _, err := a.convertInput(rest, conv)
	if err != nil {
		return err
	}
	return a.writeResult(export.DER(in), *outPath)
}

func (a *App) exportPEM(args []string) error {
	fs := flags("export pem")
	var conv convertFlags
	addConvertFlags(fs, &conv)
	var (
		outDir     = fs.String("o", ".", "출력 디렉터리")
		encryptKey = fs.Bool("encrypt-key", false, "개인키를 암호화한다")
		passStdin  = fs.Bool("password-stdin", false, "개인키 패스프레이즈를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	in, _, err := a.convertInput(rest, conv)
	if err != nil {
		return err
	}
	if err := fsops.EnsureDir(*outDir, fsops.ModeDir); err != nil {
		return err
	}

	type item struct {
		res    export.Result
		secret bool
	}
	items := []item{
		{export.CertPEM(in), false},
		{export.FullchainPEM(in), false},
	}
	if in.CA != nil {
		items = append(items, item{export.Result{
			Data: export.CertPEM(export.Input{Cert: in.CA}).Data, Filename: "ca.crt",
		}, false})
	}
	if in.HasKey() {
		var passphrase string
		if *encryptKey {
			passphrase, err = ReadSecret(SecretSource{
				Env: EnvKeyPassphrase, FromStdin: *passStdin,
				Prompt: "개인키 패스프레이즈: ", Confirm: !*passStdin,
			})
			if err != nil {
				return err
			}
		}
		keyRes, err := export.KeyPEM(in, passphrase)
		if err != nil {
			return err
		}
		items = append(items, item{keyRes, true})
	}

	written := make([]string, 0, len(items))
	for _, it := range items {
		mode := fsops.ModePublic
		if it.secret {
			mode = fsops.ModeSecret
		}
		path := filepath.Join(*outDir, it.res.Filename)
		if err := fsops.WriteAtomic(path, it.res.Data, mode); err != nil {
			return err
		}
		a.Out.Warnings(it.res.Warnings)
		written = append(written, path)
	}
	if err := a.Out.Emit(map[string]any{"files": written}); err != nil {
		return err
	}
	for _, path := range written {
		a.Out.Line("%s", path)
	}
	return nil
}

func (a *App) exportK8s(args []string) error {
	fs := flags("export k8s")
	var conv convertFlags
	addConvertFlags(fs, &conv)
	var (
		secretName = fs.String("secret-name", "", "Secret 이름 (필수)")
		namespace  = fs.String("namespace", "", "네임스페이스")
		useToken   = fs.Bool("namespace-token", false, "네임스페이스를 "+manifests.NamespaceToken+" 토큰으로 둔다")
		withCA     = fs.Bool("with-ca", false, "ca.crt 키를 추가한다 (mTLS 클라이언트 검증용)")
		appLabel   = fs.String("app", "", "app=<값> 라벨을 붙인다")
		ingHost    = fs.String("ingress-host", "", "Ingress 를 함께 만든다 (호스트명)")
		ingService = fs.String("ingress-service", "", "백엔드 서비스 (name:port)")
		ingName    = fs.String("ingress-name", "", "Ingress 이름 (기본: <secret>-ingress)")
		outPath    = fs.String("o", "", "출력 파일")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *secretName == "" {
		return certerr.Validationf("--secret-name 이 필요합니다")
	}
	in, _, err := a.convertInput(rest, conv)
	if err != nil {
		return err
	}
	keyRes, err := export.KeyPEM(in, "")
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if *appLabel != "" {
		labels["app"] = *appLabel
	}
	var caPEM []byte
	if in.CA != nil {
		caPEM = export.CertPEM(export.Input{Cert: in.CA}).Data
	}
	secret, err := manifests.TLSSecret(manifests.SecretOptions{
		Name: *secretName, Namespace: *namespace, UseToken: *useToken,
		FullchainPEM: export.FullchainPEM(in).Data, KeyPEM: keyRes.Data,
		CAPEM: caPEM, IncludeCA: *withCA, Labels: labels,
	})
	if err != nil {
		return err
	}
	docs := secret

	if *ingHost != "" {
		if *ingService == "" {
			return certerr.Validationf("--ingress-host 와 함께 --ingress-service name:port 가 필요합니다")
		}
		svc, port, err := splitServicePort(*ingService)
		if err != nil {
			return err
		}
		name := *ingName
		if name == "" {
			name = *secretName + "-ingress"
		}
		ingress, err := manifests.Ingress(manifests.IngressOptions{
			Name: name, Namespace: *namespace, UseToken: *useToken,
			Host: *ingHost, SecretName: *secretName, Service: svc, Port: port,
			SSLRedirect: true,
		})
		if err != nil {
			return err
		}
		docs = append(append(docs, []byte("---\n")...), ingress...)
	}
	return a.writeResult(export.Result{Data: docs, Filename: *secretName + "-tls.yaml"}, *outPath)
}

func splitServicePort(value string) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, certerr.Validationf("서비스는 name:port 형식이어야 합니다: %q", value)
	}
	var port int
	if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
		return "", 0, certerr.Validationf("포트를 해석할 수 없습니다: %q", parts[1])
	}
	return parts[0], port, nil
}

// writeResult 는 변환 결과를 파일이나 stdout 으로 낸다.
func (a *App) writeResult(res export.Result, outPath string) error {
	a.Out.Warnings(res.Warnings)
	if outPath == "-" {
		// 바이너리를 터미널에 쏟지 않도록 호출자가 명시적으로 "-" 를 줘야 한다.
		fmt.Fprint(a.Out.W, string(res.Data))
		return nil
	}
	path := outPath
	if path == "" {
		path = res.Filename
	}
	// 키스토어·개인키가 섞여 있을 수 있으므로 0600 으로 쓴다.
	mode := fsops.ModeSecret
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".der") ||
		strings.HasSuffix(path, ".crt") {
		mode = fsops.ModePublic
	}
	if err := fsops.WriteAtomic(path, res.Data, mode); err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{"file": path, "bytes": len(res.Data)}); err != nil {
		return err
	}
	a.Out.Line("%s", path)
	return nil
}

// --- crl ---------------------------------------------------------------------

func (a *App) crlGenerate(args []string) error {
	fs := flags("crl generate")
	passStdin := fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	slug := ""
	if len(rest) == 1 {
		slug = rest[0]
	}
	material, err := a.loadCA(slug, "", *passStdin)
	if err != nil {
		return err
	}
	g, err := crl.Generate(a.cfg, a.store, material, "cli")
	if err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{
		"path": g.Path, "number": g.Number, "count": g.Count,
		"this_update": g.ThisUpdate, "next_update": g.NextUpdate,
	}); err != nil {
		return err
	}
	a.Out.Line("%s", g.Path)
	a.Out.Printf("%s\n", crl.Describe(g))
	return nil
}

func (a *App) crlList(args []string) error {
	fs := flags("crl list")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	var caRec store.CA
	if len(rest) == 1 {
		caRec, err = a.store.GetCA(rest[0])
		if err != nil {
			return err
		}
	} else {
		list, err := a.store.ListCAs("active")
		if err != nil {
			return err
		}
		if len(list) != 1 {
			return certerr.Validationf("CA 식별자를 지정하세요: cert-gen crl list SLUG")
		}
		caRec = list[0]
	}
	revoked, err := a.store.RevokedForCA(caRec.ID)
	if err != nil {
		return err
	}
	if a.Out.JSON {
		out := make([]map[string]any, 0, len(revoked))
		for _, rec := range revoked {
			out = append(out, certJSON(rec))
		}
		return a.Out.Emit(out)
	}
	rows := make([][]string, 0, len(revoked))
	for _, rec := range revoked {
		rows = append(rows, []string{
			fmt.Sprintf("%d", rec.ID), Truncate(rec.CommonName, 26),
			shortDate(rec.RevokedAt), rec.RevokeReason,
		})
	}
	a.Out.Table([]string{"ID", "CN", "폐기일", "사유"}, rows)
	if list, err := crl.Load(a.cfg, caRec); err == nil {
		a.Out.Printf("\nCRL #%s, 다음 갱신 %s\n", list.Number, list.NextUpdate.Format("2006-01-02"))
	} else {
		a.Out.Printf("\nCRL 파일이 아직 없습니다: cert-gen crl generate %s\n", caRec.Slug)
	}
	return nil
}
