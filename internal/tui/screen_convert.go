package tui

// 3번 메뉴 — 인증서 변환.
//
// 2번과 같은 대칭을 둔다(사용자 지정 구조).
//   ① 발급 이력에서 고르기
//   ② 외부 인증서 파일 경로 입력
//
// ② 가 없으면 기능이 반쪽이 된다. 실무에서 가장 잦은 변환이 "남이 준 PEM 을 p12 로" 다.

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/manifests"
)

const (
	srcHistory = "history"
	srcFiles   = "files"
)

type convertScreen struct {
	app *Model

	form     *form
	source   *selectField
	pick     *selectField
	certPath *textField
	keyPath  *textField
	caPath   *textField
	format   *selectField
	password *textField
	alias    *textField
	outPath  *textField
	k8sName  *textField
	k8sNS    *textField

	written     []string
	warnings    []string
	lastCommand string
}

func newConvertScreen(app *Model) *convertScreen {
	s := &convertScreen{app: app}
	s.build()
	return s
}

func (s *convertScreen) build() {
	s.source = newSelectField("변환 대상", []choice{
		{Value: srcHistory, Label: "① 발급 이력에서 고르기"},
		{Value: srcFiles, Label: "② 외부 인증서 파일 입력"},
	}, "")
	s.pick = newSelectField("인증서", nil, "")
	s.certPath = newTextField("인증서 파일", "/path/cert.pem", false)
	s.keyPath = newTextField("개인키 파일", "/path/privkey.pem (키스토어에 필요)", false)
	s.caPath = newTextField("CA 파일", "/path/ca.crt", false)
	s.format = newSelectField("포맷", []choice{
		{Value: string(export.FormatP12), Label: "PKCS#12 (.p12) — 범용 키스토어"},
		{Value: string(export.FormatJKS), Label: "JKS (.jks) — 레거시 Java"},
		{Value: string(export.FormatDER), Label: "DER (.der) — 인증서만"},
		{Value: string(export.FormatPEM), Label: "PEM — cert/key/fullchain/ca 분리"},
		{Value: string(export.FormatK8s), Label: "Kubernetes tls Secret (YAML)"},
		{Value: string(export.FormatTrust), Label: "신뢰 저장소 (CA 만, p12)"},
	}, "")
	s.password = newTextField("키스토어 비밀번호", "p12·JKS 에 필요 (JKS 는 6자 이상)", false)
	s.password.input.EchoMode = 1
	s.alias = newTextField("별칭", "비우면 CN 을 소문자로", false)
	s.outPath = newTextField("출력 경로", "비우면 현재 디렉터리", false)
	s.k8sName = newTextField("Secret 이름", "web-tls (K8s 포맷에만)", false)
	s.k8sNS = newTextField("네임스페이스", "databases 또는 비움", false)

	s.form = newForm("변환", 'x',
		s.source, s.pick, s.certPath, s.keyPath, s.caPath,
		s.format, s.password, s.alias, s.outPath, s.k8sName, s.k8sNS)
}

func (s *convertScreen) Title() string { return "인증서 변환" }

func (s *convertScreen) Init() tea.Cmd {
	list, err := s.app.store.ListCerts(storeFilterAll())
	if err != nil {
		return fail(err)
	}
	choices := make([]choice, 0, len(list))
	for _, rec := range list {
		label := fmt.Sprintf("#%d %s (%s, 만료 %s)",
			rec.ID, rec.CommonName, rec.Profile, shortDate(rec.NotAfter))
		if rec.Status != "valid" {
			label += " " + rec.Status
		}
		choices = append(choices, choice{Value: fmt.Sprintf("%d", rec.ID), Label: label})
	}
	s.pick.SetChoices(choices)
	if len(choices) == 0 {
		return info("발급 이력이 없습니다. ② 로 외부 파일을 변환할 수 있습니다")
	}
	return nil
}

func (s *convertScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	return s, s.form.Update(key, s.submit)
}

func (s *convertScreen) submit() tea.Cmd {
	s.written = nil
	s.warnings = nil

	in, ref, err := s.resolveInput()
	if err != nil {
		return fail(err)
	}

	opts := export.Options{Password: s.password.Value(), Alias: s.alias.Value()}
	format := export.Format(s.format.Value())

	var (
		results []export.Result
		cliCmd  string
	)
	switch format {
	case export.FormatP12:
		res, err := export.P12(in, opts)
		if err != nil {
			return fail(err)
		}
		results = []export.Result{res}
		cliCmd = fmt.Sprintf("cert-gen export p12 %s", ref)
	case export.FormatJKS:
		res, err := export.JKS(in, opts)
		if err != nil {
			return fail(err)
		}
		results = []export.Result{res}
		cliCmd = fmt.Sprintf("cert-gen export jks %s", ref)
	case export.FormatDER:
		results = []export.Result{export.DER(in)}
		cliCmd = fmt.Sprintf("cert-gen export der %s", ref)
	case export.FormatTrust:
		res, err := export.TrustStoreP12(in, opts)
		if err != nil {
			return fail(err)
		}
		results = []export.Result{res}
		cliCmd = fmt.Sprintf("cert-gen export p12 %s  # 신뢰 저장소는 CLI 에 별도 옵션", ref)
	case export.FormatPEM:
		results = append(results, export.CertPEM(in), export.FullchainPEM(in))
		if in.CA != nil {
			results = append(results, export.Result{
				Data: export.CertPEM(export.Input{Cert: in.CA}).Data, Filename: "ca.crt",
			})
		}
		if in.HasKey() {
			res, err := export.KeyPEM(in, "")
			if err != nil {
				return fail(err)
			}
			results = append(results, res)
		}
		cliCmd = fmt.Sprintf("cert-gen export pem %s", ref)
	case export.FormatK8s:
		name := s.k8sName.Value()
		if name == "" {
			return warn("Kubernetes Secret 이름이 필요합니다")
		}
		keyRes, err := export.KeyPEM(in, "")
		if err != nil {
			return fail(err)
		}
		var caPEM []byte
		if in.CA != nil {
			caPEM = export.CertPEM(export.Input{Cert: in.CA}).Data
		}
		data, err := manifests.TLSSecret(manifests.SecretOptions{
			Name: name, Namespace: s.k8sNS.Value(),
			FullchainPEM: export.FullchainPEM(in).Data, KeyPEM: keyRes.Data,
			CAPEM: caPEM,
		})
		if err != nil {
			return fail(err)
		}
		results = []export.Result{{Data: data, Filename: name + "-tls.yaml"}}
		cliCmd = fmt.Sprintf("cert-gen export k8s %s --secret-name %s", ref, name)
		if ns := s.k8sNS.Value(); ns != "" {
			cliCmd += " --namespace " + ns
		}
	default:
		return warn("포맷을 고르세요")
	}

	dir := s.outPath.Value()
	if dir == "" {
		dir = "."
	}
	for _, res := range results {
		s.warnings = append(s.warnings, res.Warnings...)
		path := dir
		// 단일 파일 포맷이고 출력이 파일명처럼 보이면 그대로 쓴다.
		if len(results) == 1 && filepath.Ext(dir) != "" {
			path = dir
		} else {
			if err := fsops.EnsureDir(dir, fsops.ModeDir); err != nil {
				return fail(err)
			}
			path = filepath.Join(dir, res.Filename)
		}
		mode := fsops.ModeSecret
		if strings.HasSuffix(path, ".crt") || strings.HasSuffix(path, ".yaml") ||
			strings.HasSuffix(path, ".der") || strings.HasSuffix(path, "fullchain.pem") ||
			strings.HasSuffix(path, "cert.pem") {
			mode = fsops.ModePublic
		}
		if err := fsops.WriteAtomic(path, res.Data, mode); err != nil {
			return fail(err)
		}
		s.written = append(s.written, path)
	}
	s.lastCommand = cliCmd
	return tea.Batch(scrollEnd(), good("%d개 파일을 만들었습니다", len(s.written)))
}

func (s *convertScreen) resolveInput() (export.Input, string, error) {
	if s.source.Value() == srcFiles {
		cert := s.certPath.Value()
		if cert == "" {
			return export.Input{}, "", fmt.Errorf("인증서 파일 경로를 입력하세요")
		}
		in, err := export.FromFiles(export.ExternalFiles{
			CertPath: cert, KeyPath: s.keyPath.Value(), CAPath: s.caPath.Value(),
		})
		ref := "--cert " + cert
		if k := s.keyPath.Value(); k != "" {
			ref += " --key " + k
		}
		return in, ref, err
	}
	id := s.pick.Value()
	if id == "" {
		return export.Input{}, "", fmt.Errorf("인증서를 고르세요 (없으면 ② 로 외부 파일을 쓰세요)")
	}
	rec, err := s.app.store.ResolveCert(id)
	if err != nil {
		return export.Input{}, "", err
	}
	in, err := export.FromBundle(s.app.cfg, rec, "")
	return in, id, err
}

func (s *convertScreen) View(width, height int) string {
	var b strings.Builder
	b.WriteString(s.form.View(width - 2))
	for _, w := range s.warnings {
		b.WriteString("\n" + styleWarn.Render("주의: ") + styleBody.Render(w))
	}
	if len(s.written) > 0 {
		b.WriteString("\n\n" + styleOK.Render("변환 완료") + "\n")
		for _, p := range s.written {
			b.WriteString(styleBody.Render("  "+truncateDisplay(p, width-6)) + "\n")
		}
	}
	if s.lastCommand != "" {
		b.WriteString("\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
			styleBox.Width(width-4).Render(wrapJoin(s.lastCommand, width-8)))
	}
	return b.String()
}

func (s *convertScreen) Help() []string { return s.form.Help() }

func (s *convertScreen) CapturesText() bool { return s.form.CapturesText() }
