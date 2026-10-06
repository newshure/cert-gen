package tui

// 2번 메뉴 — 인증서 발급.
//
// CA 선택이 두 갈래다(사용자 지정 구조).
//   ① 발급 이력 기반    → DB 의 CA 목록에서 고른다
//   ② rootCA 디렉터리   → 외부 CA 를 그 자리에서 쓴다 (개인키를 복사하지 않는다)
//
// ② 를 두는 이유: 자가서명 도구가 흔히 "CA 는 내가 소유한다" 를 전제해 **이미 쓰고 있는
// CA 로는 발급을 못 한다.** 이 분기로 그 함정을 피한다.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
)

const (
	caSourceHistory = "history"
	caSourceDir     = "dir"
)

type issueScreen struct {
	app *Model

	form    *form
	caSrc   *selectField
	caPick  *selectField
	caDir   *textField
	caPass  *textField
	cn      *textField
	sans    *areaField
	profile *selectField
	keySrc  *selectField
	algo    *selectField
	days    *textField
	outDir  *textField

	result      *issue.Result
	warnings    []string
	lastCommand string
	extracted   []string
}

func newIssueScreen(app *Model) *issueScreen {
	s := &issueScreen{app: app}
	s.build()
	return s
}

func (s *issueScreen) build() {
	s.caSrc = newSelectField("CA 선택 방식", []choice{
		{Value: caSourceHistory, Label: "① 발급 이력에서 고르기"},
		{Value: caSourceDir, Label: "② rootCA 가 있는 디렉터리 입력"},
	}, "외부 CA 는 개인키를 복사하지 않고 그 자리에서 씁니다")
	s.caPick = newSelectField("CA", nil, "")
	s.caDir = newTextField("CA 디렉터리", "/path/to/ca  (ca.key·ca.crt 를 찾습니다)", false)
	s.caPass = newTextField("CA 패스프레이즈", "암호화된 CA 키일 때만", false)
	s.caPass.input.EchoMode = 1

	s.cn = newTextField("Common Name", "web.hd.local", true)
	// SAN 은 여러 줄이다. 한 줄 입력이면 Enter 가 제출로 먹혀 줄바꿈이 안 된다.
	s.sans = newAreaField("SAN (한 줄에 하나)",
		"dns:api.hd.local / ip:10.0.0.5 — 접두어를 생략하면 자동 판별합니다. CN 은 자동 포함됩니다", 4)
	s.profile = newSelectField("프로필", profileChoices(), "")
	s.profile.SetValue(s.app.cfg.Cert.DefaultProfile)
	s.keySrc = newSelectField("개인키", nil, "0번 메뉴에서 만든 키를 고를 수 있습니다")
	s.algo = newSelectField("알고리즘", algoChoices(), "새로 만들 때만 쓰입니다")
	s.algo.SetValue(s.app.cfg.Cert.DefaultKeyAlgo)
	s.days = newTextField("유효기간(일)", fmt.Sprintf("%d", s.app.cfg.Cert.DefaultDays), false)
	s.outDir = newTextField("번들 풀어 놓을 위치", "비우면 상태 디렉터리에만 보관", false)

	s.form = newForm("발급", 'i',
		s.caSrc, s.caPick, s.caDir, s.caPass,
		s.cn, s.sans, s.profile, s.keySrc, s.algo, s.days, s.outDir)
}

func profileChoices() []choice {
	out := make([]choice, 0, len(profiles.Leaf))
	for _, name := range profiles.Leaf {
		p, err := profiles.Get(name)
		if err != nil {
			continue
		}
		out = append(out, choice{Value: name, Label: p.Short})
	}
	return out
}

func (s *issueScreen) Title() string { return "인증서 발급" }

func (s *issueScreen) Init() tea.Cmd {
	caList, err := s.app.store.ListCAs("active")
	if err != nil {
		return fail(err)
	}
	choices := make([]choice, 0, len(caList))
	for _, rec := range caList {
		label := fmt.Sprintf("%s — %s", rec.Slug, rec.CommonName)
		if rec.IsExternal {
			label += " (외부)"
		}
		choices = append(choices, choice{Value: rec.Slug, Label: label})
	}
	s.caPick.SetChoices(choices)

	keyList, err := keymgmt.List(s.app.cfg, s.app.store)
	if err != nil {
		return fail(err)
	}
	keyChoices := []choice{{Value: keySourceNew, Label: "새로 생성"}}
	for _, item := range keyList {
		label := fmt.Sprintf("%s (%s, 쌍 %s)", item.Key.Name, item.Key.Algo, item.PairToken())
		keyChoices = append(keyChoices, choice{Value: item.Key.Name, Label: label})
	}
	s.keySrc.SetChoices(keyChoices)

	if len(choices) == 0 {
		// CA 가 없으면 발급할 수 없다. 1번으로 유도한다.
		return warn("CA 가 없습니다. 1번 메뉴에서 Root CA 를 먼저 만들거나, " +
			"CA 선택 방식을 ② 로 바꿔 외부 CA 디렉터리를 지정하세요")
	}
	return nil
}

func (s *issueScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	return s, s.form.Update(key, s.submit)
}

func (s *issueScreen) submit() tea.Cmd {
	s.warnings = nil
	s.result = nil
	s.extracted = nil

	if s.cn.Value() == "" {
		return warn("Common Name 이 필요합니다")
	}
	days := 0
	if v := s.days.Value(); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &days); err != nil {
			return warn("유효기간은 숫자여야 합니다: %q", v)
		}
	}

	material, caRef, err := s.resolveCA()
	if err != nil {
		return fail(err)
	}

	opts := issue.Options{
		Material:  material,
		Subject:   names.Subject{CommonName: s.cn.Value()},
		SANValues: s.sans.Values(),
		Profile:   s.profile.Value(),
		Days:      days,
		Frontend:  "tui",
	}
	if ref := s.keySrc.Value(); ref != "" && ref != keySourceNew {
		loaded, err := keymgmt.Load(s.app.cfg, s.app.store, ref, "")
		if err != nil {
			return fail(err)
		}
		opts.ExistingKey = loaded
	} else {
		opts.KeyAlgo = s.algo.Value()
	}

	res, err := issue.Issue(s.app.cfg, s.app.store, opts)
	if err != nil {
		return fail(err)
	}
	s.result = &res
	s.warnings = res.Warnings

	if out := s.outDir.Value(); out != "" {
		written, err := bundle.ExtractTo(res.BundlePath, out)
		if err != nil {
			return fail(err)
		}
		s.extracted = written
	}
	s.lastCommand = s.buildCommand(caRef, days)
	return tea.Batch(scrollEnd(),
		good("발급 완료: #%d %s", res.Record.ID, res.Record.CommonName))
}

// resolveCA 는 선택 방식에 따라 CA 재료를 연다.
func (s *issueScreen) resolveCA() (ca.Material, string, error) {
	passphrase := s.caPass.Value()

	if s.caSrc.Value() == caSourceDir {
		dir := s.caDir.Value()
		if dir == "" {
			return ca.Material{}, "", fmt.Errorf("CA 디렉터리를 입력하세요")
		}
		found, err := ca.DiscoverInDir(dir, "", "")
		if err != nil {
			return ca.Material{}, "", err
		}
		// 외부 CA 도 이력에 한 번 등록한다. 그래야 serial·순번 관리가 등록 CA 와 같은
		// 경로를 타고 "외부 CA 로 발급했다" 는 사실도 추적된다.
		rec, _, err := ca.AdoptExternal(s.app.cfg, s.app.store, found, "")
		if err != nil {
			return ca.Material{}, "", err
		}
		material, err := ca.LoadMaterial(s.app.cfg, s.app.store, rec, passphrase)
		return material, "--ca-dir " + dir, err
	}

	slug := s.caPick.Value()
	if slug == "" {
		return ca.Material{}, "", fmt.Errorf("CA 를 고르세요 (없으면 1번 메뉴에서 만듭니다)")
	}
	rec, err := s.app.store.GetCA(slug)
	if err != nil {
		return ca.Material{}, "", err
	}
	material, err := ca.LoadMaterial(s.app.cfg, s.app.store, rec, passphrase)
	return material, "--ca " + slug, err
}

func (s *issueScreen) buildCommand(caRef string, days int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "cert-gen cert issue %s --cn %s", caRef, s.cn.Value())
	for _, san := range s.sans.Values() {
		fmt.Fprintf(&b, " --san %s", san)
	}
	if p := s.profile.Value(); p != "" && p != s.app.cfg.Cert.DefaultProfile {
		fmt.Fprintf(&b, " --profile %s", p)
	}
	if ref := s.keySrc.Value(); ref != "" && ref != keySourceNew {
		fmt.Fprintf(&b, " --key %s", ref)
	} else if a := s.algo.Value(); a != "" && a != s.app.cfg.Cert.DefaultKeyAlgo {
		fmt.Fprintf(&b, " --key-algo %s", a)
	}
	if days > 0 && days != s.app.cfg.Cert.DefaultDays {
		fmt.Fprintf(&b, " --days %d", days)
	}
	if out := s.outDir.Value(); out != "" {
		fmt.Fprintf(&b, " -o %s", out)
	}
	return b.String()
}

func (s *issueScreen) View(width, height int) string {
	var b strings.Builder

	// 선택 방식에 따라 관련 없는 필드를 흐리게 둔다. 숨기면 Tab 순서가 바뀌어 손에 익은
	// 흐름이 깨지므로, 보이되 관계없음을 표시한다.
	b.WriteString(s.form.View(width - 2))

	for _, w := range s.warnings {
		b.WriteString("\n" + styleWarn.Render("주의: ") + styleBody.Render(w))
	}
	if s.result != nil {
		b.WriteString("\n\n" + styleOK.Render("발급 완료") + "\n")
		rec := s.result.Record
		rows := [][2]string{
			{"ID", fmt.Sprintf("%d (CA 내 %d번)", rec.ID, rec.Seq)},
			{"Subject", rec.SubjectDN},
			{"SAN", sanSummary(rec)},
			{"프로필", rec.Profile + " / " + rec.KeyAlgo},
			{"유효기간", shortDate(rec.NotBefore) + " ~ " + shortDate(rec.NotAfter)},
			{"쌍", keymgmt.PairToken(rec.PublicSHA256)},
			{"번들", s.result.BundlePath},
		}
		for _, r := range rows {
			b.WriteString(styleLabel.Render(padDisplay("  "+r[0], 10)) +
				styleBody.Render(truncateDisplay(r[1], width-14)) + "\n")
		}
		for _, p := range s.extracted {
			b.WriteString(styleDim.Render("  풀어 놓음  "+truncateDisplay(p, width-14)) + "\n")
		}
		b.WriteString("\n" + styleDim.Render("서버에 올릴 파일: fullchain.pem + privkey.pem / 클라이언트 신뢰 등록: ca.crt"))
	}
	if s.lastCommand != "" {
		b.WriteString("\n\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
			styleBox.Width(width-4).Render(wrapJoin(s.lastCommand, width-8)))
	}
	return b.String()
}

func sanSummary(rec store.Cert) string {
	if len(rec.SANs) == 0 {
		return "(없음)"
	}
	parts := make([]string, 0, len(rec.SANs))
	for _, san := range rec.SANs {
		parts = append(parts, san.Type+":"+san.Value)
	}
	return strings.Join(parts, ", ")
}

func (s *issueScreen) Help() []string { return s.form.Help() }

func (s *issueScreen) CapturesText() bool { return s.form.CapturesText() }
