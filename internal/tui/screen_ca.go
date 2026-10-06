package tui

// 1번 메뉴 — rootCA 생성.
//
// 키는 두 가지로 받는다. 즉석 생성과 0번 메뉴에서 만들어 둔 키 선택이다. 등록된 키를 쓰면
// 그 키를 **복사하지 않고 참조**한다(코어의 판단) — 복사하면 패스프레이즈를 제거해도 CA 가
// 쓰는 사본은 그대로 남아 두 상태가 갈라진다.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

const keySourceNew = "__new__"

type caScreen struct {
	app *Model

	form   *form
	cn     *textField
	org    *textField
	ou     *textField
	ctry   *textField
	keySrc *selectField
	algo   *selectField
	days   *textField
	pass   *textField

	result      *store.CA
	lastCommand string
	warnings    []string
}

func newCAScreen(app *Model) *caScreen {
	s := &caScreen{app: app}
	s.build()
	return s
}

func (s *caScreen) build() {
	s.cn = newTextField("Common Name", "HD Root CA", true)
	s.org = newTextField("Organization", "HaeDong", false)
	s.ou = newTextField("Organizational Unit", "", false)
	s.ctry = newTextField("Country", "KR", false)
	s.keySrc = newSelectField("개인키", nil, "0번 메뉴에서 만든 키를 고를 수 있습니다")
	s.algo = newSelectField("알고리즘", algoChoices(), "새로 만들 때만 쓰입니다")
	s.algo.SetValue(s.app.cfg.CA.DefaultKeyAlgo)
	s.days = newTextField("유효기간(일)", fmt.Sprintf("%d", s.app.cfg.CA.DefaultDays), false)
	// CA 키는 반대로 암호화가 기본이다. 앱 인증이 없으므로 이 패스프레이즈가 사실상
	// 유일한 서명 권한 통제다.
	s.pass = newTextField("패스프레이즈", "CA 키를 보호합니다 (비우면 평문 저장)", false)
	s.pass.input.EchoMode = 1
	s.form = newForm("CA 생성", 'g', s.cn, s.org, s.ou, s.ctry, s.keySrc, s.algo, s.days, s.pass)
}

func (s *caScreen) Title() string { return "rootCA 생성" }

func (s *caScreen) Init() tea.Cmd {
	// 등록된 키 목록을 채운다.
	list, err := keymgmt.List(s.app.cfg, s.app.store)
	if err != nil {
		return fail(err)
	}
	choices := []choice{{Value: keySourceNew, Label: "새로 생성"}}
	for _, item := range list {
		label := fmt.Sprintf("%s (%s, 쌍 %s)", item.Key.Name, item.Key.Algo, item.PairToken())
		if item.Key.Encrypted {
			label += " 암호"
		}
		choices = append(choices, choice{Value: item.Key.Name, Label: label})
	}
	s.keySrc.SetChoices(choices)
	return nil
}

func (s *caScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	return s, s.form.Update(key, s.submit)
}

func (s *caScreen) submit() tea.Cmd {
	s.warnings = nil
	days := 0
	if v := s.days.Value(); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &days); err != nil {
			return warn("유효기간은 숫자여야 합니다: %q", v)
		}
	}
	subject := names.Subject{
		CommonName: s.cn.Value(), Organization: s.org.Value(),
		OrganizationalUnit: s.ou.Value(), Country: s.ctry.Value(),
	}
	if subject.CommonName == "" {
		return warn("Common Name 이 필요합니다")
	}

	opts := ca.CreateOptions{Subject: subject, Days: days}
	keyRef := s.keySrc.Value()
	passphrase := s.pass.Value()

	if keyRef != "" && keyRef != keySourceNew {
		// 등록된 키를 쓴다. 그 키의 보호 수준은 키가 이미 가지고 있으므로 CA 쪽에서
		// 다시 암호화하지 않는다(코어가 그렇게 처리한다).
		loaded, err := keymgmt.Load(s.app.cfg, s.app.store, keyRef, passphrase)
		if err != nil {
			return fail(err)
		}
		opts.ExistingKey = loaded
	} else {
		opts.KeyAlgo = s.algo.Value()
		opts.Passphrase = passphrase
		require := passphrase != ""
		opts.RequirePassphrase = &require
		if passphrase == "" {
			s.warnings = append(s.warnings,
				"CA 개인키를 평문으로 저장합니다. 상태 디렉터리를 읽을 수 있는 사람이 곧 이 CA 입니다")
		}
	}

	rec, err := ca.CreateRoot(s.app.cfg, s.app.store, opts)
	if err != nil {
		return fail(err)
	}
	s.result = &rec

	cmd := fmt.Sprintf("cert-gen ca create --cn %q", subject.CommonName)
	if subject.Organization != "" {
		cmd += fmt.Sprintf(" --org %q", subject.Organization)
	}
	if subject.Country != "" {
		cmd += fmt.Sprintf(" --country %s", subject.Country)
	}
	if keyRef != "" && keyRef != keySourceNew {
		cmd += fmt.Sprintf(" --key %s", keyRef)
	} else {
		cmd += fmt.Sprintf(" --key-algo %s", opts.KeyAlgo)
	}
	if days > 0 {
		cmd += fmt.Sprintf(" --days %d", days)
	}
	if passphrase == "" && opts.ExistingKey == nil {
		cmd += " --no-passphrase"
	}
	s.lastCommand = cmd
	return tea.Batch(scrollEnd(), good("Root CA 를 만들었습니다: %s", rec.Slug))
}

func (s *caScreen) View(width, height int) string {
	var b strings.Builder
	b.WriteString(s.form.View(width - 2))

	for _, w := range s.warnings {
		b.WriteString("\n" + styleWarn.Render("주의: ") + styleBody.Render(w))
	}
	if s.result != nil {
		b.WriteString("\n\n" + styleOK.Render("생성 완료") + "\n")
		keyPath, certPath, _ := ca.ResolvePaths(s.app.cfg, *s.result)
		rows := [][2]string{
			{"식별자", s.result.Slug},
			{"Subject", s.result.SubjectDN},
			{"유효기간", shortDate(s.result.NotBefore) + " ~ " + shortDate(s.result.NotAfter)},
			{"지문", s.result.Fingerprint},
			{"인증서", certPath},
			{"개인키", keyPath},
		}
		for _, r := range rows {
			b.WriteString(styleLabel.Render(padDisplay("  "+r[0], 12)) +
				styleBody.Render(truncateDisplay(r[1], width-16)) + "\n")
		}
		b.WriteString("\n" + styleDim.Render("다음: 2번 메뉴에서 인증서를 발급하거나, 5번에서 클라이언트에 신뢰 등록합니다."))
	}
	if s.lastCommand != "" {
		b.WriteString("\n\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
			styleBox.Width(width-4).Render(wrapJoin(s.lastCommand, width-8)))
	}
	return b.String()
}

func wrapJoin(text string, width int) string {
	return strings.Join(wrapDisplay(text, width), "\n  ")
}

func shortDate(iso string) string {
	if len(iso) >= 10 {
		return iso[:10]
	}
	return iso
}

func (s *caScreen) Help() []string { return s.form.Help() }

func (s *caScreen) CapturesText() bool { return s.form.CapturesText() }
