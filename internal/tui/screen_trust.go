package tui

// 5번 메뉴 — 서버에 CA 신뢰 등록.
//
// 자가서명 체인은 각 호스트가 Root CA 를 신뢰해야 동작하고, 그 절차가 OS·Java 마다 다르다.
// 이 화면은 **명령을 만들어 보여 준다**(사용자 요청: "인증서 선택 시 명령어도 제공").
//
// 실행하지 않는 이유: 신뢰 저장소 변경은 그 호스트의 보안 경계를 바꾸는 일이고 거의 항상
// root 권한이 필요하다. 도구가 조용히 해 버리면 무엇이 바뀌었는지도, 되돌리는 방법도
// 사용자가 모른다. 명령을 보여 주면 읽고, 복사하고, 변경 관리 절차에 넣을 수 있다.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/trust"
)

type trustScreen struct {
	app *Model

	form     *form
	caPick   *selectField
	platform *selectField
	javaHome *textField

	target *trust.Target
}

func newTrustScreen(app *Model) *trustScreen {
	s := &trustScreen{app: app}
	s.caPick = newSelectField("CA", nil, "신뢰 등록할 Root CA")
	choices := make([]choice, 0, len(trust.Platforms))
	for _, p := range trust.Platforms {
		choices = append(choices, choice{Value: string(p), Label: trust.Label(p)})
	}
	s.platform = newSelectField("등록 대상", choices, "")
	// 현재 호스트를 추정해 기본값으로 둔다. 추정이므로 바꿀 수 있다.
	s.platform.SetValue(string(trust.DetectPlatform()))
	s.javaHome = newTextField("JAVA_HOME", "Java 대상일 때만. 비우면 $JAVA_HOME 을 그대로 둔다", false)
	s.form = newForm("명령 만들기", 'g', s.caPick, s.platform, s.javaHome)
	return s
}

func (s *trustScreen) Title() string { return "서버에 CA 신뢰 등록" }

func (s *trustScreen) Init() tea.Cmd {
	list, err := s.app.store.ListCAs("")
	if err != nil {
		return fail(err)
	}
	choices := make([]choice, 0, len(list))
	for _, rec := range list {
		choices = append(choices, choice{
			Value: rec.Slug,
			Label: fmt.Sprintf("%s — %s", rec.Slug, rec.CommonName),
		})
	}
	s.caPick.SetChoices(choices)
	if len(choices) == 0 {
		return warn("CA 가 없습니다. 1번 메뉴에서 Root CA 를 먼저 만드세요")
	}
	return nil
}

func (s *trustScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	// 스크롤은 앱 셸이 처리한다(PgUp/PgDn). 화면마다 구현하면 키가 달라진다.
	return s, s.form.Update(key, s.submit)
}

func (s *trustScreen) submit() tea.Cmd {
	slug := s.caPick.Value()
	if slug == "" {
		return warn("CA 를 고르세요")
	}
	rec, err := s.app.store.GetCA(slug)
	if err != nil {
		return fail(err)
	}
	_, certPath, _ := ca.ResolvePaths(s.app.cfg, rec)

	target, err := trust.Build(trust.Platform(s.platform.Value()), trust.Options{
		CACertPath: certPath,
		Name:       rec.Slug,
		CommonName: rec.CommonName,
		JavaHome:   s.javaHome.Value(),
	})
	if err != nil {
		return fail(err)
	}
	s.target = &target
	if target.NeedsRoot {
		return tea.Batch(scrollEnd(), info("관리자(root) 권한으로 실행해야 합니다"))
	}
	return tea.Batch(scrollEnd(), good("명령을 만들었습니다"))
}

func (s *trustScreen) View(width, height int) string {
	var b strings.Builder
	b.WriteString(s.form.View(width - 2))

	if s.target == nil {
		b.WriteString("\n" + styleDim.Render(
			"대상을 고르고 실행하면 그 환경에 맞는 등록 명령을 만들어 줍니다.") + "\n")
		b.WriteString(styleDim.Render(
			"명령은 실행하지 않습니다. 신뢰 저장소 변경은 호스트의 보안 경계를 바꾸는 일이라") + "\n")
		b.WriteString(styleDim.Render(
			"무엇이 바뀌는지 보고, 필요하면 변경 관리 절차에 넣어 직접 실행하는 편이 맞습니다.") + "\n")
		return b.String()
	}

	t := *s.target
	b.WriteString("\n" + styleTitle.Render(t.Label) + "\n")
	if t.NeedsRoot {
		b.WriteString(styleWarn.Render("관리자(root) 권한 필요") + "\n")
	}
	if t.Note != "" {
		for _, line := range wrapDisplay(t.Note, width-6) {
			b.WriteString(styleDim.Render("  "+line) + "\n")
		}
	}

	// 명령은 복사해 쓰는 것이므로 박스에 그대로 넣는다. 줄을 접으면 복사했을 때 깨진다.
	b.WriteString("\n" + styleLabel.Render("실행할 명령") + "\n")
	b.WriteString(renderCommands(t.Commands, width))

	if len(t.Verify) > 0 {
		b.WriteString("\n" + styleLabel.Render("등록 확인") + "\n")
		b.WriteString(renderCommands(t.Verify, width))
	}
	if len(t.Remove) > 0 {
		// 되돌리는 방법을 함께 주지 않으면 사용자가 손을 못 댄다.
		b.WriteString("\n" + styleLabel.Render("되돌리기") + "\n")
		b.WriteString(renderCommands(t.Remove, width))
	}
	return b.String()
}

func renderCommands(cmds []string, width int) string {
	lines := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		for _, line := range strings.Split(cmd, "\n") {
			lines = append(lines, truncateDisplay(line, width-8))
		}
	}
	return styleBox.Width(width-4).Render(strings.Join(lines, "\n")) + "\n"
}

func (s *trustScreen) Help() []string { return s.form.Help() }

func (s *trustScreen) CapturesText() bool { return s.form.CapturesText() }
