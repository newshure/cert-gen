package tui

// 0번 메뉴 — 개인키 생성·관리.
//
// 키를 먼저 만들어 두면 CA 생성(1번)과 발급(2번)에서 그 키를 고를 수 있다. 목록에 '쌍'
// 열을 두어 어느 키가 어느 인증서의 짝인지 눈으로 맞출 수 있게 한다.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/keys"
)

type keysLoadedMsg struct {
	list []keymgmt.Info
	err  error
}

type keysScreen struct {
	app  *Model
	list []keymgmt.Info
	row  int

	// creating 이면 생성 폼을 보여 준다.
	creating bool
	form     *form
	name     *textField
	algo     *selectField
	pass     *textField
	note     *textField

	lastCommand string
}

func newKeysScreen(app *Model) *keysScreen {
	return &keysScreen{app: app}
}

func (s *keysScreen) Title() string {
	if s.creating {
		return "개인키 생성"
	}
	return "개인키 관리"
}

func (s *keysScreen) Init() tea.Cmd {
	return s.reload()
}

func (s *keysScreen) reload() tea.Cmd {
	return func() tea.Msg {
		list, err := keymgmt.List(s.app.cfg, s.app.store)
		return keysLoadedMsg{list, err}
	}
}

func (s *keysScreen) buildForm() {
	s.name = newTextField("이름", "web-key (영숫자와 - _ . 만)", true)
	s.algo = newSelectField("알고리즘", algoChoices(), "")
	s.algo.SetValue(s.app.cfg.Cert.DefaultKeyAlgo)
	// 패스프레이즈는 기본으로 비워 둔다. 서버가 읽을 키에 걸면 기동할 때마다 묻는다.
	s.pass = newTextField("패스프레이즈", "비워 두면 평문 (서버 기동 시 묻지 않음)", false)
	s.pass.input.EchoMode = 1 // EchoPassword
	s.note = newTextField("메모", "용도 등", false)
	s.form = newForm("생성", 'c', s.name, s.algo, s.pass, s.note)
}

func algoChoices() []choice {
	out := make([]choice, 0, len(keys.Specs))
	for _, spec := range keys.Specs {
		out = append(out, choice{Value: spec.Name, Label: spec.Described()})
	}
	return out
}

func (s *keysScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case keysLoadedMsg:
		if msg.err != nil {
			return s, fail(msg.err)
		}
		s.list = msg.list
		if s.row >= len(s.list) {
			s.row = max(0, len(s.list)-1)
		}
		return s, nil

	case tea.KeyMsg:
		if s.creating {
			return s.updateForm(msg)
		}
		return s.updateList(msg)
	}
	return s, nil
}

func (s *keysScreen) updateForm(msg tea.KeyMsg) (screen, tea.Cmd) {
	if msg.String() == "esc" {
		s.creating = false
		return s, info("취소했습니다")
	}
	cmd := s.form.Update(msg, s.submitCreate)
	return s, cmd
}

func (s *keysScreen) submitCreate() tea.Cmd {
	name := s.name.Value()
	algo := s.algo.Value()
	pass := s.pass.Value()
	note := s.note.Value()

	info, err := keymgmt.Create(s.app.cfg, s.app.store, keymgmt.CreateOptions{
		Name: name, Algo: algo, Passphrase: pass, Note: note, Frontend: "tui",
	})
	if err != nil {
		return fail(err)
	}
	s.creating = false
	// 같은 일을 하는 CLI 명령을 보여 준다. TUI 로 익힌 절차를 스크립트로 옮길 수 있어야 한다.
	s.lastCommand = fmt.Sprintf("cert-gen key create --name %s --key-algo %s", name, algo)
	if pass != "" {
		s.lastCommand += "  # 패스프레이즈는 CERT_GEN_KEY_PASSPHRASE 로 준다"
	}
	return tea.Batch(s.reload(), good("키를 만들었습니다: %s (쌍 %s)", name, info.PairToken()))
}

func (s *keysScreen) updateList(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if s.row > 0 {
			s.row--
		}
		return s, nil
	case "down", "j":
		if s.row < len(s.list)-1 {
			s.row++
		}
		return s, nil
	case "n", "c":
		s.buildForm()
		s.creating = true
		return s, nil
	case "d":
		return s, s.deleteSelected()
	case "p":
		return s, s.togglePassphrase()
	}
	return s, nil
}

func (s *keysScreen) selected() (keymgmt.Info, bool) {
	if s.row < 0 || s.row >= len(s.list) {
		return keymgmt.Info{}, false
	}
	return s.list[s.row], true
}

func (s *keysScreen) deleteSelected() tea.Cmd {
	target, ok := s.selected()
	if !ok {
		return warn("선택한 키가 없습니다")
	}
	// 쓰이는 키는 코어가 거부한다. 여기서 미리 걸러 이유를 먼저 보여 준다.
	if target.InUse() {
		return warn("'%s' 는 쓰이는 중이라 지울 수 없습니다 (%s)", target.Key.Name, target.UsageText())
	}
	if err := keymgmt.Delete(s.app.cfg, s.app.store, target.Key.Name, "tui"); err != nil {
		return fail(err)
	}
	s.lastCommand = fmt.Sprintf("cert-gen key delete %s", target.Key.Name)
	return tea.Batch(s.reload(), good("'%s' 를 지웠습니다", target.Key.Name))
}

// togglePassphrase 는 패스프레이즈를 제거한다.
//
// 추가·변경은 입력이 필요해 폼이 있어야 한다. 여기서는 **제거만** 지원한다 —
// 서버가 기동할 때마다 패스프레이즈를 묻는 문제를 푸는 것이 이 기능의 목적이고,
// 그 경우 입력이 필요 없다(현재 패스프레이즈는 필요하므로 암호화된 키는 CLI 로 안내한다).
func (s *keysScreen) togglePassphrase() tea.Cmd {
	target, ok := s.selected()
	if !ok {
		return warn("선택한 키가 없습니다")
	}
	if target.Key.Encrypted {
		s.lastCommand = fmt.Sprintf("cert-gen key passphrase %s --remove", target.Key.Name)
		return warn("암호화된 키의 패스프레이즈 변경은 현재 패스프레이즈 입력이 필요합니다. " +
			"아래 CLI 명령을 쓰세요")
	}
	s.lastCommand = fmt.Sprintf("cert-gen key passphrase %s --set", target.Key.Name)
	return info("이 키는 평문입니다. 패스프레이즈를 걸려면 아래 CLI 명령을 쓰세요")
}

func (s *keysScreen) View(width, height int) string {
	if s.creating {
		return s.form.View(width-2) + "\n" + s.renderCommand(width)
	}

	if len(s.list) == 0 {
		return styleDim.Render("등록된 개인키가 없습니다.") + "\n\n" +
			styleBody.Render("키를 먼저 만들어 두면 CA 생성과 인증서 발급에서 그 키를 고를 수 있습니다.") + "\n" +
			styleBody.Render("장비가 키 교체를 받지 못해 같은 키로 갱신해야 하는 경우에 필요합니다.") + "\n\n" +
			styleKey.Render("n") + styleDim.Render(" 을 눌러 새 키를 만듭니다.")
	}

	headers := []string{"이름", "알고리즘", "보호", "쌍", "사용처"}
	widths := []int{18, 12, 6, 9, 20}
	var b strings.Builder
	b.WriteString(renderRow(headers, widths, styleLabel) + "\n")
	b.WriteString(styleDivider.Render(strings.Repeat("─", sumInts(widths)+len(widths)*2)) + "\n")

	for i, item := range s.list {
		protection := "평문"
		if item.Key.Encrypted {
			protection = "암호"
		}
		cells := []string{
			item.Key.Name, item.Key.Algo, protection,
			item.PairToken(), item.UsageText(),
		}
		line := renderRow(cells, widths, styleBody)
		if i == s.row {
			b.WriteString(styleMenuSelected.Render(padDisplay(line, sumInts(widths)+len(widths)*2)))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styleDim.Render("'쌍' 은 공개키 지문의 앞 8자리입니다. 인증서 목록의 같은 열과 맞춰 보면 짝을 알 수 있습니다."))
	return b.String() + "\n" + s.renderCommand(width)
}

func (s *keysScreen) renderCommand(width int) string {
	if s.lastCommand == "" {
		return ""
	}
	return "\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
		styleBox.Width(width-4).Render(truncateDisplay(s.lastCommand, width-8))
}

func (s *keysScreen) Help() []string {
	if s.creating {
		return append(s.form.Help(), "Esc 취소")
	}
	return []string{"↑↓ 이동", "n 새 키", "d 삭제", "p 패스프레이즈"}
}

func renderRow(cells []string, widths []int, style interface{ Render(...string) string }) string {
	parts := make([]string, 0, len(cells))
	for i, c := range cells {
		w := 12
		if i < len(widths) {
			w = widths[i]
		}
		parts = append(parts, padDisplay(truncateDisplay(c, w), w))
	}
	return style.Render(strings.Join(parts, "  "))
}

func sumInts(v []int) int {
	t := 0
	for _, n := range v {
		t += n
	}
	return t
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *keysScreen) CapturesText() bool {
	// 목록 화면에서는 n/d/p 가 단축키이고 글자 입력은 없다.
	return s.creating && s.form.CapturesText()
}
