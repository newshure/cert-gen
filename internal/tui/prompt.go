package tui

// 패스프레이즈 모달.
//
// 암호화된 CA 키로 갱신·폐기·CRL 생성을 하려면 패스프레이즈를 받아야 한다. 이것이 없으면
// TUI 에서 그 작업을 아예 할 수 없고, 실제로 "CLI 를 쓰세요" 로 떠넘기고 있었다.
//
// 네이티브 prompt 를 쓰지 않고 자체 모달로 만든다. 화면 밖으로 나가면 레이아웃이 깨지고
// 저작권 줄도 사라진다.

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// prompt 는 한 줄을 받는 모달이다.
type prompt struct {
	title string
	hint  string
	input textinput.Model
	// onSubmit 은 입력값을 받아 명령을 돌려준다. nil 을 돌려주면 모달이 닫히지 않는다.
	onSubmit func(value string) tea.Cmd
	// onCancel 은 취소 시 실행된다.
	onCancel func() tea.Cmd
}

func newPrompt(title, hint string, masked bool, onSubmit func(string) tea.Cmd) *prompt {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 512
	if masked {
		ti.EchoMode = textinput.EchoPassword
	}
	ti.Focus()
	return &prompt{title: title, hint: hint, input: ti, onSubmit: onSubmit}
}

// Update 는 키를 처리하고, 모달을 닫아야 하면 done=true 를 돌려준다.
func (p *prompt) Update(msg tea.Msg) (done bool, cmd tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var c tea.Cmd
		p.input, c = p.input.Update(msg)
		return false, c
	}
	switch key.String() {
	case "esc":
		// 취소. 작업을 하지 않고 닫는다 — 빈 패스프레이즈로 시도하면 엉뚱한 오류가 난다.
		if p.onCancel != nil {
			return true, p.onCancel()
		}
		return true, info("취소했습니다")
	case "enter":
		value := p.input.Value()
		if p.onSubmit == nil {
			return true, nil
		}
		return true, p.onSubmit(value)
	}
	var c tea.Cmd
	p.input, c = p.input.Update(msg)
	return false, c
}

func (p *prompt) View(width int) string {
	// 바깥 박스(styleBox)가 테두리 2 + 좌우 패딩 2 = 4칸을 쓴다. 안쪽 입력 박스도
	// 같은 만큼 쓰므로 둘을 모두 빼야 테두리가 접히지 않는다.
	const outerChrome = 4
	const innerChrome = 4

	inner := width - 10
	if inner < 24 {
		inner = 24
	}
	p.input.Width = inner - outerChrome - innerChrome - 1

	var b strings.Builder
	b.WriteString(styleTitle.Render(p.title) + "\n")
	if p.hint != "" {
		for _, line := range wrapDisplay(p.hint, inner-outerChrome) {
			b.WriteString(styleDim.Render(line) + "\n")
		}
	}
	b.WriteString("\n" +
		styleFieldFocus.Width(inner-outerChrome-innerChrome).Render(p.input.View()) + "\n")
	b.WriteString("\n" + styleDim.Render("Enter 확인   Esc 취소(C)"))

	// 모달은 불투명해야 한다. 뒤 내용이 비치면 글자가 겹쳐 읽을 수 없다.
	return styleBox.Width(inner).Render(b.String())
}
