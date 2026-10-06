package tui

// form 은 field 들을 모아 포커스를 관리한다.
//
// 각 화면이 포커스 이동을 직접 구현하면 화면마다 키가 달라진다. 한곳에 모은다.

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type form struct {
	fields []field
	index  int
	// action 은 마지막 줄의 실행 버튼 라벨이다.
	action string
	// actionKey 는 단축키다(예: 'x' → 실행(X)).
	actionKey rune
	onAction  tea.Cmd
	// focusAction 이면 포커스가 실행 버튼에 있다.
	focusAction bool
	busy        bool
}

func newForm(action string, actionKey rune, fields ...field) *form {
	f := &form{fields: fields, action: action, actionKey: actionKey}
	if len(fields) > 0 {
		fields[0].Focus()
	}
	return f
}

func (f *form) current() field {
	if f.index < len(f.fields) {
		return f.fields[f.index]
	}
	return nil
}

func (f *form) focusAt(i int) {
	for _, fl := range f.fields {
		fl.Blur()
	}
	f.focusAction = false
	switch {
	case i < 0:
		f.index = 0
	case i >= len(f.fields):
		// 마지막 다음은 실행 버튼이다.
		f.index = len(f.fields)
		f.focusAction = true
		return
	default:
		f.index = i
	}
	f.fields[f.index].Focus()
}

// Update 는 키를 현재 필드에 먼저 주고, 필드가 쓰지 않으면 포커스 이동으로 해석한다.
func (f *form) Update(msg tea.Msg, submit func() tea.Cmd) tea.Cmd {
	key, isKey := msg.(tea.KeyMsg)

	// 펼쳐진 드롭다운이 있으면 모든 키를 그쪽에 준다. 아니면 목록을 넘기는 화살표가
	// 폼 이동으로 새어 나간다.
	if cur := f.current(); cur != nil && cur.Expanded() {
		_, cmd := cur.Update(msg)
		return cmd
	}

	if !f.focusAction {
		if cur := f.current(); cur != nil {
			consumed, cmd := cur.Update(msg)
			if consumed {
				return cmd
			}
		}
	}
	if !isKey {
		return nil
	}

	switch key.String() {
	case "tab", "down":
		f.focusAt(f.index + 1)
		return nil
	case "shift+tab", "up":
		if f.focusAction {
			f.focusAt(len(f.fields) - 1)
			return nil
		}
		f.focusAt(f.index - 1)
		return nil
	case "enter":
		if f.focusAction {
			return submit()
		}
		// 마지막 필드에서 Enter 면 바로 실행한다. 폼을 끝까지 내려가 버튼을 누르는
		// 동작이 잦으므로 단축한다.
		if f.index == len(f.fields)-1 {
			return submit()
		}
		f.focusAt(f.index + 1)
		return nil
	}

	// 단축키. 텍스트 입력 중에는 글자를 삼키면 안 되므로 버튼에 포커스가 있을 때만 듣는다.
	if f.focusAction && len(key.Runes) == 1 {
		r := key.Runes[0]
		if r == f.actionKey || r == f.actionKey-32 {
			return submit()
		}
	}
	return nil
}

func (f *form) View(width int) string {
	var b strings.Builder
	for _, fl := range f.fields {
		b.WriteString(fl.Render(width) + "\n")
	}
	b.WriteString("\n" + f.renderAction(width))
	return b.String()
}

func (f *form) renderAction(width int) string {
	label := f.action
	if f.busy {
		label = "처리 중…"
	}
	// 단축키를 괄호로 표시한다(사용자 요청: 예) 취소(C)).
	if f.actionKey != 0 && !f.busy {
		label += " (" + strings.ToUpper(string(f.actionKey)) + ")"
	}
	style := styleBox
	if f.focusAction {
		style = styleFieldFocus
	}
	return style.Render(" " + label + " ")
}

// CapturesText 는 현재 필드가 글자 입력을 받는지다.
//
// 선택 필드(드롭다운)와 실행 버튼에서는 글자를 받지 않으므로, 그때 숫자키는 메뉴
// 바로가기로 쓰이는 편이 낫다.
func (f *form) CapturesText() bool {
	if f.focusAction {
		return false
	}
	switch cur := f.current(); cur.(type) {
	case *textField, *areaField:
		return true
	default:
		return false
	}
}

func (f *form) Help() []string {
	if cur := f.current(); cur != nil && cur.Expanded() {
		return []string{"↑↓ 선택", "Enter 확정", "Esc 취소"}
	}
	help := []string{"Tab/↑↓ 이동", "Enter 다음·실행"}
	if cur := f.current(); cur != nil {
		if _, ok := cur.(*selectField); ok {
			help = append(help, "스페이스 목록 열기")
		}
		if _, ok := cur.(*areaField); ok {
			help = []string{"Enter 줄바꿈", "Tab 다음 항목"}
		}
	}
	return help
}
