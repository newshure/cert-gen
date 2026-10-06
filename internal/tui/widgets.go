package tui

// 폼 위젯. Bubble Tea 의 textinput 을 쓰되, 선택 목록은 직접 만든다.
//
// 드롭다운을 직접 만드는 이유: 사용자 요청대로 **화살표로는 열리지 않고 스페이스로만**
// 열려야 한다. 기성 select 위젯은 화살표에 반응해 목록이 펼쳐지고, 그러면 항목 간 이동과
// 값 변경이 섞여 실수로 값이 바뀐다.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// field 는 폼의 한 줄이다.
type field interface {
	Label() string
	// Focus/Blur 는 포커스 이동이다.
	Focus()
	Blur()
	Focused() bool
	// Update 는 키를 처리한다. consumed 가 false 면 폼이 포커스 이동으로 해석한다.
	Update(tea.Msg) (consumed bool, cmd tea.Cmd)
	// Render 는 한 줄(또는 여러 줄)을 그린다.
	Render(width int) string
	// Value 는 현재 값이다.
	Value() string
	// Expanded 는 드롭다운이 펼쳐져 있는지다. 펼쳐져 있으면 폼이 포커스를 넘기지 않는다.
	Expanded() bool
}

// --- 텍스트 입력 --------------------------------------------------------------

type textField struct {
	label    string
	input    textinput.Model
	required bool
	help     string
}

func newTextField(label, placeholder string, required bool) *textField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.Prompt = ""
	// 넓게 둔다. 좁으면 긴 DN 이 보이지 않아 오타를 못 잡는다.
	ti.CharLimit = 512
	return &textField{label: label, input: ti, required: required}
}

func (f *textField) Label() string     { return f.label }
func (f *textField) Focus()            { f.input.Focus() }
func (f *textField) Blur()             { f.input.Blur() }
func (f *textField) Focused() bool     { return f.input.Focused() }
func (f *textField) Value() string     { return strings.TrimSpace(f.input.Value()) }
func (f *textField) Expanded() bool    { return false }
func (f *textField) SetValue(v string) { f.input.SetValue(v) }

func (f *textField) Update(msg tea.Msg) (bool, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if ok {
		switch key.String() {
		case "up", "down", "tab", "shift+tab", "enter":
			// 포커스 이동은 폼이 처리한다.
			return false, nil
		}
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return true, cmd
}

func (f *textField) Render(width int) string {
	f.input.Width = width - 4
	style := styleField
	if f.Focused() {
		style = styleFieldFocus
	}
	label := f.label
	if f.required {
		label += styleErr.Render(" *")
	}
	return styleLabel.Render(label) + "\n" + style.Width(width-2).Render(f.input.View())
}

// --- 여러 줄 입력 (SAN) -------------------------------------------------------

// areaField 는 여러 줄을 받는다.
//
// SAN 을 한 줄 입력으로 두면 Enter 가 '제출' 로 먹혀 줄바꿈이 안 된다(실제로 그렇게 만들어
// 보고 사용자가 지적한 문제다). 여기서는 Enter 가 줄바꿈이고, 폼 이동은 Tab 이다.
type areaField struct {
	label   string
	lines   []string
	row     int
	col     int
	focused bool
	help    string
	height  int
}

func newAreaField(label, help string, height int) *areaField {
	return &areaField{label: label, lines: []string{""}, help: help, height: height}
}

func (f *areaField) Label() string  { return f.label }
func (f *areaField) Focus()         { f.focused = true }
func (f *areaField) Blur()          { f.focused = false }
func (f *areaField) Focused() bool  { return f.focused }
func (f *areaField) Expanded() bool { return false }

// Value 는 줄들을 개행으로 이어 돌려준다.
func (f *areaField) Value() string { return strings.Join(f.lines, "\n") }

// Values 는 비어 있지 않은 줄만 돌려준다.
func (f *areaField) Values() []string {
	var out []string
	for _, line := range f.lines {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (f *areaField) Update(msg tea.Msg) (bool, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return false, nil
	}
	switch key.String() {
	case "tab", "shift+tab":
		return false, nil // 폼 이동
	case "enter":
		// 줄바꿈. 이것이 이 위젯의 존재 이유다.
		rest := f.lines[f.row][f.col:]
		f.lines[f.row] = f.lines[f.row][:f.col]
		f.lines = append(f.lines[:f.row+1], append([]string{rest}, f.lines[f.row+1:]...)...)
		f.row++
		f.col = 0
		return true, nil
	case "up":
		if f.row > 0 {
			f.row--
			f.col = min(f.col, len(f.lines[f.row]))
			return true, nil
		}
		return false, nil // 첫 줄에서 위로 가면 폼의 이전 필드로
	case "down":
		if f.row < len(f.lines)-1 {
			f.row++
			f.col = min(f.col, len(f.lines[f.row]))
			return true, nil
		}
		return false, nil
	case "left":
		if f.col > 0 {
			f.col--
		} else if f.row > 0 {
			f.row--
			f.col = len(f.lines[f.row])
		}
		return true, nil
	case "right":
		if f.col < len(f.lines[f.row]) {
			f.col++
		} else if f.row < len(f.lines)-1 {
			f.row++
			f.col = 0
		}
		return true, nil
	case "home":
		f.col = 0
		return true, nil
	case "end":
		f.col = len(f.lines[f.row])
		return true, nil
	case "backspace":
		switch {
		case f.col > 0:
			line := f.lines[f.row]
			f.lines[f.row] = line[:f.col-1] + line[f.col:]
			f.col--
		case f.row > 0:
			// 줄을 합친다.
			prev := f.lines[f.row-1]
			f.col = len(prev)
			f.lines[f.row-1] = prev + f.lines[f.row]
			f.lines = append(f.lines[:f.row], f.lines[f.row+1:]...)
			f.row--
		}
		return true, nil
	case "ctrl+u":
		f.lines[f.row] = ""
		f.col = 0
		return true, nil
	}
	if len(key.Runes) > 0 {
		line := f.lines[f.row]
		f.lines[f.row] = line[:f.col] + string(key.Runes) + line[f.col:]
		f.col += len(string(key.Runes))
		return true, nil
	}
	return false, nil
}

func (f *areaField) Render(width int) string {
	style := styleField
	if f.focused {
		style = styleFieldFocus
	}
	shown := make([]string, 0, f.height)
	for i := 0; i < f.height; i++ {
		if i < len(f.lines) {
			line := f.lines[i]
			if f.focused && i == f.row {
				// 커서를 보여 준다. 블록 문자 대신 밑줄 색으로 표시한다.
				at := min(f.col, len(line))
				line = line[:at] + styleKey.Render("▏") + line[at:]
			}
			shown = append(shown, line)
		} else {
			shown = append(shown, "")
		}
	}
	out := styleLabel.Render(f.label) + "\n" +
		style.Width(width-2).Render(strings.Join(shown, "\n"))
	if f.help != "" {
		out += "\n" + styleDim.Render("  "+f.help)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- 선택 (드롭다운) ----------------------------------------------------------

type choice struct {
	Value string
	Label string
}

// selectField 는 목록에서 하나를 고른다.
//
// 닫힌 상태에서 화살표는 **값을 바꾸지 않고** 폼 이동으로 넘어간다. 스페이스(또는 Enter)로
// 펼친 뒤에야 화살표가 값을 바꾼다. 사용자 요청대로다 — 항목 사이를 지나다니기만 해도
// 값이 바뀌면 의도하지 않은 설정으로 발급하게 된다.
type selectField struct {
	label    string
	choices  []choice
	index    int
	open     bool
	cursor   int
	focused  bool
	help     string
	maxShown int
}

func newSelectField(label string, choices []choice, help string) *selectField {
	return &selectField{label: label, choices: choices, help: help, maxShown: 6}
}

func (f *selectField) Label() string  { return f.label }
func (f *selectField) Focus()         { f.focused = true }
func (f *selectField) Blur()          { f.focused = false; f.open = false }
func (f *selectField) Focused() bool  { return f.focused }
func (f *selectField) Expanded() bool { return f.open }

func (f *selectField) Value() string {
	if len(f.choices) == 0 {
		return ""
	}
	return f.choices[f.index].Value
}

func (f *selectField) SetValue(v string) {
	for i, c := range f.choices {
		if c.Value == v {
			f.index = i
			return
		}
	}
}

// SetChoices 는 목록을 갈아 끼운다. 선택값이 남아 있으면 유지한다.
func (f *selectField) SetChoices(choices []choice) {
	prev := f.Value()
	f.choices = choices
	f.index, f.cursor = 0, 0
	if prev != "" {
		f.SetValue(prev)
		f.cursor = f.index
	}
}

func (f *selectField) Update(msg tea.Msg) (bool, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return false, nil
	}
	if !f.open {
		// **스페이스만** 목록을 연다. Enter 는 넘긴다 — 폼에서 Enter 는 '다음·실행' 이고,
		// 여기서 가로채면 마지막 필드가 아닌데도 제출이 막히거나 엉뚱하게 목록이 열린다.
		if key.String() == " " {
			if len(f.choices) == 0 {
				return true, warn("선택할 항목이 없습니다")
			}
			f.open = true
			f.cursor = f.index
			return true, nil
		}
		// 닫혀 있으면 화살표도 값을 바꾸지 않는다. 폼 이동으로 넘긴다.
		return false, nil
	}

	switch key.String() {
	case "up", "k":
		if f.cursor > 0 {
			f.cursor--
		}
		return true, nil
	case "down", "j":
		if f.cursor < len(f.choices)-1 {
			f.cursor++
		}
		return true, nil
	case "enter", " ":
		f.index = f.cursor
		f.open = false
		return true, nil
	case "esc":
		// 취소: 값을 바꾸지 않고 닫는다.
		f.open = false
		return true, nil
	}
	return true, nil
}

func (f *selectField) Render(width int) string {
	style := styleField
	if f.focused {
		style = styleFieldFocus
	}
	current := "(없음)"
	if len(f.choices) > 0 {
		current = f.choices[f.index].Label
	}

	marker := " ▾"
	if f.open {
		marker = " ▴"
	}
	head := styleLabel.Render(f.label) + "\n" +
		style.Width(width-2).Render(truncateDisplay(current, width-6)+styleDim.Render(marker))

	if !f.open {
		if f.focused && f.help != "" {
			head += "\n" + styleDim.Render("  "+f.help)
		} else if f.focused {
			head += "\n" + styleDim.Render("  스페이스로 목록 열기")
		}
		return head
	}

	// 펼친 목록. 창을 넘지 않게 창 단위로 보여 준다.
	start := 0
	if f.cursor >= f.maxShown {
		start = f.cursor - f.maxShown + 1
	}
	end := min(start+f.maxShown, len(f.choices))
	var b strings.Builder
	for i := start; i < end; i++ {
		line := padDisplay("  "+f.choices[i].Label, width-4)
		if i == f.cursor {
			b.WriteString(styleMenuSelected.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	if len(f.choices) > f.maxShown {
		b.WriteString(styleDim.Render(fmt.Sprintf("  (%d/%d)", f.cursor+1, len(f.choices))))
	}
	return head + "\n" + styleBox.Width(width-2).Render(strings.TrimRight(b.String(), "\n"))
}
