// Package tui — 터미널 UI. CLI 가 정본이고 이쪽은 편의 계층이다.
//
// 그래서 TUI 는 코어 패키지를 직접 부르되, CLI 가 하는 것과 **같은 일을 같은 순서로** 한다.
// 두 프런트엔드가 다른 결과를 내면 어느 쪽이 맞는지 알 수 없게 된다.
//
// 각 화면은 작업이 끝나면 '같은 일을 하는 CLI 명령' 을 함께 보여 준다. TUI 로 익힌 절차를
// 스크립트로 옮길 수 있어야 하고, 무엇이 실행되었는지도 그래야 분명해진다.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/store"
)

// focusZone 은 키 입력을 누가 받는지다.
type focusZone int

const (
	focusMenu focusZone = iota
	focusContent
)

// screen 은 우측 콘텐츠 화면 하나다.
//
// Bubble Tea 의 Model 과 모양이 같지만 반환 타입을 screen 으로 좁혀, 화면이 실수로
// 앱 전체를 교체하지 못하게 한다.
type screen interface {
	Init() tea.Cmd
	Update(tea.Msg) (screen, tea.Cmd)
	View(width, height int) string
	// Title 은 우측 상단에 쓸 제목이다.
	Title() string
	// Help 는 하단에 쓸 키 안내다.
	Help() []string
	// CapturesText 는 지금 글자 입력을 받는 중인지다.
	//
	// 숫자키를 전역 바로가기로 쓰면서 텍스트 입력도 받으려면 이 구분이 필요하다.
	// 텍스트 필드에 포커스가 있을 때 "1" 이 메뉴 이동으로 먹히면 CN 에 숫자를 넣을 수 없고,
	// 반대로 목록 화면에서 숫자가 안 먹히면 Esc 를 먼저 눌러야 해서 번거롭다.
	CapturesText() bool
}

// Model 은 앱 전체다.
type Model struct {
	cfg   config.Config
	store *store.Store

	width  int
	height int

	menuIndex int
	active    screenID
	focus     focusZone

	screens map[screenID]screen

	// status 는 하단 한 줄 알림이다.
	status      string
	statusStyle lipgloss.Style

	// quitting 이면 다음 View 에서 화면을 비운다.
	quitting bool

	// modal 이 떠 있으면 모든 키가 그쪽으로 간다.
	modal *prompt

	// scrollToEnd 가 켜진 화면은 다음 렌더에서 끝으로 이동한다.
	//
	// 작업을 실행하면 결과와 'CLI 등가 명령' 이 폼 아래에 붙는데, 폼이 길면 그것이 잘려
	// 보이지 않는다. 방금 실행한 결과를 보려고 스크롤해야 하는 것은 잘못된 동작이다.
	scrollToEnd map[screenID]bool

	// scroll 은 화면별 콘텐츠 스크롤 위치다.
	//
	// 스크롤을 각 화면이 구현하면 화면마다 키가 달라지고, 무엇보다 **넘치는 내용을 자르는
	// 일을 빠뜨리기 쉽다.** lipgloss 의 Height() 는 채우기만 하고 자르지 않아서, 긴 내용은
	// 그대로 흘러 푸터를 밀어낸다. 여기서 한 번에 처리한다.
	scroll map[screenID]int
}

// New 는 앱을 만든다.
func New(cfg config.Config, s *store.Store) *Model {
	m := &Model{
		cfg: cfg, store: s,
		active: screenHistory, menuIndex: menuIndexOf(screenHistory),
		focus:       focusMenu,
		screens:     map[screenID]screen{},
		scroll:      map[screenID]int{},
		scrollToEnd: map[screenID]bool{},
		width:       100, height: 30,
	}
	// 시작 화면은 '발급 이력' 이다. 실사용 빈도가 발급보다 "지금 뭐가 있고 언제 만료되나" 가
	// 높고, 처음 열었을 때 상태를 보여 주는 편이 자연스럽다.
	return m
}

// Run 은 TUI 를 띄운다.
func Run(cfg config.Config, s *store.Store) error {
	m := New(cfg, s)
	// AltScreen: 종료 후 원래 터미널 내용이 돌아온다. 스크롤백을 더럽히지 않는다.
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m *Model) Init() tea.Cmd {
	return m.screenFor(m.active).Init()
}

// screenFor 는 화면을 지연 생성한다.
//
// 모두 미리 만들면 쓰지 않는 화면까지 DB 를 읽는다. 처음 열 때 만들고 그 뒤로는 상태를
// 유지한다(입력 중이던 폼이 메뉴를 다녀오면 비는 일을 막는다).
func (m *Model) screenFor(id screenID) screen {
	if s, ok := m.screens[id]; ok {
		return s
	}
	var s screen
	switch id {
	case screenKeys:
		s = newKeysScreen(m)
	case screenCACreate:
		s = newCAScreen(m)
	case screenIssue:
		s = newIssueScreen(m)
	case screenConvert:
		s = newConvertScreen(m)
	case screenHistory:
		s = newHistoryScreen(m)
	case screenTrust:
		s = newTrustScreen(m)
	case screenBackup:
		s = newBackupScreen(m)
	default:
		s = newHistoryScreen(m)
	}
	m.screens[id] = s
	return s
}

// statusMsg 는 화면이 하단 알림을 요청할 때 보낸다.
type statusMsg struct {
	text string
	kind statusKind
}

type statusKind int

const (
	statusInfo statusKind = iota
	statusGood
	statusWarnKind
	statusBad
)

func info(format string, args ...any) tea.Cmd {
	return func() tea.Msg { return statusMsg{fmt.Sprintf(format, args...), statusInfo} }
}
func good(format string, args ...any) tea.Cmd {
	return func() tea.Msg { return statusMsg{fmt.Sprintf(format, args...), statusGood} }
}
func warn(format string, args ...any) tea.Cmd {
	return func() tea.Msg { return statusMsg{fmt.Sprintf(format, args...), statusWarnKind} }
}

// fail 은 오류를 사용자 문장으로 바꿔 알린다.
//
// certerr.UserMessage 를 쓰는 이유: CLI 와 같은 문장이 나와야 한다. 프런트엔드마다 다르게
// 보이면 사용자가 같은 문제를 다른 문제로 오해한다.
func fail(err error) tea.Cmd {
	return func() tea.Msg { return statusMsg{certerr.UserMessage(err), statusBad} }
}

// showPromptMsg 는 화면이 모달 입력을 요청할 때 보낸다.
type showPromptMsg struct{ p *prompt }

// askPassphrase 는 패스프레이즈 모달을 띄운다.
//
// 화면이 직접 모달을 들고 있지 않게 하는 이유: 모달이 떠 있는 동안 키를 가로채는 일은
// 앱 셸의 책임이다. 화면마다 구현하면 어떤 화면에서는 모달 위로 단축키가 새어 나간다.
func askPassphrase(title, hint string, onSubmit func(string) tea.Cmd) tea.Cmd {
	p := newPrompt(title, hint, true, onSubmit)
	return func() tea.Msg { return showPromptMsg{p} }
}

// scrollEndMsg 는 화면이 "결과를 보여 줘야 한다" 고 알릴 때 보낸다.
type scrollEndMsg struct{}

// scrollEnd 는 작업 직후 결과가 보이도록 콘텐츠를 끝으로 보낸다.
func scrollEnd() tea.Cmd {
	return func() tea.Msg { return scrollEndMsg{} }
}

// gotoScreenMsg 는 화면이 다른 화면으로 넘기기를 요청할 때 보낸다.
type gotoScreenMsg struct {
	id screenID
	// reset 이면 그 화면을 새로 만든다(이전 입력을 버린다).
	reset bool
}

func gotoScreen(id screenID, reset bool) tea.Cmd {
	return func() tea.Msg { return gotoScreenMsg{id, reset} }
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case showPromptMsg:
		m.modal = msg.p
		return m, nil

	case scrollEndMsg:
		m.scrollToEnd[m.active] = true
		return m, nil

	case statusMsg:
		m.status = msg.text
		switch msg.kind {
		case statusGood:
			m.statusStyle = styleOK
		case statusWarnKind:
			m.statusStyle = styleWarn
		case statusBad:
			m.statusStyle = styleErr
		default:
			m.statusStyle = styleDim
		}
		return m, nil

	case gotoScreenMsg:
		if msg.reset {
			delete(m.screens, msg.id)
		}
		m.scroll[msg.id] = 0
		m.active = msg.id
		m.menuIndex = menuIndexOf(msg.id)
		m.focus = focusContent
		return m, m.screenFor(msg.id).Init()

	case tea.KeyMsg:
		// 모달이 떠 있으면 전역 키조차 가로채지 않는다. Ctrl+C 만 예외로 둔다 —
		// 어떤 상태에서도 빠져나올 길은 있어야 한다.
		if m.modal != nil {
			if msg.String() == "ctrl+c" {
				m.quitting = true
				return m, tea.Quit
			}
			done, cmd := m.modal.Update(msg)
			if done {
				m.modal = nil
			}
			return m, cmd
		}
		return m, m.handleKeyWrapped(msg)
	}

	// 그 밖의 메시지(비동기 작업 결과 등)는 현재 화면에 넘긴다.
	updated, cmd := m.screenFor(m.active).Update(msg)
	m.screens[m.active] = updated
	return m, cmd
}

// handleKeyWrapped 는 handleKey 의 반환을 tea.Cmd 로 좁힌다.
func (m *Model) handleKeyWrapped(msg tea.KeyMsg) tea.Cmd {
	_, cmd := m.handleKey(msg)
	return cmd
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// 전역 키는 어디서든 듣는다. 다만 텍스트 입력 중에 글자를 삼키면 안 되므로
	// 조합키와 기능키만 전역으로 둔다.
	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		// 콘텐츠에 포커스가 있으면 메뉴로 돌아간다. 메뉴에 있으면 아무것도 하지 않는다
		// (esc 로 앱이 꺼지면 작업 중이던 폼이 날아간다).
		if m.focus == focusContent {
			m.focus = focusMenu
			return m, nil
		}
		return m, nil
	case "f5", "ctrl+r":
		m.scroll[m.active] = 0
		return m, m.screenFor(m.active).Init()
	case "pgdown":
		m.scroll[m.active] += m.contentHeight() / 2
		return m, nil
	case "pgup":
		m.scroll[m.active] = max(0, m.scroll[m.active]-m.contentHeight()/2)
		return m, nil
	}

	// Alt+숫자는 **어디서든** 메뉴 바로가기다. 텍스트 입력 중에도 듣는다.
	//
	// 맨 숫자키만 두면 폼의 텍스트 필드에 포커스가 있을 때 바로가기가 막힌다(그 자리에서는
	// 숫자가 글자여야 하므로 어쩔 수 없다). 그래서 조합키를 하나 둬서 "지금 무엇을 하고
	// 있든 다른 메뉴로 갈 수 있는" 길을 보장한다.
	if msg.Alt && len(msg.Runes) == 1 {
		for i, item := range menuItems {
			if msg.Runes[0] == item.num {
				m.menuIndex = i
				return m.openSelected()
			}
		}
	}

	if m.focus == focusMenu {
		return m.handleMenuKey(msg)
	}

	active := m.screenFor(m.active)

	// 글자 입력을 받지 않는 상태라면 숫자키는 메뉴 바로가기다.
	if !active.CapturesText() && len(msg.Runes) == 1 {
		for i, item := range menuItems {
			if msg.Runes[0] == item.num {
				m.menuIndex = i
				return m.openSelected()
			}
		}
	}

	updated, cmd := active.Update(msg)
	m.screens[m.active] = updated
	return m, cmd
}

func (m *Model) handleMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		// 화살표로 항목 이동(사용자 요청).
		if m.menuIndex > 0 {
			m.menuIndex--
		}
		return m, nil
	case "down", "j":
		if m.menuIndex < len(menuItems)-1 {
			m.menuIndex++
		}
		return m, nil
	case "home":
		m.menuIndex = 0
		return m, nil
	case "end":
		m.menuIndex = len(menuItems) - 1
		return m, nil
	case "enter", "right", "tab", " ":
		return m.openSelected()
	}

	// 숫자키로 바로 이동
	if len(msg.Runes) == 1 {
		for i, item := range menuItems {
			if msg.Runes[0] == item.num {
				m.menuIndex = i
				return m.openSelected()
			}
		}
	}
	return m, nil
}

func (m *Model) openSelected() (tea.Model, tea.Cmd) {
	id := menuItems[m.menuIndex].id
	changed := id != m.active
	m.active = id
	if changed {
		m.scroll[id] = 0
	}
	m.focus = focusContent
	m.status = ""
	if changed {
		return m, m.screenFor(id).Init()
	}
	return m, nil
}

// 레이아웃 상수. 좁은 터미널에서 깨지지 않게 하한을 둔다.
const (
	menuWidth   = 24
	minWidth    = 72
	minHeight   = 18
	footerLines = 3
)

func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	if m.width < minWidth || m.height < minHeight {
		// 좁은 터미널에서 억지로 그리면 전부 깨진다. 무엇을 하면 되는지 알려 준다.
		return styleWarn.Render(fmt.Sprintf(
			"터미널이 너무 작습니다 (%d×%d).\n최소 %d×%d 이 필요합니다. 창을 키우거나 CLI 를 쓰세요:\n  cert-gen --help",
			m.width, m.height, minWidth, minHeight))
	}

	contentWidth := m.width - menuWidth - 3 // 구분선과 여백
	bodyHeight := m.height - footerLines - 1

	menu := m.renderMenu(bodyHeight)
	divider := m.renderDivider(bodyHeight)
	content := m.renderContent(contentWidth, bodyHeight)

	body := lipgloss.JoinHorizontal(lipgloss.Top, menu, divider, content)
	out := body + "\n" + m.renderFooter()

	// 모달은 콘텐츠를 가린다. 레이아웃 바깥에 그리면 저작권 줄이 밀리므로, 콘텐츠 영역을
	// 모달로 바꿔 그린다.
	if m.modal != nil {
		modalBody := lipgloss.NewStyle().Width(contentWidth).Height(bodyHeight).
			PaddingLeft(1).PaddingTop(2).Render(m.modal.View(contentWidth))
		out = lipgloss.JoinHorizontal(lipgloss.Top, menu, divider, modalBody) +
			"\n" + m.renderFooter()
	}
	return out
}

func (m *Model) renderMenu(height int) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("cert-gen") + "\n\n")

	for i, item := range menuItems {
		label := fmt.Sprintf(" %c. %s", item.num, item.label)
		// 폭을 채워야 배경색이 항목 전체에 깔린다. 채우지 않으면 글자 길이만큼만 칠해져
		// 들쭉날쭉해 보인다.
		label = padDisplay(label, menuWidth)
		switch {
		case i == m.menuIndex && m.focus == focusMenu:
			b.WriteString(styleMenuSelected.Render(label))
		case item.id == m.active:
			// 포커스가 콘텐츠로 넘어가도 지금 보고 있는 화면은 계속 표시한다.
			b.WriteString(styleMenuActive.Render(label))
		default:
			b.WriteString(styleMenuNormal.Render(label))
		}
		b.WriteString("\n")
	}

	// 선택 중인 항목의 설명을 메뉴 아래에 둔다.
	b.WriteString("\n")
	hint := menuItems[m.menuIndex].hint
	for _, line := range wrapDisplay(hint, menuWidth-2) {
		b.WriteString(styleDim.Render(" "+line) + "\n")
	}

	return lipgloss.NewStyle().Width(menuWidth).Height(height).Render(b.String())
}

func (m *Model) renderDivider(height int) string {
	// 좌/우 구분선. 사용자 요청대로 넣는다.
	col := strings.TrimRight(strings.Repeat("│\n", height), "\n")
	return styleDivider.Render(col)
}

// contentHeight 는 콘텐츠에 쓸 수 있는 줄 수다.
func (m *Model) contentHeight() int {
	// 제목 1줄 + 빈 줄 1줄을 뺀다.
	return max(1, m.height-footerLines-1-2)
}

func (m *Model) renderContent(width, height int) string {
	s := m.screenFor(m.active)
	title := styleTitle.Render(s.Title())

	avail := height - 2
	lines := strings.Split(s.View(width, avail), "\n")

	// 작업 직후라면 끝으로 보낸다.
	if m.scrollToEnd[m.active] {
		m.scroll[m.active] = max(0, len(lines)-avail)
		delete(m.scrollToEnd, m.active)
	}

	// 넘치는 내용을 **자른다.** 자르지 않으면 푸터와 저작권 줄이 밀려 사라진다.
	offset := m.scroll[m.active]
	if offset > len(lines)-1 {
		offset = max(0, len(lines)-1)
		m.scroll[m.active] = offset
	}
	visible := lines[offset:]
	overflow := false
	if len(visible) > avail {
		visible = visible[:avail]
		overflow = true
	}
	body := strings.Join(visible, "\n")

	// 잘렸다는 사실과 넘기는 방법을 알려 준다. 조용히 자르면 사용자는 내용이 없다고 믿는다.
	if overflow || offset > 0 {
		marker := fmt.Sprintf("  … %d/%d줄  PgUp/PgDn 으로 넘깁니다",
			min(offset+avail, len(lines)), len(lines))
		body = strings.Join(visible[:max(0, len(visible)-1)], "\n") + "\n" + styleDim.Render(marker)
	}

	return lipgloss.NewStyle().Width(width).Height(height).
		PaddingLeft(1).Render(title + "\n\n" + body)
}

// fitHints 는 키 안내를 폭에 맞춘다.
//
// 80칸 터미널에서 안내가 넘치면 줄이 접혀 레이아웃이 깨진다. 넘치면 **뒤쪽부터** 버린다 —
// 앞쪽이 그 화면에서 실제로 쓰는 키이고, 뒤쪽(F5·Ctrl+C 같은 전역 키)은 없어도 짐작할 수 있다.
func fitHints(keys []string, width int) string {
	const sep = "   "
	for n := len(keys); n > 0; n-- {
		joined := strings.Join(keys[:n], sep)
		if displayWidth(joined) <= width {
			if n < len(keys) {
				// 생략했다는 사실을 알린다. ? 로 전체 도움말을 볼 수 있어야 한다.
				withMark := joined + sep + "…"
				if displayWidth(withMark) <= width {
					return withMark
				}
			}
			return joined
		}
	}
	return truncateDisplay(strings.Join(keys, sep), width)
}

func mentionsEsc(keys []string) bool {
	for _, k := range keys {
		if strings.Contains(k, "Esc") {
			return true
		}
	}
	return false
}

func (m *Model) renderFooter() string {
	var keys []string
	if m.modal != nil {
		keys = []string{"Enter 확인", "Esc 취소", "Ctrl+C 종료"}
		status := ""
		if m.status != "" {
			status = m.statusStyle.Render(truncateDisplay(m.status, m.width-2))
		}
		return status + "\n" + styleFooter.Render(fitHints(keys, m.width-1)) + "\n" +
			styleFooter.Render(truncateDisplay(copyrightLine, m.width-1))
	}
	if m.focus == focusMenu {
		keys = []string{"↑↓ 이동", "Enter 열기", "0-5 바로가기", "q 종료"}
	} else {
		keys = m.screenFor(m.active).Help()
		// 화면이 이미 Esc 용도를 안내했으면(예: "Esc 목록") 중복해서 넣지 않는다.
		if !mentionsEsc(keys) {
			keys = append(keys, "Esc 메뉴")
		}
		keys = append(keys, "Alt+0~5 바로가기", "F5 새로고침", "Ctrl+C 종료")
	}
	help := styleFooter.Render(fitHints(keys, m.width-1))

	status := ""
	if m.status != "" {
		status = m.statusStyle.Render(truncateDisplay(m.status, m.width-2))
	}
	return status + "\n" + help + "\n" + styleFooter.Render(truncateDisplay(copyrightLine, m.width-1))
}
