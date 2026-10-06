package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

// newTestApp 은 임시 상태 디렉터리에 앱을 띄운다.
func newTestApp(t *testing.T) *Model {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Cert.DefaultKeyAlgo = "ec-p256"
	cfg.CA.DefaultKeyAlgo = "ec-p256"
	if err := fsops.EnsureDir(cfg.DataDir, fsops.ModeDir); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(cfg.DBPath(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	m := New(cfg, s)
	m.width, m.height = 120, 40
	return m
}

// makeCA 는 테스트용 Root CA 를 만든다. 패스프레이즈 없이 만든다(테스트 편의).
func makeCA(t *testing.T, m *Model) (store.CA, error) {
	t.Helper()
	noPass := false
	return ca.CreateRoot(m.cfg, m.store, ca.CreateOptions{
		Subject: names.Subject{CommonName: "HD Root CA"}, RequirePassphrase: &noPass,
	})
}

// key 는 키 입력을 흉내낸다.
func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEscape}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// send 는 메시지를 넣고 반환된 명령을 즉시 실행해 그 결과까지 반영한다.
//
// Bubble Tea 런타임이 없으므로 tea.Cmd 를 직접 돌려야 한다. 그렇지 않으면 화면이
// 데이터를 읽지 못해 테스트가 빈 화면만 보게 된다.
func send(t *testing.T, m *Model, msg tea.Msg) {
	t.Helper()
	model, cmd := m.Update(msg)
	if model != m {
		t.Fatal("Update 가 다른 모델을 돌려줬다")
	}
	drain(t, m, cmd, 0)
}

func drain(t *testing.T, m *Model, cmd tea.Cmd, depth int) {
	t.Helper()
	if cmd == nil || depth > 8 {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	// tea.Batch 는 BatchMsg 를 돌려준다. 각각을 재귀로 처리한다.
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			drain(t, m, c, depth+1)
		}
		return
	}
	_, next := m.Update(msg)
	drain(t, m, next, depth+1)
}

func typeText(t *testing.T, m *Model, text string) {
	t.Helper()
	for _, r := range text {
		send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func TestStartsOnHistoryWithMenuFocus(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	if m.active != screenHistory {
		t.Errorf("시작 화면 = %v, 기대 발급 이력", m.active)
	}
	if m.focus != focusMenu {
		t.Error("시작 포커스가 메뉴가 아니다")
	}
	view := m.View()
	// 좌측 메뉴 6개가 모두 보여야 한다.
	for _, item := range menuItems {
		if !strings.Contains(view, item.label) {
			t.Errorf("메뉴에 %q 가 없다", item.label)
		}
	}
}

func TestMenuHasAllSixUserSpecifiedEntries(t *testing.T) {
	// 사용자가 지정한 구조 그대로여야 한다. 번호도 고정이다.
	want := []struct {
		num   rune
		label string
	}{
		{'0', "개인키 생성·관리"},
		{'1', "rootCA 생성"},
		{'2', "인증서 발급"},
		{'3', "인증서 변환"},
		{'4', "발급 이력·만료 조회"},
		{'5', "서버에 CA 신뢰 등록"},
		{'6', "백업 · 복원"},
	}
	if len(menuItems) != len(want) {
		t.Fatalf("메뉴 수 = %d, 기대 %d", len(menuItems), len(want))
	}
	for i, w := range want {
		if menuItems[i].num != w.num || menuItems[i].label != w.label {
			t.Errorf("%d번 = %c/%q, 기대 %c/%q",
				i, menuItems[i].num, menuItems[i].label, w.num, w.label)
		}
	}
}

func TestFooterShowsCopyright(t *testing.T) {
	// 사용자 지정 문구다. 모든 화면에 떠야 한다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	for _, item := range menuItems {
		send(t, m, key(string(item.num)))
		view := m.View()
		for _, want := range []string{"HaeDong", "theknowledges.net", "출처 명시"} {
			if !strings.Contains(view, want) {
				t.Errorf("%s 화면 하단에 %q 가 없다", item.label, want)
			}
		}
	}
}

func TestDividerIsPresent(t *testing.T) {
	// 사용자 요청: 좌측 메뉴와 우측 콘텐츠 사이에 구분선은 있는 게 맞다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	if !strings.Contains(m.View(), "│") {
		t.Error("좌/우 구분선이 없다")
	}
}

func TestNumberKeysJumpFromMenu(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	for _, item := range menuItems {
		m.focus = focusMenu
		send(t, m, key(string(item.num)))
		if m.active != item.id {
			t.Errorf("%c 키로 %v 로 가지 않았다 (현재 %v)", item.num, item.id, m.active)
		}
		// 숫자키로 열면 포커스가 콘텐츠로 넘어가야 한다.
		if m.focus != focusContent {
			t.Errorf("%c 키 이후 포커스가 콘텐츠가 아니다", item.num)
		}
	}
}

func TestAltNumberJumpsEvenWhileTypingText(t *testing.T) {
	// 맨 숫자키는 텍스트 입력 중에는 글자여야 하므로 바로가기로 쓸 수 없다.
	// Alt+숫자는 어디서든 동작해야 한다 — 그래야 폼 중간에서도 다른 메뉴로 갈 수 있다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("1")) // CA 생성 (첫 필드가 텍스트)
	typeText(t, m, "HD")
	if !m.screenFor(screenCACreate).CapturesText() {
		t.Fatal("전제 조건 실패: 텍스트를 받는 상태가 아니다")
	}

	// 맨 숫자는 글자로 들어가야 한다.
	send(t, m, key("4"))
	cs := m.screenFor(screenCACreate).(*caScreen)
	if cs.cn.Value() != "HD4" {
		t.Errorf("텍스트 필드에 숫자가 입력되지 않았다: %q", cs.cn.Value())
	}
	if m.active != screenCACreate {
		t.Error("텍스트 입력 중에 맨 숫자가 화면을 바꿨다")
	}

	// Alt+숫자는 화면을 바꿔야 한다.
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}, Alt: true})
	if m.active != screenHistory {
		t.Errorf("Alt+4 로 이력 화면으로 가지 않았다 (현재 %v)", m.active)
	}
	// 입력해 둔 값은 남아야 한다.
	if cs.cn.Value() != "HD4" {
		t.Errorf("화면을 옮기며 입력이 날아갔다: %q", cs.cn.Value())
	}
}

func TestNumberKeysJumpFromListScreens(t *testing.T) {
	// 목록 화면은 글자를 받지 않으므로 맨 숫자키가 바로 동작해야 한다.
	// (Esc 를 먼저 눌러야 하면 번거롭다)
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4")) // 이력 화면
	if m.screenFor(screenHistory).CapturesText() {
		t.Fatal("이력 화면이 글자를 받는다고 보고한다")
	}
	send(t, m, key("0"))
	if m.active != screenKeys {
		t.Errorf("목록 화면에서 숫자키가 듣지 않았다 (현재 %v)", m.active)
	}
}

func TestArrowKeysMoveMenu(t *testing.T) {
	// 사용자 요청: 항목 이동에 화살표키 지원.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	m.focus = focusMenu
	m.menuIndex = 0
	send(t, m, key("down"))
	if m.menuIndex != 1 {
		t.Errorf("↓ 후 인덱스 = %d", m.menuIndex)
	}
	send(t, m, key("up"))
	if m.menuIndex != 0 {
		t.Errorf("↑ 후 인덱스 = %d", m.menuIndex)
	}
	// 경계에서 넘어가지 않아야 한다.
	send(t, m, key("up"))
	if m.menuIndex != 0 {
		t.Errorf("첫 항목에서 ↑ 가 넘어갔다: %d", m.menuIndex)
	}
	m.menuIndex = len(menuItems) - 1
	send(t, m, key("down"))
	if m.menuIndex != len(menuItems)-1 {
		t.Errorf("마지막 항목에서 ↓ 가 넘어갔다: %d", m.menuIndex)
	}
}

func TestEscReturnsFocusToMenuWithoutQuitting(t *testing.T) {
	// esc 로 앱이 꺼지면 작업 중이던 폼이 날아간다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("2"))
	if m.focus != focusContent {
		t.Fatal("전제 조건 실패")
	}
	send(t, m, key("esc"))
	if m.focus != focusMenu {
		t.Error("Esc 로 메뉴로 돌아가지 않았다")
	}
	if m.quitting {
		t.Error("Esc 가 앱을 종료시켰다")
	}
	// 메뉴에서 또 눌러도 종료되지 않아야 한다.
	send(t, m, key("esc"))
	if m.quitting {
		t.Error("메뉴에서 Esc 가 앱을 종료시켰다")
	}
}

func TestNoBlockGlyphsInAnyView(t *testing.T) {
	// 사용자 요청: "ㅁ 같은 문자는 너무 어지러움". 반칸 블록 글리프를 쓰지 않는다.
	// (폰트에 따라 ㅁ 로 깨지고, 깨지지 않아도 화면이 어지러워진다)
	forbidden := []string{"▔", "▁", "▊", "▎", "▀", "▄", "█", "▌", "▐", "░", "▒", "▓"}
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	for _, item := range menuItems {
		send(t, m, key(string(item.num)))
		view := m.View()
		for _, g := range forbidden {
			if strings.Contains(view, g) {
				t.Errorf("%s 화면에 블록 문자 %q 가 있다", item.label, g)
			}
		}
	}
}

func TestSmallTerminalShowsGuidanceNotGarbage(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 40, Height: 10})
	view := m.View()
	if !strings.Contains(view, "너무 작습니다") {
		t.Errorf("좁은 터미널 안내가 없다:\n%s", view)
	}
	// 무엇을 하면 되는지 알려 줘야 한다.
	if !strings.Contains(view, "cert-gen") {
		t.Error("CLI 대안 안내가 없다")
	}
}

// --- 드롭다운 동작 (사용자 요청) ---------------------------------------------

func TestSelectDoesNotOpenOnEnter(t *testing.T) {
	// 폼에서 Enter 는 '다음·실행' 이다. 드롭다운이 Enter 를 가로채면 제출이 막힌다.
	sel := newSelectField("테스트", []choice{
		{Value: "a", Label: "첫째"}, {Value: "b", Label: "둘째"},
	}, "")
	sel.Focus()
	consumed, _ := sel.Update(key("enter"))
	if consumed {
		t.Error("닫힌 드롭다운이 Enter 를 삼켰다")
	}
	if sel.Expanded() {
		t.Error("Enter 로 드롭다운이 열렸다")
	}
}

func TestSelectDoesNotOpenOnArrowKeys(t *testing.T) {
	// 사용자 요청: 화살표 이동 시 바로 표시하지 않고 스페이스바로 선택 시 드롭다운 작동.
	// 지나다니기만 해도 값이 바뀌면 의도하지 않은 설정으로 발급하게 된다.
	sel := newSelectField("테스트", []choice{
		{Value: "a", Label: "첫째"}, {Value: "b", Label: "둘째"},
	}, "")
	sel.Focus()

	consumed, _ := sel.Update(key("down"))
	if consumed {
		t.Error("닫힌 드롭다운이 ↓ 를 삼켰다 (폼 이동이 막힌다)")
	}
	if sel.Expanded() {
		t.Error("↓ 로 드롭다운이 열렸다")
	}
	if sel.Value() != "a" {
		t.Errorf("↓ 로 값이 바뀌었다: %q", sel.Value())
	}

	// 스페이스로만 열려야 한다.
	consumed, _ = sel.Update(key("space"))
	if !consumed || !sel.Expanded() {
		t.Error("스페이스로 열리지 않았다")
	}
	// 열린 뒤에는 화살표가 커서를 움직인다.
	sel.Update(key("down"))
	sel.Update(key("enter"))
	if sel.Expanded() {
		t.Error("Enter 후에도 열려 있다")
	}
	if sel.Value() != "b" {
		t.Errorf("선택이 반영되지 않았다: %q", sel.Value())
	}
}

func TestSelectEscCancelsWithoutChangingValue(t *testing.T) {
	sel := newSelectField("테스트", []choice{
		{Value: "a", Label: "첫째"}, {Value: "b", Label: "둘째"},
	}, "")
	sel.Focus()
	sel.Update(key("space"))
	sel.Update(key("down"))
	sel.Update(key("esc"))
	if sel.Expanded() {
		t.Error("Esc 로 닫히지 않았다")
	}
	if sel.Value() != "a" {
		t.Errorf("Esc 가 값을 바꿨다: %q", sel.Value())
	}
}

func TestSelectWithNoChoicesWarnsInsteadOfOpening(t *testing.T) {
	sel := newSelectField("테스트", nil, "")
	sel.Focus()
	consumed, cmd := sel.Update(key("space"))
	if !consumed {
		t.Error("빈 목록에서 스페이스가 처리되지 않았다")
	}
	if sel.Expanded() {
		t.Error("빈 목록이 열렸다")
	}
	if cmd == nil {
		t.Error("빈 목록 안내가 없다")
	}
}

func TestSelectKeepsValueWhenChoicesReload(t *testing.T) {
	// Init 이 목록을 다시 채울 때 선택이 날아가면 폼을 다시 채워야 한다.
	sel := newSelectField("CA", []choice{{Value: "x", Label: "X"}, {Value: "y", Label: "Y"}}, "")
	sel.SetValue("y")
	sel.SetChoices([]choice{{Value: "x", Label: "X"}, {Value: "y", Label: "Y"}, {Value: "z", Label: "Z"}})
	if sel.Value() != "y" {
		t.Errorf("목록 갱신 후 선택이 날아갔다: %q", sel.Value())
	}
}

// --- SAN 여러 줄 입력 (사용자가 지적한 문제) ---------------------------------

func TestAreaFieldEnterInsertsNewline(t *testing.T) {
	// 사용자 지적: "SAN 입력: 엔터 줄바꿈 안됨". 한 줄 입력이면 Enter 가 제출로 먹힌다.
	area := newAreaField("SAN", "", 4)
	area.Focus()
	for _, r := range "dns:a.hd.local" {
		area.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	consumed, _ := area.Update(key("enter"))
	if !consumed {
		t.Fatal("Enter 가 처리되지 않았다 (폼 제출로 새어 나간다)")
	}
	for _, r := range "ip:10.0.0.5" {
		area.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	values := area.Values()
	if len(values) != 2 {
		t.Fatalf("줄 수 = %d (%v)", len(values), values)
	}
	if values[0] != "dns:a.hd.local" || values[1] != "ip:10.0.0.5" {
		t.Errorf("내용이 다르다: %v", values)
	}
}

func TestAreaFieldTabLeavesField(t *testing.T) {
	// Enter 가 줄바꿈이므로 폼 이동은 Tab 이어야 한다.
	area := newAreaField("SAN", "", 4)
	area.Focus()
	consumed, _ := area.Update(key("tab"))
	if consumed {
		t.Error("Tab 을 삼켰다 (폼 이동이 막힌다)")
	}
}

func TestAreaFieldBackspaceJoinsLines(t *testing.T) {
	area := newAreaField("SAN", "", 4)
	area.Focus()
	area.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	area.Update(key("enter"))
	area.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	// 줄 머리에서 backspace 두 번: b 지우고 줄 합치기
	area.Update(key("backspace"))
	area.Update(key("backspace"))
	if got := area.Values(); len(got) != 1 || got[0] != "a" {
		t.Errorf("줄 합치기가 되지 않았다: %v", got)
	}
}

func TestAreaFieldDropsBlankLines(t *testing.T) {
	// 빈 줄이 SAN 으로 넘어가면 검증에서 엉뚱한 오류가 난다.
	area := newAreaField("SAN", "", 4)
	area.Focus()
	area.Update(key("enter"))
	for _, r := range "dns:a.hd.local" {
		area.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	area.Update(key("enter"))
	area.Update(key("enter"))
	if got := area.Values(); len(got) != 1 {
		t.Errorf("빈 줄이 걸러지지 않았다: %v", got)
	}
}

// --- 폭 계산 ------------------------------------------------------------------

func TestDisplayWidthCountsKoreanAsTwo(t *testing.T) {
	cases := map[string]int{"web": 3, "웹서버": 6, "web-웹": 6, "": 0}
	for in, want := range cases {
		if got := displayWidth(in); got != want {
			t.Errorf("displayWidth(%q) = %d, 기대 %d", in, got, want)
		}
	}
}

func TestPadDisplayFillsToExactWidth(t *testing.T) {
	// 메뉴 항목 배경색이 들쭉날쭉하지 않으려면 폭이 정확해야 한다.
	for _, s := range []string{"web", "개인키 생성·관리", "rootCA 생성", ""} {
		if got := displayWidth(padDisplay(s, 24)); got != 24 {
			t.Errorf("padDisplay(%q, 24) 폭 = %d", s, got)
		}
	}
}

func TestWrapDisplayNeverExceedsWidth(t *testing.T) {
	text := "cert-gen 은 실행한 디렉터리에 cert-gen-data 를 만들어 CA 와 인증서를 보관합니다. " +
		"아주아주아주아주아주아주아주아주긴단어도처리해야한다"
	for _, w := range []int{10, 20, 40} {
		for _, line := range wrapDisplay(text, w) {
			if displayWidth(line) > w {
				t.Errorf("폭 %d 에서 %d칸 줄이 나왔다: %q", w, displayWidth(line), line)
			}
		}
	}
}

// --- 실제 흐름 ----------------------------------------------------------------

func TestKeyCreateFlowThroughTUI(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)

	send(t, m, key("0")) // 개인키 메뉴
	send(t, m, key("n")) // 새 키
	typeText(t, m, "web-key")
	send(t, m, key("tab")) // 알고리즘
	send(t, m, key("tab")) // 패스프레이즈
	send(t, m, key("tab")) // 메모
	send(t, m, key("tab")) // 실행 버튼
	send(t, m, key("enter"))

	list, err := keymgmt.List(m.cfg, m.store)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Key.Name != "web-key" {
		t.Fatalf("키가 만들어지지 않았다: %+v", list)
	}
	// 기본은 평문이어야 한다(서버 무인 기동).
	if list[0].Key.Encrypted {
		t.Error("TUI 기본값이 암호화된 키다")
	}
	view := m.View()
	if !strings.Contains(view, "web-key") {
		t.Errorf("목록에 새 키가 없다:\n%s", view)
	}
	// 같은 일을 하는 CLI 명령을 보여 줘야 한다.
	if !strings.Contains(view, "cert-gen key create") {
		t.Errorf("CLI 등가 명령이 없다:\n%s", view)
	}
}

func TestCACreateFlowThroughTUI(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)

	send(t, m, key("1")) // rootCA 생성
	typeText(t, m, "HD Root CA")
	send(t, m, key("tab")) // org
	typeText(t, m, "HaeDong")
	// 나머지는 기본값. 실행 버튼까지 Tab 으로 내려간다.
	for i := 0; i < 6; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))

	list, err := m.store.ListCAs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("CA 수 = %d", len(list))
	}
	if list[0].CommonName != "HD Root CA" {
		t.Errorf("CN = %q", list[0].CommonName)
	}
	// 작업 직후에는 결과가 보여야 한다 — 스크롤하지 않고 바로.
	view := m.View()
	if !strings.Contains(view, "cert-gen ca create") {
		t.Errorf("작업 직후 CLI 등가 명령이 보이지 않는다:\n%s", view)
	}
	all := scrollAll(t, m)
	// 패스프레이즈 없이 만들었으면 경고해야 한다.
	if !strings.Contains(all, "평문") {
		t.Errorf("평문 저장 경고가 없다:\n%s", all)
	}
}

func TestIssueFlowThroughTUI(t *testing.T) {
	m := newTestApp(t)
	// CA 를 미리 만들어 둔다.
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)

	send(t, m, key("2")) // 인증서 발급
	// CA 선택 방식(기본 ①) → CA 선택 → 디렉터리 → 패스프레이즈 → CN
	for i := 0; i < 4; i++ {
		send(t, m, key("tab"))
	}
	typeText(t, m, "web.hd.local")
	send(t, m, key("tab")) // SAN
	typeText(t, m, "ip:10.0.0.5")
	send(t, m, key("tab")) // 프로필
	for i := 0; i < 4; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))

	certs, err := m.store.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("발급 수 = %d", len(certs))
	}
	rec := certs[0]
	if rec.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", rec.CommonName)
	}
	if rec.CAID != caRec.ID {
		t.Errorf("CA 가 다르다: %d", rec.CAID)
	}
	// CN 자동 포함 + 지정한 IP
	var sawCN, sawIP bool
	for _, san := range rec.SANs {
		if san.Value == "web.hd.local" {
			sawCN = true
		}
		if san.Value == "10.0.0.5" {
			sawIP = true
		}
	}
	if !sawCN || !sawIP {
		t.Errorf("SAN 이 다르다: %+v", rec.SANs)
	}
	if view := m.View(); !strings.Contains(view, "cert-gen cert issue") {
		t.Errorf("작업 직후 CLI 등가 명령이 보이지 않는다:\n%s", view)
	}
}

func TestIssueScreenGuidesWhenNoCA(t *testing.T) {
	// CA 가 없으면 1번으로 유도해야 한다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("2"))
	if !strings.Contains(m.status, "1번 메뉴") {
		t.Errorf("CA 없음 안내가 없다: %q", m.status)
	}
}

func TestHistoryShowsIssuedCertAndPairToken(t *testing.T) {
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))

	view := m.View()
	if !strings.Contains(view, "web.hd.local") {
		t.Errorf("목록에 인증서가 없다:\n%s", view)
	}
	// 사용자 요청: private key - cert 쌍을 표현한다.
	token := keymgmt.PairToken(res.Record.PublicSHA256)
	if !strings.Contains(view, token) {
		t.Errorf("쌍 토큰 %q 이 목록에 없다:\n%s", token, view)
	}
}

func TestHistoryDetailAndVerify(t *testing.T) {
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter")) // 상세
	view := m.View()
	for _, want := range []string{"Subject", "serial", "지문", "쌍 토큰"} {
		if !strings.Contains(view, want) {
			t.Errorf("상세에 %q 가 없다:\n%s", want, view)
		}
	}
	send(t, m, key("v")) // 검증
	view = m.View()
	if !strings.Contains(view, "검증 결과") {
		t.Errorf("검증 결과가 없다:\n%s", view)
	}
	if !strings.Contains(view, "[통과]") {
		t.Errorf("검증 항목이 표시되지 않았다:\n%s", view)
	}
}

func TestHistoryFilterCycles(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	first := m.screenFor(screenHistory).Title()
	send(t, m, key("f"))
	second := m.screenFor(screenHistory).Title()
	if first == second {
		t.Errorf("f 로 보기가 바뀌지 않았다: %q", first)
	}
}

func TestTrustScreenProducesCommands(t *testing.T) {
	// 사용자 요청: ca, jks 등록 메뉴에서 인증서 선택 시 명령어도 제공.
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("5"))
	// CA → 대상 → JAVA_HOME → 실행
	for i := 0; i < 3; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))

	// 긴 내용은 잘리고 PgDn 으로 넘긴다. 스크롤하며 모아서 확인한다.
	all := scrollAll(t, m)
	for _, want := range []string{"실행할 명령", "등록 확인", "되돌리기"} {
		if !strings.Contains(all, want) {
			t.Errorf("%q 안내가 없다:\n%s", want, all)
		}
	}
}

// scrollAll 은 끝까지 PgDn 하며 본 내용을 모은다.
//
// 넘치는 내용은 앱 셸이 자르므로, 한 번의 View() 로는 전체를 볼 수 없다.
func scrollAll(t *testing.T, m *Model) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(m.View())
	for i := 0; i < 30; i++ {
		before := m.scroll[m.active]
		send(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
		if m.scroll[m.active] == before {
			break
		}
		b.WriteString("\n" + m.View())
	}
	return b.String()
}

func TestTrustScreenJavaTarget(t *testing.T) {
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("5"))

	ts, ok := m.screenFor(screenTrust).(*trustScreen)
	if !ok {
		t.Fatal("신뢰 화면이 아니다")
	}
	ts.platform.SetValue("java")
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("enter"))

	all := scrollAll(t, m)
	if !strings.Contains(all, "keytool -importcert") {
		t.Errorf("keytool 명령이 없다:\n%s", all)
	}
	// Java 가 OS 신뢰를 보지 않는다는 사실은 반드시 알려야 한다.
	if !strings.Contains(all, "OS 신뢰 저장소를 보지 않습니다") {
		t.Errorf("Java 별개 안내가 없다:\n%s", all)
	}
}

func TestConvertScreenGuidesWhenNoHistory(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("3"))
	// 이력이 없어도 외부 파일 경로가 있다는 것을 알려야 한다.
	if !strings.Contains(m.status, "외부 파일") {
		t.Errorf("외부 파일 안내가 없다: %q", m.status)
	}
}

func TestScreenStatePersistsAcrossMenuSwitch(t *testing.T) {
	// 입력 중이던 폼이 메뉴를 다녀오면 비어 버리면 안 된다.
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("1"))
	typeText(t, m, "HD Root CA")
	send(t, m, key("esc")) // 메뉴로
	send(t, m, key("4"))   // 다른 화면
	send(t, m, key("esc"))
	send(t, m, key("1")) // 돌아오기

	cs, ok := m.screenFor(screenCACreate).(*caScreen)
	if !ok {
		t.Fatal("CA 화면이 아니다")
	}
	if cs.cn.Value() != "HD Root CA" {
		t.Errorf("입력이 날아갔다: %q", cs.cn.Value())
	}
}

func TestQuitFromMenu(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	m.focus = focusMenu
	_, cmd := m.Update(key("q"))
	if !m.quitting {
		t.Error("q 로 종료되지 않았다")
	}
	if cmd == nil {
		t.Error("종료 명령이 없다")
	}
	if m.View() != "" {
		t.Error("종료 중인데 화면이 그려진다")
	}
}

func TestAllScreensRenderWithoutPanic(t *testing.T) {
	// 화면 하나가 패닉하면 앱 전체가 죽는다. 데이터가 있는 경우와 없는 경우 모두 본다.
	for _, withData := range []bool{false, true} {
		m := newTestApp(t)
		if withData {
			caRec, err := makeCA(t, m)
			if err != nil {
				t.Fatal(err)
			}
			material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issue.Issue(m.cfg, m.store, issue.Options{
				Material: material, Subject: names.Subject{CommonName: "web.hd.local"},
				Frontend: "test",
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := keymgmt.Create(m.cfg, m.store, keymgmt.CreateOptions{
				Name: "spare", Frontend: "test",
			}); err != nil {
				t.Fatal(err)
			}
		}
		drain(t, m, m.Init(), 0)
		for _, item := range menuItems {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("데이터=%v, %s 화면이 패닉했다: %v", withData, item.label, r)
					}
				}()
				send(t, m, key(string(item.num)))
				if view := m.View(); view == "" {
					t.Errorf("데이터=%v, %s 화면이 비었다", withData, item.label)
				}
				// 좁은 폭에서도 깨지지 않아야 한다.
				send(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
				_ = m.View()
				send(t, m, tea.WindowSizeMsg{Width: 200, Height: 60})
				_ = m.View()
			}()
		}
	}
}

func TestLongContentDoesNotPushOutFooter(t *testing.T) {
	// lipgloss 의 Height() 는 채우기만 하고 자르지 않는다. 긴 내용을 그대로 흘리면
	// 푸터와 저작권 줄이 밀려 사라진다. 신뢰 등록 화면이 가장 길다.
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 110, Height: 24}) // 일부러 낮게
	send(t, m, key("5"))
	for i := 0; i < 3; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))

	view := m.View()
	lines := strings.Split(view, "\n")
	if len(lines) > 24 {
		t.Errorf("화면이 %d줄로 터미널 높이(24)를 넘었다", len(lines))
	}
	// 저작권 줄은 반드시 남아야 한다.
	if !strings.Contains(view, "theknowledges.net") {
		t.Errorf("긴 내용이 저작권 줄을 밀어냈다:\n%s", view)
	}
	// 잘렸다는 사실을 알려야 한다. 조용히 자르면 내용이 없다고 믿는다.
	if !strings.Contains(view, "PgUp/PgDn") {
		t.Errorf("잘림 안내가 없다:\n%s", view)
	}
}

func TestPageDownScrollsContent(t *testing.T) {
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 110, Height: 24})
	send(t, m, key("5"))
	for i := 0; i < 3; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))

	before := m.View()
	send(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
	after := m.View()
	if before == after {
		t.Error("PgDn 이 화면을 바꾸지 않았다")
	}
	if m.scroll[screenTrust] == 0 {
		t.Error("스크롤 위치가 올라가지 않았다")
	}
	// 끝까지 내려도 깨지지 않아야 한다.
	for i := 0; i < 20; i++ {
		send(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
	}
	if view := m.View(); !strings.Contains(view, "theknowledges.net") {
		t.Errorf("과도한 스크롤 후 화면이 깨졌다:\n%s", view)
	}
	// 되돌아올 수 있어야 한다.
	for i := 0; i < 30; i++ {
		send(t, m, tea.KeyMsg{Type: tea.KeyPgUp})
	}
	if m.scroll[screenTrust] != 0 {
		t.Errorf("PgUp 으로 처음으로 돌아오지 않았다: %d", m.scroll[screenTrust])
	}
}

func TestScrollResetsOnScreenChange(t *testing.T) {
	// 다른 화면에 갔다 오면 스크롤이 남아 있어 내용이 중간부터 보이면 혼란스럽다.
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 110, Height: 24})
	send(t, m, key("5"))
	for i := 0; i < 3; i++ {
		send(t, m, key("tab"))
	}
	send(t, m, key("enter"))
	send(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
	if m.scroll[screenTrust] == 0 {
		t.Fatal("전제 조건 실패")
	}
	send(t, m, key("esc"))
	send(t, m, key("4"))
	send(t, m, key("esc"))
	send(t, m, key("5"))
	if m.scroll[screenTrust] != 0 {
		t.Errorf("화면을 옮긴 뒤에도 스크롤이 남았다: %d", m.scroll[screenTrust])
	}
}

func TestEveryScreenFitsTerminalHeight(t *testing.T) {
	// 어느 화면도 터미널을 넘지 않아야 한다.
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := issue.Issue(m.cfg, m.store, issue.Options{
			Material: material,
			Subject:  names.Subject{CommonName: "host.hd.local"},
			Frontend: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	drain(t, m, m.Init(), 0)
	for _, size := range []tea.WindowSizeMsg{
		{Width: 80, Height: 20}, {Width: 100, Height: 24}, {Width: 160, Height: 50},
	} {
		send(t, m, size)
		for _, item := range menuItems {
			send(t, m, key(string(item.num)))
			view := m.View()
			if n := len(strings.Split(view, "\n")); n > size.Height {
				t.Errorf("%dx%d, %s 화면이 %d줄이다", size.Width, size.Height, item.label, n)
			}
		}
	}
}

func TestFooterDoesNotDuplicateEsc(t *testing.T) {
	// 화면이 "Esc 목록" 을 안내하는데 앱이 "Esc 메뉴" 를 또 붙이면 무엇이 맞는지 알 수 없다.
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter")) // 상세 — 여기서 Esc 는 '목록' 이다

	footer := m.renderFooter()
	if n := strings.Count(footer, "Esc"); n != 1 {
		t.Errorf("푸터에 Esc 안내가 %d개 있다: %q", n, footer)
	}
	if !strings.Contains(footer, "Esc 목록") {
		t.Errorf("화면이 안내한 Esc 용도가 사라졌다: %q", footer)
	}
}

// --- 패스프레이즈 모달 --------------------------------------------------------

func seedEncryptedCA(t *testing.T, m *Model) store.Cert {
	t.Helper()
	caRec, err := ca.CreateRoot(m.cfg, m.store, ca.CreateOptions{
		Subject: names.Subject{CommonName: "enc Root CA"}, Passphrase: "ca-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !caRec.KeyEncrypted {
		t.Fatal("전제 조건 실패: CA 키가 암호화되지 않았다")
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "ca-secret")
	if err != nil {
		t.Fatal(err)
	}
	res, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Record
}

func TestEncryptedCARenewPromptsForPassphrase(t *testing.T) {
	// 모달이 없으면 암호화된 CA 로는 TUI 에서 갱신을 전혀 할 수 없다(실제로 그랬다).
	m := newTestApp(t)
	rec := seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter")) // 상세
	send(t, m, key("r"))     // 갱신

	if m.modal == nil {
		t.Fatal("패스프레이즈 모달이 뜨지 않았다")
	}
	view := m.View()
	if !strings.Contains(view, "CA 패스프레이즈") {
		t.Errorf("모달 제목이 없다:\n%s", view)
	}
	// 모달이 떠 있어도 저작권 줄은 남아야 한다.
	if !strings.Contains(view, "theknowledges.net") {
		t.Errorf("모달이 저작권 줄을 밀어냈다:\n%s", view)
	}

	typeText(t, m, "ca-secret")
	send(t, m, key("enter"))
	if m.modal != nil {
		t.Error("확인 후 모달이 닫히지 않았다")
	}
	certs, err := m.store.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("갱신되지 않았다: %d건", len(certs))
	}
	previous, err := m.store.GetCert(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if previous.Status != "superseded" {
		t.Errorf("이전 건 상태 = %s", previous.Status)
	}
}

func TestModalMasksPassphrase(t *testing.T) {
	m := newTestApp(t)
	seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("r"))
	typeText(t, m, "ca-secret")

	view := m.View()
	// 패스프레이즈가 화면에 그대로 보이면 어깨너머로 읽힌다.
	if strings.Contains(view, "ca-secret") {
		t.Errorf("패스프레이즈가 평문으로 표시됐다:\n%s", view)
	}
}

func TestModalWrongPassphraseReportsKeyUnlock(t *testing.T) {
	m := newTestApp(t)
	seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("r"))
	typeText(t, m, "wrong")
	send(t, m, key("enter"))

	if m.modal != nil {
		t.Error("모달이 닫히지 않았다")
	}
	// 재입력을 유도하는 문장이어야 한다.
	if !strings.Contains(m.status, "패스프레이즈") {
		t.Errorf("오류가 패스프레이즈 문제를 말하지 않는다: %q", m.status)
	}
	certs, err := m.store.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("틀린 패스프레이즈로 갱신이 됐다: %d건", len(certs))
	}
}

func TestModalEscCancelsWithoutAction(t *testing.T) {
	m := newTestApp(t)
	seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("x")) // 폐기
	if m.modal == nil {
		t.Fatal("모달이 뜨지 않았다")
	}
	send(t, m, key("esc"))
	if m.modal != nil {
		t.Error("Esc 로 모달이 닫히지 않았다")
	}
	certs, err := m.store.ListCerts(store.CertFilter{Status: "revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Error("취소했는데 폐기됐다")
	}
}

func TestModalSwallowsGlobalShortcuts(t *testing.T) {
	// 모달 위로 Alt+숫자나 q 가 새어 나가면 입력 중에 화면이 바뀐다.
	m := newTestApp(t)
	seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("r"))

	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}, Alt: true})
	if m.modal == nil {
		t.Error("Alt+숫자가 모달을 닫았다")
	}
	if m.active != screenHistory {
		t.Error("모달 중에 화면이 바뀌었다")
	}
	send(t, m, tea.KeyMsg{Type: tea.KeyF5})
	if m.modal == nil {
		t.Error("F5 가 모달을 닫았다")
	}
	// Ctrl+C 는 예외 — 어떤 상태에서도 빠져나올 길은 있어야 한다.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !m.quitting {
		t.Error("모달 중에 Ctrl+C 로 종료할 수 없다")
	}
}

func TestRevokeReasonIsSelectable(t *testing.T) {
	// 사유를 고를 수 없으면 전부 unspecified 로 폐기되고 CRL 을 받는 쪽은 이유를 모른다.
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("s")) // 사유 변경
	hs := m.screenFor(screenHistory).(*historyScreen)
	if hs.revokeReason == "unspecified" {
		t.Error("s 키로 사유가 바뀌지 않았다")
	}
	chosen := hs.revokeReason
	send(t, m, key("x"))

	updated, err := m.store.GetCert(res.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "revoked" {
		t.Fatalf("폐기되지 않았다: %s", updated.Status)
	}
	if updated.RevokeReason != chosen {
		t.Errorf("폐기 사유 = %q, 기대 %q", updated.RevokeReason, chosen)
	}
}

// --- 백업 화면 ----------------------------------------------------------------

func TestBackupCreateThroughTUI(t *testing.T) {
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("6"))
	// 동작(기본 ①생성) → 경로 → 실행 버튼
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("enter"))

	view := m.View()
	if !strings.Contains(view, "백업 완료") {
		t.Errorf("백업이 만들어지지 않았다:\n%s", view)
	}
	// CA 개인키가 들어 있다는 사실은 반드시 알려야 한다.
	if !strings.Contains(view, "CA 개인키") {
		t.Errorf("CA 개인키 포함 경고가 없다:\n%s", view)
	}
	if !strings.Contains(view, "cert-gen backup create") {
		t.Errorf("CLI 등가 명령이 없다:\n%s", view)
	}
}

func TestBackupRestoreRequiresConfirmation(t *testing.T) {
	// 복원은 상태 디렉터리 전체를 대체한다. 드라이런 보고서를 먼저 보여 주고 확인을 받아야 한다.
	m := newTestApp(t)
	caRec, err := makeCA(t, m)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(m.cfg, m.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issue.Issue(m.cfg, m.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("6"))
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("enter"))
	bs := m.screenFor(screenBackup).(*backupScreen)
	if bs.created == nil {
		t.Fatalf("백업이 만들어지지 않았다 (status=%q)", m.status)
	}
	archive := bs.created.Path

	// 복원으로 바꾸고 경로를 넣어 실행 → 드라이런 보고서 + 확인 대기
	bs.action.SetValue(actionRestore)
	bs.path.SetValue(archive)
	send(t, m, key("enter"))
	if !bs.awaitingConfirm {
		t.Fatalf("확인을 받지 않고 넘어갔다 (status=%q)", m.status)
	}
	all := scrollAll(t, m)
	for _, want := range []string{"복원 드라이런", "복원 위치", "기존 보관"} {
		if !strings.Contains(all, want) {
			t.Errorf("드라이런 보고서에 %q 가 없다", want)
		}
	}

	// n 으로 취소하면 아무것도 바뀌지 않아야 한다.
	send(t, m, key("n"))
	if bs.awaitingConfirm {
		t.Error("n 으로 취소되지 않았다")
	}
	certs, err := m.store.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("취소했는데 상태가 바뀌었다: %d건", len(certs))
	}
}

func TestBackupScreenRejectsBadArchive(t *testing.T) {
	m := newTestApp(t)
	drain(t, m, m.Init(), 0)
	send(t, m, key("6"))
	bs := m.screenFor(screenBackup).(*backupScreen)
	bs.action.SetValue(actionRestore)
	bs.path.SetValue(filepath.Join(t.TempDir(), "nope.tar.gz"))
	send(t, m, key("tab")) // 경로
	send(t, m, key("tab")) // 실행 버튼
	send(t, m, key("enter"))
	if bs.awaitingConfirm {
		t.Error("없는 파일로 확인 대기에 들어갔다")
	}
	if m.status == "" {
		t.Error("오류를 알리지 않았다")
	}
}

func TestBackupConfirmIgnoresOtherKeys(t *testing.T) {
	// 확인 대기 중에 엉뚱한 키로 복원이 진행되면 안 된다.
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, key("6"))
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("enter"))
	bs := m.screenFor(screenBackup).(*backupScreen)
	if bs.created == nil {
		t.Fatalf("백업이 만들어지지 않았다 (status=%q)", m.status)
	}
	bs.action.SetValue(actionRestore)
	bs.path.SetValue(bs.created.Path)
	send(t, m, key("enter"))
	if !bs.awaitingConfirm {
		t.Fatal("전제 조건 실패")
	}
	for _, k := range []string{"enter", "tab", "r", "x", "0"} {
		send(t, m, key(k))
		if !bs.awaitingConfirm {
			t.Fatalf("%q 키가 확인 대기를 벗어났다", k)
		}
	}
}

func TestNoRenderedLineExceedsTerminalWidth(t *testing.T) {
	// 중첩된 박스의 폭을 잘못 계산하면 테두리가 접혀 화면이 깨진다(모달에서 실제로 그랬다).
	// 모든 화면·모달에서 어떤 줄도 터미널 폭을 넘지 않아야 한다.
	m := newTestApp(t)
	rec := seedEncryptedCA(t, m)
	if _, err := keymgmt.Create(m.cfg, m.store, keymgmt.CreateOptions{
		Name: "spare", Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_ = rec
	drain(t, m, m.Init(), 0)

	check := func(label string, width int) {
		t.Helper()
		for _, line := range strings.Split(m.View(), "\n") {
			if w := displayWidth(stripANSI(line)); w > width {
				t.Errorf("%s: %d칸 줄이 폭 %d 를 넘었다: %q", label, w, width, stripANSI(line))
				return
			}
		}
	}

	// 화면 이동은 Alt+숫자로 한다. 맨 숫자는 텍스트 필드에서 글자로 들어가므로
	// (설계대로) 폼 화면에 들어간 뒤에는 바로가기로 쓸 수 없다.
	jump := func(num rune) {
		t.Helper()
		send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{num}, Alt: true})
	}
	for _, width := range []int{80, 100, 140} {
		send(t, m, tea.WindowSizeMsg{Width: width, Height: 30})
		for _, item := range menuItems {
			jump(item.num)
			check(fmt.Sprintf("%s(%d)", item.label, width), width)
		}
		// 모달도 본다.
		jump('4')
		send(t, m, key("enter"))
		send(t, m, key("r"))
		if m.modal == nil {
			t.Fatal("모달이 뜨지 않았다")
		}
		check(fmt.Sprintf("모달(%d)", width), width)
		typeText(t, m, "ca-secret")
		check(fmt.Sprintf("모달 입력중(%d)", width), width)
		send(t, m, key("esc"))
	}
}
