package tui

// 색과 테두리. 한곳에 모아 두면 화면마다 다른 모양이 나오는 것을 막는다.
//
// 블록 문자(▔▁▊▎ 같은 반칸 글리프)는 쓰지 않는다. 폰트에 따라 ㅁ 로 깨지고, 깨지지 않아도
// 화면이 어지러워진다. 테두리는 가는 선(─│┌)만 쓰고, 강조는 배경색으로 한다.

import "github.com/charmbracelet/lipgloss"

var (
	colorFg     = lipgloss.AdaptiveColor{Light: "#1f2328", Dark: "#e6e6e6"}
	colorDim    = lipgloss.AdaptiveColor{Light: "#6a737d", Dark: "#8b949e"}
	colorAccent = lipgloss.AdaptiveColor{Light: "#0550ae", Dark: "#58a6ff"}
	colorOK     = lipgloss.AdaptiveColor{Light: "#1a7f37", Dark: "#3fb950"}
	colorWarn   = lipgloss.AdaptiveColor{Light: "#9a6700", Dark: "#d29922"}
	colorErr    = lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#f85149"}
	colorSelBG  = lipgloss.AdaptiveColor{Light: "#ddf4ff", Dark: "#163a5f"}
	colorActBG  = lipgloss.AdaptiveColor{Light: "#eaeef2", Dark: "#21262d"}
	colorBorder = lipgloss.AdaptiveColor{Light: "#d0d7de", Dark: "#30363d"}
)

var (
	styleTitle = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleDim   = lipgloss.NewStyle().Foreground(colorDim)
	styleOK    = lipgloss.NewStyle().Foreground(colorOK)
	styleWarn  = lipgloss.NewStyle().Foreground(colorWarn)
	styleErr   = lipgloss.NewStyle().Foreground(colorErr)
	styleBody  = lipgloss.NewStyle().Foreground(colorFg)
	styleLabel = lipgloss.NewStyle().Foreground(colorDim)

	// 좌측 메뉴: 선택 중인 항목에 배경색을 넣는다(사용자 요청).
	styleMenuSelected = lipgloss.NewStyle().
				Background(colorSelBG).Foreground(colorFg).Bold(true)
	// 포커스가 콘텐츠로 넘어가도 '지금 보고 있는 화면' 은 계속 표시한다.
	styleMenuActive = lipgloss.NewStyle().Background(colorActBG).Foreground(colorFg)
	styleMenuNormal = lipgloss.NewStyle().Foreground(colorFg)

	// 좌/우 구분선 (사용자 요청: | 구분선은 있는 게 맞다)
	styleDivider = lipgloss.NewStyle().Foreground(colorBorder)

	styleFooter = lipgloss.NewStyle().Foreground(colorDim)
	styleKey    = lipgloss.NewStyle().Foreground(colorAccent)

	// 입력 필드: 테두리 대신 밑줄 느낌을 주지 않고, 가는 선 테두리만 쓴다.
	styleField = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).BorderForeground(colorBorder).
			Padding(0, 1)
	styleFieldFocus = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).BorderForeground(colorAccent).
			Padding(0, 1)

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).BorderForeground(colorBorder).
			Padding(0, 1)
)

// copyright 는 화면 하단에 항상 띄운다(사용자 지정 문구).
const copyrightLine = "저작권자: HaeDong   출처: https://theknowledges.net   사용조건: 출처 명시 시 자유 사용"
