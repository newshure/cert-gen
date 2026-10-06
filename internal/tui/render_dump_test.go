package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestDumpModal 은 모달 화면을 그대로 찍어 눈으로 확인하기 위한 것이다.
// CERT_GEN_TUI_DUMP=1 일 때만 출력한다.
func TestDumpModal(t *testing.T) {
	if os.Getenv("CERT_GEN_TUI_DUMP") == "" {
		t.Skip("CERT_GEN_TUI_DUMP=1 로 실행하면 화면을 찍는다")
	}
	m := newTestApp(t)
	seedEncryptedCA(t, m)
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 112, Height: 30})
	send(t, m, key("4"))
	send(t, m, key("enter"))
	send(t, m, key("r"))
	typeText(t, m, "ca-secret")

	fmt.Println("================ 패스프레이즈 모달 ================")
	fmt.Println(stripANSI(m.View()))
	fmt.Println("==================================================")
}

func TestDumpBackup(t *testing.T) {
	if os.Getenv("CERT_GEN_TUI_DUMP") == "" {
		t.Skip("CERT_GEN_TUI_DUMP=1 로 실행하면 화면을 찍는다")
	}
	m := newTestApp(t)
	if _, err := makeCA(t, m); err != nil {
		t.Fatal(err)
	}
	drain(t, m, m.Init(), 0)
	send(t, m, tea.WindowSizeMsg{Width: 112, Height: 30})
	send(t, m, key("6"))
	send(t, m, key("tab"))
	send(t, m, key("tab"))
	send(t, m, key("enter"))

	fmt.Println("================ 백업 화면 ================")
	fmt.Println(stripANSI(m.View()))
	fmt.Println("===========================================")
}

// stripANSI 는 색 코드를 떼어 낸다(로그로 보기 위함).
func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x1b:
			inEscape = true
		case inEscape && (c == 'm' || c == 'K' || c == 'H' || c == 'J'):
			inEscape = false
		case !inEscape:
			b.WriteByte(c)
		}
	}
	return b.String()
}
