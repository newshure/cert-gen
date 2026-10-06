package cli

// 출력. 사람이 읽는 표와 --json 두 가지를 낸다.
//
// 표 폭 계산에 동아시아 문자를 2칸으로 센다. 한글 CN 이 섞이면 단순 len() 으로는 열이 어긋나
// 표가 읽기 어려워진다.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Out 은 출력 대상과 모드를 담는다.
type Out struct {
	W     io.Writer
	Err   io.Writer
	JSON  bool
	Quiet bool
}

// Printf 는 사람이 읽는 출력이다. --quiet 면 생략한다.
func (o Out) Printf(format string, args ...any) {
	if o.Quiet || o.JSON {
		return
	}
	fmt.Fprintf(o.W, format, args...)
}

// Line 은 한 줄 출력이다(--quiet 에서도 식별자 등 최소 출력에 쓴다).
func (o Out) Line(format string, args ...any) {
	if o.JSON {
		return
	}
	fmt.Fprintf(o.W, format+"\n", args...)
}

// Warn 은 경고를 stderr 로 낸다. --quiet 에서도 낸다 — 경고를 숨기면 의미가 없다.
func (o Out) Warn(format string, args ...any) {
	fmt.Fprintf(o.Err, "경고: "+format+"\n", args...)
}

// Warnings 는 경고 목록을 낸다.
func (o Out) Warnings(list []string) {
	for _, w := range list {
		o.Warn("%s", w)
	}
}

// Emit 은 --json 일 때 JSON 을 낸다.
func (o Out) Emit(value any) error {
	if !o.JSON {
		return nil
	}
	enc := json.NewEncoder(o.W)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

// Table 은 정렬된 표를 낸다.
func (o Out) Table(headers []string, rows [][]string) {
	if o.JSON {
		return
	}
	if len(rows) == 0 {
		fmt.Fprintln(o.W, "(없음)")
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = displayWidth(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && displayWidth(cell) > widths[i] {
				widths[i] = displayWidth(cell)
			}
		}
	}
	writeRow(o.W, headers, widths)
	seps := make([]string, len(headers))
	for i := range seps {
		seps[i] = strings.Repeat("-", widths[i])
	}
	writeRow(o.W, seps, widths)
	for _, row := range rows {
		writeRow(o.W, row, widths)
	}
}

func writeRow(w io.Writer, cells []string, widths []int) {
	parts := make([]string, 0, len(cells))
	for i, cell := range cells {
		pad := 0
		if i < len(widths) {
			pad = widths[i] - displayWidth(cell)
		}
		if pad < 0 {
			pad = 0
		}
		parts = append(parts, cell+strings.Repeat(" ", pad))
	}
	fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
}

// displayWidth 는 터미널에서 차지하는 칸 수다.
//
// 한글·한자·가나는 2칸이다. len() 이나 문자 수로 세면 한글 CN 이 섞인 표의 열이 어긋난다.
func displayWidth(s string) int {
	width := 0
	for _, r := range s {
		if isWide(r) {
			width += 2
		} else {
			width++
		}
	}
	return width
}

func isWide(r rune) bool {
	// 한글, CJK 통합 한자, 가나, 전각 기호. 이 범위로 실무에 나오는 경우는 모두 덮는다.
	switch {
	case r >= 0x1100 && r <= 0x115F, // 한글 자모
		r >= 0x2E80 && r <= 0xA4CF, // CJK 라디칼 ~ 이
		r >= 0xAC00 && r <= 0xD7A3, // 한글 음절
		r >= 0xF900 && r <= 0xFAFF, // CJK 호환 한자
		r >= 0xFE30 && r <= 0xFE6F, // CJK 호환 기호
		r >= 0xFF00 && r <= 0xFF60, // 전각 영숫자
		r >= 0xFFE0 && r <= 0xFFE6:
		return true
	}
	return unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r)
}

// padRight 는 표시 폭 기준으로 오른쪽을 공백으로 채운다.
//
// fmt 의 %-Ns 는 바이트를 세므로 한글이 섞이면 어긋난다.
func padRight(s string, width int) string {
	pad := width - displayWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// Truncate 는 표 셀을 폭 기준으로 줄인다.
func Truncate(s string, max int) string {
	if displayWidth(s) <= max {
		return s
	}
	var b strings.Builder
	width := 0
	for _, r := range s {
		w := 1
		if isWide(r) {
			w = 2
		}
		if width+w > max-1 {
			break
		}
		b.WriteRune(r)
		width += w
	}
	return b.String() + "…"
}
