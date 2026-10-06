package tui

// 표시 폭 계산. 한글·한자·가나는 2칸이다.
//
// lipgloss 도 폭을 계산하지만 Width()/Height() 로 박스를 맞출 때만 쓰고, 우리가 직접
// 문자열을 자르거나 채울 때는 이 함수들을 쓴다. len() 으로 세면 한글 CN 이 섞인 표의
// 열이 어긋난다.

import (
	"strings"
	"unicode"
)

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if isWideRune(r) {
			w += 2
		} else if r == '\t' {
			w += 4
		} else {
			w++
		}
	}
	return w
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // 한글 자모
		r >= 0x2E80 && r <= 0xA4CF, // CJK 라디칼·부수·한자
		r >= 0xAC00 && r <= 0xD7A3, // 한글 음절
		r >= 0xF900 && r <= 0xFAFF, // CJK 호환 한자
		r >= 0xFE30 && r <= 0xFE6F, // CJK 호환 기호
		r >= 0xFF00 && r <= 0xFF60, // 전각 영숫자
		r >= 0xFFE0 && r <= 0xFFE6:
		return true
	}
	return unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r)
}

// padDisplay 는 표시 폭 기준으로 오른쪽을 채운다.
func padDisplay(s string, width int) string {
	s = truncateDisplay(s, width)
	if pad := width - displayWidth(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// truncateDisplay 는 표시 폭 기준으로 자른다. 자르면 끝에 … 를 붙인다.
func truncateDisplay(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := 1
		if isWideRune(r) {
			w = 2
		}
		if used+w > width-1 {
			break
		}
		b.WriteRune(r)
		used += w
	}
	return b.String() + "…"
}

// wrapDisplay 는 표시 폭에 맞춰 줄바꿈한다.
//
// 한국어는 공백 없이 길게 이어지는 경우가 많아, 단어 단위로만 접으면 폭을 넘긴다.
// 단어가 폭보다 길면 글자 단위로 자른다.
func wrapDisplay(text string, width int) []string {
	if width <= 0 {
		return nil
	}
	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		cur := ""
		for _, w := range words {
			switch {
			case cur == "":
				cur = w
			case displayWidth(cur)+1+displayWidth(w) <= width:
				cur += " " + w
			default:
				lines = append(lines, cur)
				cur = w
			}
			// 한 단어가 폭보다 길면 글자 단위로 쪼갠다.
			for displayWidth(cur) > width {
				head := truncateDisplay(cur, width)
				head = strings.TrimSuffix(head, "…")
				if head == "" {
					break
				}
				lines = append(lines, head)
				cur = strings.TrimPrefix(cur, head)
			}
		}
		if cur != "" {
			lines = append(lines, cur)
		}
	}
	return lines
}
