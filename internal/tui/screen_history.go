package tui

// 4번 메뉴 — 발급 이력·만료 조회.
//
// 이력·serial 을 SQLite 로 관리하는데 그것을 **보는 입구**가 없으면 요구사항이 반쪽이 된다.
// 실사용 빈도는 발급보다 "지금 뭐가 있고 언제 만료되나" 가 높으므로 시작 화면으로 둔다.
// 검증·갱신·폐기를 거는 자리도 여기다.

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/store"
	"github.com/newshure/cert-gen/internal/verify"
)

func storeFilterAll() store.CertFilter { return store.CertFilter{} }

type historyLoadedMsg struct {
	list []store.Cert
	err  error
}

type historyScreen struct {
	app *Model

	list []store.Cert
	row  int

	// filter 는 현재 보기다.
	filterIdx int

	// detail 이 켜지면 선택한 인증서의 상세를 보여 준다.
	detail bool
	report *verify.Report

	// revokeReason 은 다음 폐기에 쓸 사유다. s 키로 돈다.
	revokeReason string

	lastCommand string
}

var historyFilters = []struct {
	label  string
	filter store.CertFilter
}{
	{"전체", store.CertFilter{}},
	{"유효", store.CertFilter{Status: "valid"}},
	{"만료 30일 내", store.CertFilter{ExpiringIn: intPtr(30)}},
	{"만료 90일 내", store.CertFilter{ExpiringIn: intPtr(90)}},
	{"폐기", store.CertFilter{Status: "revoked"}},
	{"대체됨", store.CertFilter{Status: "superseded"}},
}

func intPtr(v int) *int { return &v }

func newHistoryScreen(app *Model) *historyScreen {
	return &historyScreen{app: app, revokeReason: "unspecified"}
}

func (s *historyScreen) Title() string {
	if s.detail {
		return "인증서 상세"
	}
	return "발급 이력 · 만료 조회  [" + historyFilters[s.filterIdx].label + "]"
}

func (s *historyScreen) Init() tea.Cmd { return s.reload() }

func (s *historyScreen) reload() tea.Cmd {
	filter := historyFilters[s.filterIdx].filter
	return func() tea.Msg {
		list, err := s.app.store.ListCerts(filter)
		return historyLoadedMsg{list, err}
	}
}

func (s *historyScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case historyLoadedMsg:
		if msg.err != nil {
			return s, fail(msg.err)
		}
		s.list = msg.list
		if s.row >= len(s.list) {
			s.row = max(0, len(s.list)-1)
		}
		return s, nil
	case tea.KeyMsg:
		return s.handleKey(msg)
	}
	return s, nil
}

func (s *historyScreen) handleKey(msg tea.KeyMsg) (screen, tea.Cmd) {
	if s.detail {
		switch msg.String() {
		case "esc", "backspace", "left":
			s.detail = false
			s.report = nil
			return s, nil
		case "v":
			return s, s.verifySelected()
		case "r":
			return s, s.renewSelected()
		case "x":
			return s, s.revokeSelected()
		case "s":
			return s, s.cycleRevokeReason()
		}
		return s, nil
	}

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
	case "home":
		s.row = 0
		return s, nil
	case "end":
		s.row = max(0, len(s.list)-1)
		return s, nil
	case "enter", "right":
		if len(s.list) == 0 {
			return s, warn("발급 이력이 없습니다. 2번 메뉴에서 발급하세요")
		}
		s.detail = true
		s.report = nil
		return s, nil
	case "f":
		// 보기 전환. 숫자키는 좌측 메뉴 바로가기에 쓰이므로 f 로 돈다.
		s.filterIdx = (s.filterIdx + 1) % len(historyFilters)
		s.row = 0
		return s, s.reload()
	case "v":
		return s, s.verifySelected()
	}
	return s, nil
}

func (s *historyScreen) selected() (store.Cert, bool) {
	if s.row < 0 || s.row >= len(s.list) {
		return store.Cert{}, false
	}
	return s.list[s.row], true
}

func (s *historyScreen) verifySelected() tea.Cmd {
	rec, ok := s.selected()
	if !ok {
		return warn("선택한 인증서가 없습니다")
	}
	in, err := export.FromBundle(s.app.cfg, rec, "")
	if err != nil {
		return fail(err)
	}
	caRec, err := s.app.store.GetCA(fmt.Sprintf("%d", rec.CAID))
	if err != nil {
		return fail(err)
	}
	host := ""
	if len(rec.SANs) > 0 && rec.SANs[0].Type == "dns" {
		host = rec.SANs[0].Value
	}
	report, err := verify.Run(s.app.cfg, in, verify.Options{
		Hostname: host, CheckRevocation: true, CARecord: &caRec, CrossCheckOpenSSL: true,
	})
	if err != nil {
		return fail(err)
	}
	s.report = &report
	s.detail = true
	s.lastCommand = fmt.Sprintf("cert-gen cert verify %d", rec.ID)
	if report.OK() {
		return good("검증 통과")
	}
	return warn("검증 실패 %d건", len(report.Failures()))
}

// withCAMaterial 은 CA 재료를 열어 fn 에 넘긴다.
//
// CA 키가 암호화되어 있으면 패스프레이즈 모달을 띄우고, 입력을 받은 뒤에 fn 을 실행한다.
// 이 간접이 없으면 암호화된 CA 로는 TUI 에서 갱신·폐기를 전혀 할 수 없다.
func (s *historyScreen) withCAMaterial(rec store.Cert, label string,
	fn func(ca.Material) tea.Cmd) tea.Cmd {

	caRec, err := s.app.store.GetCA(fmt.Sprintf("%d", rec.CAID))
	if err != nil {
		return fail(err)
	}
	if !caRec.KeyEncrypted {
		material, err := ca.LoadMaterial(s.app.cfg, s.app.store, caRec, "")
		if err != nil {
			return fail(err)
		}
		return fn(material)
	}
	return askPassphrase(
		fmt.Sprintf("CA 패스프레이즈 — %s", label),
		fmt.Sprintf("CA %q 의 개인키가 암호화되어 있습니다. %s에는 CA 서명이 필요합니다.",
			caRec.Slug, label),
		func(passphrase string) tea.Cmd {
			material, err := ca.LoadMaterial(s.app.cfg, s.app.store, caRec, passphrase)
			if err != nil {
				// 패스프레이즈 오류는 재입력을 유도해야 한다. 설정 문제와 섞으면
				// 사용자가 무엇을 고쳐야 할지 모른다.
				return fail(err)
			}
			return fn(material)
		})
}

func (s *historyScreen) renewSelected() tea.Cmd {
	rec, ok := s.selected()
	if !ok {
		return warn("선택한 인증서가 없습니다")
	}
	return s.withCAMaterial(rec, "갱신", func(material ca.Material) tea.Cmd {
		res, err := issue.Renew(s.app.cfg, s.app.store, issue.RenewOptions{
			Material: material, Record: rec, Frontend: "tui",
		})
		if err != nil {
			return fail(err)
		}
		s.lastCommand = fmt.Sprintf("cert-gen cert renew %d", rec.ID)
		s.detail = false
		return tea.Batch(s.reload(),
			good("갱신 완료: #%d → #%d (새 키). 서버의 privkey.pem 도 교체해야 합니다",
				rec.ID, res.Record.ID))
	})
}

func (s *historyScreen) revokeSelected() tea.Cmd {
	rec, ok := s.selected()
	if !ok {
		return warn("선택한 인증서가 없습니다")
	}
	if rec.Status == "revoked" {
		return warn("이미 폐기된 인증서입니다 (%s, %s)", shortDate(rec.RevokedAt), rec.RevokeReason)
	}
	return s.withCAMaterial(rec, "폐기", func(material ca.Material) tea.Cmd {
		out, err := crl.Revoke(s.app.cfg, s.app.store, material, rec, s.revokeReason, "tui")
		if err != nil {
			return fail(err)
		}
		s.lastCommand = fmt.Sprintf("cert-gen cert revoke %d --reason %s", rec.ID, s.revokeReason)
		s.detail = false
		return tea.Batch(s.reload(),
			good("폐기했습니다(%s). %s", s.revokeReason, crl.Describe(out.CRL)))
	})
}

// cycleRevokeReason 은 폐기 사유를 돈다.
//
// 사유를 고를 수 없으면 전부 unspecified 로 폐기되고, CRL 을 받는 쪽은 왜 폐기됐는지
// 알 수 없다. keyCompromise 와 superseded 는 대응이 전혀 다르다.
func (s *historyScreen) cycleRevokeReason() tea.Cmd {
	names := crl.ReasonNames()
	idx := 0
	for i, n := range names {
		if n == s.revokeReason {
			idx = i
		}
	}
	s.revokeReason = names[(idx+1)%len(names)]
	reason, _ := crl.ReasonFor(s.revokeReason)
	return info("폐기 사유: %s (%s) — x 로 폐기합니다", reason.Name, reason.Label)
}

func (s *historyScreen) View(width, height int) string {
	if s.detail {
		return s.viewDetail(width)
	}
	if len(s.list) == 0 {
		return styleDim.Render("해당 조건의 인증서가 없습니다.") + "\n\n" +
			styleKey.Render("f") + styleDim.Render(" 로 보기를 바꾸거나, 2번 메뉴에서 발급하세요.")
	}

	headers := []string{"ID", "CN", "프로필", "만료", "남음", "상태", "쌍"}
	widths := []int{5, 24, 14, 11, 7, 11, 9}
	var b strings.Builder
	b.WriteString(renderRow(headers, widths, styleLabel) + "\n")
	b.WriteString(styleDivider.Render(strings.Repeat("─", sumInts(widths)+len(widths)*2)) + "\n")

	for i, rec := range s.list {
		remaining, urgent := remainingDays(rec.NotAfter)
		cells := []string{
			fmt.Sprintf("%d", rec.ID), rec.CommonName, rec.Profile,
			shortDate(rec.NotAfter), remaining, rec.Status,
			keymgmt.PairToken(rec.PublicSHA256),
		}
		line := renderRow(cells, widths, styleBody)
		switch {
		case i == s.row:
			b.WriteString(styleMenuSelected.Render(padDisplay(line, sumInts(widths)+len(widths)*2)))
		case rec.Status == "revoked":
			b.WriteString(styleDim.Render(line))
		case urgent:
			b.WriteString(styleWarn.Render(line))
		default:
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// remainingDays 는 남은 일수와 '임박' 여부다.
func remainingDays(notAfter string) (string, bool) {
	t, err := store.ParseTime(notAfter)
	if err != nil {
		return "?", false
	}
	days := int(time.Until(t).Hours() / 24)
	switch {
	case days < 0:
		return "만료", true
	case days <= 30:
		return fmt.Sprintf("%d일", days), true
	default:
		return fmt.Sprintf("%d일", days), false
	}
}

func (s *historyScreen) viewDetail(width int) string {
	rec, ok := s.selected()
	if !ok {
		return styleDim.Render("선택한 인증서가 없습니다.")
	}
	var b strings.Builder
	rows := [][2]string{
		{"ID", fmt.Sprintf("%d (CA 내 %d번)", rec.ID, rec.Seq)},
		{"Subject", rec.SubjectDN},
		{"SAN", sanSummary(rec)},
		{"프로필", rec.Profile + " / " + rec.KeyAlgo},
		{"유효기간", shortDate(rec.NotBefore) + " ~ " + shortDate(rec.NotAfter)},
		{"serial", rec.SerialHex},
		{"지문", rec.Fingerprint},
		{"쌍 토큰", keymgmt.PairToken(rec.PublicSHA256)},
		{"상태", rec.Status},
		{"개인키", yesNo(rec.HasPrivateKey)},
		{"출처", rec.Source},
		{"번들", rec.BundlePath},
	}
	if rec.RevokeReason != "" {
		rows = append(rows, [2]string{"폐기", rec.RevokeReason + " (" + shortDate(rec.RevokedAt) + ")"})
	}
	if rec.Note != "" {
		rows = append(rows, [2]string{"메모", rec.Note})
	}
	for _, r := range rows {
		b.WriteString(styleLabel.Render(padDisplay("  "+r[0], 12)) +
			styleBody.Render(truncateDisplay(r[1], width-16)) + "\n")
	}

	if s.report != nil {
		b.WriteString("\n" + styleLabel.Render("  검증 결과") + "\n")
		for _, c := range s.report.Checks {
			mark, style := statusMark(c.Status)
			b.WriteString("  " + style.Render(padDisplay(mark, 9)) +
				styleBody.Render(padDisplay(c.Name, 18)) +
				styleDim.Render(truncateDisplay(c.Detail, width-34)) + "\n")
		}
		counts := s.report.Counts()
		b.WriteString(fmt.Sprintf("\n  통과 %d / 경고 %d / 건너뜀 %d / 실패 %d\n",
			counts[verify.StatusPass], counts[verify.StatusWarn],
			counts[verify.StatusSkip], counts[verify.StatusFail]))
	}
	if s.lastCommand != "" {
		b.WriteString("\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
			styleBox.Width(width-4).Render(truncateDisplay(s.lastCommand, width-8)))
	}
	return b.String()
}

func statusMark(st verify.Status) (string, interface{ Render(...string) string }) {
	switch st {
	case verify.StatusPass:
		return "[통과]", styleOK
	case verify.StatusFail:
		return "[실패]", styleErr
	case verify.StatusWarn:
		return "[경고]", styleWarn
	default:
		return "[건너뜀]", styleDim
	}
}

func yesNo(v bool) string {
	if v {
		return "있음"
	}
	return "없음 (CSR 서명 건)"
}

func (s *historyScreen) Help() []string {
	if s.detail {
		return []string{"v 검증", "r 갱신(R)", "x 폐기(X)",
			"s 사유:" + s.revokeReason, "Esc 목록"}
	}
	return []string{"↑↓ 이동", "Enter 상세", "f 보기전환", "v 검증"}
}

// CapturesText 는 항상 false 다. 이 화면은 목록·상세뿐이고 글자 입력을 받지 않는다.
func (s *historyScreen) CapturesText() bool { return false }
