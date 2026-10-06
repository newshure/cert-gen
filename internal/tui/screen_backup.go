package tui

// 6번 메뉴 — 백업·복원.
//
// 사용자가 지정한 5개 메뉴 뒤에 덧붙인 항목이다. 요구사항에 "백업/복원 포함" 이 있는데
// 그것을 하는 입구가 없었다.
//
// 복원은 되돌릴 수 없는 동작에 가깝다(기존 것은 옆으로 치워 두지만). 그래서 **반드시
// 드라이런 보고서를 먼저 보여 주고**, 확인을 받은 뒤에 적용한다.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/newshure/cert-gen/internal/backup"
)

const (
	actionCreate  = "create"
	actionRestore = "restore"
)

type backupScreen struct {
	app *Model

	form   *form
	action *selectField
	path   *textField

	created *backup.Result
	plan    *backup.Plan
	// awaitingConfirm 이면 Enter 가 '복원 실행' 이다.
	awaitingConfirm bool
	lastCommand     string
}

func newBackupScreen(app *Model) *backupScreen {
	s := &backupScreen{app: app}
	// 동작을 명시적으로 고르게 한다. "경로가 비면 백업, 있으면 복원" 같은 암묵적 분기는
	// 되돌릴 수 없는 동작(복원)을 실수로 고르게 만든다. 2·3번 메뉴의 ①/② 분기와 같은 방식이다.
	s.action = newSelectField("동작", []choice{
		{Value: actionCreate, Label: "① 백업 생성"},
		{Value: actionRestore, Label: "② 백업에서 복원 (상태 디렉터리를 대체합니다)"},
	}, "")
	s.path = newTextField("백업 파일 경로", "복원할 .tar.gz 파일 (복원에만 쓰입니다)", false)
	s.form = newForm("실행", 'r', s.action, s.path)
	return s
}

func (s *backupScreen) Title() string { return "백업 · 복원" }

func (s *backupScreen) Init() tea.Cmd { return nil }

func (s *backupScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	// 복원 확인 대기 중에는 y/n 만 듣는다. 다른 키로 실수로 진행되면 안 된다.
	if s.awaitingConfirm {
		switch key.String() {
		case "y", "Y":
			return s, s.applyRestore()
		case "n", "N", "esc":
			s.awaitingConfirm = false
			s.plan = nil
			return s, info("복원을 취소했습니다")
		}
		return s, nil
	}
	return s, s.form.Update(key, s.submit)
}

func (s *backupScreen) submit() tea.Cmd {
	if s.action.Value() == actionRestore {
		path := s.path.Value()
		if path == "" {
			return warn("복원할 백업 파일 경로를 입력하세요")
		}
		return s.inspectRestore(path)
	}
	return s.createBackup()
}

func (s *backupScreen) createBackup() tea.Cmd {
	s.plan = nil
	s.awaitingConfirm = false
	res, err := backup.Create(s.app.cfg, s.app.store, "", "tui")
	if err != nil {
		return fail(err)
	}
	s.created = &res
	s.lastCommand = "cert-gen backup create"
	return tea.Batch(scrollEnd(),
		warn("백업을 만들었습니다. 이 파일에는 CA 개인키가 들어 있습니다"))
}

func (s *backupScreen) inspectRestore(path string) tea.Cmd {
	s.created = nil
	plan, err := backup.Inspect(s.app.cfg, s.app.store, path)
	if err != nil {
		return fail(err)
	}
	s.plan = &plan
	s.lastCommand = fmt.Sprintf("cert-gen backup restore %s --dry-run", path)
	if !plan.OK() {
		s.awaitingConfirm = false
		return tea.Batch(scrollEnd(), warn("이 백업으로는 복원할 수 없습니다"))
	}
	// 확인을 받은 뒤에만 적용한다.
	s.awaitingConfirm = true
	return tea.Batch(scrollEnd(),
		warn("위 내용을 확인하세요. 복원하려면 y, 취소는 n"))
}

func (s *backupScreen) applyRestore() tea.Cmd {
	if s.plan == nil {
		return warn("복원 계획이 없습니다")
	}
	plan := *s.plan
	if err := backup.Apply(s.app.cfg, s.app.store, plan, "tui"); err != nil {
		return fail(err)
	}
	s.awaitingConfirm = false
	s.plan = nil
	s.lastCommand = fmt.Sprintf("cert-gen backup restore %s --yes", plan.ArchivePath)
	// 복원하면 DB 내용이 전부 바뀐다. 모든 화면을 다시 만들어야 한다 —
	// 그대로 두면 이전 데이터가 캐시된 화면이 남는다.
	for id := range s.app.screens {
		if id != screenBackup {
			delete(s.app.screens, id)
		}
	}
	return tea.Batch(scrollEnd(),
		good("복원했습니다. 기존 상태는 %s 에 보관했습니다", plan.MoveExistingTo))
}

func (s *backupScreen) View(width, height int) string {
	var b strings.Builder
	b.WriteString(s.form.View(width - 2))
	if s.action.Value() == actionCreate {
		b.WriteString("\n" + styleDim.Render(
			"백업은 "+s.app.cfg.BackupPath()+" 에 만들어집니다.") + "\n")
	} else {
		b.WriteString("\n" + styleDim.Render(
			"먼저 검증하고 보고서를 보여 줍니다. 확인 후에만 복원합니다.") + "\n")
	}

	if s.created != nil {
		res := s.created
		b.WriteString("\n" + styleOK.Render("백업 완료") + "\n")
		rows := [][2]string{
			{"파일", res.Path},
			{"크기", fmt.Sprintf("%d바이트", res.Size)},
			{"SHA256", res.SHA256},
			{"파일 수", fmt.Sprintf("%d", len(res.Manifest.Files))},
			{"내용", fmt.Sprintf("CA %d / 인증서 %d / 개인키 %d",
				res.Manifest.Counts.CAs, res.Manifest.Counts.Certs, res.Manifest.Counts.Keys)},
		}
		for _, r := range rows {
			b.WriteString(styleLabel.Render(padDisplay("  "+r[0], 10)) +
				styleBody.Render(truncateDisplay(r[1], width-14)) + "\n")
		}
		for _, w := range res.Warnings {
			b.WriteString("\n" + styleErr.Render("경고: ") + styleBody.Render(w) + "\n")
		}
	}

	if s.plan != nil {
		b.WriteString("\n" + styleTitle.Render("복원 드라이런") + "\n")
		for _, line := range strings.Split(s.plan.Describe(), "\n") {
			if line == "" {
				continue
			}
			b.WriteString(styleBody.Render("  "+truncateDisplay(line, width-6)) + "\n")
		}
		for _, p := range s.plan.Problems {
			b.WriteString(styleErr.Render("  문제: ") + styleBody.Render(truncateDisplay(p, width-12)) + "\n")
		}
		for _, w := range s.plan.Warnings {
			b.WriteString(styleWarn.Render("  주의: ") + styleBody.Render(truncateDisplay(w, width-12)) + "\n")
		}
		if s.awaitingConfirm {
			b.WriteString("\n" + styleWarn.Render("  복원하려면 y, 취소는 n") + "\n")
		}
	}

	if s.lastCommand != "" {
		b.WriteString("\n" + styleLabel.Render("같은 일을 하는 CLI 명령") + "\n" +
			styleBox.Width(width-4).Render(wrapJoin(s.lastCommand, width-8)))
	}
	return b.String()
}

func (s *backupScreen) Help() []string {
	if s.awaitingConfirm {
		return []string{"y 복원 실행", "n 취소"}
	}
	return s.form.Help()
}

func (s *backupScreen) CapturesText() bool {
	if s.awaitingConfirm {
		// 확인 대기 중에는 글자를 받지 않는다. y/n 만 듣는다.
		return false
	}
	return s.form.CapturesText()
}
