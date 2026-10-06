package cli

import (
	"fmt"

	"github.com/newshure/cert-gen/internal/backup"
	"github.com/newshure/cert-gen/internal/certerr"
)

func (a *App) backupCreate(args []string) error {
	fs := flags("backup create")
	outPath := fs.String("o", "", "출력 파일 (기본: <상태 디렉터리>/backups/cert-gen-backup-<시각>.tar.gz)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	res, err := backup.Create(a.cfg, a.store, *outPath, "cli")
	if err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{
		"path": res.Path, "bytes": res.Size, "sha256": res.SHA256,
		"files": len(res.Manifest.Files), "counts": res.Manifest.Counts,
	}); err != nil {
		return err
	}
	a.Out.Line("%s", res.Path)
	a.Out.Printf("백업을 만들었습니다.\n")
	a.Out.Printf("  크기          %s\n", humanBytes(res.Size))
	a.Out.Printf("  SHA256        %s\n", res.SHA256)
	a.Out.Printf("  파일          %d개\n", len(res.Manifest.Files))
	c := res.Manifest.Counts
	a.Out.Printf("  내용          CA %d / 인증서 %d / 개인키 %d\n", c.CAs, c.Certs, c.Keys)
	a.Out.Warnings(res.Warnings)
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f TiB", value/unit)
}

func (a *App) backupRestore(args []string) error {
	fs := flags("backup restore")
	var (
		dryRun = fs.Bool("dry-run", false, "검증과 보고만 하고 복원하지 않는다")
		yes    = fs.Bool("yes", false, "확인 없이 진행")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("복원할 백업 파일을 하나 지정하세요")
	}
	// 상태 디렉터리가 아직 없을 수도 있다(새 호스트로 옮기는 경우).
	if err := a.open(true); err != nil {
		return err
	}
	plan, err := backup.Inspect(a.cfg, a.store, rest[0])
	if err != nil {
		return err
	}

	if err := a.Out.Emit(map[string]any{
		"ok": plan.OK(), "archive": plan.ArchivePath,
		"target_data_dir": plan.TargetDataDir, "move_existing_to": plan.MoveExistingTo,
		"manifest": plan.Manifest, "problems": plan.Problems, "warnings": plan.Warnings,
		"applied": false,
	}); err != nil {
		return err
	}
	a.Out.Printf("%s", plan.Describe())
	a.Out.Warnings(plan.Warnings)
	for _, p := range plan.Problems {
		a.Out.Printf("%s\n", "문제: "+p)
	}

	if !plan.OK() {
		return certerr.Statef("복원할 수 없습니다. 위 문제를 먼저 해결하세요")
	}
	if *dryRun {
		a.Out.Printf("\n드라이런입니다. 아무것도 바꾸지 않았습니다.\n")
		return nil
	}
	if !*yes {
		// 복원은 상태 디렉터리 전체를 대체한다. 기존 것은 보관되지만 확인은 받아야 한다.
		if !confirm("현재 상태 디렉터리를 대체합니다. 진행합니까?") {
			return certerr.Validationf("취소했습니다")
		}
	}

	// backup.Apply 가 DB 를 닫는다. 닫지 않고 디렉터리를 옮기면 이후 쿼리가 사라진
	// 파일을 가리킨다.
	store := a.store
	a.store = nil
	if err := backup.Apply(a.cfg, store, plan, "cli"); err != nil {
		return err
	}
	a.Out.Line("복원했습니다: %s", a.cfg.DataDir)
	if plan.MoveExistingTo != "" {
		a.Out.Printf("기존 상태는 %s 에 보관했습니다. 확인 후 지우세요.\n", plan.MoveExistingTo)
	}
	return nil
}
