package cli

// doctor — 환경 점검.
//
// 발급이 실패하기 **전에** 문제를 찾는 것이 목적이다. 그래서 "무엇을 확인했는지" 를 항목으로
// 남기고, 확인하지 못한 것은 통과가 아니라 '건너뜀' 으로 구분한다(verify 와 같은 원칙).
//
// 종료코드는 실패 항목이 있으면 1 이다. 경고와 건너뜀은 실패가 아니다 — 경고로 종료코드를
// 올리면 cron 에서 쓸 수 없게 된다.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/store"
)

type checkState string

const (
	checkPass checkState = "pass"
	checkFail checkState = "fail"
	checkWarn checkState = "warn"
	checkSkip checkState = "skip"
)

type doctorCheck struct {
	Name   string     `json:"name"`
	State  checkState `json:"state"`
	Detail string     `json:"detail"`
}

type doctorReport struct {
	checks []doctorCheck
}

func (r *doctorReport) add(name string, state checkState, format string, args ...any) {
	r.checks = append(r.checks, doctorCheck{name, state, fmt.Sprintf(format, args...)})
}

func (r *doctorReport) failed() int {
	n := 0
	for _, c := range r.checks {
		if c.State == checkFail {
			n++
		}
	}
	return n
}

func (a *App) cmdDoctor(args []string) error {
	fs := flags("doctor")
	deep := fs.Bool("deep", false, "번들 해시까지 검사한다 (건수가 많으면 느리다)")
	if _, err := parse(fs, args); err != nil {
		return err
	}

	var r doctorReport

	// 설정과 상태 디렉터리. 여기서 실패하면 나머지는 볼 것이 없다.
	if err := a.open(false); err != nil {
		r.add("상태 디렉터리", checkFail, "%s", certerr.UserMessage(err))
		a.renderDoctor(r)
		return certerr.Statef("점검 실패 %d건", r.failed())
	}
	r.add("설정", checkPass, "%s", configSourceText(a))
	a.checkDataDir(&r)
	a.checkSchema(&r)
	a.checkCAs(&r)
	a.checkKeys(&r)
	a.checkCerts(&r)
	a.checkBundles(&r, *deep)
	a.checkCRLs(&r)
	a.checkOpenSSL(&r)

	a.renderDoctor(r)
	if n := r.failed(); n > 0 {
		return certerr.Statef("점검 실패 %d건", n)
	}
	return nil
}

func configSourceText(a *App) string {
	if a.cfg.Source == "" {
		return "설정 파일 없음 (기본값으로 동작)"
	}
	return a.cfg.Source
}

func (a *App) checkDataDir(r *doctorReport) {
	dir := a.cfg.DataDir
	info, err := os.Stat(dir)
	if err != nil {
		r.add("상태 디렉터리", checkFail, "%s 를 읽을 수 없습니다: %v", dir, err)
		return
	}
	_ = info
	note := fmt.Sprintf("%s (%s)", dir, string(a.cfg.DataDirSource))
	// 권한이 느슨하면 CA 개인키를 읽을 수 있는 사람이 늘어난다. 앱 인증이 없으므로
	// 파일 권한이 실질적인 접근 통제다.
	if !fsops.IsTight(dir) {
		r.add("상태 디렉터리", checkWarn,
			"%s — 권한이 %s 입니다. 0750 을 권합니다 (CA 개인키가 들어 있습니다)",
			note, fsops.ModeString(dir))
	} else {
		r.add("상태 디렉터리", checkPass, "%s — %s", note, fsops.ModeString(dir))
	}

	// 쓰기 가능한지. 읽기 전용 마운트에서 발급이 중간에 실패하는 것보다 먼저 아는 편이 낫다.
	probe := filepath.Join(a.cfg.TmpDir(), ".doctor-write-probe")
	if err := fsops.EnsureDir(a.cfg.TmpDir(), fsops.ModeDir); err != nil {
		r.add("쓰기 권한", checkFail, "%v", certerr.UserMessage(err))
		return
	}
	if err := fsops.WriteAtomic(probe, []byte("ok"), fsops.ModeSecret); err != nil {
		r.add("쓰기 권한", checkFail, "%v", certerr.UserMessage(err))
		return
	}
	_ = os.Remove(probe)
	r.add("쓰기 권한", checkPass, "쓸 수 있습니다")
}

func (a *App) checkSchema(r *doctorReport) {
	version, err := a.store.SchemaVersionOf()
	if err != nil {
		r.add("DB", checkFail, "%s", certerr.UserMessage(err))
		return
	}
	switch {
	case version > store.SchemaVersion:
		r.add("DB", checkFail,
			"스키마 v%d 는 이 프로그램이 아는 버전(v%d)보다 새롭습니다. 더 새 버전을 쓰세요",
			version, store.SchemaVersion)
	case version < store.SchemaVersion:
		r.add("DB", checkWarn, "스키마 v%d (현재 v%d). 다음 실행에서 올라갑니다",
			version, store.SchemaVersion)
	default:
		r.add("DB", checkPass, "스키마 v%d — %s", version, a.cfg.DBPath())
	}
}

func (a *App) checkCAs(r *doctorReport) {
	list, err := a.store.ListCAs("")
	if err != nil {
		r.add("CA", checkFail, "%s", certerr.UserMessage(err))
		return
	}
	if len(list) == 0 {
		// 실패가 아니다. 아직 만들지 않았을 수 있다.
		r.add("CA", checkSkip, "CA 가 없습니다 ('cert-gen ca create' 로 만듭니다)")
		return
	}

	var problems, warnings int
	for _, rec := range list {
		keyPath, certPath, _ := ca.ResolvePaths(a.cfg, rec)
		// DB 에는 있는데 파일이 없으면 그 CA 로는 서명할 수 없다.
		for label, path := range map[string]string{"개인키": keyPath, "인증서": certPath} {
			if !fsops.IsFile(path) {
				r.add("CA "+rec.Slug, checkFail, "%s 파일이 없습니다: %s", label, path)
				problems++
			}
		}
		if !keyPermOK(keyPath) {
			r.add("CA "+rec.Slug, checkFail,
				"개인키 권한이 %s 입니다. 0600 이어야 합니다", fsops.ModeString(keyPath))
			problems++
		}
		if !rec.KeyEncrypted {
			// 거부할 일은 아니다. 다만 앱 인증이 없으므로 이것이 유일한 서명 통제였다.
			r.add("CA "+rec.Slug, checkWarn,
				"개인키가 평문입니다. 상태 디렉터리를 읽을 수 있는 사람이 곧 이 CA 입니다")
			warnings++
		}
		if expiry, err := store.ParseTime(rec.NotAfter); err == nil {
			days := int(time.Until(expiry).Hours() / 24)
			switch {
			case days < 0:
				r.add("CA "+rec.Slug, checkFail,
					"CA 가 만료되었습니다(%s). 이 CA 로는 발급할 수 없습니다", shortDate(rec.NotAfter))
				problems++
			case days <= 90:
				// CA 교체는 발급한 인증서 전부를 다시 만드는 일이다. 미리 알아야 한다.
				r.add("CA "+rec.Slug, checkWarn,
					"CA 만료까지 %d일 남았습니다. 교체하면 발급한 인증서를 전부 다시 만들어야 합니다", days)
				warnings++
			}
		}
	}
	if problems == 0 && warnings == 0 {
		r.add("CA", checkPass, "%d개 — 파일·권한·유효기간 정상", len(list))
	}
}

func (a *App) checkKeys(r *doctorReport) {
	list, err := keymgmt.List(a.cfg, a.store)
	if err != nil {
		r.add("개인키", checkFail, "%s", certerr.UserMessage(err))
		return
	}
	if len(list) == 0 {
		r.add("개인키", checkSkip, "등록된 키가 없습니다")
		return
	}
	bad := 0
	for _, info := range list {
		path := filepath.Join(a.cfg.DataDir, info.Key.Path)
		if !fsops.IsFile(path) {
			r.add("개인키 "+info.Key.Name, checkFail, "파일이 없습니다: %s", path)
			bad++
			continue
		}
		if !keyPermOK(path) {
			r.add("개인키 "+info.Key.Name, checkFail,
				"권한이 %s 입니다. 0600 이어야 합니다", fsops.ModeString(path))
			bad++
		}
	}
	if bad == 0 {
		r.add("개인키", checkPass, "%d개 — 파일·권한 정상", len(list))
	}
}

func (a *App) checkCerts(r *doctorReport) {
	all, err := a.store.ListCerts(store.CertFilter{})
	if err != nil {
		r.add("인증서", checkFail, "%s", certerr.UserMessage(err))
		return
	}
	if len(all) == 0 {
		r.add("인증서", checkSkip, "발급 이력이 없습니다")
		return
	}

	var expired, soon, revoked int
	for _, rec := range all {
		if rec.Status == "revoked" {
			revoked++
			continue
		}
		if rec.Status != "valid" {
			continue
		}
		expiry, err := store.ParseTime(rec.NotAfter)
		if err != nil {
			continue
		}
		days := int(time.Until(expiry).Hours() / 24)
		switch {
		case days < 0:
			expired++
		case days <= 30:
			soon++
		}
	}
	detail := fmt.Sprintf("%d건 (유효 %d / 폐기 %d)", len(all), len(all)-revoked, revoked)
	switch {
	case expired > 0:
		// 만료는 경고다. 이미 쓰이지 않을 수도 있고, 우리가 할 수 있는 것은 알리는 것뿐이다.
		r.add("인증서", checkWarn, "%s — **만료 %d건**, 30일 내 만료 %d건", detail, expired, soon)
	case soon > 0:
		r.add("인증서", checkWarn, "%s — 30일 내 만료 %d건 ('cert-gen cert list --expiring-in 30')",
			detail, soon)
	default:
		r.add("인증서", checkPass, "%s — 30일 내 만료 없음", detail)
	}
}

func (a *App) checkBundles(r *doctorReport, deep bool) {
	all, err := a.store.ListCerts(store.CertFilter{})
	if err != nil {
		return
	}
	if len(all) == 0 {
		return
	}
	var missing, corrupt int
	for _, rec := range all {
		if rec.BundlePath == "" {
			continue
		}
		path := filepath.Join(a.cfg.DataDir, rec.BundlePath)
		if !fsops.IsFile(path) {
			r.add(fmt.Sprintf("번들 #%d", rec.ID), checkFail, "파일이 없습니다: %s", rec.BundlePath)
			missing++
			continue
		}
		if !deep || rec.BundleSHA256 == "" {
			continue
		}
		if err := bundle.VerifyDigest(path, rec.BundleSHA256); err != nil {
			r.add(fmt.Sprintf("번들 #%d", rec.ID), checkFail, "%s", certerr.UserMessage(err))
			corrupt++
		}
	}
	switch {
	case missing > 0 || corrupt > 0:
		// 개별 항목을 이미 보고했으므로 요약만 남긴다.
		return
	case deep:
		r.add("번들", checkPass, "%d건 — 파일과 해시 모두 일치", len(all))
	default:
		r.add("번들", checkPass, "%d건 — 파일 존재 확인 (해시는 --deep)", len(all))
	}
}

func (a *App) checkCRLs(r *doctorReport) {
	list, err := a.store.ListCAs("")
	if err != nil || len(list) == 0 {
		return
	}
	var stale, missing int
	for _, rec := range list {
		revoked, err := a.store.RevokedForCA(rec.ID)
		if err != nil {
			continue
		}
		parsed, err := crl.Load(a.cfg, rec)
		if err != nil {
			if len(revoked) > 0 {
				// 폐기한 것이 있는데 CRL 이 없으면 폐기가 아무 효력이 없다.
				r.add("CRL "+rec.Slug, checkFail,
					"폐기 %d건이 있는데 CRL 이 없습니다 ('cert-gen crl generate %s')",
					len(revoked), rec.Slug)
				missing++
			}
			continue
		}
		if parsed.NextUpdate.Before(time.Now()) {
			// 만료된 CRL 은 검증하는 쪽이 거부하거나 폐기 확인을 건너뛴다. 둘 다 나쁘다.
			r.add("CRL "+rec.Slug, checkWarn,
				"nextUpdate 가 지났습니다(%s). 다시 만들어 배포하세요",
				parsed.NextUpdate.Format("2006-01-02"))
			stale++
			continue
		}
		if len(parsed.RevokedCertificateEntries) != len(revoked) {
			r.add("CRL "+rec.Slug, checkWarn,
				"CRL 의 폐기 수(%d)가 DB(%d)와 다릅니다. 다시 만드세요",
				len(parsed.RevokedCertificateEntries), len(revoked))
			stale++
		}
	}
	if stale == 0 && missing == 0 {
		r.add("CRL", checkPass, "폐기 목록과 일치하거나 폐기한 것이 없습니다")
	}
}

func (a *App) checkOpenSSL(r *doctorReport) {
	bin := a.cfg.Tools.OpenSSL
	if bin == "" {
		bin = "openssl"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		// 실패가 아니다. 교차 검증만 건너뛰고 발급·변환은 모두 동작한다.
		r.add("openssl", checkSkip,
			"%s 를 찾을 수 없습니다. 교차 검증만 건너뜁니다(발급·변환에는 영향 없음)", bin)
		return
	}
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		r.add("openssl", checkWarn, "%s 를 실행할 수 없습니다: %v", path, err)
		return
	}
	r.add("openssl", checkPass, "%s", firstLine(string(out)))
}

// keyPermOK 는 개인키 파일이 소유자에게만 열려 있는지다.
//
// 디렉터리의 IsTight(other 만 본다)보다 엄격하다. 개인키는 **그룹에도** 열려 있으면 안 된다 —
// 같은 그룹의 다른 사람이 CA 가 된다.
func keyPermOK(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// 파일이 없는 경우는 호출부가 따로 보고한다. 여기서 또 실패로 세지 않는다.
		return true
	}
	if !info.Mode().IsRegular() {
		return true
	}
	return info.Mode().Perm()&0o077 == 0
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func (a *App) renderDoctor(r doctorReport) {
	if a.Out.JSON {
		counts := map[string]int{}
		for _, c := range r.checks {
			counts[string(c.State)]++
		}
		_ = a.Out.Emit(map[string]any{
			"ok": r.failed() == 0, "checks": r.checks, "counts": counts,
			"data_dir": a.cfg.DataDir,
		})
		return
	}
	markWidth, nameWidth := 0, 0
	for _, c := range r.checks {
		if w := displayWidth(doctorMark(c.State)); w > markWidth {
			markWidth = w
		}
		if w := displayWidth(c.Name); w > nameWidth {
			nameWidth = w
		}
	}
	for _, c := range r.checks {
		a.Out.Line("  %s %s  %s",
			padRight(doctorMark(c.State), markWidth), padRight(c.Name, nameWidth), c.Detail)
	}
	counts := map[checkState]int{}
	for _, c := range r.checks {
		counts[c.State]++
	}
	a.Out.Printf("\n통과 %d / 경고 %d / 건너뜀 %d / 실패 %d\n",
		counts[checkPass], counts[checkWarn], counts[checkSkip], counts[checkFail])
}

func doctorMark(s checkState) string {
	switch s {
	case checkPass:
		return "[통과]"
	case checkFail:
		return "[실패]"
	case checkWarn:
		return "[경고]"
	default:
		return "[건너뜀]"
	}
}
