package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

type env struct {
	cfg   config.Config
	store *store.Store
}

func setup(t *testing.T) env {
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
	return env{cfg, s}
}

// seed 는 CA 하나, 인증서 둘, 개인키 하나를 만든다.
func (e env) seed(t *testing.T) (store.CA, []store.Cert) {
	t.Helper()
	noPass := false
	caRec, err := ca.CreateRoot(e.cfg, e.store, ca.CreateOptions{
		Subject: names.Subject{CommonName: "hd Root CA"}, RequirePassphrase: &noPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(e.cfg, e.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	var certs []store.Cert
	for _, cn := range []string{"web.hd.local", "api.hd.local"} {
		res, err := issue.Issue(e.cfg, e.store, issue.Options{
			Material: material, Subject: names.Subject{CommonName: cn}, Frontend: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, res.Record)
	}
	if _, err := keymgmt.Create(e.cfg, e.store, keymgmt.CreateOptions{
		Name: "spare", Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	return caRec, certs
}

func TestCreateProducesVerifiableArchive(t *testing.T) {
	e := setup(t)
	e.seed(t)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !fsops.IsFile(res.Path) {
		t.Fatal("백업 파일이 없다")
	}
	// 백업은 CA 개인키를 담는다. 월드 리더블이면 안 된다.
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("백업 권한 = %o, 기대 600", perm)
	}
	// 그 사실을 사용자에게 알려야 한다.
	if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, " "), "CA 개인키") {
		t.Errorf("CA 개인키 포함 경고가 없다: %v", res.Warnings)
	}
	if res.Manifest.Counts.CAs != 1 || res.Manifest.Counts.Certs != 2 || res.Manifest.Counts.Keys != 1 {
		t.Errorf("요약이 다르다: %+v", res.Manifest.Counts)
	}

	// 아카이브가 자기 매니페스트와 일치해야 한다.
	plan, err := Inspect(e.cfg, e.store, res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.OK() {
		t.Errorf("방금 만든 백업이 검증에 실패했다: %v", plan.Problems)
	}
}

func TestArchiveContainsEverythingNeeded(t *testing.T) {
	e := setup(t)
	caRec, certs := e.seed(t)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, entry := range res.Manifest.Files {
		paths[entry.Path] = true
	}
	// DB 스냅샷
	if !paths[DBName] {
		t.Error("DB 스냅샷이 없다")
	}
	// CA 개인키·인증서
	for _, want := range []string{
		"ca/" + caRec.Slug + "/ca.key", "ca/" + caRec.Slug + "/ca.crt",
	} {
		if !paths[want] {
			t.Errorf("%s 가 백업에 없다 (목록: %v)", want, keysOf(paths))
		}
	}
	// 번들
	for _, c := range certs {
		if !paths[filepath.ToSlash(c.BundlePath)] {
			t.Errorf("번들 %s 가 백업에 없다", c.BundlePath)
		}
	}
	// 등록된 개인키
	if !paths["keys/spare.key"] {
		t.Errorf("등록 개인키가 백업에 없다 (목록: %v)", keysOf(paths))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDBSnapshotIsConsistentNotRawCopy(t *testing.T) {
	// WAL 모드에서 .sqlite3 만 복사하면 -wal 에 남은 커밋이 빠져 찢어진 스냅샷이 나온다.
	// VACUUM INTO 스냅샷은 방금 커밋한 내용을 담고 있어야 한다.
	e := setup(t)
	e.seed(t)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if _, err := Create(e.cfg, e.store, out, "test"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := extractTo(out, dir); err != nil {
		t.Fatal(err)
	}
	snap, err := store.Open(filepath.Join(dir, DBName), false)
	if err != nil {
		t.Fatalf("스냅샷 DB 를 열 수 없다: %v", err)
	}
	defer snap.Close()

	certs, err := snap.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Errorf("스냅샷의 인증서 수 = %d, 기대 2 (찢어진 스냅샷)", len(certs))
	}
	cas, err := snap.ListCAs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Errorf("스냅샷의 CA 수 = %d", len(cas))
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if _, err := Create(e.cfg, e.store, out, "test"); err != nil {
		t.Fatal(err)
	}
	// 덮어쓰면 이전 백업이 사라진다. 백업은 되돌릴 마지막 수단이므로 거부한다.
	if _, err := Create(e.cfg, e.store, out, "test"); !certerr.IsKind(err, certerr.KindConflict) {
		t.Errorf("기존 백업을 덮어썼다: %v", err)
	}
}

func TestCreateIsReproducible(t *testing.T) {
	// 같은 상태에서 같은 바이트가 나와야 "백업이 변했는가" 를 해시로 판단할 수 있다.
	e := setup(t)
	e.seed(t)
	dir := t.TempDir()
	first, err := Create(e.cfg, e.store, filepath.Join(dir, "a.tar.gz"), "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(e.cfg, e.store, filepath.Join(dir, "b.tar.gz"), "test")
	if err != nil {
		t.Fatal(err)
	}
	// 매니페스트의 created_at 이 다르므로 전체 해시는 다를 수 있다. 파일 내용 해시는
	// 같아야 한다 — 그것이 "데이터가 변하지 않았다" 의 근거다.
	firstFiles := map[string]string{}
	for _, f := range first.Manifest.Files {
		firstFiles[f.Path] = f.SHA256
	}
	for _, f := range second.Manifest.Files {
		if f.Path == DBName {
			continue // VACUUM 결과는 페이지 배치가 달라질 수 있다
		}
		if firstFiles[f.Path] != f.SHA256 {
			t.Errorf("%s 의 해시가 두 백업에서 다르다", f.Path)
		}
	}
}

// --- 검증 (음성 통제) ---------------------------------------------------------

func TestInspectDetectsTamperedFile(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	// 아카이브 안의 CA 개인키를 바꿔치기한다. 이것을 못 잡으면 남의 CA 키로 복원된다.
	tampered := rewriteArchive(t, res.Path, func(name string, data []byte) []byte {
		if strings.HasSuffix(name, "ca.key") {
			return []byte("-----BEGIN PRIVATE KEY-----\nEVIL\n-----END PRIVATE KEY-----\n")
		}
		return data
	})
	plan, err := Inspect(e.cfg, e.store, tampered)
	if err != nil {
		// 읽기 단계에서 거부해도 올바른 처리다.
		return
	}
	if plan.OK() {
		t.Fatal("변조된 백업이 검증을 통과했다")
	}
	if !strings.Contains(strings.Join(plan.Problems, " "), "다릅니다") {
		t.Errorf("문제 설명이 원인을 말하지 않는다: %v", plan.Problems)
	}
}

func TestInspectDetectsExtraFile(t *testing.T) {
	// 매니페스트에 없는 파일이 끼어 있으면 누가 넣은 것이다.
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	extra := appendToArchive(t, res.Path, "ca/injected.crt", []byte("x"), 0o644)
	plan, err := Inspect(e.cfg, e.store, extra)
	if err != nil {
		return
	}
	if plan.OK() {
		t.Fatal("매니페스트에 없는 파일이 통과했다")
	}
}

func TestInspectDetectsTruncation(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	// 파일 하나를 뺀다.
	dropped := rewriteArchiveSkipping(t, res.Path, func(name string) bool {
		return strings.HasSuffix(name, "ca.crt")
	})
	plan, err := Inspect(e.cfg, e.store, dropped)
	if err != nil {
		return
	}
	if plan.OK() {
		t.Fatal("파일이 빠진 백업이 통과했다")
	}
	if !strings.Contains(strings.Join(plan.Problems, " "), "없습니다") {
		t.Errorf("빠진 파일을 지적하지 않는다: %v", plan.Problems)
	}
}

func TestInspectRejectsNonBackupArchive(t *testing.T) {
	e := setup(t)
	// 매니페스트가 없는 보통 tar.gz
	path := filepath.Join(t.TempDir(), "random.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	_ = writeTarFile(tw, "hello.txt", []byte("hi"), 0o644)
	tw.Close()
	gz.Close()
	f.Close()

	if _, err := Inspect(e.cfg, e.store, path); err == nil {
		t.Error("백업이 아닌 아카이브가 통과했다")
	}
}

func TestInspectRejectsGarbage(t *testing.T) {
	e := setup(t)
	path := filepath.Join(t.TempDir(), "junk.tar.gz")
	if err := os.WriteFile(path, []byte("not gzip at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(e.cfg, e.store, path); err == nil {
		t.Error("쓰레기 파일이 통과했다")
	}
}

func TestInspectMissingFile(t *testing.T) {
	e := setup(t)
	_, err := Inspect(e.cfg, e.store, filepath.Join(t.TempDir(), "nope.tar.gz"))
	if !certerr.IsKind(err, certerr.KindNotFound) {
		t.Errorf("없는 파일이 notfound 가 아니다: %v", err)
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	// 매니페스트의 스키마 버전만 올린다(해시는 매니페스트 자신에는 적용되지 않는다).
	future := rewriteArchive(t, res.Path, func(name string, data []byte) []byte {
		if name != ManifestName {
			return data
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		m.SchemaVersion = store.SchemaVersion + 5
		out, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	plan, err := Inspect(e.cfg, e.store, future)
	if err != nil {
		t.Fatal(err)
	}
	if plan.OK() {
		t.Fatal("더 새로운 스키마의 백업이 통과했다")
	}
	if !strings.Contains(strings.Join(plan.Problems, " "), "새롭습니다") {
		t.Errorf("스키마 문제를 지적하지 않는다: %v", plan.Problems)
	}
	// Apply 도 거부해야 한다.
	if err := Apply(e.cfg, nil, plan, "test"); err == nil {
		t.Error("문제가 있는 계획으로 Apply 가 진행됐다")
	}
}

// --- 경로 탈출 (zip slip) -----------------------------------------------------

func TestExtractRejectsPathTraversal(t *testing.T) {
	// tar 는 "../../etc/passwd" 같은 이름을 담을 수 있다. 우리가 만들지 않은 아카이브도
	// 읽으므로 이 검사는 선택이 아니다.
	for _, evil := range []string{
		"../escape.pem", "../../escape.pem", "ca/../../escape.pem", "/etc/passwd",
	} {
		path := filepath.Join(t.TempDir(), "evil.tar.gz")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		_ = writeTarFile(tw, ManifestName, []byte(`{"tool":"cert_gen"}`), 0o600)
		_ = writeTarFile(tw, evil, []byte("pwned"), 0o644)
		tw.Close()
		gz.Close()
		f.Close()

		dest := filepath.Join(t.TempDir(), "out")
		if err := fsops.EnsureDir(dest, fsops.ModeDir); err != nil {
			t.Fatal(err)
		}
		err = extractTo(path, dest)
		if err == nil {
			// 거부하지 않았다면 최소한 밖으로 나가지 않았어야 한다.
			outside := filepath.Join(filepath.Dir(dest), "escape.pem")
			if fsops.Exists(outside) {
				t.Fatalf("%q 가 대상 디렉터리 밖에 파일을 썼다: %s", evil, outside)
			}
			t.Errorf("%q 가 거부되지 않았다", evil)
			continue
		}
		if !strings.Contains(err.Error(), "탈출") && !strings.Contains(err.Error(), "절대경로") {
			t.Errorf("%q: 오류가 원인을 말하지 않는다: %v", evil, err)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	dest := "/tmp/restore"
	for _, bad := range []string{"../x", "../../x", "a/../../x", "/abs/x", "", "."} {
		if _, err := safeJoin(dest, bad); err == nil {
			t.Errorf("safeJoin 이 %q 를 허용했다", bad)
		}
	}
	for _, good := range []string{"ca/root/ca.key", "bundles/2027/1.zip", DBName} {
		got, err := safeJoin(dest, good)
		if err != nil {
			t.Errorf("safeJoin 이 %q 를 거부했다: %v", good, err)
			continue
		}
		if !strings.HasPrefix(got, dest) {
			t.Errorf("safeJoin(%q) = %q, dest 밖이다", good, got)
		}
	}
}

func TestExtractRejectsSymlink(t *testing.T) {
	// 심볼릭 링크를 담으면 복원이 그 링크를 따라 밖에 쓸 수 있다. 우리는 일반 파일만 담는다.
	e := setup(t)
	path := filepath.Join(t.TempDir(), "link.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	manifest := Manifest{
		Tool: "cert_gen", Files: []FileEntry{{Path: "evil", Size: 0, SHA256: ""}},
	}
	data, _ := json.Marshal(manifest)
	_ = writeTarFile(tw, ManifestName, data, 0o600)
	_ = tw.WriteHeader(&tar.Header{
		Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd",
		Mode: 0o777, ModTime: time.Now(),
	})
	tw.Close()
	gz.Close()
	f.Close()

	plan, err := Inspect(e.cfg, e.store, path)
	if err != nil {
		return // 읽기에서 거부해도 좋다
	}
	if plan.OK() {
		t.Error("심볼릭 링크가 든 백업이 통과했다")
	}
}

// --- 복원 --------------------------------------------------------------------

func TestRestoreRoundTrip(t *testing.T) {
	e := setup(t)
	caRec, certs := e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	e.store.Close()

	// 전혀 다른 위치에 복원한다.
	target := config.Default()
	target.DataDir = filepath.Join(t.TempDir(), "restored")
	plan, err := Inspect(target, nil, res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.OK() {
		t.Fatalf("검증 실패: %v", plan.Problems)
	}
	if plan.MoveExistingTo != "" {
		t.Error("없는 디렉터리를 치우려 한다")
	}
	if err := Apply(target, nil, plan, "test"); err != nil {
		t.Fatal(err)
	}

	s2, err := store.Open(target.DBPath(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	gotCAs, err := s2.ListCAs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCAs) != 1 || gotCAs[0].Slug != caRec.Slug {
		t.Fatalf("CA 가 복원되지 않았다: %+v", gotCAs)
	}
	gotCerts, err := s2.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCerts) != len(certs) {
		t.Errorf("인증서 수 = %d, 기대 %d", len(gotCerts), len(certs))
	}

	// 복원한 CA 로 **실제로 발급이 되어야** 한다. 파일이 있는 것만으로는 부족하다.
	material, err := ca.LoadMaterial(target, s2, gotCAs[0], "")
	if err != nil {
		t.Fatalf("복원한 CA 를 열 수 없다: %v", err)
	}
	if _, err := issue.Issue(target, s2, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "after-restore.hd.local"},
		Frontend: "test",
	}); err != nil {
		t.Fatalf("복원 후 발급이 되지 않는다: %v", err)
	}

	// 개인키 권한이 복원되어야 한다.
	keyPath, _, _ := ca.ResolvePaths(target, gotCAs[0])
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("복원한 CA 개인키 권한 = %o, 기대 600", perm)
	}
	// 등록된 개인키도 복원되어야 한다.
	keys, err := keymgmt.List(target, s2)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("개인키 수 = %d", len(keys))
	}
	if _, err := keymgmt.Load(target, s2, "spare", ""); err != nil {
		t.Errorf("복원한 개인키를 열 수 없다: %v", err)
	}
}

func TestRestoreMovesExistingAside(t *testing.T) {
	// 복원이 잘못됐을 때 되돌릴 길을 남겨야 한다. 지우지 않고 옆으로 치운다.
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}

	// 백업 이후에 인증서를 하나 더 발급한다 — 이것이 복원으로 사라질 내용이다.
	caRec, err := e.store.GetCA("hd-root-ca")
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(e.cfg, e.store, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issue.Issue(e.cfg, e.store, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "later.hd.local"}, Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	// 닫은 뒤에는 nil 을 넘긴다. 현재 내용 요약을 위해 따로 연다.
	live, err := store.Open(e.cfg.DBPath(), false)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Inspect(e.cfg, live, res.Path)
	live.Close()
	if err != nil {
		t.Fatal(err)
	}
	if plan.MoveExistingTo == "" {
		t.Fatal("기존 디렉터리를 치울 계획이 없다")
	}
	// 무엇을 잃는지 보여 줘야 한다.
	if plan.ExistingCounts == nil || plan.ExistingCounts.Certs != 3 {
		t.Errorf("현재 내용 요약이 틀렸다: %+v", plan.ExistingCounts)
	}
	if err := Apply(e.cfg, nil, plan, "test"); err != nil {
		t.Fatal(err)
	}

	// 기존 것이 그 자리에 보관되어야 한다.
	if !fsops.IsFile(filepath.Join(plan.MoveExistingTo, "cert-gen.sqlite3")) {
		t.Errorf("기존 디렉터리가 보관되지 않았다: %s", plan.MoveExistingTo)
	}
	old, err := store.Open(filepath.Join(plan.MoveExistingTo, "cert-gen.sqlite3"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldCerts, err := old.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(oldCerts) != 3 {
		t.Errorf("보관된 DB 의 인증서 수 = %d, 기대 3", len(oldCerts))
	}

	// 복원된 쪽은 백업 시점(2건)이어야 한다.
	restored, err := store.Open(e.cfg.DBPath(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	newCerts, err := restored.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(newCerts) != 2 {
		t.Errorf("복원된 인증서 수 = %d, 기대 2", len(newCerts))
	}
}

func TestInspectDoesNotChangeAnything(t *testing.T) {
	// 드라이런이 무엇도 바꾸지 않아야 한다.
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, e.cfg.DataDir)
	if _, err := Inspect(e.cfg, e.store, res.Path); err != nil {
		t.Fatal(err)
	}
	after := snapshotTree(t, e.cfg.DataDir)
	// tmp/ 는 스냅샷 작업으로 달라질 수 있으니 제외한다.
	for path, sum := range before {
		// tmp/ 와 SQLite 런타임 파일(-wal, -shm)은 제외한다. 데이터가 아니고,
		// DB 를 열기만 해도 바뀐다.
		if strings.Contains(path, "/tmp/") ||
			strings.HasSuffix(path, "-wal") || strings.HasSuffix(path, "-shm") {
			continue
		}
		if after[path] != sum {
			t.Errorf("드라이런이 %s 를 바꿨다", path)
		}
	}
	if len(after) < len(before)-2 {
		t.Errorf("드라이런이 파일을 지웠다: %d → %d", len(before), len(after))
	}
}

func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		sum, err := fsops.SHA256File(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = sum
		return nil
	})
	return out
}

func TestDescribeMentionsWhatMatters(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Inspect(e.cfg, e.store, res.Path)
	if err != nil {
		t.Fatal(err)
	}
	text := plan.Describe()
	for _, want := range []string{"백업 파일", "스키마", "복원 위치", "기존 보관", "CA 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("보고서에 %q 가 없다:\n%s", want, text)
		}
	}
	// 복원이 전부 대체한다는 사실은 경고로 나와야 한다.
	if !strings.Contains(strings.Join(plan.Warnings, " "), "대체") {
		t.Errorf("대체 경고가 없다: %v", plan.Warnings)
	}
}

func TestRestoreWarnsOnDifferentDataDir(t *testing.T) {
	// 외부 CA 는 절대경로를 쓴다. 위치가 바뀌면 그 경로가 그대로 있어야 동작한다.
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	target := config.Default()
	target.DataDir = filepath.Join(t.TempDir(), "elsewhere")
	plan, err := Inspect(target, nil, res.Path)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan.Warnings, " ")
	if !strings.Contains(joined, "is_external") {
		t.Errorf("위치 변경 경고가 없다: %v", plan.Warnings)
	}
}

func TestAuditRecordsBackupAndRestore(t *testing.T) {
	e := setup(t)
	e.seed(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	res, err := Create(e.cfg, e.store, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := e.store.RecentAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "backup.create" {
			found = true
		}
	}
	if !found {
		t.Error("감사 로그에 backup.create 가 없다")
	}
	e.store.Close()

	plan, err := Inspect(e.cfg, nil, res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(e.cfg, nil, plan, "test"); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(e.cfg.DBPath(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	entries, err = s2.RecentAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, entry := range entries {
		if entry.Action == "backup.restore" {
			found = true
			if !strings.Contains(entry.Detail, "moved_existing_to") {
				t.Errorf("감사 로그에 보관 위치가 없다: %s", entry.Detail)
			}
		}
	}
	if !found {
		t.Error("감사 로그에 backup.restore 가 없다")
	}
}

// --- 아카이브 조작 도우미 -----------------------------------------------------

func rewriteArchive(t *testing.T, src string, transform func(name string, data []byte) []byte) string {
	t.Helper()
	return rebuild(t, src, func(name string) bool { return false }, transform, nil)
}

func rewriteArchiveSkipping(t *testing.T, src string, skip func(name string) bool) string {
	t.Helper()
	return rebuild(t, src, skip, nil, nil)
}

func appendToArchive(t *testing.T, src, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	return rebuild(t, src, func(string) bool { return false }, nil,
		&extraEntry{name: name, data: data, mode: mode})
}

type extraEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func rebuild(t *testing.T, src string, skip func(string) bool,
	transform func(string, []byte) []byte, extra *extraEntry) string {
	t.Helper()

	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	gzr, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	dst := filepath.Join(t.TempDir(), "rebuilt.tar.gz")
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(out)
	tw := tar.NewWriter(gzw)

	for {
		header, err := tr.Next()
		if err != nil {
			break
		}
		data := make([]byte, header.Size)
		if _, err := readFull(tr, data); err != nil && header.Size > 0 {
			t.Fatal(err)
		}
		if skip(header.Name) {
			continue
		}
		if transform != nil {
			data = transform(header.Name, data)
		}
		if err := writeTarFile(tw, header.Name, data, os.FileMode(header.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if err := writeTarFile(tw, extra.name, extra.data, extra.mode); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gzw.Close()
	out.Close()
	return dst
}

func readFull(r *tar.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}
