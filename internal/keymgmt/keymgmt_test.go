package keymgmt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

func setup(t *testing.T) (config.Config, *store.Store) {
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
	return cfg, s
}

func TestCreateWritesTightPermissions(t *testing.T) {
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{Name: "web-key", Algo: "ec-p256", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	stat, err := os.Stat(abs)
	if err != nil {
		t.Fatal(err)
	}
	if perm := stat.Mode().Perm(); perm != 0o600 {
		t.Errorf("개인키 권한 = %o, 기대 600", perm)
	}
	// 기본은 평문이다. 암호화하면 서버가 기동할 때마다 패스프레이즈를 묻는다.
	if info.Key.Encrypted {
		t.Error("기본값이 암호화된 키다")
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ENCRYPTED") {
		t.Error("패스프레이즈 없이 암호화됐다")
	}
	if len(info.PairToken()) != 8 {
		t.Errorf("쌍 토큰 = %q", info.PairToken())
	}
	if info.InUse() {
		t.Error("새 키가 사용 중으로 나온다")
	}
}

func TestCreateEncryptsWhenAsked(t *testing.T) {
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{
		Name: "ca-key", Algo: "ec-p384", Passphrase: "key-pass", Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !info.Key.Encrypted {
		t.Error("DB 에 암호화 표시가 없다")
	}
	// 패스프레이즈 없이는 못 열려야 한다.
	if _, err := Load(cfg, s, "ca-key", ""); !certerr.IsKind(err, certerr.KindKeyUnlock) {
		t.Errorf("패스프레이즈 없이 열렸거나 오류 종류가 다르다: %v", err)
	}
	if _, err := Load(cfg, s, "ca-key", "key-pass"); err != nil {
		t.Errorf("올바른 패스프레이즈로 열리지 않았다: %v", err)
	}
}

func TestCreateRejectsPathTraversalInName(t *testing.T) {
	// 이름이 파일 경로가 된다. 막지 않으면 상태 디렉터리 밖에 쓸 수 있다.
	cfg, s := setup(t)
	for _, name := range []string{"../escape", "a/b", `a\b`, "..", "web key", "키"} {
		if _, err := Create(cfg, s, CreateOptions{Name: name, Frontend: "test"}); !certerr.IsKind(err, certerr.KindValidation) {
			t.Errorf("위험한 이름 %q 가 통과했다: %v", name, err)
		}
	}
}

func TestCreateRejectsEmptyName(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{Frontend: "test"}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("빈 이름이 통과했다: %v", err)
	}
}

func TestCreateRejectsDuplicateName(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{Name: "dup", Frontend: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err := Create(cfg, s, CreateOptions{Name: "dup", Frontend: "test"})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Fatalf("중복 이름이 통과했다: %v", err)
	}
	// 실패했으면 기존 키 파일이 멀쩡해야 한다.
	list, err := List(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("키 수 = %d", len(list))
	}
}

func TestLoadDetectsReplacedKeyFile(t *testing.T) {
	// 파일이 교체되면 쌍 토큰이 거짓이 된다. 조용히 쓰면 안 된다.
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{Name: "web-key", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := keys.ToPEM(other, "")
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	if err := os.WriteFile(abs, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(cfg, s, "web-key", "")
	if !certerr.IsKind(err, certerr.KindState) {
		t.Fatalf("교체된 키가 통과했다: %v", err)
	}
	if !strings.Contains(err.Error(), "교체") {
		t.Errorf("오류가 원인을 말하지 않는다: %v", err)
	}
}

func TestLoadReportsMissingFile(t *testing.T) {
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{Name: "web-key", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, info.Key.Path)); err != nil {
		t.Fatal(err)
	}
	_, err = Load(cfg, s, "web-key", "")
	if err == nil {
		t.Fatal("파일이 없는데 통과했다")
	}
	if !strings.Contains(err.Error(), "DB 에는 있으나") {
		t.Errorf("오류가 상황을 설명하지 않는다: %v", err)
	}
}

func TestPassphraseRemoveAndSet(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{
		Name: "web-key", Passphrase: "first", Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	// 제거: 서버가 기동 때마다 묻지 않게 하는 흐름이다.
	info, err := SetPassphrase(cfg, s, "web-key", "first", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Key.Encrypted {
		t.Error("제거했는데 DB 에 암호화 표시가 남았다")
	}
	data, err := os.ReadFile(filepath.Join(cfg.DataDir, info.Key.Path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ENCRYPTED") {
		t.Error("파일이 여전히 암호화되어 있다 — DB 와 파일이 어긋났다")
	}
	if _, err := Load(cfg, s, "web-key", ""); err != nil {
		t.Errorf("제거 후 평문으로 열리지 않는다: %v", err)
	}

	// 다시 설정
	info, err = SetPassphrase(cfg, s, "web-key", "", "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Key.Encrypted {
		t.Error("설정했는데 DB 에 표시가 없다")
	}
	if _, err := Load(cfg, s, "web-key", "second"); err != nil {
		t.Errorf("새 패스프레이즈로 열리지 않는다: %v", err)
	}
}

func TestPassphraseWrongCurrentFails(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{
		Name: "web-key", Passphrase: "right", Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := SetPassphrase(cfg, s, "web-key", "wrong", "new", "test")
	if !certerr.IsKind(err, certerr.KindKeyUnlock) {
		t.Fatalf("틀린 현재 패스프레이즈가 통과했다: %v", err)
	}
	// 실패했으면 원래 패스프레이즈가 그대로여야 한다.
	if _, err := Load(cfg, s, "web-key", "right"); err != nil {
		t.Errorf("실패 후 원래 키가 깨졌다: %v", err)
	}
}

func TestKeyIsUsableForCAAndIssue(t *testing.T) {
	// 0번 메뉴의 존재 이유. 만들어 둔 키를 CA 와 발급에서 고를 수 있어야 한다.
	cfg, s := setup(t)
	caKey, err := Create(cfg, s, CreateOptions{Name: "root-key", Algo: "ec-p384", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	loadedCA, err := Load(cfg, s, "root-key", "")
	if err != nil {
		t.Fatal(err)
	}
	caRec, err := ca.CreateRoot(cfg, s, ca.CreateOptions{
		Subject: names.Subject{CommonName: "hd Root CA"}, ExistingKey: loadedCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if caRec.KeyID == nil || *caRec.KeyID != caKey.Key.ID {
		t.Errorf("CA 가 등록된 키를 가리키지 않는다: %v", caRec.KeyID)
	}

	leafKey, err := Create(cfg, s, CreateOptions{Name: "web-key", Algo: "ec-p256", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	loadedLeaf, err := Load(cfg, s, "web-key", "")
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(cfg, s, caRec, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := issue.Issue(cfg, s, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local"},
		ExistingKey: loadedLeaf, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 쌍 토큰이 키와 인증서에서 같아야 한다. 이것이 목록에서 짝을 맞추는 근거다.
	if PairToken(res.Record.PublicSHA256) != leafKey.PairToken() {
		t.Errorf("쌍 토큰이 다르다: 키 %s, 인증서 %s",
			leafKey.PairToken(), PairToken(res.Record.PublicSHA256))
	}

	// 이제 두 키 모두 사용 중이어야 한다.
	for _, name := range []string{"root-key", "web-key"} {
		info, err := Get(cfg, s, name)
		if err != nil {
			t.Fatal(err)
		}
		if !info.InUse() {
			t.Errorf("%s 가 미사용으로 나온다: %s", name, info.UsageText())
		}
	}
}

func TestDeleteRefusesKeyInUse(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{Name: "root-key", Algo: "ec-p384", Frontend: "test"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(cfg, s, "root-key", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.CreateRoot(cfg, s, ca.CreateOptions{
		Subject: names.Subject{CommonName: "hd Root CA"}, ExistingKey: loaded,
	}); err != nil {
		t.Fatal(err)
	}
	// 쓰이는 키를 지우면 CA 가 서명을 못 한다.
	err = Delete(cfg, s, "root-key", "test")
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Fatalf("사용 중인 키가 삭제됐다: %v", err)
	}
	if !strings.Contains(err.Error(), "hd-root-ca") {
		t.Errorf("오류가 사용처를 말하지 않는다: %v", err)
	}
	// 파일이 그대로여야 한다.
	if _, err := Load(cfg, s, "root-key", ""); err != nil {
		t.Errorf("거부 후 키가 깨졌다: %v", err)
	}
}

func TestDeleteUnusedKeyRemovesFileAndRow(t *testing.T) {
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{Name: "spare", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	if err := Delete(cfg, s, "spare", "test"); err != nil {
		t.Fatal(err)
	}
	if fsops.Exists(abs) {
		t.Error("키 파일이 남았다")
	}
	if _, err := Get(cfg, s, "spare"); !certerr.IsKind(err, certerr.KindNotFound) {
		t.Errorf("DB 행이 남았다: %v", err)
	}
}

func TestImportPreservesEncryptionState(t *testing.T) {
	cfg, s := setup(t)
	signer, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	encPEM, err := keys.ToPEM(signer, "outside-pass")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "external.key")
	if err := os.WriteFile(path, encPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Import(cfg, s, path, "brought-in", "outside-pass", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	// 가져오면서 보호 수준이 조용히 내려가면 안 된다.
	if !info.Key.Encrypted {
		t.Error("암호화된 키를 가져왔는데 평문으로 등록됐다")
	}
	data, err := os.ReadFile(filepath.Join(cfg.DataDir, info.Key.Path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ENCRYPTED") {
		t.Error("저장된 파일이 평문이다")
	}
	if info.Key.Source != "imported" {
		t.Errorf("source = %q", info.Key.Source)
	}
}

func TestImportRejectsDuplicatePublicKey(t *testing.T) {
	cfg, s := setup(t)
	info, err := Create(cfg, s, CreateOptions{Name: "original", Frontend: "test"})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(cfg.DataDir, info.Key.Path)
	copyPath := filepath.Join(t.TempDir(), "copy.key")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// 같은 키를 다른 이름으로 두 번 등록하면 쌍 토큰이 중복돼 추적이 무의미해진다.
	_, err = Import(cfg, s, copyPath, "duplicate", "", "", "test")
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Fatalf("같은 공개키가 두 번 등록됐다: %v", err)
	}
}

func TestListReportsUsage(t *testing.T) {
	cfg, s := setup(t)
	for _, name := range []string{"a", "b"} {
		if _, err := Create(cfg, s, CreateOptions{Name: name, Frontend: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := List(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("키 수 = %d", len(list))
	}
	for _, info := range list {
		if info.UsageText() != "미사용" {
			t.Errorf("%s 사용처 = %q", info.Key.Name, info.UsageText())
		}
	}
}

func TestPublicPEM(t *testing.T) {
	cfg, s := setup(t)
	if _, err := Create(cfg, s, CreateOptions{Name: "web-key", Frontend: "test"}); err != nil {
		t.Fatal(err)
	}
	data, err := PublicPEM(cfg, s, "web-key", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "BEGIN PUBLIC KEY") {
		t.Errorf("공개키 PEM 이 아니다: %q", data)
	}
	// 공개키에 개인키가 섞이면 안 된다.
	if strings.Contains(string(data), "PRIVATE") {
		t.Error("공개키 출력에 개인키가 섞였다")
	}
}
