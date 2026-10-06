package ca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
)

const caPass = "test-ca-passphrase"

func setup(t *testing.T) (config.Config, *store.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
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

func createRoot(t *testing.T, cfg config.Config, s *store.Store, cn string) store.CA {
	t.Helper()
	rec, err := CreateRoot(cfg, s, CreateOptions{
		Subject:    names.Subject{CommonName: cn, Organization: "HD", Country: "KR"},
		Passphrase: caPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestCreateRootWritesTightPermissions(t *testing.T) {
	cfg, s := setup(t)
	rec := createRoot(t, cfg, s, "hd Root CA")

	keyPath, certPath, chainPath := ResolvePaths(cfg, rec)
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// 개인키가 group/other 에 읽히면 패스프레이즈 말고는 통제가 없다.
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("개인키 권한 = %o, 기대 600", perm)
	}
	certInfo, _ := os.Stat(certPath)
	if perm := certInfo.Mode().Perm(); perm != 0o644 {
		t.Errorf("인증서 권한 = %o, 기대 644", perm)
	}
	if chainPath != "" {
		t.Error("Root CA 에 체인 경로가 생겼다")
	}
	if !rec.IsRoot() || rec.IsExternal || !rec.KeyEncrypted {
		t.Errorf("CA 레코드가 다르다: %+v", rec)
	}
}

func TestCreateRootIsSelfSignedWithCABit(t *testing.T) {
	cfg, s := setup(t)
	rec := createRoot(t, cfg, s, "hd Root CA")

	m, err := LoadMaterial(cfg, s, rec, caPass)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cert.Issuer.String() != m.Cert.Subject.String() {
		t.Error("자기서명이 아니다")
	}
	if !IsCACert(m.Cert) {
		t.Error("CA:TRUE 가 아니다")
	}
	if m.Root() != m.Cert {
		t.Error("Root 는 자기 자신이어야 한다")
	}
}

func TestWrongPassphraseIsDistinguishable(t *testing.T) {
	cfg, s := setup(t)
	rec := createRoot(t, cfg, s, "hd Root CA")
	_, err := LoadMaterial(cfg, s, rec, "wrong")
	if !certerr.IsKind(err, certerr.KindKeyUnlock) {
		t.Fatalf("패스프레이즈 오류로 구분되지 않는다: %v", err)
	}
}

func TestPassphrasePolicy(t *testing.T) {
	cfg, s := setup(t)
	// encrypt_key=true 인데 패스프레이즈가 없으면 조용히 평문 저장하지 않고 거부한다.
	_, err := CreateRoot(cfg, s, CreateOptions{Subject: names.Subject{CommonName: "No Pass CA"}})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("패스프레이즈 누락이 거부되지 않았다: %v", err)
	}

	// CA 단위로 해제할 수 있어야 한다.
	no := false
	rec, err := CreateRoot(cfg, s, CreateOptions{
		Subject: names.Subject{CommonName: "Open CA"}, RequirePassphrase: &no,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyEncrypted {
		t.Error("--no-passphrase 인데 암호화되었다")
	}
	keyPath, _, _ := ResolvePaths(cfg, rec)
	data, _ := os.ReadFile(keyPath)
	if keys.IsEncryptedPEM(data) {
		t.Error("키 파일이 암호화되어 있다")
	}
	// 패스프레이즈 없이 바로 열려야 한다(프롬프트가 없다).
	if _, err := LoadMaterial(cfg, s, rec, ""); err != nil {
		t.Fatalf("패스프레이즈 없는 CA 를 열 수 없다: %v", err)
	}
}

func TestSlugCollisionGetsSuffix(t *testing.T) {
	cfg, s := setup(t)
	first := createRoot(t, cfg, s, "Dup CA")
	second := createRoot(t, cfg, s, "Dup CA")
	if first.Slug != "dup-ca" || second.Slug != "dup-ca-2" {
		t.Errorf("slug = %q, %q", first.Slug, second.Slug)
	}
}

// --- 외부 디렉터리 ------------------------------------------------------------

// writeExternalCA 는 cert_gen 밖에서 만든 CA 를 흉내 낸다.
func writeExternalCA(t *testing.T, dir, passphrase string, isCA bool, keyName, certName string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate("rsa2048")
	if err != nil {
		t.Fatal(err)
	}
	profileName := profiles.RootCA
	if !isCA {
		profileName = profiles.Server
	}
	p, _ := profiles.Get(profileName)
	subject, _ := names.BuildSubject(names.Subject{CommonName: "External CA", Organization: "Ext"})
	nb, na, _ := certbuild.ValidityWindow(3650, 5)
	serial, _ := certbuild.NewSerial()
	var sans []names.SAN
	if !isCA {
		sans, _ = names.BuildSANs("ext.example.com", nil)
	}
	cert, _, err := certbuild.Build(certbuild.Request{
		Subject: subject, PublicKey: key.Public(), Signer: key, Profile: p,
		Serial: serial, NotBefore: nb, NotAfter: na, SANs: sans,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := keys.ToPEM(key, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyName), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, certName), certbuild.CertPEM(cert), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverPrefersConventionalNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")
	found, err := DiscoverInDir(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(found.CertPath) != "ca.crt" || filepath.Base(found.KeyPath) != "ca.key" {
		t.Errorf("관례명을 찾지 못했다: %+v", found)
	}
	if !found.IsSelfSigned() || found.KeyEncrypted {
		t.Errorf("상태가 다르다: selfsigned=%v enc=%v", found.IsSelfSigned(), found.KeyEncrypted)
	}
}

func TestDiscoverDetectsEncryptedKeyAndGlobs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "extpw", true, "mycorp-key.pem", "mycorp.pem")
	found, err := DiscoverInDir(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !found.KeyEncrypted {
		t.Error("암호화 키를 알아보지 못했다")
	}
	if filepath.Base(found.CertPath) != "mycorp.pem" {
		t.Errorf("글로브 탐색 실패: %s", found.CertPath)
	}
}

func TestDiscoverRejectsNonCAEmptyAndAmbiguous(t *testing.T) {
	base := t.TempDir()

	nonCA := filepath.Join(base, "nonca")
	writeExternalCA(t, nonCA, "", false, "ca.key", "ca.crt")
	if _, err := DiscoverInDir(nonCA, "", ""); err == nil ||
		!strings.Contains(err.Error(), "CA:TRUE") {
		t.Errorf("CA 가 아닌 인증서가 통과했다: %v", err)
	}

	empty := filepath.Join(base, "empty")
	os.MkdirAll(empty, 0o750)
	if _, err := DiscoverInDir(empty, "", ""); err == nil {
		t.Error("빈 디렉터리가 통과했다")
	}

	if _, err := DiscoverInDir(filepath.Join(base, "missing"), "", ""); err == nil {
		t.Error("없는 디렉터리가 통과했다")
	}

	// 추측하지 않는다. 후보가 여러 개면 사용자가 지정하게 한다.
	ambiguous := filepath.Join(base, "ambi")
	writeExternalCA(t, ambiguous, "", true, "a-key.pem", "a.pem")
	writeExternalCA(t, ambiguous, "", true, "b-key.pem", "b.pem")
	if _, err := DiscoverInDir(ambiguous, "", ""); err == nil ||
		!strings.Contains(err.Error(), "여러 개") {
		t.Errorf("모호한 후보가 통과했다: %v", err)
	}
	// 명시 지정은 통과해야 한다.
	if _, err := DiscoverInDir(ambiguous,
		filepath.Join(ambiguous, "b-key.pem"), filepath.Join(ambiguous, "b.pem")); err != nil {
		t.Errorf("명시 지정이 실패했다: %v", err)
	}
}

func TestAdoptExternalDoesNotCopyKey(t *testing.T) {
	cfg, s := setup(t)
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")

	found, err := DiscoverInDir(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	rec, adopted, err := AdoptExternal(cfg, s, found, "")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted || !rec.IsExternal {
		t.Errorf("외부 CA 로 등록되지 않았다: %+v", rec)
	}
	if rec.SourceDir != found.Dir {
		t.Errorf("source_dir = %q", rec.SourceDir)
	}
	// 개인키는 원래 자리에 그대로 있어야 한다. 복사하면 "CA 가 두 곳" 이 된다.
	if rec.KeyPath != filepath.Join(found.Dir, "ca.key") {
		t.Errorf("key_path 가 절대경로가 아니다: %q", rec.KeyPath)
	}
	if fsops.Exists(filepath.Join(cfg.CADir(), rec.Slug)) {
		t.Error("data_dir 에 사본이 생겼다")
	}
	if !strings.HasPrefix(rec.Slug, "ext-") {
		t.Errorf("외부 CA 접두어가 없다: %q", rec.Slug)
	}
}

func TestAdoptExternalIsIdempotentAndFollowsMoves(t *testing.T) {
	cfg, s := setup(t)
	base := t.TempDir()
	dir := filepath.Join(base, "pki")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")

	found, _ := DiscoverInDir(dir, "", "")
	first, _, err := AdoptExternal(cfg, s, found, "")
	if err != nil {
		t.Fatal(err)
	}
	found2, _ := DiscoverInDir(dir, "", "")
	again, adopted, err := AdoptExternal(cfg, s, found2, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID || adopted {
		t.Error("같은 CA 가 두 번 등록되었다")
	}
	cas, _ := s.ListCAs("")
	if len(cas) != 1 {
		t.Fatalf("CA 가 %d개다", len(cas))
	}

	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	found3, _ := DiscoverInDir(moved, "", "")
	third, _, err := AdoptExternal(cfg, s, found3, "")
	if err != nil {
		t.Fatal(err)
	}
	if third.ID != first.ID {
		t.Error("경로 이동 후 새 행이 생겼다")
	}
	if third.SourceDir != found3.Dir {
		t.Errorf("source_dir 가 갱신되지 않았다: %q", third.SourceDir)
	}
}

func TestMismatchedPairCaughtAtLoad(t *testing.T) {
	// 암호화된 키는 adopt 시점에 대조할 수 없다. LoadMaterial 에서 반드시 걸려야 한다.
	cfg, s := setup(t)
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")

	other, _ := keys.Generate("rsa2048")
	otherPEM, _ := keys.ToPEM(other, "")
	os.WriteFile(filepath.Join(dir, "ca.key"), otherPEM, 0o600)

	found, _ := DiscoverInDir(dir, "", "")
	rec, _, err := AdoptExternal(cfg, s, found, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMaterial(cfg, s, rec, ""); err == nil ||
		!strings.Contains(err.Error(), "짝이 맞지 않습니다") {
		t.Fatalf("짝 불일치가 검출되지 않았다: %v", err)
	}
}

func TestMissingExternalKeyReportsSourceDir(t *testing.T) {
	cfg, s := setup(t)
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")
	found, _ := DiscoverInDir(dir, "", "")
	rec, _, _ := AdoptExternal(cfg, s, found, "")

	os.Remove(filepath.Join(dir, "ca.key"))
	_, err := LoadMaterial(cfg, s, rec, "")
	if err == nil || !strings.Contains(err.Error(), "마운트") {
		t.Fatalf("외부 CA 경로 안내가 없다: %v", err)
	}
}

func TestImportCopiesKeyIntoDataDir(t *testing.T) {
	cfg, s := setup(t)
	dir := filepath.Join(t.TempDir(), "pki")
	writeExternalCA(t, dir, "extpw", true, "ca.key", "ca.crt")

	rec, err := ImportExisting(cfg, s, ImportOptions{
		KeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "ca.crt"),
		Passphrase: "extpw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.IsExternal {
		t.Error("import 인데 외부 CA 로 등록되었다")
	}
	keyPath, _, _ := ResolvePaths(cfg, rec)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("복사된 키 권한 = %o", info.Mode().Perm())
	}
	// 원본의 암호화 상태를 유지한다(재암호화하면 패스프레이즈 관리가 갈라진다).
	data, _ := os.ReadFile(keyPath)
	if !keys.IsEncryptedPEM(data) {
		t.Error("복사하며 암호화가 풀렸다")
	}
	if _, err := LoadMaterial(cfg, s, rec, "extpw"); err != nil {
		t.Fatalf("복사된 CA 를 열 수 없다: %v", err)
	}
}

func TestImportRejectsMismatchAndDuplicate(t *testing.T) {
	cfg, s := setup(t)
	base := t.TempDir()
	dir := filepath.Join(base, "pki")
	other := filepath.Join(base, "other")
	writeExternalCA(t, dir, "", true, "ca.key", "ca.crt")
	writeExternalCA(t, other, "", true, "ca.key", "ca.crt")

	_, err := ImportExisting(cfg, s, ImportOptions{
		KeyFile: filepath.Join(other, "ca.key"), CertFile: filepath.Join(dir, "ca.crt"),
	})
	if err == nil || !strings.Contains(err.Error(), "짝이 맞지 않습니다") {
		t.Errorf("짝 불일치가 통과했다: %v", err)
	}

	if _, err := ImportExisting(cfg, s, ImportOptions{
		KeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "ca.crt"),
	}); err != nil {
		t.Fatal(err)
	}
	_, err = ImportExisting(cfg, s, ImportOptions{
		KeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "ca.crt"),
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Errorf("중복 import 가 통과했다: %v", err)
	}
}
