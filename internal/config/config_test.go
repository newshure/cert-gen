package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
)

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestDefaultsUseCurrentDirectory(t *testing.T) {
	// Windows·리눅스가 같게 동작해야 한다: 데이터는 "실행한 곳" 에 생긴다.
	dir := t.TempDir()
	chdir(t, dir)

	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, DataDirName)
	if cfg.DataDir != want {
		t.Errorf("data_dir = %q, 기대 %q", cfg.DataDir, want)
	}
	if cfg.DataDirSource != SourceCurrent {
		t.Errorf("출처 = %q", cfg.DataDirSource)
	}
	if cfg.Cert.DefaultDays != 397 || !cfg.CA.EncryptKey {
		t.Errorf("기본값이 다르다: %+v", cfg)
	}
	// 설정 파일은 상태 디렉터리 안에 있다(순환을 피한다).
	if cfg.ConfigPath() != filepath.Join(want, ConfigFileName) {
		t.Errorf("config 경로 = %q", cfg.ConfigPath())
	}
}

func TestDataDirPriority(t *testing.T) {
	base := t.TempDir()
	chdir(t, base)

	// 환경변수가 현재 디렉터리를 이긴다.
	t.Setenv(EnvDataDir, filepath.Join(base, "from-env"))
	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(base, "from-env") || cfg.DataDirSource != SourceEnv {
		t.Errorf("환경변수가 적용되지 않았다: %q (%s)", cfg.DataDir, cfg.DataDirSource)
	}

	// --data-dir 가 환경변수를 이긴다.
	cfg, err = Load("", filepath.Join(base, "from-flag"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(base, "from-flag") || cfg.DataDirSource != SourceFlag {
		t.Errorf("플래그가 적용되지 않았다: %q (%s)", cfg.DataDir, cfg.DataDirSource)
	}
}

func TestDoesNotSearchUpward(t *testing.T) {
	// 규칙은 하나뿐이다: 실행한 디렉터리. 위로 찾아 올라가지 않는다.
	base := t.TempDir()
	dataDir := filepath.Join(base, DataDirName)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "cert-gen.sqlite3"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(base, "a", "b")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	chdir(t, deep)

	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(deep, DataDirName) {
		t.Errorf("상위를 집었다: %q", cfg.DataDir)
	}
	// 안내가 경로와 바꾸는 방법을 알려 줘야 한다.
	guide := cfg.Guide()
	for _, needle := range []string{cfg.DataDir, "--data-dir", EnvDataDir, "cert-gen init"} {
		if !strings.Contains(guide, needle) {
			t.Errorf("안내에 %q 가 없다:\n%s", needle, guide)
		}
	}
}

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfigFileInsideDataDir(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, DataDirName)
	writeConfig(t, dataDir, "[cert]\ndefault_days = 30\n[ca]\nencrypt_key = false\n")
	chdir(t, base)

	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cert.DefaultDays != 30 || cfg.CA.EncryptKey {
		t.Fatalf("상태 디렉터리 안의 설정이 적용되지 않았다: %+v", cfg)
	}
	if cfg.Source != filepath.Join(dataDir, ConfigFileName) {
		t.Errorf("Source = %q", cfg.Source)
	}

	// 환경변수가 파일을 덮는다.
	t.Setenv("CERT_GEN_CERT_DEFAULT_DAYS", "90")
	cfg, err = Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cert.DefaultDays != 90 {
		t.Errorf("환경변수가 파일을 덮지 못했다: %d", cfg.Cert.DefaultDays)
	}
}

func TestUnknownKeyIsRejected(t *testing.T) {
	// 오타를 조용히 무시하면 "설정했는데 안 먹는다" 로 이어진다.
	base := t.TempDir()
	writeConfig(t, filepath.Join(base, DataDirName), "[cert]\ndefault_dayz = 30\n")
	chdir(t, base)

	_, err := Load("", "")
	if !certerr.IsKind(err, certerr.KindConfig) || !strings.Contains(err.Error(), "default_dayz") {
		t.Fatalf("오타가 거부되지 않았다: %v", err)
	}
}

func TestDataDirIsNotConfigurableFromFile(t *testing.T) {
	// 설정 파일이 자기 위치를 정하면 순환이 된다. data_dir 키는 아예 없어야 한다.
	base := t.TempDir()
	writeConfig(t, filepath.Join(base, DataDirName), "[app]\ndata_dir = \"/elsewhere\"\n")
	chdir(t, base)

	if _, err := Load("", ""); !certerr.IsKind(err, certerr.KindConfig) {
		t.Fatalf("설정 파일의 data_dir 가 거부되지 않았다: %v", err)
	}
}

func TestMissingExplicitConfigIsRejected(t *testing.T) {
	chdir(t, t.TempDir())
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml"), ""); !certerr.IsKind(err, certerr.KindConfig) {
		t.Fatal("없는 설정 파일이 통과했다")
	}
}

func TestBadEnvValueIsRejected(t *testing.T) {
	chdir(t, t.TempDir())
	t.Setenv("CERT_GEN_CERT_DEFAULT_DAYS", "많이")
	if _, err := Load("", ""); !certerr.IsKind(err, certerr.KindConfig) {
		t.Fatal("잘못된 환경변수가 통과했다")
	}
}

// TestExampleConfigLoads 는 deploy/config.example.toml 이 실제로 로드되는지 본다.
//
// Go 는 모르는 키를 **거부**하므로, 예시 파일이 스키마에서 벗어나면 그것을 복사한 사용자가
// 바로 오류를 만난다. 예시가 스키마에서 벗어나지 않는지 고정한다.
func TestExampleConfigLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.toml"))
	if err != nil {
		t.Skipf("예시 설정을 찾을 수 없다: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("예시 설정이 로드되지 않는다: %v", err)
	}
	// 예시의 값이 실제로 반영되는지도 본다. 주석만 맞고 키 이름이 틀렸을 수 있다.
	if cfg.CA.DefaultKeyAlgo != "ec-p384" {
		t.Errorf("ca.default_key_algo = %q", cfg.CA.DefaultKeyAlgo)
	}
	if cfg.Cert.DefaultDays != 397 {
		t.Errorf("cert.default_days = %d", cfg.Cert.DefaultDays)
	}
	if cfg.Tools.OpenSSL != "openssl" {
		t.Errorf("tools.openssl = %q", cfg.Tools.OpenSSL)
	}
}
