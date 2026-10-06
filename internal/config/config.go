// Package config — 설정 로딩.
//
// 우선순위: --data-dir > 환경변수 CERT_GEN_<SECTION>_<KEY> > -c/--config >
// CERT_GEN_CONFIG > 플랫폼 기본 경로 > 기본값.
//
// 경로를 코드에 박지 않는 이유: 같은 바이너리가 (a) 전용 계정 + /var/lib/cert-gen,
// (b) 사용자 홈, (c) Windows 사용자 프로필, (d) 테스트용 임시 디렉터리에서 모두 돌아야 한다.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/newshure/cert-gen/internal/certerr"
)

const (
	// EnvConfig 는 설정 파일 경로를 가리킨다.
	EnvConfig = "CERT_GEN_CONFIG"
	// EnvCAPassphrase 는 CA 패스프레이즈를 비대화형으로 넘긴다.
	// argv 와 달리 프로세스 목록에 노출되지 않는다.
	EnvCAPassphrase = "CERT_GEN_CA_PASSPHRASE"
	// EnvKeyPassphrase 는 지정한 개인키의 패스프레이즈다.
	EnvKeyPassphrase = "CERT_GEN_KEY_PASSPHRASE"
	// EnvStorePassword 는 PKCS#12·JKS 키스토어 비밀번호다.
	EnvStorePassword = "CERT_GEN_STORE_PASSWORD"
)

// App 은 앱 소유 상태 경로 설정이다.
//
// DataDir 는 **설정 파일에 없다.** 설정 파일이 자기 위치를 정하면 순환이 된다.
// 경로는 --data-dir / CERT_GEN_DATA_DIR / 현재 디렉터리로만 정한다(paths.go 참조).
type App struct {
	// BackupDir 가 비면 DataDir/backups 를 쓴다. 다른 디스크에 두고 싶을 때만 지정한다.
	BackupDir string `toml:"backup_dir"`
}

// CAConfig 는 CA 생성·보호 기본값이다.
type CAConfig struct {
	DefaultKeyAlgo string `toml:"default_key_algo"`
	DefaultDays    int    `toml:"default_days"`
	// EncryptKey 가 false 면 CA 개인키를 평문 저장한다.
	// 이 도구에는 앱 인증이 없다. 즉 이 패스프레이즈가 사실상 유일한 서명 권한 통제다.
	EncryptKey        bool `toml:"encrypt_key"`
	CRLNextUpdateDays int  `toml:"crl_next_update_days"`
}

// CertConfig 는 leaf 발급 기본값이다.
type CertConfig struct {
	// 폐쇄망에 구형 Java·장비가 있을 수 있어 leaf 기본은 RSA 로 둔다.
	DefaultKeyAlgo string `toml:"default_key_algo"`
	DefaultProfile string `toml:"default_profile"`
	// 공인 CA 관례(397일). 사설 CA 에 강제되는 값은 아니며 --days 로 올릴 수 있다.
	DefaultDays int `toml:"default_days"`
	MaxDays     int `toml:"max_days"`
	// 시계 오차가 있는 장비에서 "아직 유효하지 않음" 을 피하기 위한 백데이트(분).
	BackdateMinutes int `toml:"backdate_minutes"`
}

// Tools 는 외부 바이너리다.
//
// openssl 하나뿐이고 그것도 **교차 검증용**이다. 없으면 그 검사만 건너뛴다.
// PKCS#12·JKS·CRL 은 전부 Go 로 직접 쓰므로 keytool 이 필요하지 않다.
//
// keytool 과 command_timeout 설정은 제거했다. 설정에 남겨 두면 "값을 바꾸면 동작이
// 달라진다" 고 오해하게 되는데, 부르는 코드가 없어서 아무 효과가 없었다.
type Tools struct {
	OpenSSL string `toml:"openssl"`
}

// Config 는 전체 설정이다.
type Config struct {
	App   App        `toml:"app"`
	CA    CAConfig   `toml:"ca"`
	Cert  CertConfig `toml:"cert"`
	Tools Tools      `toml:"tools"`

	// 아래는 설정 파일에서 오지 않는다.
	DataDir       string        `toml:"-"`
	DataDirSource DataDirSource `toml:"-"`
	Source        string        `toml:"-"` // 읽은 설정 파일 경로(없으면 빈 문자열)
}

// Default 는 기본값이다. DataDir 는 호출자가 ResolveDataDir 로 채운다.
func Default() Config {
	return Config{
		CA: CAConfig{
			DefaultKeyAlgo:    "ec-p384",
			DefaultDays:       3650,
			EncryptKey:        true,
			CRLNextUpdateDays: 30,
		},
		Cert: CertConfig{
			DefaultKeyAlgo:  "rsa2048",
			DefaultProfile:  "server",
			DefaultDays:     397,
			MaxDays:         3650,
			BackdateMinutes: 5,
		},
		Tools: Tools{OpenSSL: "openssl"},
	}
}

// 파생 경로. 단일 출처로 둔다.

func (c Config) DBPath() string     { return filepath.Join(c.DataDir, "cert-gen.sqlite3") }
func (c Config) CADir() string      { return filepath.Join(c.DataDir, "ca") }
func (c Config) KeyDir() string     { return filepath.Join(c.DataDir, "keys") }
func (c Config) BundleDir() string  { return filepath.Join(c.DataDir, "bundles") }
func (c Config) CRLDir() string     { return filepath.Join(c.DataDir, "crl") }
func (c Config) TmpDir() string     { return filepath.Join(c.DataDir, "tmp") }
func (c Config) ConfigPath() string { return ConfigPathIn(c.DataDir) }

// BackupPath 는 백업 디렉터리다.
func (c Config) BackupPath() string {
	if c.App.BackupDir != "" {
		return c.App.BackupDir
	}
	return filepath.Join(c.DataDir, "backups")
}

// Load 는 설정을 읽는다.
//
// 순서가 중요하다: **먼저 상태 디렉터리를 정하고** 그 안의 설정 파일을 읽는다.
// 설정 파일이 자기 위치를 정하면 순환이 되기 때문이다.
func Load(configPath, dataDir string) (Config, error) {
	cfg := Default()
	cfg.DataDir, cfg.DataDirSource = ResolveDataDir(dataDir)

	path, explicit := resolveConfigPath(configPath, cfg.DataDir)
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			if explicit {
				return Config{}, certerr.Configf("설정 파일이 없습니다: %s", path)
			}
		} else {
			md, err := toml.DecodeFile(path, &cfg)
			if err != nil {
				return Config{}, certerr.WrapConfig(err, "설정 파일 문법 오류: %s: %v", path, err)
			}
			// 오타를 조용히 무시하면 "설정했는데 안 먹는다" 로 이어진다. 명시적으로 거부한다.
			if undecoded := md.Undecoded(); len(undecoded) > 0 {
				keys := make([]string, 0, len(undecoded))
				for _, k := range undecoded {
					keys = append(keys, k.String())
				}
				return Config{}, certerr.Configf(
					"설정에 알 수 없는 항목이 있습니다: %s", strings.Join(keys, ", "))
			}
			cfg.Source = path
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if cfg.App.BackupDir != "" {
		cfg.App.BackupDir = abs(expand(cfg.App.BackupDir))
	}
	return cfg, nil
}

func resolveConfigPath(configPath, dataDir string) (path string, explicit bool) {
	if configPath != "" {
		return expand(configPath), true
	}
	if env := os.Getenv(EnvConfig); env != "" {
		return expand(env), true
	}
	// 기본값은 상태 디렉터리 안이다. 상태와 설정이 한 곳에 모여 백업·이동이 한 번에 된다.
	return ConfigPathIn(dataDir), false
}

func expand(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// applyEnv 는 CERT_GEN_<SECTION>_<KEY> 환경변수를 적용한다.
// 리플렉션으로 도는 이유: 필드가 늘 때마다 분기를 추가하는 것을 피하기 위함이다.
func applyEnv(cfg *Config) error {
	sections := []struct {
		name string
		ptr  any
	}{
		{"APP", &cfg.App},
		{"CA", &cfg.CA},
		{"CERT", &cfg.Cert},
		{"TOOLS", &cfg.Tools},
	}
	for _, section := range sections {
		v := reflect.ValueOf(section.ptr).Elem()
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			tag := t.Field(i).Tag.Get("toml")
			if tag == "" || tag == "-" {
				continue
			}
			env := "CERT_GEN_" + section.name + "_" + strings.ToUpper(tag)
			raw, ok := os.LookupEnv(env)
			if !ok {
				continue
			}
			if err := setField(v.Field(i), raw, env); err != nil {
				return err
			}
		}
	}
	return nil
}

func setField(field reflect.Value, raw, env string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
	case reflect.Bool:
		field.SetBool(isTruthy(raw))
	case reflect.Int:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return certerr.Configf("%s 값이 숫자가 아닙니다: %q", env, raw)
		}
		field.SetInt(int64(n))
	case reflect.Float64:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return certerr.Configf("%s 값이 숫자가 아닙니다: %q", env, raw)
		}
		field.SetFloat(f)
	default:
		return certerr.Configf("%s 를 적용할 수 없습니다(지원하지 않는 타입)", env)
	}
	return nil
}

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Describe 는 진단 출력용 요약이다.
func (c Config) Describe() string {
	source := c.Source
	if source == "" {
		source = "기본값 (설정 파일 없음)"
	}
	return fmt.Sprintf("설정 %s / data_dir %s (%s)", source, c.DataDir, c.DataDirSource)
}
