package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// DataDirName 은 상태 디렉터리의 이름이다.
//
// 이 이름 하나로 Windows·리눅스가 **완전히 같게** 동작한다. 플랫폼별 기본 경로
// (/var/lib, %LOCALAPPDATA% 등)를 쓰지 않는 이유:
//
//   - 설치 과정이 없는 단일 바이너리다. "어디서 실행했는지" 가 곧 "데이터가 어디 있는지" 인
//     것이 가장 예측 가능하다.
//   - 플랫폼마다 다른 숨은 경로에 CA 개인키가 생기면 백업·이동·점검이 어려워진다.
//   - Windows 에는 0600 이 없어 보호가 경로의 ACL 에 달려 있는데, 사용자가 직접 고른
//     디렉터리면 그 책임이 명확하다.
const DataDirName = "cert-gen-data"

// ConfigFileName 은 상태 디렉터리 안의 설정 파일 이름이다.
//
// 설정 파일이 data_dir 를 담으면 순환이 된다(설정을 읽어야 경로를 알고, 경로를 알아야
// 설정을 읽는다). 그래서 data_dir 는 플래그·환경변수·현재 디렉터리로만 정하고, 설정 파일은
// 그 안에 둔다. 상태와 설정이 한 곳에 모여 백업·이동도 한 번에 된다.
const ConfigFileName = "config.toml"

// EnvDataDir 는 상태 디렉터리를 환경변수로 지정한다(cron·서비스처럼 CWD 가 불확실한 경우).
const EnvDataDir = "CERT_GEN_DATA_DIR"

// DataDirSource 는 경로가 어떻게 정해졌는지다. 화면에 그대로 보여 준다 —
// "내 데이터가 어디 있나" 를 추측하게 만들지 않기 위함이다.
type DataDirSource string

const (
	SourceFlag    DataDirSource = "--data-dir"
	SourceEnv     DataDirSource = EnvDataDir
	SourceCurrent DataDirSource = "현재 디렉터리"
)

// ResolveDataDir 는 상태 디렉터리를 정한다.
//
//  1. --data-dir
//  2. CERT_GEN_DATA_DIR
//  3. <현재 디렉터리>/cert-gen-data
//
// 찾아 올라가지 않는다. 규칙이 하나뿐이어야 "어디에 생기는지" 가 분명하다.
// 다른 디렉터리에서 실행해 초기화되지 않은 경로를 보게 되면, 조회 명령이 그 경로를 적어
// 거부하고 다음에 무엇을 할지 안내한다(Guide 참조).
func ResolveDataDir(flagValue string) (string, DataDirSource) {
	if flagValue != "" {
		return abs(expand(flagValue)), SourceFlag
	}
	if env := os.Getenv(EnvDataDir); env != "" {
		return abs(expand(env)), SourceEnv
	}
	cwd, err := os.Getwd()
	if err != nil {
		// CWD 를 알 수 없는 드문 경우. 상대경로로 떨어뜨린다.
		return DataDirName, SourceCurrent
	}
	return filepath.Join(cwd, DataDirName), SourceCurrent
}

// Guide 는 "데이터가 어디 있는지" 를 설명하는 한 덩어리다.
// 초기화되지 않은 경로에서 명령을 쓴 경우 이것을 그대로 보여 준다.
func (c Config) Guide() string {
	return fmt.Sprintf(`상태 디렉터리: %s  (%s)

cert-gen 은 **실행한 디렉터리**에 %s/ 를 만들어 CA·인증서를 보관합니다.
Windows·리눅스가 같습니다.

  다른 곳의 데이터를 쓰려면   cert-gen --data-dir <경로> <명령>
  고정해 두려면              export %s=<경로>   (Windows: set %s=<경로>)
  여기에 새로 만들려면        cert-gen init`,
		c.DataDir, c.DataDirSource, DataDirName, EnvDataDir, EnvDataDir)
}

// ConfigPathIn 은 상태 디렉터리 안의 설정 파일 경로다.
func ConfigPathIn(dataDir string) string { return filepath.Join(dataDir, ConfigFileName) }

func abs(path string) string {
	if result, err := filepath.Abs(path); err == nil {
		return result
	}
	return path
}
