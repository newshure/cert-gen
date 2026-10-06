//go:build !windows

package fsops

import (
	"fmt"
	"os"

	"github.com/newshure/cert-gen/internal/certerr"
)

// Chmod 는 유닉스에서 그대로 모드를 적용한다.
func Chmod(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return certerr.WrapState(err, "권한을 바꿀 수 없습니다: %s (%v)", path, err)
	}
	return nil
}

// ModeString 은 표시용 권한 문자열이다. 8진수로 낸다(0750 처럼).
//
// FileMode.String() 은 기호 표현("drwxr-x---")을 주는데, 권한을 8진수로 지정하는 문서·
// 명령(chmod 0750)과 눈으로 맞추기 어렵다.
func ModeString(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

// IsTight 는 other 에 열려 있지 않은지 본다(data_dir 점검용).
func IsTight(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o007 == 0
}

// SecurityNote 는 이 플랫폼의 보호 수단을 설명한다. 화면에 그대로 쓴다.
func SecurityNote() string { return "파일 권한 0600" }
