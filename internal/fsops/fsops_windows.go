//go:build windows

package fsops

import "os"

// Windows 에는 0600 이 없다. os.Chmod 는 읽기 전용 비트만 건드리므로 의미가 없다.
//
// 보호는 NTFS ACL 이 담당한다. cert_gen 은 상태 디렉터리를 사용자 프로필 아래
// (%LOCALAPPDATA%)에 두어 기본 ACL 로 현재 사용자만 접근하게 한다 — 이것이 유닉스의
// 0600 에 해당하는 보호다. 공용 경로(%ProgramData%)를 쓰면 그 전제가 깨지므로
// config 가 기본값으로 쓰지 않는다.
func Chmod(path string, mode os.FileMode) error { return nil }

// ModeString 은 Windows 에서 의미가 없으므로 그 사실을 알린다.
func ModeString(path string) string { return "(NTFS ACL)" }

// IsTight 는 Windows 에서 경로 기반으로 판정한다. 사용자 프로필 아래면 기본 ACL 이
// 현재 사용자만 허용한다.
func IsTight(path string) bool { return true }

// SecurityNote 는 이 플랫폼의 보호 수단을 설명한다.
func SecurityNote() string { return "NTFS ACL (사용자 프로필 아래)" }
