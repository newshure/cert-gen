// Package certerr — 오류 계층.
//
// CLI·TUI 가 같은 문장을 내고, 종료코드로 원인을 구분할 수 있게 한다.
// 코어는 이 패키지의 오류만 돌려주고, 프런트엔드는 Message() 를 그대로 출력한다.
package certerr

import (
	"errors"
	"fmt"
)

// Kind 는 오류 종류다. 종료코드가 여기 붙는다.
type Kind int

const (
	KindGeneral      Kind = iota // 1
	KindValidation               // 2  입력이 잘못됨
	KindNotFound                 // 4  대상 없음
	KindConflict                 // 5  중복(slug·지문)
	KindVerification             // 6  검증 실패
	KindToolMissing              // 69 외부 도구 없음
	KindState                    // 74 상태·IO·번들·백업 문제
	KindKeyUnlock                // 77 개인키를 열 수 없음(패스프레이즈)
	KindConfig                   // 78 설정 오류
)

// ExitCode 는 셸 종료코드다. 스크립트가 "패스프레이즈 문제" 와 "설정 문제" 를
// 구분할 수 있도록 77/78 을 나눠 둔다.
func (k Kind) ExitCode() int {
	switch k {
	case KindValidation:
		return 2
	case KindNotFound:
		return 4
	case KindConflict:
		return 5
	case KindVerification:
		return 6
	case KindToolMissing:
		return 69
	case KindState:
		return 74
	case KindKeyUnlock:
		return 77
	case KindConfig:
		return 78
	default:
		return 1
	}
}

// Error 는 cert_gen 이 의도적으로 내는 오류다.
type Error struct {
	Kind Kind
	Msg  string
	Err  error // 원인(있으면). 사용자에게는 보이지 않고 디버깅용이다.
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

// Message 는 사용자에게 보여줄 한 줄(여러 줄일 수도 있다).
func (e *Error) Message() string { return e.Msg }

func newf(kind Kind, cause error, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...), Err: cause}
}

// 각 종류별 생성자. 호출부가 짧아지도록 두 가지씩 둔다(원인 없음 / 원인 감싸기).

func Validationf(format string, args ...any) *Error {
	return newf(KindValidation, nil, format, args...)
}
func NotFoundf(format string, args ...any) *Error { return newf(KindNotFound, nil, format, args...) }
func Conflictf(format string, args ...any) *Error { return newf(KindConflict, nil, format, args...) }
func Statef(format string, args ...any) *Error    { return newf(KindState, nil, format, args...) }
func Configf(format string, args ...any) *Error   { return newf(KindConfig, nil, format, args...) }
func Generalf(format string, args ...any) *Error  { return newf(KindGeneral, nil, format, args...) }

func Verificationf(format string, args ...any) *Error {
	return newf(KindVerification, nil, format, args...)
}

// KeyUnlockf 는 패스프레이즈 문제다. 프런트엔드가 이것만 보고 '재입력' 을 유도할 수 있어야
// 한다 — 설정 문제와 섞으면 사용자가 무엇을 고쳐야 할지 알 수 없다.
func KeyUnlockf(format string, args ...any) *Error { return newf(KindKeyUnlock, nil, format, args...) }

// ToolMissingf 는 외부 도구가 없어 '그 기능만' 쓸 수 없다는 뜻이다.
func ToolMissingf(format string, args ...any) *Error {
	return newf(KindToolMissing, nil, format, args...)
}

// Wrap 계열: 원인을 보존하면서 사용자 문장을 붙인다.

func WrapValidation(err error, format string, args ...any) *Error {
	return newf(KindValidation, err, format, args...)
}
func WrapState(err error, format string, args ...any) *Error {
	return newf(KindState, err, format, args...)
}
func WrapConfig(err error, format string, args ...any) *Error {
	return newf(KindConfig, err, format, args...)
}
func WrapKeyUnlock(err error, format string, args ...any) *Error {
	return newf(KindKeyUnlock, err, format, args...)
}
func WrapConflict(err error, format string, args ...any) *Error {
	return newf(KindConflict, err, format, args...)
}

// ExitCodeOf 는 어떤 오류든 종료코드로 바꾼다. cert_gen 오류가 아니면 1 이다.
func ExitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind.ExitCode()
	}
	return 1
}

// IsKind 는 특정 종류인지 본다(예: 패스프레이즈 재입력 유도).
func IsKind(err error, kind Kind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == kind
}

// UserMessage 는 사용자에게 보여줄 문장이다. 예상하지 못한 오류는 그대로 노출한다
// (감추면 원인을 찾을 수 없다).
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Message()
	}
	return err.Error()
}
