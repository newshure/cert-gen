// 패스프레이즈 입력. 명령행 인자로는 **절대** 받지 않는다.
//
// argv 는 /proc/<pid>/cmdline 으로 같은 호스트의 다른 사용자에게 보인다. 그래서 받는 경로를
// 세 가지로 제한한다. 환경변수, stdin, 그리고 TTY 프롬프트다.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/newshure/cert-gen/internal/certerr"
)

const (
	// EnvCAPassphrase 는 CA 개인키 패스프레이즈다.
	EnvCAPassphrase = "CERT_GEN_CA_PASSPHRASE"
	// EnvExportPassword 는 키스토어(p12/JKS) 비밀번호다.
	EnvExportPassword = "CERT_GEN_EXPORT_PASSWORD"
	// EnvKeyPassphrase 는 외부 개인키 파일의 패스프레이즈다.
	EnvKeyPassphrase = "CERT_GEN_KEY_PASSPHRASE"
)

// SecretSource 는 비밀값을 어디서 읽을지다.
type SecretSource struct {
	// Env 는 먼저 확인할 환경변수 이름이다.
	Env string
	// FromStdin 이면 stdin 에서 한 줄을 읽는다(--*-stdin 플래그).
	FromStdin bool
	// Prompt 는 TTY 프롬프트 문구다. 비어 있으면 프롬프트하지 않는다.
	Prompt string
	// Confirm 이면 프롬프트를 두 번 받아 비교한다(새로 만들 때).
	Confirm bool
}

// ReadSecret 은 비밀값을 읽는다. 어느 경로도 쓸 수 없으면 빈 문자열을 돌려준다.
func ReadSecret(src SecretSource) (string, error) {
	if src.Env != "" {
		if value, ok := os.LookupEnv(src.Env); ok {
			return value, nil
		}
	}
	if src.FromStdin {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", certerr.Validationf("stdin 에서 비밀값을 읽을 수 없습니다: %v", err)
		}
		// 개행만 제거한다. 공백이 비밀값의 일부일 수 있다.
		return strings.TrimRight(line, "\r\n"), nil
	}
	if src.Prompt == "" {
		return "", nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// 비대화형에서 조용히 빈 값으로 넘어가면 "패스프레이즈 없는 CA" 가 만들어진다.
		return "", certerr.Validationf(
			"대화형 입력이 불가능합니다. 환경변수 %s 또는 해당 --*-stdin 옵션을 쓰세요", src.Env)
	}
	first, err := promptHidden(src.Prompt)
	if err != nil {
		return "", err
	}
	if !src.Confirm {
		return first, nil
	}
	second, err := promptHidden("다시 입력: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", certerr.Validationf("입력한 값이 서로 다릅니다")
	}
	return first, nil
}

func promptHidden(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", certerr.Validationf("입력을 읽을 수 없습니다: %v", err)
	}
	return string(data), nil
}
