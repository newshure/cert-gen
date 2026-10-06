// Package trust — CA 인증서를 서버·클라이언트의 신뢰 저장소에 등록한다.
//
// 자가서명 체인은 각 호스트가 Root CA 를 신뢰해야만 동작한다. 그 등록 절차가 OS 와 Java 에
// 따라 전부 다르고, 실무에서 가장 자주 막히는 지점이다.
//
// 설계 판단: 이 패키지는 **기본적으로 명령을 만들어 주고 실행하지 않는다.**
//
// 신뢰 저장소 변경은 그 호스트의 보안 경계를 바꾸는 일이고 거의 항상 root 권한이 필요하다.
// 도구가 조용히 해 버리면 (a) 무엇이 바뀌었는지 사용자가 모르고, (b) 되돌리는 방법도 모르고,
// (c) sudo 를 삼켜야 한다. 명령을 보여 주면 사용자가 읽고, 복사하고, 필요하면 변경 관리
// 절차에 넣을 수 있다. Apply 로 실행할 수도 있지만 그것은 명시적 선택이어야 한다.
package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
)

// Platform 은 신뢰 저장소의 종류다.
type Platform string

const (
	// RHEL 계열: /etc/pki/ca-trust/source/anchors + update-ca-trust
	PlatformRHEL Platform = "rhel"
	// Debian/Ubuntu 계열: /usr/local/share/ca-certificates + update-ca-certificates
	PlatformDebian Platform = "debian"
	// Windows: certutil -addstore Root
	PlatformWindows Platform = "windows"
	// Java: keytool -importcert (cacerts). OS 신뢰와 **별개**다.
	PlatformJava Platform = "java"
	// 컨테이너 이미지 빌드에 넣을 형태
	PlatformContainer Platform = "container"
	// 애플리케이션 런타임이 환경변수로 읽는 형태(curl/python/node/git)
	PlatformRuntime Platform = "runtime"
)

// Target 은 등록 대상 하나다.
type Target struct {
	Platform Platform
	Label    string
	// Note 는 이 대상의 주의사항이다.
	Note string
	// Commands 는 사용자가 실행할 명령이다. 순서대로 실행한다.
	Commands []string
	// NeedsRoot 는 관리자 권한이 필요한지다.
	NeedsRoot bool
	// Verify 는 등록을 확인하는 명령이다.
	Verify []string
	// Remove 는 되돌리는 명령이다. 되돌릴 방법을 함께 주지 않으면 사용자가 손을 못 댄다.
	Remove []string
}

// Options 는 안내 생성 입력이다.
type Options struct {
	// CACertPath 는 ca.crt 의 경로다.
	CACertPath string
	// Name 은 저장소에 쓸 이름이다(파일명·별칭). 보통 CA slug.
	Name string
	// JavaHome 이 비어 있으면 명령에 $JAVA_HOME 을 그대로 둔다.
	JavaHome string
	// CommonName 은 안내 문구에 쓴다.
	CommonName string
}

// DetectPlatform 은 현재 호스트의 OS 신뢰 저장소 종류를 추정한다.
//
// 추정이다. 틀릴 수 있으므로 호출자가 바꿀 수 있어야 한다.
func DetectPlatform() Platform {
	if runtime.GOOS == "windows" {
		return PlatformWindows
	}
	// 파일 존재로 계열을 가린다. /etc/os-release 파싱보다 단순하고, 실제로 중요한 것은
	// "어느 디렉터리에 넣고 어느 명령을 돌리는가" 이므로 이 쪽이 직접적이다.
	for _, probe := range []struct {
		path     string
		platform Platform
	}{
		{"/etc/pki/ca-trust/source/anchors", PlatformRHEL},
		{"/usr/local/share/ca-certificates", PlatformDebian},
	} {
		if dirExists(probe.path) {
			return probe.platform
		}
	}
	// 알 수 없으면 RHEL 로 둔다. 이 저장소의 대상 환경이 Rocky Linux 다.
	return PlatformRHEL
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// Build 는 지정한 대상의 등록 안내를 만든다.
func Build(platform Platform, opts Options) (Target, error) {
	if opts.CACertPath == "" {
		return Target{}, certerr.Validationf("CA 인증서 경로가 필요합니다")
	}
	name := opts.Name
	if name == "" {
		name = "cert-gen-ca"
	}
	src := opts.CACertPath

	switch platform {
	case PlatformRHEL:
		dst := "/etc/pki/ca-trust/source/anchors/" + name + ".crt"
		return Target{
			Platform: platform, Label: "Linux OS 신뢰 저장소 (RHEL·Rocky·CentOS·Fedora)",
			NeedsRoot: true,
			Note: "update-ca-trust 가 /etc/pki/ca-trust/extracted 아래 묶음을 다시 만듭니다. " +
				"이미 떠 있는 프로세스는 반영되지 않으므로 해당 서비스를 재시작해야 합니다",
			Commands: []string{
				fmt.Sprintf("sudo cp %s %s", shellQuote(src), shellQuote(dst)),
				fmt.Sprintf("sudo chmod 644 %s", shellQuote(dst)),
				"sudo update-ca-trust extract",
			},
			Verify: []string{
				fmt.Sprintf("openssl verify -CAfile /etc/pki/tls/certs/ca-bundle.crt %s", shellQuote(src)),
				fmt.Sprintf("trust list | grep -A2 %s", shellQuote(opts.CommonName)),
			},
			Remove: []string{
				fmt.Sprintf("sudo rm %s", shellQuote(dst)),
				"sudo update-ca-trust extract",
			},
		}, nil

	case PlatformDebian:
		// 확장자가 .crt 여야 한다. update-ca-certificates 가 .crt 만 읽는다 —
		// .pem 으로 넣으면 조용히 무시되고 "넣었는데 안 된다" 가 된다.
		dst := "/usr/local/share/ca-certificates/" + name + ".crt"
		return Target{
			Platform: platform, Label: "Linux OS 신뢰 저장소 (Debian·Ubuntu)",
			NeedsRoot: true,
			Note: "확장자는 반드시 .crt 여야 합니다. update-ca-certificates 는 .crt 만 읽으므로 " +
				".pem 으로 넣으면 조용히 무시됩니다",
			Commands: []string{
				fmt.Sprintf("sudo cp %s %s", shellQuote(src), shellQuote(dst)),
				fmt.Sprintf("sudo chmod 644 %s", shellQuote(dst)),
				"sudo update-ca-certificates",
			},
			Verify: []string{
				fmt.Sprintf("openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt %s", shellQuote(src)),
				fmt.Sprintf("ls -l /etc/ssl/certs | grep %s", shellQuote(name)),
			},
			Remove: []string{
				fmt.Sprintf("sudo rm %s", shellQuote(dst)),
				"sudo update-ca-certificates --fresh",
			},
		}, nil

	case PlatformWindows:
		return Target{
			Platform: platform, Label: "Windows 인증서 저장소 (로컬 컴퓨터)",
			NeedsRoot: true,
			Note: "관리자 권한 명령 프롬프트 또는 PowerShell 에서 실행합니다. " +
				"-addstore Root 는 로컬 컴퓨터 전체에 적용됩니다(현재 사용자만 하려면 -user 를 붙입니다)",
			Commands: []string{
				fmt.Sprintf(`certutil -addstore -f Root "%s"`, windowsPath(src)),
			},
			Verify: []string{
				fmt.Sprintf(`certutil -store Root | findstr /C:"%s"`, opts.CommonName),
				fmt.Sprintf(`powershell -Command "Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*%s*' }"`,
					opts.CommonName),
			},
			Remove: []string{
				"certutil -store Root    :: 먼저 serial 을 확인한다",
				"certutil -delstore Root <serial>",
			},
		}, nil

	case PlatformJava:
		// Java 는 OS 신뢰 저장소를 보지 않는다. 별도로 넣어야 한다 —
		// 이것을 모르고 "OS 에 넣었는데 Java 앱만 안 된다" 로 오는 경우가 가장 많다.
		javaHome := opts.JavaHome
		if javaHome == "" {
			javaHome = "$JAVA_HOME"
		}
		cacerts := javaHome + "/lib/security/cacerts"
		alias := strings.ToLower(name)
		return Target{
			Platform: platform, Label: "Java 신뢰 저장소 (cacerts)",
			NeedsRoot: true,
			Note: "Java 는 OS 신뢰 저장소를 보지 않습니다. 반드시 따로 등록해야 합니다. " +
				"기본 비밀번호는 changeit 입니다. JDK 8 이하는 경로가 $JAVA_HOME/jre/lib/security/cacerts 입니다. " +
				"JDK 를 교체하면 다시 등록해야 합니다",
			Commands: []string{
				fmt.Sprintf("sudo keytool -importcert -trustcacerts -noprompt \\\n"+
					"    -alias %s \\\n"+
					"    -file %s \\\n"+
					"    -keystore %s \\\n"+
					"    -storepass changeit",
					shellQuote(alias), shellQuote(src), shellQuote(cacerts)),
			},
			Verify: []string{
				fmt.Sprintf("keytool -list -keystore %s -storepass changeit -alias %s",
					shellQuote(cacerts), shellQuote(alias)),
			},
			Remove: []string{
				fmt.Sprintf("sudo keytool -delete -alias %s -keystore %s -storepass changeit",
					shellQuote(alias), shellQuote(cacerts)),
			},
		}, nil

	case PlatformContainer:
		return Target{
			Platform: platform, Label: "컨테이너 이미지 (Dockerfile)",
			Note: "이미지 빌드 시점에 넣습니다. 폐쇄망이면 ca.crt 를 빌드 컨텍스트에 함께 둡니다. " +
				"런타임에 볼륨으로 넣으려면 update-ca-trust 를 실행할 수 없으니 " +
				"아래 runtime 방식(환경변수)을 쓰십시오",
			Commands: []string{
				"# RHEL 계열 베이스",
				fmt.Sprintf("COPY %s /etc/pki/ca-trust/source/anchors/%s.crt",
					filepath.Base(src), name),
				"RUN update-ca-trust extract",
				"",
				"# Debian 계열 베이스",
				fmt.Sprintf("COPY %s /usr/local/share/ca-certificates/%s.crt",
					filepath.Base(src), name),
				"RUN update-ca-certificates",
				"",
				"# Alpine 베이스",
				fmt.Sprintf("COPY %s /usr/local/share/ca-certificates/%s.crt",
					filepath.Base(src), name),
				"RUN apk add --no-cache ca-certificates && update-ca-certificates",
			},
		}, nil

	case PlatformRuntime:
		// OS 신뢰 저장소를 건드릴 수 없는 경우(비특권 컨테이너, 공유 호스트)의 우회로.
		return Target{
			Platform: platform, Label: "애플리케이션 런타임 (환경변수 · root 불필요)",
			Note: "OS 신뢰 저장소를 바꿀 수 없을 때 씁니다. 해당 프로세스에만 적용되고 " +
				"호스트 전체에는 영향이 없습니다",
			Commands: []string{
				fmt.Sprintf("export SSL_CERT_FILE=%s          # OpenSSL, curl", shellQuote(src)),
				fmt.Sprintf("export REQUESTS_CA_BUNDLE=%s     # Python requests", shellQuote(src)),
				fmt.Sprintf("export CURL_CA_BUNDLE=%s         # curl", shellQuote(src)),
				fmt.Sprintf("export NODE_EXTRA_CA_CERTS=%s    # Node.js", shellQuote(src)),
				fmt.Sprintf("export GIT_SSL_CAINFO=%s         # git", shellQuote(src)),
				fmt.Sprintf("export AWS_CA_BUNDLE=%s          # AWS CLI", shellQuote(src)),
			},
			Verify: []string{
				fmt.Sprintf("curl --cacert %s https://<호스트>/ -v 2>&1 | grep -i 'SSL certificate verify'",
					shellQuote(src)),
			},
		}, nil
	}
	return Target{}, certerr.Validationf("알 수 없는 신뢰 저장소 종류입니다: %q", platform)
}

// Platforms 는 화면·CLI 에 보여 줄 순서다.
var Platforms = []Platform{
	PlatformRHEL, PlatformDebian, PlatformWindows,
	PlatformJava, PlatformContainer, PlatformRuntime,
}

// PlatformNames 는 선택 가능한 이름들이다.
func PlatformNames() []string {
	out := make([]string, 0, len(Platforms))
	for _, p := range Platforms {
		out = append(out, string(p))
	}
	return out
}

// Label 은 이름에 대한 사람이 읽는 설명이다.
func Label(p Platform) string {
	t, err := Build(p, Options{CACertPath: "ca.crt"})
	if err != nil {
		return string(p)
	}
	return t.Label
}

// Script 는 대상의 명령을 복사해 쓸 수 있는 한 덩어리로 만든다.
func (t Target) Script() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", t.Label)
	if t.NeedsRoot {
		b.WriteString("# 관리자(root) 권한이 필요합니다.\n")
	}
	if t.Note != "" {
		for _, line := range wrap(t.Note, 76) {
			fmt.Fprintf(&b, "# %s\n", line)
		}
	}
	b.WriteString("\n")
	for _, cmd := range t.Commands {
		b.WriteString(cmd + "\n")
	}
	if len(t.Verify) > 0 {
		b.WriteString("\n# 확인\n")
		for _, cmd := range t.Verify {
			b.WriteString(cmd + "\n")
		}
	}
	if len(t.Remove) > 0 {
		b.WriteString("\n# 되돌리기\n")
		for _, cmd := range t.Remove {
			b.WriteString(cmd + "\n")
		}
	}
	return b.String()
}

// wrap 은 주석 줄을 폭에 맞춰 접는다.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	var (
		lines []string
		cur   string
	)
	for _, w := range words {
		if cur == "" {
			cur = w
			continue
		}
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// shellQuote 는 셸에 안전하게 넘길 수 있게 인용한다.
//
// 경로에 공백이 들어가는 경우가 실제로 있고(Windows 의 Program Files, 사용자 디렉터리),
// 인용하지 않으면 사용자가 복사한 명령이 조용히 다른 파일을 가리킨다.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '-', r == '_', r == '=', r == ':', r == '$':
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func windowsPath(s string) string { return strings.ReplaceAll(s, "/", `\`) }
