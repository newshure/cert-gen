package trust

import (
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
)

func opts() Options {
	return Options{
		CACertPath: "/var/lib/cert-gen/ca/hd-root-ca/ca.crt",
		Name:       "hd-root-ca",
		CommonName: "HD Root CA",
	}
}

func TestEveryPlatformBuilds(t *testing.T) {
	for _, p := range Platforms {
		target, err := Build(p, opts())
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if target.Label == "" {
			t.Errorf("%s: 설명이 없다", p)
		}
		if len(target.Commands) == 0 {
			t.Errorf("%s: 명령이 없다", p)
		}
		// 되돌리는 방법을 주지 않으면 사용자가 손을 못 댄다.
		// (컨테이너·런타임은 이미지 재빌드/변수 해제라 별도 명령이 없다)
		if p != PlatformContainer && p != PlatformRuntime && len(target.Remove) == 0 {
			t.Errorf("%s: 되돌리기 명령이 없다", p)
		}
		if p != PlatformContainer && p != PlatformRuntime && len(target.Verify) == 0 {
			t.Errorf("%s: 확인 명령이 없다", p)
		}
	}
}

func TestUnknownPlatformRejected(t *testing.T) {
	if _, err := Build("plan9", opts()); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("알 수 없는 종류가 통과했다: %v", err)
	}
}

func TestMissingCertPathRejected(t *testing.T) {
	if _, err := Build(PlatformRHEL, Options{}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("경로 없이 통과했다: %v", err)
	}
}

func TestRHELUsesAnchorsAndExtract(t *testing.T) {
	target, err := Build(PlatformRHEL, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	for _, want := range []string{
		"/etc/pki/ca-trust/source/anchors/hd-root-ca.crt",
		"update-ca-trust extract",
		"chmod 644",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("RHEL 안내에 %q 가 없다:\n%s", want, script)
		}
	}
	if !target.NeedsRoot {
		t.Error("root 권한 필요 표시가 없다")
	}
	// 이미 떠 있는 프로세스는 반영되지 않는다 — 가장 자주 나오는 질문이다.
	if !strings.Contains(script, "재시작") {
		t.Error("서비스 재시작 안내가 없다")
	}
}

func TestDebianWarnsAboutCrtExtension(t *testing.T) {
	// update-ca-certificates 는 .crt 만 읽는다. .pem 으로 넣으면 조용히 무시된다.
	target, err := Build(PlatformDebian, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	if !strings.Contains(script, "/usr/local/share/ca-certificates/hd-root-ca.crt") {
		t.Errorf("Debian 경로가 틀렸다:\n%s", script)
	}
	if !strings.Contains(script, "update-ca-certificates") {
		t.Error("update-ca-certificates 가 없다")
	}
	if !strings.Contains(script, ".crt") || !strings.Contains(target.Note, ".crt") {
		t.Error(".crt 확장자 경고가 없다")
	}
}

func TestWindowsUsesCertutilAddstoreRoot(t *testing.T) {
	target, err := Build(PlatformWindows, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	if !strings.Contains(script, "certutil -addstore -f Root") {
		t.Errorf("certutil 명령이 없다:\n%s", script)
	}
	// 경로는 백슬래시로 바꿔야 한다. 슬래시를 그대로 두면 certutil 이 받지 않는다.
	if strings.Contains(script, "/var/lib/cert-gen/ca") {
		t.Errorf("Windows 경로가 변환되지 않았다:\n%s", script)
	}
	if !strings.Contains(script, `\var\lib\cert-gen\ca`) {
		t.Errorf("백슬래시 경로가 없다:\n%s", script)
	}
	if !strings.Contains(script, "delstore") {
		t.Error("되돌리기(delstore) 안내가 없다")
	}
	if !strings.Contains(target.Note, "관리자") {
		t.Error("관리자 권한 안내가 없다")
	}
}

func TestJavaIsSeparateFromOSStore(t *testing.T) {
	// "OS 에 넣었는데 Java 앱만 안 된다" 가 가장 흔한 사고다. 그 사실을 반드시 알려야 한다.
	target, err := Build(PlatformJava, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(target.Note, "OS 신뢰 저장소를 보지 않습니다") {
		t.Errorf("Java 가 OS 신뢰와 별개라는 안내가 없다: %q", target.Note)
	}
	script := target.Script()
	for _, want := range []string{
		"keytool -importcert", "-trustcacerts", "-noprompt",
		"lib/security/cacerts", "changeit", "hd-root-ca",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("Java 안내에 %q 가 없다:\n%s", want, script)
		}
	}
	// JDK 8 경로 차이와 JDK 교체 시 재등록도 실무에서 걸리는 지점이다.
	if !strings.Contains(target.Note, "jre/lib/security") {
		t.Error("JDK 8 경로 안내가 없다")
	}
	if !strings.Contains(target.Note, "JDK 를 교체하면") {
		t.Error("JDK 교체 시 재등록 안내가 없다")
	}
}

func TestJavaUsesGivenJavaHome(t *testing.T) {
	o := opts()
	o.JavaHome = "/usr/lib/jvm/java-21-openjdk"
	target, err := Build(PlatformJava, o)
	if err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(target.Commands, "\n")
	if !strings.Contains(cmds, "/usr/lib/jvm/java-21-openjdk/lib/security/cacerts") {
		t.Errorf("지정한 JAVA_HOME 이 쓰이지 않았다:\n%s", cmds)
	}
	// 실행할 **명령**에 변수가 남으면 안 된다. 안내 문구(Note)에는 JDK 8 경로 설명으로
	// $JAVA_HOME 이 의도적으로 들어 있으므로 Script() 전체를 보면 안 된다.
	if strings.Contains(cmds, "$JAVA_HOME") {
		t.Error("JAVA_HOME 을 줬는데 명령에 변수가 남았다")
	}
}

func TestJavaFallsBackToJavaHomeVariable(t *testing.T) {
	target, err := Build(PlatformJava, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(target.Commands, "\n"), "$JAVA_HOME") {
		t.Error("JAVA_HOME 을 모를 때 변수를 그대로 두지 않았다")
	}
}

func TestContainerCoversThreeBaseFamilies(t *testing.T) {
	target, err := Build(PlatformContainer, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	for _, want := range []string{
		"update-ca-trust extract",            // RHEL
		"update-ca-certificates",             // Debian
		"apk add --no-cache ca-certificates", // Alpine
		"COPY",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("컨테이너 안내에 %q 가 없다:\n%s", want, script)
		}
	}
	// COPY 에는 절대경로가 아니라 파일명이 들어가야 한다(빌드 컨텍스트 기준).
	if strings.Contains(script, "COPY /var/lib") {
		t.Errorf("COPY 에 절대경로가 들어갔다:\n%s", script)
	}
}

func TestRuntimeCoversCommonToolchains(t *testing.T) {
	// OS 신뢰 저장소를 바꿀 수 없는 경우(비특권 컨테이너)의 우회로.
	target, err := Build(PlatformRuntime, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	for _, want := range []string{
		"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("런타임 안내에 %q 가 없다:\n%s", want, script)
		}
	}
	// root 가 필요 없다는 것이 이 방식의 핵심이다.
	if target.NeedsRoot {
		t.Error("런타임 방식에 root 필요 표시가 붙었다")
	}
}

func TestPathsWithSpacesAreQuoted(t *testing.T) {
	// Windows 의 Program Files, 사용자 디렉터리 등 공백이 들어가는 경우가 실제로 있다.
	// 인용하지 않으면 사용자가 복사한 명령이 조용히 다른 파일을 가리킨다.
	o := opts()
	o.CACertPath = "/home/my user/pki files/ca.crt"
	for _, p := range []Platform{PlatformRHEL, PlatformDebian, PlatformJava} {
		target, err := Build(p, o)
		if err != nil {
			t.Fatal(err)
		}
		script := target.Script()
		if !strings.Contains(script, `'/home/my user/pki files/ca.crt'`) {
			t.Errorf("%s: 공백 경로가 인용되지 않았다:\n%s", p, script)
		}
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	// 경로에 작은따옴표가 있으면 인용이 깨져 명령이 전혀 다른 뜻이 된다.
	got := shellQuote(`/tmp/it's here/ca.crt`)
	if !strings.Contains(got, `'\''`) {
		t.Errorf("작은따옴표가 이스케이프되지 않았다: %s", got)
	}
	if shellQuote("/plain/path.crt") != "/plain/path.crt" {
		t.Error("안전한 경로에 불필요한 인용이 붙었다")
	}
	if shellQuote("") != "''" {
		t.Error("빈 문자열이 인용되지 않았다")
	}
}

func TestScriptHasVerifyAndRemoveSections(t *testing.T) {
	target, err := Build(PlatformRHEL, opts())
	if err != nil {
		t.Fatal(err)
	}
	script := target.Script()
	for _, want := range []string{"# 확인", "# 되돌리기", "관리자(root) 권한"} {
		if !strings.Contains(script, want) {
			t.Errorf("스크립트에 %q 절이 없다:\n%s", want, script)
		}
	}
}

func TestDetectPlatformReturnsSomethingUsable(t *testing.T) {
	p := DetectPlatform()
	found := false
	for _, known := range Platforms {
		if p == known {
			found = true
		}
	}
	if !found {
		t.Errorf("추정 결과가 알 수 없는 값이다: %q", p)
	}
	// 추정 결과로 안내를 만들 수 있어야 한다.
	if _, err := Build(p, opts()); err != nil {
		t.Errorf("추정한 종류로 안내를 만들 수 없다: %v", err)
	}
}

func TestLabelsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Platforms {
		label := Label(p)
		if seen[label] {
			t.Errorf("설명이 중복된다: %q", label)
		}
		seen[label] = true
	}
}
