package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestEveryCommandRegistersFlagsWithoutPanic 은 모든 하위 명령의 FlagSet 을 실제로 만든다.
//
// Go 의 flag 패키지는 같은 이름을 두 번 등록하면 **panic** 한다. 그리고 그 panic 은 그
// 명령을 처음 실행하는 순간에야 터진다 — 컴파일도 통과하고 다른 명령은 멀쩡하다.
// 실제로 cert issue 에서 DN 의 -o(Organization)와 출력 -o 가 충돌해 이 사고가 났다.
// 이 테스트는 모든 명령을 한 번씩 건드려 그런 충돌을 빌드 단계에서 잡는다.
func TestEveryCommandRegistersFlagsWithoutPanic(t *testing.T) {
	commands := [][]string{
		{"init"}, {"where"}, {"doctor"}, {"apply"},
		{"ca", "create"}, {"ca", "list"}, {"ca", "show"}, {"ca", "export"},
		{"ca", "adopt"}, {"ca", "import"},
		{"cert", "issue"}, {"cert", "list"}, {"cert", "show"}, {"cert", "renew"},
		{"cert", "revoke"}, {"cert", "verify"}, {"cert", "bundle"},
		{"csr", "create"}, {"csr", "sign"},
		{"export", "p12"}, {"export", "jks"}, {"export", "der"},
		{"export", "pem"}, {"export", "k8s"},
		{"crl", "generate"}, {"crl", "list"},
		{"key", "create"}, {"key", "list"}, {"key", "show"},
		{"key", "passphrase"}, {"key", "delete"}, {"key", "import"},
		{"trust", "show"},
		{"backup", "create"}, {"backup", "restore"},
		{"tui"},
	}
	for _, cmd := range commands {
		label := strings.Join(cmd, " ")
		t.Run(label, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s 의 플래그 등록이 panic 했다: %v", label, r)
				}
			}()
			app := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}}
			// -h 를 주면 플래그를 모두 등록한 뒤 사용법을 내고 끝난다. 실제 동작은 하지 않으므로
			// DB 를 만들지 않고 등록 충돌만 본다.
			_ = app.dispatch(append(cmd, "-h"))
		})
	}
}

// TestDNAndOutputFlagsDoNotCollide 는 위 사고의 회귀 테스트다.
func TestDNAndOutputFlagsDoNotCollide(t *testing.T) {
	fs := flags("probe")
	subjectFlags(fs)
	// 출력 디렉터리 -o 를 추가로 등록할 수 있어야 한다.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DN 플래그가 -o 를 선점했다: %v", r)
		}
	}()
	fs.String("o", "", "출력")
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	app := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}}
	err := app.dispatch([]string{"nonsense"})
	if err == nil {
		t.Fatal("알 수 없는 명령이 통과했다")
	}
	// 무엇을 하면 되는지 알려 줘야 한다.
	if !strings.Contains(err.Error(), "help") {
		t.Errorf("도움말 안내가 없다: %v", err)
	}
}

func TestUnknownSubcommandListsOptions(t *testing.T) {
	app := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}}
	err := app.dispatch([]string{"ca", "nonsense"})
	if err == nil {
		t.Fatal("알 수 없는 하위 명령이 통과했다")
	}
	for _, want := range []string{"create", "list", "show"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("사용 가능 목록에 %q 가 없다: %v", want, err)
		}
	}
}

func TestDisplayWidthCountsEastAsianAsTwo(t *testing.T) {
	// 한글 CN 이 섞인 표의 열이 어긋나지 않게 하는 핵심이다.
	cases := map[string]int{
		"web":   3,
		"웹서버":   6,
		"web-웹": 6,
		"":      0,
		"ｗｅｂ":   6,
	}
	for input, want := range cases {
		if got := displayWidth(input); got != want {
			t.Errorf("displayWidth(%q) = %d, 기대 %d", input, got, want)
		}
	}
}

func TestTruncateRespectsWidth(t *testing.T) {
	if got := Truncate("web.hd.local", 8); displayWidth(got) > 8 {
		t.Errorf("Truncate 결과가 폭을 넘는다: %q (%d칸)", got, displayWidth(got))
	}
	if got := Truncate("웹서버-운영-인증서", 10); displayWidth(got) > 10 {
		t.Errorf("한글 Truncate 가 폭을 넘는다: %q (%d칸)", got, displayWidth(got))
	}
	// 짧으면 그대로 둬야 한다.
	if got := Truncate("web", 10); got != "web" {
		t.Errorf("짧은 문자열이 변형됐다: %q", got)
	}
}

func TestTableAlignsWithWideCharacters(t *testing.T) {
	var buf bytes.Buffer
	out := Out{W: &buf, Err: &bytes.Buffer{}}
	out.Table([]string{"CN", "키"}, [][]string{
		{"web.hd.local", "rsa2048"},
		{"웹서버", "ec-p256"},
	})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("줄 수 = %d\n%s", len(lines), buf.String())
	}
	// 두 번째 열의 시작 위치가 모든 줄에서 같아야 한다.
	var starts []int
	for _, line := range lines {
		idx := strings.LastIndex(line, "  ")
		if idx < 0 {
			continue
		}
		starts = append(starts, displayWidth(line[:idx]))
	}
	for i := 1; i < len(starts); i++ {
		if starts[i] != starts[0] {
			t.Errorf("열 위치가 어긋난다: %v\n%s", starts, buf.String())
			break
		}
	}
}

func TestQuietSuppressesPrintfButNotWarn(t *testing.T) {
	var w, e bytes.Buffer
	out := Out{W: &w, Err: &e, Quiet: true}
	out.Printf("사람용 설명\n")
	out.Warn("이건 숨기면 안 된다")
	if w.Len() != 0 {
		t.Errorf("--quiet 인데 설명이 나왔다: %q", w.String())
	}
	// 경고를 숨기면 --quiet 의 의미가 없어진다.
	if !strings.Contains(e.String(), "숨기면 안 된다") {
		t.Errorf("--quiet 가 경고까지 숨겼다: %q", e.String())
	}
}

func TestJSONModeSuppressesHumanOutput(t *testing.T) {
	var w, e bytes.Buffer
	out := Out{W: &w, Err: &e, JSON: true}
	out.Printf("사람용\n")
	out.Line("식별자")
	out.Table([]string{"a"}, [][]string{{"b"}})
	if w.Len() != 0 {
		t.Errorf("--json 인데 사람용 출력이 섞였다: %q", w.String())
	}
	if err := out.Emit(map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), `"k": "v"`) {
		t.Errorf("JSON 이 나오지 않았다: %q", w.String())
	}
}

func TestPermuteMovesFlagsBeforePositionals(t *testing.T) {
	// 표준 flag 는 첫 비플래그에서 멈춘다. permute 없이는 아래 --hostname 이 조용히 무시된다.
	fs := flags("probe")
	host := fs.String("hostname", "", "호스트명")
	verbose := fs.Bool("verbose", false, "자세히")
	rest, err := parse(fs, []string{"1", "--hostname", "web.hd.local", "--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if *host != "web.hd.local" {
		t.Errorf("위치 인자 뒤의 --hostname 이 무시됐다: %q", *host)
	}
	if !*verbose {
		t.Error("위치 인자 뒤의 불리언 플래그가 무시됐다")
	}
	if len(rest) != 1 || rest[0] != "1" {
		t.Errorf("위치 인자 = %v, 기대 [1]", rest)
	}
}

func TestPermuteDoesNotSwallowPositionalAfterBoolFlag(t *testing.T) {
	// --json 1 에서 1 은 --json 의 값이 아니라 위치 인자다.
	fs := flags("probe")
	asJSON := fs.Bool("json", false, "JSON")
	rest, err := parse(fs, []string{"--json", "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !*asJSON {
		t.Error("--json 이 반영되지 않았다")
	}
	if len(rest) != 1 || rest[0] != "1" {
		t.Errorf("불리언 플래그가 위치 인자를 삼켰다: %v", rest)
	}
}

func TestPermuteKeepsValueWithItsFlag(t *testing.T) {
	fs := flags("probe")
	days := fs.Int("days", 0, "일")
	rest, err := parse(fs, []string{"web", "--days", "90", "extra"})
	if err != nil {
		t.Fatal(err)
	}
	if *days != 90 {
		t.Errorf("--days = %d", *days)
	}
	if len(rest) != 2 || rest[0] != "web" || rest[1] != "extra" {
		t.Errorf("위치 인자 순서가 깨졌다: %v", rest)
	}
}

func TestPermuteHandlesEqualsForm(t *testing.T) {
	fs := flags("probe")
	host := fs.String("hostname", "", "호스트명")
	rest, err := parse(fs, []string{"1", "--hostname=web.hd.local"})
	if err != nil {
		t.Fatal(err)
	}
	if *host != "web.hd.local" {
		t.Errorf("--key=value 형식이 깨졌다: %q", *host)
	}
	if len(rest) != 1 {
		t.Errorf("위치 인자 = %v", rest)
	}
}

func TestPermuteRespectsDoubleDash(t *testing.T) {
	// -- 뒤는 전부 위치 인자다. 사용자가 명시적으로 경계를 그었으면 지켜야 한다.
	fs := flags("probe")
	host := fs.String("hostname", "", "호스트명")
	rest, err := parse(fs, []string{"--", "--hostname", "literal"})
	if err != nil {
		t.Fatal(err)
	}
	if *host != "" {
		t.Errorf("-- 뒤의 토큰이 플래그로 해석됐다: %q", *host)
	}
	if len(rest) != 2 {
		t.Errorf("위치 인자 = %v, 기대 2개", rest)
	}
}

func TestPermuteRepeatableFlag(t *testing.T) {
	fs := flags("probe")
	var sans repeatable
	fs.Var(&sans, "san", "SAN")
	rest, err := parse(fs, []string{"--san", "dns:a", "web", "--san", "ip:10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sans) != 2 || sans[0] != "dns:a" || sans[1] != "ip:10.0.0.5" {
		t.Errorf("반복 플래그가 깨졌다: %v", sans)
	}
	if len(rest) != 1 || rest[0] != "web" {
		t.Errorf("위치 인자 = %v", rest)
	}
}

func TestPadRightUsesDisplayWidth(t *testing.T) {
	if got := padRight("키 강도", 12); displayWidth(got) != 12 {
		t.Errorf("padRight 결과 폭 = %d, 기대 12 (%q)", displayWidth(got), got)
	}
	if got := padRight("EKU", 12); displayWidth(got) != 12 {
		t.Errorf("padRight 결과 폭 = %d, 기대 12", displayWidth(got))
	}
}
