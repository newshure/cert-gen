// Package cli — 명령줄 프런트엔드. CLI 가 정본이고 TUI 는 편의 계층이다.
package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/store"
)

// Version 은 빌드 시 -ldflags 로 주입한다.
var Version = "dev"

// App 은 전역 플래그와 열린 자원을 담는다.
type App struct {
	Out      Out
	cfg      config.Config
	store    *store.Store
	dataFlag string
	confFlag string
}

const usage = `cert-gen %s — 자가서명 인증서 생성기 (로컬 CA)

사용법:
  cert-gen [전역 옵션] <명령> [하위 명령] [옵션]

전역 옵션:
  --data-dir DIR    상태 디렉터리 (기본: <현재 디렉터리>/cert-gen-data)
  -c, --config FILE 설정 파일 (기본: <상태 디렉터리>/config.toml)
  --json            결과를 JSON 으로 출력
  -q, --quiet       사람이 읽는 출력을 생략
  -v, --version     버전 출력

명령:
  init                         상태 디렉터리와 DB 를 만든다
  where                        상태 디렉터리 위치와 규칙을 보여 준다
  doctor                       환경 점검 (권한·DB·CA·만료·CRL·openssl). --deep 으로 번들 해시까지

  key create --name NAME       개인키를 만들어 둔다 (CA·발급에서 고를 수 있다)
  key list                     개인키 목록 (쌍 토큰으로 인증서와 짝을 맞춘다)
  key show NAME                개인키 상세·사용처
  key import --file FILE        외부 개인키를 가져온다
  key passphrase NAME          패스프레이즈 설정/제거(--remove)
  key delete NAME              개인키 삭제 (쓰이는 중이면 거부)

  ca create                    Root CA 를 만든다 (--cn 필수, --org/--ou/--country)
  ca list                      CA 목록
  ca show SLUG                 CA 상세
  ca export SLUG               ca.crt 를 내보낸다 (클라이언트 신뢰 등록용)
  ca adopt --dir DIR           외부 CA 를 복사 없이 등록해 발급에 쓴다
  ca import --key K --cert C   외부 CA 를 상태 디렉터리로 복사해 등록한다

  apply FILE...                openssl .cnf 를 읽어 CA 생성·발급을 한 번에
                               (한 파일에 --- 로 블록을 나누거나, 파일을 여러 개 주거나)

  cert issue                   인증서를 발급한다 (--config 로 openssl .cnf 입력 가능)
  cert list                    발급 이력
  cert show REF                상세 (ID | serial | CN)
  cert renew REF               갱신 (기본: 새 키)
  cert revoke REF              폐기하고 CRL 을 다시 만든다
  cert verify REF              검증 (체인·호스트명·폐기)
  cert bundle REF              번들 zip 을 꺼낸다

  csr create                   외부 CA 제출용 CSR 을 만든다
  csr sign --csr FILE          받은 CSR 을 우리 CA 로 서명한다

  export p12 REF               PKCS#12
  export jks REF               Java KeyStore
  export der REF               DER
  export pem REF               PEM (cert/key/fullchain/ca)
  export k8s REF               kubernetes.io/tls Secret (+ Ingress)

  crl generate SLUG            CRL 을 다시 만든다
  crl list SLUG                폐기 목록

  backup create                상태 디렉터리 전체를 tar.gz 로 묶는다 (CA 개인키 포함)
  backup restore FILE          백업을 복원한다 (--dry-run 으로 먼저 확인)

  trust show [SLUG]            OS·Java 신뢰 저장소 등록 명령을 만든다
  tui                          터미널 UI 를 띄운다

비밀값은 명령행 인자로 받지 않는다 (/proc/<pid>/cmdline 노출).
환경변수나 --*-stdin 옵션, 또는 TTY 프롬프트를 쓴다.
  %s, %s, %s

'cert-gen <명령> -h' 로 각 명령의 옵션을 본다.
`

// Run 은 진입점이다. 종료 코드를 돌려준다.
func Run(args []string) int {
	app := &App{Out: Out{W: os.Stdout, Err: os.Stderr}}

	global := flag.NewFlagSet("cert-gen", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = func() { app.printUsage() }
	global.StringVar(&app.dataFlag, "data-dir", "", "상태 디렉터리")
	global.StringVar(&app.confFlag, "config", "", "설정 파일")
	global.StringVar(&app.confFlag, "c", "", "설정 파일 (단축)")
	global.BoolVar(&app.Out.JSON, "json", false, "JSON 출력")
	global.BoolVar(&app.Out.Quiet, "quiet", false, "조용히")
	global.BoolVar(&app.Out.Quiet, "q", false, "조용히 (단축)")
	showVersion := global.Bool("version", false, "버전")
	global.BoolVar(showVersion, "v", false, "버전 (단축)")

	if err := global.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(os.Stdout, "cert-gen %s\n", Version)
		return 0
	}
	rest := global.Args()
	if len(rest) == 0 {
		app.printUsage()
		return 2
	}

	defer func() {
		if app.store != nil {
			app.store.Close()
		}
	}()

	err := app.dispatch(rest)
	if err == nil {
		return 0
	}
	// 오류는 한 가지 형식으로만 낸다. 프런트엔드마다 다르게 보이면 사용자가 같은 문제를
	// 다른 문제로 오해한다.
	fmt.Fprintf(os.Stderr, "오류: %s\n", certerr.UserMessage(err))
	return certerr.ExitCodeOf(err)
}

func (a *App) printUsage() {
	fmt.Fprintf(os.Stderr, usage, Version,
		EnvCAPassphrase, EnvExportPassword, EnvKeyPassphrase)
}

func (a *App) dispatch(args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return a.cmdInit(rest)
	case "doctor":
		return a.cmdDoctor(rest)
	case "where":
		return a.cmdWhere(rest)
	case "tui":
		return a.cmdTUI(rest)
	case "key":
		return a.group("key", rest, map[string]handler{
			"create": a.keyCreate, "list": a.keyList, "show": a.keyShow,
			"passphrase": a.keyPassphrase, "delete": a.keyDelete, "import": a.keyImport,
		})
	case "backup":
		return a.group("backup", rest, map[string]handler{
			"create": a.backupCreate, "restore": a.backupRestore,
		})
	case "trust":
		return a.group("trust", rest, map[string]handler{
			"show": a.trustShow,
		})
	case "ca":
		return a.group("ca", rest, map[string]handler{
			"create": a.caCreate, "list": a.caList, "show": a.caShow,
			"export": a.caExport, "adopt": a.caAdopt, "import": a.caImport,
		})
	case "apply":
		return a.cmdApply(rest)
	case "cert":
		return a.group("cert", rest, map[string]handler{
			"issue": a.certIssue, "list": a.certList, "show": a.certShow,
			"renew": a.certRenew, "revoke": a.certRevoke,
			"verify": a.certVerify, "bundle": a.certBundle,
		})
	case "csr":
		return a.group("csr", rest, map[string]handler{
			"create": a.csrCreate, "sign": a.csrSign,
		})
	case "export":
		return a.group("export", rest, map[string]handler{
			"p12": a.exportP12, "jks": a.exportJKS, "der": a.exportDER,
			"pem": a.exportPEM, "k8s": a.exportK8s,
		})
	case "crl":
		return a.group("crl", rest, map[string]handler{
			"generate": a.crlGenerate, "list": a.crlList,
		})
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	default:
		return certerr.Validationf("알 수 없는 명령입니다: %q ('cert-gen help' 로 목록을 봅니다)", cmd)
	}
}

type handler func([]string) error

func (a *App) group(name string, args []string, table map[string]handler) error {
	if len(args) == 0 {
		return certerr.Validationf("%s 하위 명령이 필요합니다: %s", name, strings.Join(sortedHandlers(table), " | "))
	}
	sub, rest := args[0], args[1:]
	h, ok := table[sub]
	if !ok {
		return certerr.Validationf("알 수 없는 %s 하위 명령입니다: %q (사용 가능: %s)",
			name, sub, strings.Join(sortedHandlers(table), " | "))
	}
	return h(rest)
}

func sortedHandlers(table map[string]handler) []string {
	out := make([]string, 0, len(table))
	for k := range table {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// open 은 설정을 읽고 DB 를 연다. create 가 false 면 DB 가 없으면 오류다.
func (a *App) open(create bool) error {
	cfg, err := config.Load(a.confFlag, a.dataFlag)
	if err != nil {
		return err
	}
	a.cfg = cfg
	s, err := store.Open(cfg.DBPath(), create)
	if err != nil {
		return err
	}
	a.store = s
	return nil
}

// flags 는 하위 명령용 FlagSet 을 만든다.
func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parse 는 플래그를 해석하고 남은 위치 인자를 돌려준다.
//
// 표준 flag 패키지는 **첫 비플래그 인자에서 해석을 멈춘다.** 그래서 그대로 쓰면
// `cert verify 1 --hostname web.hd.local` 의 --hostname 이 조용히 무시되고, 사용자는
// 옵션을 줬는데 반영되지 않은 결과를 받는다. 조용히 틀리는 쪽이 오류보다 나쁘다.
// 해석 전에 플래그를 앞으로 모아 이 문제를 없앤다(GNU getopt 의 permute 와 같은 동작).
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	reordered, err := permute(fs, args)
	if err != nil {
		return nil, err
	}
	if err := fs.Parse(reordered); err != nil {
		// flag 패키지가 이미 메시지를 냈다(-h 포함). 종료 코드만 맞춘다.
		return nil, certerr.Validationf("옵션을 해석할 수 없습니다")
	}
	return fs.Args(), nil
}

// permute 는 플래그를 앞으로, 위치 인자를 뒤로 모은다.
//
// 값을 받는 플래그와 불리언 플래그를 구분해야 한다. `--json 1` 에서 1 은 --json 의 값이
// 아니라 위치 인자인데, 구분하지 않으면 1 을 삼켜 버린다.
func permute(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagsPart, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// 이후는 모두 위치 인자다. 사용자가 명시적으로 경계를 그었다.
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		flagsPart = append(flagsPart, arg)

		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			continue // --key=value 는 그 자체로 완결이다
		}
		if name == "h" || name == "help" {
			continue
		}
		def := fs.Lookup(name)
		if def == nil {
			// 모르는 플래그다. 여기서 판단하지 않고 flag.Parse 가 제 메시지를 내게 둔다.
			continue
		}
		if isBoolFlag(def) {
			continue
		}
		// 값을 받는 플래그다. 다음 토큰을 함께 옮긴다.
		if i+1 < len(args) {
			i++
			flagsPart = append(flagsPart, args[i])
		}
	}
	if len(positional) == 0 {
		return flagsPart, nil
	}
	// 위치 인자 앞에 항상 -- 를 넣는다. 경계를 명시하면 '-' 로 시작하는 값(예: CN 이
	// "-weird")도 플래그로 오해되지 않는다.
	out := append(flagsPart, "--")
	return append(out, positional...), nil
}

// isBoolFlag 는 값을 받지 않는 플래그인지다. flag 패키지의 비공개 인터페이스와 같은 모양이다.
func isBoolFlag(def *flag.Flag) bool {
	b, ok := def.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}
