package cli

import (
	"fmt"
	"strings"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keymgmt"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/trust"
	"github.com/newshure/cert-gen/internal/tui"
)

// --- key --------------------------------------------------------------------

func (a *App) keyCreate(args []string) error {
	fs := flags("key create")
	var (
		name      = fs.String("name", "", "키 이름 (필수)")
		algo      = fs.String("key-algo", "", "알고리즘 ("+strings.Join(keys.Names(), ", ")+")")
		note      = fs.String("note", "", "메모")
		encrypt   = fs.Bool("encrypt", false, "패스프레이즈로 암호화한다")
		passStdin = fs.Bool("passphrase-stdin", false, "패스프레이즈를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *name == "" && len(rest) == 1 {
		*name = rest[0]
	}
	if *name == "" {
		return certerr.Validationf("--name 이 필요합니다")
	}
	if err := a.open(true); err != nil {
		return err
	}
	var passphrase string
	if *encrypt {
		passphrase, err = ReadSecret(SecretSource{
			Env: EnvKeyPassphrase, FromStdin: *passStdin,
			Prompt: "개인키 패스프레이즈: ", Confirm: !*passStdin,
		})
		if err != nil {
			return err
		}
		if passphrase == "" {
			return certerr.Validationf("--encrypt 를 줬는데 패스프레이즈가 비어 있습니다")
		}
	}
	info, err := keymgmt.Create(a.cfg, a.store, keymgmt.CreateOptions{
		Name: *name, Algo: *algo, Passphrase: passphrase, Note: *note, Frontend: "cli",
	})
	if err != nil {
		return err
	}
	if err := a.Out.Emit(keyJSON(info)); err != nil {
		return err
	}
	a.Out.Line("%s", info.Key.Name)
	a.Out.Printf("개인키를 만들었습니다.\n")
	a.printKey(info)
	if passphrase == "" {
		a.Out.Printf("\n패스프레이즈가 없습니다 — 서버가 기동할 때 묻지 않습니다(의도된 기본값).\n")
	}
	return nil
}

func keyJSON(info keymgmt.Info) map[string]any {
	return map[string]any{
		"id": info.Key.ID, "name": info.Key.Name, "algo": info.Key.Algo,
		"encrypted": info.Key.Encrypted, "path": info.Key.Path,
		"public_sha256": info.Key.PublicSHA256, "pair": info.PairToken(),
		"source": info.Key.Source, "note": info.Key.Note,
		"used_by_cas": info.UsedByCAs, "used_by_certs": info.UsedByCerts,
	}
}

func (a *App) printKey(info keymgmt.Info) {
	a.Out.Printf("  이름          %s\n", info.Key.Name)
	a.Out.Printf("  알고리즘      %s\n", info.Key.Algo)
	a.Out.Printf("  보호          %s\n", encryptedNote(info.Key.Encrypted))
	a.Out.Printf("  쌍 토큰       %s\n", info.PairToken())
	a.Out.Printf("  경로          %s\n", info.Key.Path)
	a.Out.Printf("  사용처        %s\n", info.UsageText())
}

func (a *App) keyList(args []string) error {
	fs := flags("key list")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	list, err := keymgmt.List(a.cfg, a.store)
	if err != nil {
		return err
	}
	if a.Out.JSON {
		out := make([]map[string]any, 0, len(list))
		for _, info := range list {
			out = append(out, keyJSON(info))
		}
		return a.Out.Emit(out)
	}
	rows := make([][]string, 0, len(list))
	for _, info := range list {
		protection := "평문"
		if info.Key.Encrypted {
			protection = "암호"
		}
		rows = append(rows, []string{
			info.Key.Name, info.Key.Algo, protection, info.PairToken(), info.UsageText(),
		})
	}
	a.Out.Table([]string{"이름", "알고리즘", "보호", "쌍", "사용처"}, rows)
	if len(list) == 0 {
		a.Out.Printf("\n등록된 키가 없습니다. 'cert-gen key create --name <이름>' 으로 만듭니다.\n")
	} else {
		a.Out.Printf("\n'쌍' 은 공개키 지문 앞 8자리입니다. cert list 의 같은 열과 맞춰 짝을 확인합니다.\n")
	}
	return nil
}

func (a *App) keyShow(args []string) error {
	fs := flags("key show")
	pub := fs.Bool("public", false, "공개키 PEM 을 출력한다")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("키 이름 또는 id 를 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	info, err := keymgmt.Get(a.cfg, a.store, rest[0])
	if err != nil {
		return err
	}
	if err := a.Out.Emit(keyJSON(info)); err != nil {
		return err
	}
	a.printKey(info)
	if len(info.UsedByCAs) > 0 {
		a.Out.Printf("  CA            %s\n", strings.Join(info.UsedByCAs, ", "))
	}
	if len(info.UsedByCerts) > 0 {
		a.Out.Printf("  인증서        %s\n", strings.Join(info.UsedByCerts, ", "))
	}
	if *pub {
		data, err := keymgmt.PublicPEM(a.cfg, a.store, rest[0], "")
		if err != nil {
			return err
		}
		fmt.Fprint(a.Out.W, string(data))
	}
	return nil
}

func (a *App) keyPassphrase(args []string) error {
	fs := flags("key passphrase")
	var (
		remove       = fs.Bool("remove", false, "패스프레이즈를 제거한다 (서버 무인 기동용)")
		currentStdin = fs.Bool("current-stdin", false, "현재 패스프레이즈를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("키 이름 또는 id 를 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	info, err := keymgmt.Get(a.cfg, a.store, rest[0])
	if err != nil {
		return err
	}

	var current string
	if info.Key.Encrypted {
		current, err = ReadSecret(SecretSource{
			Env: EnvKeyPassphrase, FromStdin: *currentStdin, Prompt: "현재 패스프레이즈: ",
		})
		if err != nil {
			return err
		}
	}
	var next string
	if !*remove {
		next, err = ReadSecret(SecretSource{Prompt: "새 패스프레이즈: ", Confirm: true})
		if err != nil {
			return err
		}
		if next == "" {
			return certerr.Validationf(
				"새 패스프레이즈가 비어 있습니다. 제거하려면 --remove 를 쓰세요")
		}
	}
	updated, err := keymgmt.SetPassphrase(a.cfg, a.store, rest[0], current, next, "cli")
	if err != nil {
		return err
	}
	if err := a.Out.Emit(keyJSON(updated)); err != nil {
		return err
	}
	if *remove {
		a.Out.Line("패스프레이즈를 제거했습니다: %s", updated.Key.Name)
		if updated.InUse() {
			a.Out.Warn("이 키는 쓰이는 중입니다(%s). 개인키가 이제 평문으로 저장됩니다",
				updated.UsageText())
		}
	} else {
		a.Out.Line("패스프레이즈를 설정했습니다: %s", updated.Key.Name)
		a.Out.Warn("이 키를 서버에 쓰면 기동할 때마다 패스프레이즈를 묻습니다")
	}
	return nil
}

func (a *App) keyDelete(args []string) error {
	fs := flags("key delete")
	yes := fs.Bool("yes", false, "확인 없이 진행")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("키 이름 또는 id 를 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	info, err := keymgmt.Get(a.cfg, a.store, rest[0])
	if err != nil {
		return err
	}
	if !*yes {
		a.Out.Printf("삭제 대상: %s (%s, 쌍 %s)\n", info.Key.Name, info.Key.Algo, info.PairToken())
		if !confirm("개인키 파일이 지워집니다. 되돌릴 수 없습니다. 진행합니까?") {
			return certerr.Validationf("취소했습니다")
		}
	}
	if err := keymgmt.Delete(a.cfg, a.store, rest[0], "cli"); err != nil {
		return err
	}
	a.Out.Line("%s 를 지웠습니다", info.Key.Name)
	return nil
}

func (a *App) keyImport(args []string) error {
	fs := flags("key import")
	var (
		path      = fs.String("file", "", "가져올 개인키 파일 (필수)")
		name      = fs.String("name", "", "등록할 이름 (기본: 파일명)")
		note      = fs.String("note", "", "메모")
		passStdin = fs.Bool("passphrase-stdin", false, "개인키 패스프레이즈를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *path == "" && len(rest) == 1 {
		*path = rest[0]
	}
	if *path == "" {
		return certerr.Validationf("--file 이 필요합니다")
	}
	if err := a.open(true); err != nil {
		return err
	}
	passphrase, err := ReadSecret(SecretSource{Env: EnvKeyPassphrase, FromStdin: *passStdin})
	if err != nil {
		return err
	}
	info, err := keymgmt.Import(a.cfg, a.store, *path, *name, passphrase, *note, "cli")
	if err != nil {
		return err
	}
	if err := a.Out.Emit(keyJSON(info)); err != nil {
		return err
	}
	a.Out.Line("%s", info.Key.Name)
	a.Out.Printf("개인키를 가져왔습니다(원본의 암호화 상태를 유지했습니다).\n")
	a.printKey(info)
	return nil
}

// --- trust ------------------------------------------------------------------

func (a *App) trustShow(args []string) error {
	fs := flags("trust show")
	var (
		platform = fs.String("platform", "", "대상 ("+strings.Join(trust.PlatformNames(), " | ")+")")
		javaHome = fs.String("java-home", "", "JAVA_HOME (java 대상)")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	slug := ""
	if len(rest) == 1 {
		slug = rest[0]
	} else {
		list, err := a.store.ListCAs("")
		if err != nil {
			return err
		}
		if len(list) != 1 {
			return certerr.Validationf("CA 식별자를 지정하세요: cert-gen trust show SLUG")
		}
		slug = list[0].Slug
	}
	rec, err := a.store.GetCA(slug)
	if err != nil {
		return err
	}
	_, certPath, _ := ca.ResolvePaths(a.cfg, rec)

	targets := trust.Platforms
	if *platform != "" {
		targets = []trust.Platform{trust.Platform(*platform)}
	}
	type block struct {
		Platform  string   `json:"platform"`
		Label     string   `json:"label"`
		NeedsRoot bool     `json:"needs_root"`
		Note      string   `json:"note"`
		Commands  []string `json:"commands"`
		Verify    []string `json:"verify"`
		Remove    []string `json:"remove"`
	}
	var blocks []block
	for _, p := range targets {
		t, err := trust.Build(p, trust.Options{
			CACertPath: certPath, Name: rec.Slug,
			CommonName: rec.CommonName, JavaHome: *javaHome,
		})
		if err != nil {
			return err
		}
		blocks = append(blocks, block{
			Platform: string(p), Label: t.Label, NeedsRoot: t.NeedsRoot,
			Note: t.Note, Commands: t.Commands, Verify: t.Verify, Remove: t.Remove,
		})
		if !a.Out.JSON {
			a.Out.Printf("%s\n", t.Script())
		}
	}
	if err := a.Out.Emit(map[string]any{"ca": rec.Slug, "ca_cert": certPath, "targets": blocks}); err != nil {
		return err
	}
	if !a.Out.JSON && *platform == "" {
		a.Out.Printf("특정 대상만 보려면: cert-gen trust show %s --platform <%s>\n",
			rec.Slug, strings.Join(trust.PlatformNames(), "|"))
	}
	return nil
}

// --- tui --------------------------------------------------------------------

func (a *App) cmdTUI(args []string) error {
	fs := flags("tui")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if !fsops.IsTTY() {
		// TTY 가 아니면 TUI 는 깨진다. CLI 등가 명령을 알려 준다 — TUI 는 편의 계층이고
		// CLI 가 정본이라는 설계를 여기서 드러낸다.
		return certerr.Validationf(
			"터미널이 아니어서 TUI 를 띄울 수 없습니다. CLI 를 쓰세요:\n" +
				"  cert-gen init\n" +
				"  cert-gen ca create --cn \"<조직> Root CA\"\n" +
				"  cert-gen cert issue --cn <호스트명>\n" +
				"  cert-gen cert list")
	}
	if err := a.open(true); err != nil {
		return err
	}
	return tui.Run(a.cfg, a.store)
}
