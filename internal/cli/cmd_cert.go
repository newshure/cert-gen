package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/osslconf"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
	"github.com/newshure/cert-gen/internal/verify"
)

// mergeSubject 는 dst 의 **빈 필드만** src 로 채운다.
//
// 명령행으로 준 값이 .cnf 값을 이기게 하기 위해서다(dst 가 명령행, src 가 .cnf). CN 은
// 호출부가 따로 처리하므로 여기서는 나머지만 본다.
func mergeSubject(dst *names.Subject, src names.Subject) {
	if dst.Organization == "" {
		dst.Organization = src.Organization
	}
	if dst.OrganizationalUnit == "" {
		dst.OrganizationalUnit = src.OrganizationalUnit
	}
	if dst.Country == "" {
		dst.Country = src.Country
	}
	if dst.State == "" {
		dst.State = src.State
	}
	if dst.Locality == "" {
		dst.Locality = src.Locality
	}
	if dst.Email == "" {
		dst.Email = src.Email
	}
}

// repeatable 은 반복 지정 가능한 플래그다(--san 을 여러 번).
type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func (a *App) certIssue(args []string) error {
	fs := flags("cert issue")
	subj := subjectFlags(fs)
	var sans repeatable
	fs.Var(&sans, "san", "SAN. 반복 지정. 접두어 dns:/ip:/uri:/email: 생략 시 자동 판별")
	var (
		caSlug    = fs.String("ca", "", "CA 식별자 (발급 이력 기반)")
		caDir     = fs.String("ca-dir", "", "CA 가 있는 디렉터리 (외부 CA)")
		profile   = fs.String("profile", "", "프로필 ("+strings.Join(profiles.Leaf, " | ")+")")
		keyAlgo   = fs.String("key-algo", "", "키 알고리즘 ("+strings.Join(keys.Names(), ", ")+")")
		days      = fs.Int("days", 0, "유효기간(일)")
		note      = fs.String("note", "", "메모")
		outDir    = fs.String("o", "", "번들을 이 디렉터리에 풀어 놓는다")
		passStdin = fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
		confPath  = fs.String("config", "", "openssl .cnf 에서 DN·SAN 을 읽는다 (--cn/--san 이 덮어쓴다)")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}

	// --config 가 있으면 .cnf 에서 DN·SAN·프로필을 먼저 채우고, 명령행 플래그가 그 위를
	// 덮어쓴다. "설정을 바탕으로 하되 이번만 CN 을 바꾼다" 같은 흐름을 막지 않기 위해서다.
	sanValues := []string(sans)
	if *confPath != "" {
		spec, err := osslconf.ParseFile(*confPath)
		if err != nil {
			return err
		}
		if spec.IsCA {
			// CA 설정으로 leaf 를 발급하면 안 된다. apply 로 CA 를 만들라고 안내한다.
			return certerr.Validationf(
				"이 설정은 CA 용입니다(basicConstraints CA:TRUE). "+
					"CA 를 만들려면 'cert-gen apply %s' 또는 'cert-gen ca create' 를 쓰세요", *confPath)
		}
		a.Out.Warnings(spec.Warnings)
		if subj.CommonName == "" {
			subj.CommonName = spec.Subject.CommonName
		}
		mergeSubject(subj, spec.Subject)
		if len(sanValues) == 0 {
			sanValues = spec.SANValues
		}
		if *profile == "" {
			*profile = spec.Profile
		}
	}

	if subj.CommonName == "" {
		return certerr.Validationf("--cn 이 필요합니다 (또는 --config 로 CN 이 든 .cnf 를 주세요)")
	}
	if err := a.open(true); err != nil {
		return err
	}
	material, err := a.loadCA(*caSlug, *caDir, *passStdin)
	if err != nil {
		return err
	}
	res, err := issue.Issue(a.cfg, a.store, issue.Options{
		Material: material, Subject: *subj, SANValues: sanValues,
		Profile: *profile, KeyAlgo: *keyAlgo, Days: *days, Note: *note, Frontend: "cli",
	})
	if err != nil {
		return err
	}
	a.Out.Warnings(res.Warnings)

	var extracted []string
	if *outDir != "" {
		extracted, err = bundle.ExtractTo(res.BundlePath, *outDir)
		if err != nil {
			return err
		}
	}
	if err := a.Out.Emit(map[string]any{
		"id": res.Record.ID, "serial": res.Record.SerialHex,
		"common_name": res.Record.CommonName, "subject_dn": res.Record.SubjectDN,
		"profile": res.Record.Profile, "key_algo": res.Record.KeyAlgo,
		"not_before": res.Record.NotBefore, "not_after": res.Record.NotAfter,
		"fingerprint_sha256": res.Record.Fingerprint, "bundle": res.BundlePath,
		"extracted": extracted, "warnings": res.Warnings,
	}); err != nil {
		return err
	}
	a.Out.Line("%d", res.Record.ID)
	a.Out.Printf("인증서를 발급했습니다.\n")
	a.printCert(res.Record)
	a.Out.Printf("  번들          %s\n", res.BundlePath)
	for _, path := range extracted {
		a.Out.Printf("  풀어 놓음     %s\n", path)
	}
	a.Out.Printf("\n서버에 올릴 파일: fullchain.pem + privkey.pem\n")
	a.Out.Printf("클라이언트 신뢰 등록: ca.crt\n")
	a.Out.Printf("번들 꺼내기: cert-gen cert bundle %d -o <디렉터리>\n", res.Record.ID)
	return nil
}

func (a *App) printCert(rec store.Cert) {
	a.Out.Printf("  ID            %d (CA 내 %d번)\n", rec.ID, rec.Seq)
	a.Out.Printf("  Subject       %s\n", rec.SubjectDN)
	a.Out.Printf("  SAN           %s\n", sanText(rec))
	a.Out.Printf("  프로필        %s\n", rec.Profile)
	a.Out.Printf("  키            %s\n", rec.KeyAlgo)
	a.Out.Printf("  유효기간      %s ~ %s\n", shortDate(rec.NotBefore), shortDate(rec.NotAfter))
	a.Out.Printf("  serial        %s\n", certbuild.FormatColons(rec.SerialHex))
	a.Out.Printf("  지문(SHA256)  %s\n", rec.Fingerprint)
	if rec.PublicSHA256 != "" {
		// 키-인증서 쌍을 눈으로 맞출 수 있게 짧은 토큰을 보여 준다.
		a.Out.Printf("  쌍 토큰       %s\n", shortToken(rec.PublicSHA256))
	}
	if rec.Status != "valid" {
		a.Out.Printf("  상태          %s", rec.Status)
		if rec.RevokeReason != "" {
			a.Out.Printf(" (%s, %s)", rec.RevokeReason, shortDate(rec.RevokedAt))
		}
		a.Out.Printf("\n")
	}
}

func shortToken(sha string) string {
	if len(sha) < 8 {
		return sha
	}
	return sha[:8]
}

func sanText(rec store.Cert) string {
	if len(rec.SANs) == 0 {
		return "(없음)"
	}
	parts := make([]string, 0, len(rec.SANs))
	for _, san := range rec.SANs {
		parts = append(parts, san.Type+":"+san.Value)
	}
	return strings.Join(parts, ", ")
}

func certJSON(rec store.Cert) map[string]any {
	sans := make([]map[string]string, 0, len(rec.SANs))
	for _, san := range rec.SANs {
		sans = append(sans, map[string]string{"type": san.Type, "value": san.Value})
	}
	return map[string]any{
		"id": rec.ID, "seq": rec.Seq, "serial": rec.SerialHex,
		"common_name": rec.CommonName, "subject_dn": rec.SubjectDN, "sans": sans,
		"profile": rec.Profile, "key_algo": rec.KeyAlgo,
		"not_before": rec.NotBefore, "not_after": rec.NotAfter,
		"fingerprint_sha256": rec.Fingerprint, "public_sha256": rec.PublicSHA256,
		"status": rec.Status, "revoked_at": rec.RevokedAt, "revoke_reason": rec.RevokeReason,
		"has_private_key": rec.HasPrivateKey, "source": rec.Source,
		"bundle_path": rec.BundlePath, "note": rec.Note,
	}
}

func (a *App) certList(args []string) error {
	fs := flags("cert list")
	var (
		caSlug     = fs.String("ca", "", "CA 식별자로 필터")
		status     = fs.String("status", "", "상태 (valid|revoked|superseded)")
		search     = fs.String("search", "", "CN 검색")
		expiringIn = fs.Int("expiring-in", 0, "N일 내 만료만")
		limit      = fs.Int("limit", 0, "최대 건수")
	)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.open(false); err != nil {
		return err
	}
	filter := store.CertFilter{Status: *status, Search: *search, Limit: *limit}
	if *expiringIn > 0 {
		filter.ExpiringIn = expiringIn
	}
	if *caSlug != "" {
		rec, err := a.store.GetCA(*caSlug)
		if err != nil {
			return err
		}
		filter.CAID = &rec.ID
	}
	list, err := a.store.ListCerts(filter)
	if err != nil {
		return err
	}
	if a.Out.JSON {
		out := make([]map[string]any, 0, len(list))
		for _, rec := range list {
			out = append(out, certJSON(rec))
		}
		return a.Out.Emit(out)
	}
	rows := make([][]string, 0, len(list))
	for _, rec := range list {
		rows = append(rows, []string{
			fmt.Sprintf("%d", rec.ID), Truncate(rec.CommonName, 26), rec.Profile,
			rec.KeyAlgo, shortDate(rec.NotAfter), rec.Status, shortToken(rec.PublicSHA256),
		})
	}
	a.Out.Table([]string{"ID", "CN", "프로필", "키", "만료", "상태", "쌍"}, rows)
	return nil
}

func (a *App) certShow(args []string) error {
	fs := flags("cert show")
	showPEM := fs.Bool("pem", false, "인증서 PEM 을 출력한다")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("대상을 하나 지정하세요: ID | serial | CN")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return err
	}
	if err := a.Out.Emit(certJSON(rec)); err != nil {
		return err
	}
	a.printCert(rec)
	a.Out.Printf("  번들          %s\n", filepath.Join(a.cfg.DataDir, rec.BundlePath))
	if *showPEM {
		in, err := export.FromBundle(a.cfg, rec, "")
		if err != nil {
			return err
		}
		fmt.Fprint(a.Out.W, string(export.CertPEM(in).Data))
	}
	return nil
}

func (a *App) certRenew(args []string) error {
	fs := flags("cert renew")
	var (
		days      = fs.Int("days", 0, "유효기간(일)")
		keyAlgo   = fs.String("key-algo", "", "새 키 알고리즘 (기본: 기존과 동일)")
		passStdin = fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("갱신할 대상을 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return err
	}
	caRec, err := a.store.GetCA(fmt.Sprintf("%d", rec.CAID))
	if err != nil {
		return err
	}
	material, err := a.loadCA(caRec.Slug, "", *passStdin)
	if err != nil {
		return err
	}
	res, err := issue.Renew(a.cfg, a.store, issue.RenewOptions{
		Material: material, Record: rec, Days: *days, KeyAlgo: *keyAlgo, Frontend: "cli",
	})
	if err != nil {
		return err
	}
	a.Out.Warnings(res.Warnings)
	if err := a.Out.Emit(map[string]any{
		"id": res.Record.ID, "renewed_from": rec.ID,
		"serial": res.Record.SerialHex, "bundle": res.BundlePath,
	}); err != nil {
		return err
	}
	a.Out.Line("%d", res.Record.ID)
	a.Out.Printf("갱신했습니다 (이전 #%d → 새 #%d). 이전 건은 superseded 로 표시했습니다.\n",
		rec.ID, res.Record.ID)
	a.printCert(res.Record)
	a.Out.Printf("  번들          %s\n", res.BundlePath)
	a.Out.Printf("\n새 키로 발급했습니다. 서버의 privkey.pem 도 함께 교체해야 합니다.\n")
	return nil
}

func (a *App) certRevoke(args []string) error {
	fs := flags("cert revoke")
	var (
		reason    = fs.String("reason", "", "폐기 사유 ("+strings.Join(crl.ReasonNames(), " | ")+")")
		passStdin = fs.Bool("passphrase-stdin", false, "CA 패스프레이즈를 stdin 에서 읽는다")
		yes       = fs.Bool("yes", false, "확인 없이 진행")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("폐기할 대상을 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return err
	}
	if !*yes {
		// 폐기는 되돌릴 수 없다. 대상을 보여 주고 확인을 받는다.
		a.Out.Printf("폐기 대상: #%d %s (serial %s, 만료 %s)\n",
			rec.ID, rec.CommonName, certbuild.ShortSerial(rec.SerialHex), shortDate(rec.NotAfter))
		if !confirm("폐기하면 되돌릴 수 없습니다. 진행합니까?") {
			return certerr.Validationf("취소했습니다")
		}
	}
	caRec, err := a.store.GetCA(fmt.Sprintf("%d", rec.CAID))
	if err != nil {
		return err
	}
	material, err := a.loadCA(caRec.Slug, "", *passStdin)
	if err != nil {
		return err
	}
	out, err := crl.Revoke(a.cfg, a.store, material, rec, *reason, "cli")
	if err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{
		"id": out.Record.ID, "status": out.Record.Status,
		"reason": out.Reason.Name, "reason_code": out.Reason.Code,
		"crl": out.CRL.Path, "crl_number": out.CRL.Number, "crl_count": out.CRL.Count,
	}); err != nil {
		return err
	}
	a.Out.Line("#%d 폐기", out.Record.ID)
	a.Out.Printf("사유: %s (%s)\n", out.Reason.Name, out.Reason.Label)
	a.Out.Printf("CRL 을 다시 만들었습니다: %s\n", crl.Describe(out.CRL))
	a.Out.Printf("\n폐기가 효력을 가지려면 검증하는 쪽이 이 CRL 을 읽어야 합니다.\n")
	a.Out.Printf("  nginx:  ssl_crl %s;  (갱신 후 reload 필요)\n", out.CRL.Path)
	return nil
}

func confirm(question string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func (a *App) certVerify(args []string) error {
	fs := flags("cert verify")
	var (
		hostname     = fs.String("hostname", "", "이 호스트명이 SAN 과 맞는지 확인")
		noRevocation = fs.Bool("no-revocation", false, "CRL 폐기 확인을 건너뛴다")
		noCrossCheck = fs.Bool("no-openssl", false, "openssl 교차 검증을 건너뛴다")
	)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("검증할 대상을 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return err
	}
	in, err := export.FromBundle(a.cfg, rec, "")
	if err != nil {
		return err
	}
	caRec, err := a.store.GetCA(fmt.Sprintf("%d", rec.CAID))
	if err != nil {
		return err
	}
	host := *hostname
	if host == "" && len(rec.SANs) > 0 && rec.SANs[0].Type == "dns" {
		// 기본으로 CN(=첫 SAN)을 검사한다. 호스트명 검사를 건너뛰면 가장 중요한 확인이 빠진다.
		host = rec.SANs[0].Value
	}
	report, err := verify.Run(a.cfg, in, verify.Options{
		Hostname: host, CheckRevocation: !*noRevocation, CARecord: &caRec,
		CrossCheckOpenSSL: !*noCrossCheck,
	})
	if err != nil {
		return err
	}

	if a.Out.JSON {
		checks := make([]map[string]string, 0, len(report.Checks))
		for _, c := range report.Checks {
			checks = append(checks, map[string]string{
				"name": c.Name, "status": string(c.Status), "detail": c.Detail,
			})
		}
		if err := a.Out.Emit(map[string]any{
			"id": rec.ID, "ok": report.OK(), "hostname": host, "checks": checks,
		}); err != nil {
			return err
		}
	} else {
		a.Out.Printf("#%d %s\n\n", rec.ID, rec.CommonName)
		// 패딩을 표시 폭으로 계산한다. %-16s 는 바이트를 세므로 한글 항목명에서 어긋난다.
		markWidth, nameWidth := 0, 0
		for _, c := range report.Checks {
			if w := displayWidth(statusMark(c.Status)); w > markWidth {
				markWidth = w
			}
			if w := displayWidth(c.Name); w > nameWidth {
				nameWidth = w
			}
		}
		for _, c := range report.Checks {
			a.Out.Printf("  %s %s  %s\n",
				padRight(statusMark(c.Status), markWidth),
				padRight(c.Name, nameWidth), c.Detail)
		}
		counts := report.Counts()
		a.Out.Printf("\n통과 %d / 경고 %d / 건너뜀 %d / 실패 %d\n",
			counts[verify.StatusPass], counts[verify.StatusWarn],
			counts[verify.StatusSkip], counts[verify.StatusFail])
	}
	if !report.OK() {
		return certerr.Verificationf("검증에 실패한 항목이 %d개 있습니다", len(report.Failures()))
	}
	return nil
}

func statusMark(s verify.Status) string {
	switch s {
	case verify.StatusPass:
		return "[통과]"
	case verify.StatusFail:
		return "[실패]"
	case verify.StatusWarn:
		return "[경고]"
	default:
		return "[건너뜀]"
	}
}

func (a *App) certBundle(args []string) error {
	fs := flags("cert bundle")
	outDir := fs.String("o", ".", "출력 디렉터리")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return certerr.Validationf("대상을 하나 지정하세요")
	}
	if err := a.open(false); err != nil {
		return err
	}
	rec, err := a.store.ResolveCert(rest[0])
	if err != nil {
		return err
	}
	path := filepath.Join(a.cfg.DataDir, rec.BundlePath)
	// 꺼내기 전에 무결성을 확인한다. 변조된 번들을 서버에 올리면 원인을 찾기 어렵다.
	if rec.BundleSHA256 != "" {
		if err := bundle.VerifyDigest(path, rec.BundleSHA256); err != nil {
			return err
		}
	}
	written, err := bundle.ExtractTo(path, *outDir)
	if err != nil {
		return err
	}
	if err := a.Out.Emit(map[string]any{"id": rec.ID, "files": written}); err != nil {
		return err
	}
	for _, p := range written {
		a.Out.Line("%s", p)
	}
	a.Out.Printf("\n%s 의 USAGE.txt 에 적용 방법이 있습니다.\n", *outDir)
	return nil
}
