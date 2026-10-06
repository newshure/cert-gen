package crl

import (
	"crypto/x509"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

const caPass = "test-ca-passphrase"

type env struct {
	cfg      config.Config
	store    *store.Store
	material ca.Material
}

func setup(t *testing.T) env {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Cert.DefaultKeyAlgo = "ec-p256"
	cfg.CA.DefaultKeyAlgo = "ec-p256"
	if err := fsops.EnsureDir(cfg.DataDir, fsops.ModeDir); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(cfg.DBPath(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	rec, err := ca.CreateRoot(cfg, s, ca.CreateOptions{
		Subject: names.Subject{CommonName: "hd Root CA", Organization: "HD"}, Passphrase: caPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(cfg, s, rec, caPass)
	if err != nil {
		t.Fatal(err)
	}
	return env{cfg: cfg, store: s, material: material}
}

func (e env) issue(t *testing.T, cn string) issue.Result {
	t.Helper()
	res, err := issue.Issue(e.cfg, e.store, issue.Options{
		Material: e.material, Subject: names.Subject{CommonName: cn}, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestReasonLookup(t *testing.T) {
	// 빈 이름은 unspecified 다. 사유를 안 적었다고 폐기를 막으면 급할 때 손이 묶인다.
	r, err := ReasonFor("")
	if err != nil || r.Name != "unspecified" || r.Code != 0 {
		t.Errorf("빈 사유 = %+v, %v", r, err)
	}
	r, err = ReasonFor("keyCompromise")
	if err != nil || r.Code != 1 {
		t.Errorf("keyCompromise = %+v, %v", r, err)
	}
	if _, err := ReasonFor("nonsense"); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("없는 사유가 통과했다: %v", err)
	}
	// certificateHold(6)는 의도적으로 빼 두었다 — 해제 경로를 만들지 않았으므로
	// 넣으면 되돌릴 수 없는 보류가 된다.
	for _, r := range Reasons {
		if r.Code == 6 {
			t.Error("certificateHold 가 들어 있다 — 해제 경로가 없으면 넣어서는 안 된다")
		}
		if r.Code == 7 || r.Code == 8 {
			t.Errorf("미사용/델타 전용 reasonCode 가 들어 있다: %d", r.Code)
		}
	}
}

func TestGenerateEmptyCRLIsValid(t *testing.T) {
	// 빈 CRL 은 "폐기된 것이 없다" 는 유효한 진술이다. 파일이 없는 것과는 다르다
	// (없으면 검증하는 쪽이 보통 실패시킨다).
	e := setup(t)
	g, err := Generate(e.cfg, e.store, e.material, "test")
	if err != nil {
		t.Fatal(err)
	}
	if g.Count != 0 {
		t.Errorf("폐기 수 = %d", g.Count)
	}
	if !fsops.IsFile(g.Path) {
		t.Fatalf("CRL 파일이 없다: %s", g.Path)
	}
	list, err := x509.ParseRevocationList(g.DER)
	if err != nil {
		t.Fatalf("CRL 파싱 실패: %v", err)
	}
	if err := list.CheckSignatureFrom(e.material.Cert); err != nil {
		t.Errorf("CRL 서명이 CA 와 맞지 않는다: %v", err)
	}
	if len(list.RevokedCertificateEntries) != 0 {
		t.Error("빈 CRL 에 항목이 있다")
	}
	if !list.NextUpdate.After(time.Now()) {
		t.Errorf("nextUpdate 가 과거다: %s", list.NextUpdate)
	}
	// CRL 은 공개 정보다. 검증하는 쪽이 읽어야 한다.
	info, err := os.Stat(g.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("CRL 권한 = %o, 기대 644", perm)
	}
}

func TestRevokePutsCertInCRL(t *testing.T) {
	e := setup(t)
	res := e.issue(t, "web.hd.local")

	out, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test")
	if err != nil {
		t.Fatal(err)
	}
	if out.Record.Status != "revoked" {
		t.Errorf("상태 = %s", out.Record.Status)
	}
	if out.Record.RevokeReason != "keyCompromise" {
		t.Errorf("사유 = %q", out.Record.RevokeReason)
	}
	if out.Record.RevokedAt == "" {
		t.Error("폐기 시각이 없다")
	}
	// 폐기와 동시에 CRL 이 다시 만들어져야 한다. 여기서 멈추면 폐기가 아무 효력이 없다.
	if out.CRL.Count != 1 {
		t.Fatalf("CRL 항목 수 = %d", out.CRL.Count)
	}
	list, err := x509.ParseRevocationList(out.CRL.DER)
	if err != nil {
		t.Fatal(err)
	}
	entry := list.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(res.Cert.SerialNumber) != 0 {
		t.Error("CRL 의 serial 이 폐기한 인증서와 다르다")
	}
	if entry.ReasonCode != 1 {
		t.Errorf("reasonCode = %d, 기대 1(keyCompromise)", entry.ReasonCode)
	}

	revoked, err := IsRevoked(list, e.material.Cert, res.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("폐기한 인증서가 CRL 조회에서 잡히지 않는다")
	}
}

func TestUnspecifiedReasonOmitsReasonCode(t *testing.T) {
	// RFC 5280 §5.3.1: 기본값(unspecified)은 생략한다. 넣으면 일부 검증기가 경고한다.
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	out, err := Revoke(e.cfg, e.store, e.material, res.Record, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(out.CRL.DER)
	if err != nil {
		t.Fatal(err)
	}
	if list.RevokedCertificateEntries[0].ReasonCode != 0 {
		t.Errorf("unspecified 에 reasonCode 가 들어갔다: %d",
			list.RevokedCertificateEntries[0].ReasonCode)
	}
}

func TestDoubleRevokeIsConflict(t *testing.T) {
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	out, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test")
	if err != nil {
		t.Fatal(err)
	}
	// 두 번째는 거부. 통과시키면 폐기 시각과 사유가 조용히 덮어써진다.
	_, err = Revoke(e.cfg, e.store, e.material, out.Record, "superseded", "test")
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Fatalf("중복 폐기가 conflict 가 아니다: %v", err)
	}
	reloaded, err := e.store.GetCert(res.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RevokeReason != "keyCompromise" {
		t.Errorf("원래 사유가 덮어써졌다: %q", reloaded.RevokeReason)
	}
}

func TestRevokeSupersededIsAllowed(t *testing.T) {
	// 갱신으로 대체된 인증서도 키가 유출되면 폐기해야 한다.
	e := setup(t)
	original := e.issue(t, "web.hd.local")
	if _, err := issue.Renew(e.cfg, e.store, issue.RenewOptions{
		Material: e.material, Record: original.Record, Frontend: "test",
	}); err != nil {
		t.Fatal(err)
	}
	superseded, err := e.store.GetCert(original.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if superseded.Status != "superseded" {
		t.Fatalf("전제 조건 실패: 상태 = %s", superseded.Status)
	}
	out, err := Revoke(e.cfg, e.store, e.material, superseded, "keyCompromise", "test")
	if err != nil {
		t.Fatalf("superseded 인증서를 폐기할 수 없다: %v", err)
	}
	if out.CRL.Count != 1 {
		t.Errorf("CRL 항목 수 = %d", out.CRL.Count)
	}
}

func TestRevokeRejectsWrongCA(t *testing.T) {
	// 다른 CA 의 키로는 폐기를 증명할 수 없다 — CRL 서명이 맞지 않는다.
	// **같은 store 안에** CA 둘을 만들어야 하는 테스트다. 별도 DB 를 쓰면 CA id 가 둘 다
	// 1 이 되어 가드가 우연히 통과하고, 테스트가 엉뚱한 이유로 성공한다.
	e := setup(t)
	res := e.issue(t, "web.hd.local")

	secondRec, err := ca.CreateRoot(e.cfg, e.store, ca.CreateOptions{
		Subject: names.Subject{CommonName: "other Root CA"}, Passphrase: caPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondRec.ID == e.material.Record.ID {
		t.Fatal("전제 조건 실패: 두 CA 의 id 가 같다")
	}
	second, err := ca.LoadMaterial(e.cfg, e.store, secondRec, caPass)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Revoke(e.cfg, e.store, second, res.Record, "keyCompromise", "test")
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("다른 CA 로 폐기가 됐다: %v", err)
	}
	// 거부했으면 상태가 그대로여야 한다.
	reloaded, err := e.store.GetCert(res.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != "valid" {
		t.Errorf("거부했는데 상태가 %s 로 바뀌었다", reloaded.Status)
	}
}

func TestSetCertStatusOnMissingIDFails(t *testing.T) {
	// 0행 UPDATE 를 성공으로 넘기면 "폐기했다" 고 보고한 뒤 아무것도 폐기되지 않는다.
	e := setup(t)
	err := e.store.Tx(func(tx *sql.Tx) error {
		return e.store.SetCertStatus(tx, 99999, "revoked", store.Now(), "keyCompromise")
	})
	if !certerr.IsKind(err, certerr.KindNotFound) {
		t.Fatalf("없는 인증서의 상태 변경이 성공했다: %v", err)
	}
}

func TestCRLNumberIsMonotonic(t *testing.T) {
	// 검증하는 쪽이 이 번호로 더 새로운 CRL 을 판별한다. 되돌아가면 옛 CRL 이 채택된다.
	e := setup(t)
	var last int64
	for i := 0; i < 3; i++ {
		g, err := Generate(e.cfg, e.store, e.material, "test")
		if err != nil {
			t.Fatal(err)
		}
		if g.Number <= last {
			t.Fatalf("CRL 번호가 증가하지 않았다: %d → %d", last, g.Number)
		}
		list, err := x509.ParseRevocationList(g.DER)
		if err != nil {
			t.Fatal(err)
		}
		if list.Number.Int64() != g.Number {
			t.Errorf("DER 안 번호(%d)와 기록(%d)이 다르다", list.Number.Int64(), g.Number)
		}
		last = g.Number
	}
}

func TestGenerateOverwritesPreviousFile(t *testing.T) {
	// CRL 은 매번 다시 만든다. 덮어쓰지 못하면 첫 CRL 이 영원히 남아 폐기가 반영되지 않는다.
	e := setup(t)
	first, err := Generate(e.cfg, e.store, e.material, "test")
	if err != nil {
		t.Fatal(err)
	}
	res := e.issue(t, "web.hd.local")
	if _, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Errorf("디스크의 CRL 에 폐기가 반영되지 않았다: %d건",
			len(list.RevokedCertificateEntries))
	}
}

func TestLoadReadsWhatWeWrote(t *testing.T) {
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	if _, err := Revoke(e.cfg, e.store, e.material, res.Record, "superseded", "test"); err != nil {
		t.Fatal(err)
	}
	list, err := Load(e.cfg, e.material.Record)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Errorf("항목 수 = %d", len(list.RevokedCertificateEntries))
	}
	revoked, err := IsRevoked(list, e.material.Cert, res.Cert)
	if err != nil || !revoked {
		t.Errorf("폐기 조회 = %v, %v", revoked, err)
	}
}

func TestLoadMissingIsNotFound(t *testing.T) {
	e := setup(t)
	_, err := Load(e.cfg, e.material.Record)
	if !certerr.IsKind(err, certerr.KindNotFound) {
		t.Fatalf("없는 CRL 이 notfound 가 아니다: %v", err)
	}
	// 무엇을 하면 되는지 알려 줘야 한다.
	if !strings.Contains(err.Error(), "generate") {
		t.Errorf("해결 방법 안내가 없다: %v", err)
	}
}

func TestIsRevokedRejectsForeignCRL(t *testing.T) {
	// 서명을 확인하지 않으면 누구나 빈 CRL 을 놓아 폐기를 무효화할 수 있다.
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	if _, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test"); err != nil {
		t.Fatal(err)
	}
	list, err := Load(e.cfg, e.material.Record)
	if err != nil {
		t.Fatal(err)
	}
	other := setup(t)
	if _, err := IsRevoked(list, other.material.Cert, res.Cert); !certerr.IsKind(err, certerr.KindVerification) {
		t.Fatalf("남의 CA 로 CRL 서명 확인이 통과했다: %v", err)
	}
}

func TestNonExistentCertNotInCRL(t *testing.T) {
	e := setup(t)
	revokedCert := e.issue(t, "a.hd.local")
	other := e.issue(t, "b.hd.local")
	out, err := Revoke(e.cfg, e.store, e.material, revokedCert.Record, "keyCompromise", "test")
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(out.CRL.DER)
	if err != nil {
		t.Fatal(err)
	}
	// 폐기하지 않은 인증서가 CRL 에 잡히면 멀쩡한 서비스가 죽는다.
	revoked, err := IsRevoked(list, e.material.Cert, other.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("폐기하지 않은 인증서가 CRL 에 있다")
	}
}

func TestOpenSSLReadsOurCRL(t *testing.T) {
	// 교차 검증. nginx 의 ssl_crl 등이 이 파일을 먹어야 하므로 외부 도구가 읽어야 한다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	out, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test")
	if err != nil {
		t.Fatal(err)
	}

	text, err := exec.Command(openssl, "crl", "-in", out.CRL.Path, "-inform", "DER",
		"-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl 이 CRL 을 읽지 못했다: %v\n%s", err, text)
	}
	body := string(text)
	if !strings.Contains(body, "Key Compromise") {
		t.Errorf("openssl 출력에 폐기 사유가 없다:\n%s", body)
	}
	if !strings.Contains(strings.ToUpper(body), strings.ToUpper(certbuild.ShortSerial(res.Record.SerialHex))) {
		t.Errorf("openssl 출력에 폐기한 serial 이 없다:\n%s", body)
	}

	// CA 로 CRL 서명을 확인한다 — openssl 의 눈으로 본 교차 검증.
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, certbuild.CertPEM(e.material.Cert), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := exec.Command(openssl, "crl", "-in", out.CRL.Path, "-inform", "DER",
		"-CAfile", caPath, "-noout").CombinedOutput(); err != nil {
		t.Fatalf("openssl 이 CRL 서명을 확인하지 못했다: %v\n%s", err, res)
	}
}

func TestOpenSSLVerifyRejectsRevokedCert(t *testing.T) {
	// 가장 강한 증명: 폐기한 인증서가 openssl verify -crl_check 에서 **실패해야** 한다.
	// 여기까지 확인하지 않으면 "폐기했다" 는 우리 기록일 뿐이다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	e := setup(t)
	target := e.issue(t, "revoked.hd.local")
	survivor := e.issue(t, "alive.hd.local")
	out, err := Revoke(e.cfg, e.store, e.material, target.Record, "keyCompromise", "test")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	crlPEM := filepath.Join(dir, "crl.pem")
	// openssl verify 는 CAfile 에 CA 와 CRL 을 PEM 으로 함께 넣는 형태를 받는다.
	combined := append(certbuild.CertPEM(e.material.Cert), out.CRL.PEM...)
	if err := os.WriteFile(caPath, combined, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crlPEM, out.CRL.PEM, 0o644); err != nil {
		t.Fatal(err)
	}

	revokedPath := filepath.Join(dir, "revoked.crt")
	if err := os.WriteFile(revokedPath, certbuild.CertPEM(target.Cert), 0o644); err != nil {
		t.Fatal(err)
	}
	alivePath := filepath.Join(dir, "alive.crt")
	if err := os.WriteFile(alivePath, certbuild.CertPEM(survivor.Cert), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := exec.Command(openssl, "verify", "-crl_check", "-CAfile", caPath, revokedPath).CombinedOutput()
	if err == nil {
		t.Errorf("폐기한 인증서가 -crl_check 를 통과했다:\n%s", res)
	}
	if !strings.Contains(string(res), "revoked") {
		t.Errorf("실패 사유가 폐기가 아니다:\n%s", res)
	}

	// 음성 통제: 폐기하지 않은 인증서는 같은 CRL 로도 통과해야 한다.
	// 통과하지 않으면 위 실패가 CRL 때문인지 다른 이유인지 알 수 없다.
	if res, err := exec.Command(openssl, "verify", "-crl_check",
		"-CAfile", caPath, alivePath).CombinedOutput(); err != nil {
		t.Errorf("폐기하지 않은 인증서가 -crl_check 에서 실패했다: %v\n%s", err, res)
	}
}

func TestGenerateRejectsNonCRLSignCA(t *testing.T) {
	// cRLSign 없는 CA 로 만든 CRL 은 검증하는 쪽이 거부한다. 만들어 주면 안 된다.
	e := setup(t)
	stripped := e.material
	modified := *e.material.Cert
	modified.KeyUsage = x509.KeyUsageCertSign // cRLSign 제거
	stripped.Cert = &modified
	if _, err := Generate(e.cfg, e.store, stripped, "test"); !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("cRLSign 없는 CA 로 CRL 이 만들어졌다: %v", err)
	}
}

func TestRevokeWritesAudit(t *testing.T) {
	e := setup(t)
	res := e.issue(t, "web.hd.local")
	if _, err := Revoke(e.cfg, e.store, e.material, res.Record, "keyCompromise", "test"); err != nil {
		t.Fatal(err)
	}
	entries, err := e.store.RecentAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	var sawRevoke, sawCRL bool
	for _, entry := range entries {
		switch entry.Action {
		case "cert.revoke":
			sawRevoke = true
			if !strings.Contains(entry.Detail, "keyCompromise") {
				t.Errorf("감사 로그에 사유가 없다: %s", entry.Detail)
			}
		case "crl.generate":
			sawCRL = true
		}
	}
	if !sawRevoke {
		t.Error("감사 로그에 cert.revoke 가 없다")
	}
	if !sawCRL {
		t.Error("감사 로그에 crl.generate 가 없다")
	}
}

func TestDescribe(t *testing.T) {
	e := setup(t)
	g, err := Generate(e.cfg, e.store, e.material, "test")
	if err != nil {
		t.Fatal(err)
	}
	text := Describe(g)
	if !strings.Contains(text, "CRL #1") {
		t.Errorf("요약에 번호가 없다: %s", text)
	}
}
