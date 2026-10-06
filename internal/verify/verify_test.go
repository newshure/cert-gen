package verify

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keys"
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

func (e env) issueInput(t *testing.T, cn, profile string, days int, sans ...string) (export.Input, store.Cert) {
	t.Helper()
	res, err := issue.Issue(e.cfg, e.store, issue.Options{
		Material: e.material, Subject: names.Subject{CommonName: cn},
		SANValues: sans, Profile: profile, Days: days, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := export.FromBundle(e.cfg, res.Record, "")
	if err != nil {
		t.Fatal(err)
	}
	return in, res.Record
}

// check 는 보고서에서 항목 하나를 찾는다.
func check(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("보고서에 %q 항목이 없다. 있는 항목: %v", name, checkNames(r))
	return Check{}
}

func checkNames(r Report) []string {
	out := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		out = append(out, c.Name+"="+string(c.Status))
	}
	return out
}

func TestHealthyCertPassesEverything(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397, "ip:10.0.0.5")

	report, err := Run(e.cfg, in, Options{Hostname: "web.hd.local", CrossCheckOpenSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() {
		t.Fatalf("정상 인증서가 실패했다: %v", report.Failures())
	}
	for _, name := range []string{"유효기간", "키-인증서 짝", "체인 검증", "호스트명 매칭",
		"AKI/SKI", "CN in SAN", "basicConstraints", "EKU", "keyUsage", "키 강도"} {
		if c := check(t, report, name); c.Status != StatusPass {
			t.Errorf("%s = %s (%s)", name, c.Status, c.Detail)
		}
	}
	// 교차 검증이 실제로 돌았는지. skip 이면 openssl 이 없는 것이다.
	if c := check(t, report, "openssl 교차 검증"); c.Status == StatusSkip {
		t.Log("openssl 교차 검증 skip: " + c.Detail)
	} else if c.Status != StatusPass {
		t.Errorf("openssl 교차 검증 = %s (%s)", c.Status, c.Detail)
	}
}

func TestWrongHostnameFails(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)

	report, err := Run(e.cfg, in, Options{Hostname: "other.hd.local"})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() {
		t.Fatal("호스트명이 다른데 통과했다")
	}
	c := check(t, report, "호스트명 매칭")
	if c.Status != StatusFail {
		t.Errorf("상태 = %s", c.Status)
	}
	// 무엇과 비교했는지 보여 줘야 사용자가 고칠 수 있다.
	if !strings.Contains(c.Detail, "web.hd.local") {
		t.Errorf("실제 SAN 을 알려 주지 않는다: %s", c.Detail)
	}
}

func TestWildcardHostnameMatching(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "*.hd.local", "server", 397)

	for _, host := range []string{"web.hd.local", "api.hd.local"} {
		report, err := Run(e.cfg, in, Options{Hostname: host})
		if err != nil {
			t.Fatal(err)
		}
		if c := check(t, report, "호스트명 매칭"); c.Status != StatusPass {
			t.Errorf("%s 가 와일드카드에 매칭되지 않았다: %s", host, c.Detail)
		}
	}
	// RFC 6125: 와일드카드는 레이블 하나만 덮는다. 다단 하위는 매칭되지 않아야 한다.
	report, err := Run(e.cfg, in, Options{Hostname: "deep.web.hd.local"})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "호스트명 매칭"); c.Status != StatusFail {
		t.Errorf("와일드카드가 다단 하위를 덮었다: %s", c.Detail)
	}
}

func TestExpiredCertFails(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 1)

	// 발급 후 시간이 지난 상황을 시각으로 만든다.
	future := time.Now().AddDate(0, 0, 10)
	report, err := Run(e.cfg, in, Options{Now: future})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() {
		t.Fatal("만료된 인증서가 통과했다")
	}
	c := check(t, report, "유효기간")
	if c.Status != StatusFail || !strings.Contains(c.Detail, "만료") {
		t.Errorf("유효기간 = %s (%s)", c.Status, c.Detail)
	}
	// 체인 검증도 같은 시각 기준으로 실패해야 한다. 통과하면 시각이 전달되지 않은 것이다.
	if c := check(t, report, "체인 검증"); c.Status != StatusFail {
		t.Errorf("만료 시점에 체인 검증이 통과했다: %s", c.Detail)
	}
}

func TestNotYetValidFails(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	past := time.Now().AddDate(0, 0, -30)
	report, err := Run(e.cfg, in, Options{Now: past})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "유효기간")
	if c.Status != StatusFail || !strings.Contains(c.Detail, "아직") {
		t.Errorf("유효기간 = %s (%s)", c.Status, c.Detail)
	}
}

func TestNearExpiryWarns(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	// 만료 20일 전. 갱신을 준비할 시간을 알려 줘야 한다.
	soon := in.Cert.NotAfter.AddDate(0, 0, -20)
	report, err := Run(e.cfg, in, Options{Now: soon})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "유효기간")
	if c.Status != StatusWarn {
		t.Errorf("만료 임박이 경고가 아니다: %s (%s)", c.Status, c.Detail)
	}
	// 경고는 실패가 아니다.
	if !report.OK() {
		t.Errorf("경고가 실패로 집계됐다: %v", report.Failures())
	}
}

func TestMismatchedKeyFails(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	other, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	in.Key = other

	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "키-인증서 짝")
	if c.Status != StatusFail {
		t.Errorf("짝이 아닌 키가 통과했다: %s", c.Detail)
	}
}

func TestMissingKeyIsSkipNotPass(t *testing.T) {
	// 확인하지 못한 것을 통과로 보여 주면 사용자가 검증됐다고 믿는다.
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	in.Key = nil

	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "키-인증서 짝")
	if c.Status != StatusSkip {
		t.Errorf("개인키 없음 = %s, 기대 skip", c.Status)
	}
	// skip 은 실패가 아니다 — CSR 서명 건은 정상적으로 키가 없다.
	if !report.OK() {
		t.Errorf("skip 이 실패로 집계됐다: %v", report.Failures())
	}
}

func TestWrongCAFailsChain(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	other := setup(t)
	in.CA = other.material.Cert

	report, err := Run(e.cfg, in, Options{CrossCheckOpenSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "체인 검증"); c.Status != StatusFail {
		t.Errorf("다른 CA 로 체인이 섰다: %s", c.Detail)
	}
	if c := check(t, report, "AKI/SKI"); c.Status != StatusFail {
		t.Errorf("AKI 불일치가 잡히지 않았다: %s", c.Detail)
	}
	// 둘 다 거부했으면 교차 검증은 '일치'다 — 엇갈림이 아니다.
	if c := check(t, report, "openssl 교차 검증"); c.Status == StatusFail {
		t.Errorf("둘 다 거부했는데 엇갈림으로 보고됐다: %s", c.Detail)
	}
}

func TestMissingCAIsSkip(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	in.CA = nil

	report, err := Run(e.cfg, in, Options{CrossCheckOpenSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "체인 검증"); c.Status != StatusSkip {
		t.Errorf("CA 없음 = %s, 기대 skip", c.Status)
	}
	if c := check(t, report, "openssl 교차 검증"); c.Status != StatusSkip {
		t.Errorf("CA 없이 교차 검증이 돌았다: %s", c.Detail)
	}
}

func TestClientProfileVerifiesWithoutServerAuth(t *testing.T) {
	// KeyUsages 를 비워 두면 Go 가 ServerAuth 를 요구한다. client 전용 인증서가 그 때문에
	// 실패하면 원인을 오해하게 된다.
	e := setup(t)
	in, _ := e.issueInput(t, "agent.hd.local", "client", 397)

	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "체인 검증"); c.Status != StatusPass {
		t.Errorf("client 인증서의 체인 검증이 실패했다: %s", c.Detail)
	}
	if c := check(t, report, "EKU"); !strings.Contains(c.Detail, "clientAuth") {
		t.Errorf("EKU 요약이 틀렸다: %s", c.Detail)
	}
}

func TestCACertIsWarnedAsNonLeaf(t *testing.T) {
	e := setup(t)
	in := export.Input{Cert: e.material.Cert, CA: e.material.Cert, Label: "hd Root CA"}

	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "basicConstraints")
	if c.Status != StatusWarn || !strings.Contains(c.Detail, "CA:TRUE") {
		t.Errorf("CA 인증서가 leaf 로 취급됐다: %s (%s)", c.Status, c.Detail)
	}
}

func TestRevokedCertFailsWhenCheckingRevocation(t *testing.T) {
	e := setup(t)
	in, record := e.issueInput(t, "web.hd.local", "server", 397)

	// 폐기 전: CRL 이 없으므로 skip 이어야 한다(실패가 아니다 — 아직 만들지 않았을 수 있다).
	report, err := Run(e.cfg, in, Options{
		CheckRevocation: true, CARecord: &e.material.Record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "폐기 확인"); c.Status != StatusSkip {
		t.Errorf("CRL 없음 = %s, 기대 skip (%s)", c.Status, c.Detail)
	}

	if _, err := crl.Revoke(e.cfg, e.store, e.material, record, "keyCompromise", "test"); err != nil {
		t.Fatal(err)
	}

	report, err = Run(e.cfg, in, Options{
		CheckRevocation: true, CARecord: &e.material.Record,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "폐기 확인")
	if c.Status != StatusFail {
		t.Fatalf("폐기된 인증서가 통과했다: %s (%s)", c.Status, c.Detail)
	}
	if report.OK() {
		t.Error("폐기 실패가 전체 결과에 반영되지 않았다")
	}
}

func TestLiveCertPassesRevocationCheck(t *testing.T) {
	// 음성 통제: 폐기하지 않은 인증서는 같은 CRL 로 통과해야 한다. 통과하지 않으면
	// 위 테스트의 실패가 CRL 때문인지 알 수 없다.
	e := setup(t)
	target, targetRec := e.issueInput(t, "revoked.hd.local", "server", 397)
	survivor, _ := e.issueInput(t, "alive.hd.local", "server", 397)
	_ = target

	if _, err := crl.Revoke(e.cfg, e.store, e.material, targetRec, "keyCompromise", "test"); err != nil {
		t.Fatal(err)
	}
	report, err := Run(e.cfg, survivor, Options{
		CheckRevocation: true, CARecord: &e.material.Record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "폐기 확인"); c.Status != StatusPass {
		t.Errorf("폐기하지 않은 인증서가 폐기로 잡혔다: %s (%s)", c.Status, c.Detail)
	}
}

func TestRevocationSkippedWithoutCARecord(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	report, err := Run(e.cfg, in, Options{CheckRevocation: true})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(t, report, "폐기 확인"); c.Status != StatusSkip {
		t.Errorf("CA 레코드 없이 폐기 확인이 돌았다: %s", c.Detail)
	}
}

func TestRevocationNotCheckedByDefault(t *testing.T) {
	// 기본으로 CRL 을 읽으면 CRL 이 없는 환경에서 늘 skip 항목이 떠 보고가 시끄러워진다.
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.Name == "폐기 확인" {
			t.Error("요청하지 않은 폐기 확인이 보고서에 있다")
		}
	}
}

func TestCrossCheckDisabledByDefault(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.Name == "openssl 교차 검증" {
			t.Error("요청하지 않은 교차 검증이 돌았다")
		}
	}
}

func TestCrossCheckUsesConfiguredBinary(t *testing.T) {
	// 설정의 경로를 무시하고 PATH 의 openssl 을 쓰면, 폐쇄망에서 지정한 바이너리가 쓰이지 않는다.
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	e.cfg.Tools.OpenSSL = "definitely-not-a-real-openssl-binary"

	report, err := Run(e.cfg, in, Options{CrossCheckOpenSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, report, "openssl 교차 검증")
	if c.Status != StatusSkip {
		t.Errorf("없는 바이너리인데 %s: %s", c.Status, c.Detail)
	}
	if !strings.Contains(c.Detail, "definitely-not-a-real") {
		t.Errorf("설정한 경로를 쓰지 않았다: %s", c.Detail)
	}
}

func TestRunRejectsNilCert(t *testing.T) {
	e := setup(t)
	if _, err := Run(e.cfg, export.Input{}, Options{}); err == nil {
		t.Error("인증서 없이 통과했다")
	}
}

func TestReportCounts(t *testing.T) {
	e := setup(t)
	in, _ := e.issueInput(t, "web.hd.local", "server", 397)
	in.Key = nil // skip 하나를 만든다
	report, err := Run(e.cfg, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	counts := report.Counts()
	if counts[StatusSkip] < 1 {
		t.Errorf("skip 집계 = %d", counts[StatusSkip])
	}
	if counts[StatusPass] < 1 {
		t.Errorf("pass 집계 = %d", counts[StatusPass])
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != len(report.Checks) {
		t.Errorf("집계 합(%d)이 항목 수(%d)와 다르다", total, len(report.Checks))
	}
}

func TestExternalFilesPathVerifies(t *testing.T) {
	// 외부 파일로 받은 인증서도 같은 검증을 통과해야 한다.
	e := setup(t)
	in, record := e.issueInput(t, "web.hd.local", "server", 397)
	dir := t.TempDir()
	keyPEM, err := keys.ToPEM(in.Key, "")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := fsops.WriteAtomic(path, data, fsops.ModeSecret); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPath := write("cert.pem", certPEMOf(t, in))
	keyPath := write("key.pem", keyPEM)
	caPath := write("ca.crt", certPEMOf2(t, in))

	external, err := export.FromFiles(export.ExternalFiles{
		CertPath: certPath, KeyPath: keyPath, CAPath: caPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(e.cfg, external, Options{Hostname: record.CommonName, CrossCheckOpenSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() {
		t.Errorf("외부 파일 경유 검증이 실패했다: %v", report.Failures())
	}
}

func certPEMOf(t *testing.T, in export.Input) []byte {
	t.Helper()
	return export.CertPEM(in).Data
}

func certPEMOf2(t *testing.T, in export.Input) []byte {
	t.Helper()
	caOnly := export.Input{Cert: in.CA}
	return export.CertPEM(caOnly).Data
}
