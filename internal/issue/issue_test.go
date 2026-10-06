package issue

import (
	"crypto/x509"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

const caPass = "test-ca-passphrase"

func setup(t *testing.T) (config.Config, *store.Store, ca.Material) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	// 테스트가 RSA-4096 생성에 시간을 쓰지 않도록 leaf 기본을 EC 로 둔다.
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
		Subject:    names.Subject{CommonName: "hd Root CA", Organization: "HD", Country: "KR"},
		Passphrase: caPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ca.LoadMaterial(cfg, s, rec, caPass)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, s, material
}

func issueOne(t *testing.T, cfg config.Config, s *store.Store, m ca.Material, cn string, sans ...string) Result {
	t.Helper()
	res, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: cn, Organization: "HD"},
		SANValues: sans, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestIssueProducesVerifiableChain(t *testing.T) {
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local", "ip:10.0.0.5")

	// 가장 강한 증명: 발급한 인증서가 우리 Root 로 실제 검증되고 호스트명이 맞는다.
	pool := x509.NewCertPool()
	pool.AddCert(m.Root())
	if _, err := res.Cert.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: "web.hd.local",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("발급한 인증서가 Root 로 검증되지 않는다: %v", err)
	}
	if res.Cert.IsCA {
		t.Error("leaf 에 CA:TRUE 가 붙었다")
	}
	// CN 이 SAN 에 자동 포함되어야 한다. CN-only 는 현대 클라이언트가 거부한다.
	if len(res.Cert.DNSNames) == 0 || res.Cert.DNSNames[0] != "web.hd.local" {
		t.Errorf("CN 이 SAN 에 없다: %v", res.Cert.DNSNames)
	}
	if len(res.Cert.IPAddresses) != 1 || res.Cert.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IP SAN 이 다르다: %v", res.Cert.IPAddresses)
	}
	// not_before 백데이트: 클라이언트 시계가 조금 빠르면 방금 발급한 인증서가 거부된다.
	if !res.Cert.NotBefore.Before(time.Now().Add(-time.Minute)) {
		t.Errorf("not_before 가 백데이트되지 않았다: %s", res.Cert.NotBefore)
	}
}

func TestIssueWritesBundleWithMatchingDigest(t *testing.T) {
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local")

	if !fsops.IsFile(res.BundlePath) {
		t.Fatalf("번들이 없다: %s", res.BundlePath)
	}
	// DB 가 기록한 지문과 실제 파일이 일치해야 한다. 어긋나면 백업 검증이 거짓 양성을 낸다.
	if err := bundle.VerifyDigest(res.BundlePath, res.Record.BundleSHA256); err != nil {
		t.Errorf("번들 지문 불일치: %v", err)
	}
	if res.Record.BundlePath == "" {
		t.Error("DB 에 번들 경로가 기록되지 않았다")
	}
	// 기록된 경로는 data_dir 기준 상대경로여야 한다(백업·이전 시 절대경로는 깨진다).
	if filepath.IsAbs(res.Record.BundlePath) {
		t.Errorf("번들 경로가 절대경로다: %s", res.Record.BundlePath)
	}
	if filepath.Join(cfg.DataDir, res.Record.BundlePath) != res.BundlePath {
		t.Error("상대경로가 실제 경로와 맞지 않는다")
	}
	if !res.Record.HasPrivateKey {
		t.Error("키를 생성했는데 has_private_key=0")
	}

	members, err := bundle.Members(res.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := members[bundle.MemberKey]; !ok {
		t.Error("번들에 개인키가 없다")
	}
	// 서버에 올릴 키는 패스프레이즈가 없어야 한다. 있으면 nginx 가 부팅 때마다 묻는다.
	if strings.Contains(string(members[bundle.MemberKey]), "ENCRYPTED") {
		t.Error("leaf 개인키가 암호화되어 있다 — 무인 재시작이 깨진다")
	}
	// Root 가 직접 발급했으면 chain.pem 은 없고 ca.crt 로 제공한다.
	if _, ok := members[bundle.MemberChain]; ok {
		t.Error("Root 직접 발급인데 chain.pem 이 생겼다")
	}
	if _, ok := members[bundle.MemberCA]; !ok {
		t.Error("ca.crt 가 없다 — 클라이언트가 신뢰 등록할 것이 없다")
	}
}

func TestIssueRecordsSerialAndSeq(t *testing.T) {
	cfg, s, m := setup(t)
	first := issueOne(t, cfg, s, m, "a.hd.local")
	second := issueOne(t, cfg, s, m, "b.hd.local")

	if first.Record.Seq != 1 || second.Record.Seq != 2 {
		t.Errorf("순번이 1,2 가 아니다: %d, %d", first.Record.Seq, second.Record.Seq)
	}
	if first.Record.SerialHex == second.Record.SerialHex {
		t.Error("serial 이 중복됐다")
	}
	if first.Record.Status != "valid" {
		t.Errorf("상태 = %s", first.Record.Status)
	}
	if first.Record.Source != "generated" {
		t.Errorf("source = %s", first.Record.Source)
	}
}

func TestConcurrentIssuanceHasNoDuplicateSerialOrSeq(t *testing.T) {
	// 경합 회귀 테스트. 순번 할당이 BEGIN IMMEDIATE 밖으로 새면 여기서 중복이 난다.
	cfg, s, m := setup(t)
	const n = 8

	var wg sync.WaitGroup
	results := make([]Result, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := Issue(cfg, s, Options{
				Material: m, Subject: names.Subject{CommonName: "node.hd.local"},
				Frontend: "test", Note: "concurrent",
			})
			results[idx], errs[idx] = res, err
		}(i)
	}
	wg.Wait()

	seqs := map[int64]bool{}
	serials := map[string]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("동시 발급 %d 실패: %v", i, err)
		}
		rec := results[i].Record
		if seqs[rec.Seq] {
			t.Errorf("순번 중복: %d", rec.Seq)
		}
		if serials[rec.SerialHex] {
			t.Errorf("serial 중복: %s", rec.SerialHex)
		}
		seqs[rec.Seq] = true
		serials[rec.SerialHex] = true
		// 번들 경로도 겹치면 안 된다(같은 CN 8건).
		if !fsops.IsFile(results[i].BundlePath) {
			t.Errorf("번들이 없다: %s", results[i].BundlePath)
		}
	}
	if len(seqs) != n {
		t.Errorf("고유 순번 수 = %d, 기대 %d", len(seqs), n)
	}
}

func TestBundleWriteFailureRollsBackRow(t *testing.T) {
	// 번들을 못 쓰면 DB 행도 없어야 한다. 남으면 "목록에는 있는데 다운로드가 안 되는" 유령이 된다.
	cfg, s, m := setup(t)

	// bundles 디렉터리를 파일로 만들어 두면 그 아래로 쓸 수 없다.
	blocker := filepath.Join(cfg.DataDir, "bundles")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := s.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "web.hd.local"}, Frontend: "test",
	}); err == nil {
		t.Fatal("번들을 쓸 수 없는데 발급이 성공했다")
	}
	after, err := s.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("보상 삭제가 되지 않았다: %d → %d 건", len(before), len(after))
	}
}

func TestIssueRejectsDaysOverMax(t *testing.T) {
	cfg, s, m := setup(t)
	cfg.Cert.MaxDays = 100
	_, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "web.hd.local"}, Days: 101, Frontend: "test",
	})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("상한 초과가 validation 오류가 아니다: %v", err)
	}
	// 거부했으면 순번만 쓰고 끝나야 한다 — 행이 남으면 안 된다.
	certs, _ := s.ListCerts(store.CertFilter{})
	if len(certs) != 0 {
		t.Errorf("거부했는데 인증서 행이 생겼다: %d건", len(certs))
	}
}

func TestIssueWarnsOverBrowserLimit(t *testing.T) {
	cfg, s, m := setup(t)
	res, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "web.hd.local"}, Days: 800, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 거부가 아니라 경고다. 사설 CA 에 397일은 강제 규칙이 아니다.
	if len(res.Warnings) == 0 {
		t.Error("397일 초과에 경고가 없다")
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "397") {
		t.Errorf("경고 문구에 근거가 없다: %v", res.Warnings)
	}
}

func TestIssueWarnsWhenCAExpiresFirst(t *testing.T) {
	cfg, s, _ := setup(t)
	// CA 를 30일만 유효하게 만든 뒤 397일 leaf 를 발급한다.
	cfg.CA.DefaultDays = 30
	rec, err := ca.CreateRoot(cfg, s, ca.CreateOptions{
		Subject: names.Subject{CommonName: "short Root CA"}, Passphrase: caPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ca.LoadMaterial(cfg, s, rec, caPass)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "web.hd.local"}, Days: 397, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "CA") {
		t.Errorf("CA 선만료 경고가 없다: %v", res.Warnings)
	}
}

func TestIssueRejectsCAProfile(t *testing.T) {
	cfg, s, m := setup(t)
	// leaf 발급으로 CA 를 만들 수 있으면 1단계 제한이 무의미해진다.
	_, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "evil Root"}, Profile: "root-ca", Frontend: "test",
	})
	if err == nil {
		t.Fatal("root-ca 프로필로 leaf 발급이 됐다")
	}
}

func TestIssueRequiresSANWhenCNIsNotHostname(t *testing.T) {
	cfg, s, m := setup(t)
	_, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "Payment Gateway Client"}, Frontend: "test",
	})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("SAN 없는 비호스트명 CN 이 통과했다: %v", err)
	}
}

func TestIssueClientProfileHasNoServerAuth(t *testing.T) {
	cfg, s, m := setup(t)
	res, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "agent.hd.local"},
		Profile: "client", Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, eku := range res.Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Error("client 프로필에 serverAuth 가 들어갔다")
		}
	}
	found := false
	for _, eku := range res.Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("client 프로필에 clientAuth 가 없다")
	}
}

func TestIssueWithExistingKeyLinksKeyID(t *testing.T) {
	cfg, s, m := setup(t)
	// 미리 만든 키를 쓰는 흐름(0번 메뉴). 인증서 행이 그 키를 가리켜야 쌍을 추적할 수 있다.
	// 키 관리 모듈은 아직 포팅 전이므로 그 모듈이 만들 상태를 여기서 직접 구성한다.
	signer, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	publicSHA, err := keys.PublicDigest(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := keys.ToPEM(signer, "")
	if err != nil {
		t.Fatal(err)
	}
	keyRel := filepath.Join("keys", "web-key.key")
	if err := fsops.EnsureDir(filepath.Dir(filepath.Join(cfg.DataDir, keyRel)), fsops.ModeDir); err != nil {
		t.Fatal(err)
	}
	if err := fsops.WriteAtomic(filepath.Join(cfg.DataDir, keyRel), keyPEM, fsops.ModeSecret); err != nil {
		t.Fatal(err)
	}
	var keyID int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		keyID, txErr = s.InsertKey(tx, store.Key{
			Name: "web-key", Algo: "ec-p256", Path: keyRel,
			PublicSHA256: publicSHA, Source: "generated", CreatedAt: store.Now(),
		})
		return txErr
	}); err != nil {
		t.Fatal(err)
	}
	loaded := &ca.LoadedKey{
		Key: signer, Algo: "ec-p256", KeyID: &keyID, Path: keyRel, Origin: "registered",
	}
	res, err := Issue(cfg, s, Options{
		Material: m, Subject: names.Subject{CommonName: "web.hd.local"},
		ExistingKey: loaded, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.KeyID == nil || loaded.KeyID == nil || *res.Record.KeyID != *loaded.KeyID {
		t.Errorf("인증서가 등록된 키를 가리키지 않는다: %v", res.Record.KeyID)
	}
	// 같은 공개키이므로 pair token 이 일치해야 한다.
	certs, err := s.CertsForKey(res.Record.PublicSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("공개키로 찾은 인증서 = %d건", len(certs))
	}
}

func TestRenewKeepsSubjectAndSANsAndSupersedes(t *testing.T) {
	cfg, s, m := setup(t)
	original := issueOne(t, cfg, s, m, "web.hd.local", "dns:www.hd.local", "ip:10.0.0.5")

	renewed, err := Renew(cfg, s, RenewOptions{
		Material: m, Record: original.Record, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Record.SubjectDN != original.Record.SubjectDN {
		t.Errorf("DN 이 바뀌었다:\n이전 %s\n이후 %s", original.Record.SubjectDN, renewed.Record.SubjectDN)
	}
	if len(renewed.Record.SANs) != len(original.Record.SANs) {
		t.Errorf("SAN 개수가 다르다: %d → %d", len(original.Record.SANs), len(renewed.Record.SANs))
	}
	if renewed.Record.SerialHex == original.Record.SerialHex {
		t.Error("갱신인데 serial 이 같다")
	}
	// 기본은 새 키다. 키를 재사용하면 유출 대응으로서의 갱신이 무의미해진다.
	if renewed.Record.PublicSHA256 == original.Record.PublicSHA256 {
		t.Error("갱신 기본값이 키 재사용이다")
	}
	if renewed.Record.RenewedFrom == nil || *renewed.Record.RenewedFrom != original.Record.ID {
		t.Errorf("renewed_from 연결이 없다: %v", renewed.Record.RenewedFrom)
	}
	previous, err := s.GetCert(original.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	// superseded 는 폐기와 구분한다. 폐기로 바꾸면 CRL 에 잘못 올라간다.
	if previous.Status != "superseded" {
		t.Errorf("이전 인증서 상태 = %s, 기대 superseded", previous.Status)
	}
	if previous.RevokedAt != "" {
		t.Error("갱신이 폐기 시각을 남겼다")
	}
}

func TestRenewDoesNotTouchRevokedPrevious(t *testing.T) {
	cfg, s, m := setup(t)
	original := issueOne(t, cfg, s, m, "web.hd.local")
	if err := s.Tx(func(tx *sql.Tx) error {
		return s.SetCertStatus(tx, original.Record.ID, "revoked", store.Now(), "keyCompromise")
	}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.GetCert(original.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Renew(cfg, s, RenewOptions{Material: m, Record: reloaded, Frontend: "test"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetCert(original.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 폐기된 건을 superseded 로 덮으면 CRL 에서 빠져 사고가 된다.
	if after.Status != "revoked" {
		t.Errorf("폐기 상태가 %s 로 바뀌었다", after.Status)
	}
	if after.RevokeReason != "keyCompromise" {
		t.Errorf("폐기 사유가 유실됐다: %q", after.RevokeReason)
	}
}

func TestIssueWritesAudit(t *testing.T) {
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local")

	entries, err := s.RecentAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "cert.issue" && e.Target == "web.hd.local" {
			found = true
			if !e.OK {
				t.Error("성공한 발급이 ok=0 으로 남았다")
			}
		}
	}
	if !found {
		t.Error("감사 로그에 cert.issue 가 없다")
	}
	// 감사 로그에 비밀이 새지 않아야 한다.
	for _, e := range entries {
		if strings.Contains(e.Detail, caPass) {
			t.Error("감사 로그에 패스프레이즈가 들어갔다")
		}
	}
	_ = res
}
