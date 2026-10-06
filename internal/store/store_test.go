package store

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/names"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cert-gen.sqlite3"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleCA(overrides func(*CA)) CA {
	c := CA{
		Slug: "root", CommonName: "Root CA", SubjectDN: "CN=Root CA", KeyAlgo: "ec-p384",
		KeyEncrypted: true, KeyPath: "ca/root/ca.key", CertPath: "ca/root/ca.crt",
		SerialHex: "0abc", Fingerprint: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		NotBefore: Now(), NotAfter: Now(),
	}
	if overrides != nil {
		overrides(&c)
	}
	return c
}

func insertCA(t *testing.T, s *Store, c CA) int64 {
	t.Helper()
	var id int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var err error
		id, err = s.InsertCA(tx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOpenWithoutInitIsRejected(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing.sqlite3"), false)
	if err == nil || !certerr.IsKind(err, certerr.KindState) {
		t.Fatalf("초기화 안 된 DB 가 통과했다: %v", err)
	}
}

func TestSchemaVersion(t *testing.T) {
	s := openTemp(t)
	v, err := s.SchemaVersionOf()
	if err != nil || v != SchemaVersion {
		t.Fatalf("버전 = %d, %v", v, err)
	}
}

func TestFutureSchemaIsRefused(t *testing.T) {
	// 더 새 버전이 만든 DB 를 구 버전이 건드리면 데이터가 깨진다. 거부가 정답이다.
	path := filepath.Join(t.TempDir(), "cert-gen.sqlite3")
	s, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE schema_meta SET value='999' WHERE key='schema_version'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Open(path, false); err == nil {
		t.Fatal("미래 스키마가 통과했다")
	}
}

func TestDuplicateSlugAndFingerprint(t *testing.T) {
	s := openTemp(t)
	insertCA(t, s, sampleCA(nil))

	err := s.Tx(func(tx *sql.Tx) error {
		_, err := s.InsertCA(tx, sampleCA(func(c *CA) {
			c.Fingerprint = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		}))
		return err
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Errorf("slug 중복이 거부되지 않았다: %v", err)
	}

	err = s.Tx(func(tx *sql.Tx) error {
		_, err := s.InsertCA(tx, sampleCA(func(c *CA) { c.Slug = "other" }))
		return err
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Errorf("지문 중복이 거부되지 않았다: %v", err)
	}
}

func TestFindCAByFingerprintEnablesExternalReuse(t *testing.T) {
	// 외부 디렉터리를 두 번 지정해도 CA 행이 두 개가 되면 안 된다.
	s := openTemp(t)
	id := insertCA(t, s, sampleCA(func(c *CA) {
		c.Slug = "ext"
		c.IsExternal = true
		c.SourceDir = "/srv/pki"
	}))
	found, ok := s.FindCAByFingerprint(sampleCA(nil).Fingerprint)
	if !ok || found.ID != id || !found.IsExternal || found.SourceDir != "/srv/pki" {
		t.Fatalf("외부 CA 재사용 조회 실패: %+v ok=%v", found, ok)
	}
}

func TestAllocateSeqHasNoDuplicatesUnderConcurrency(t *testing.T) {
	// CLI 가 동시에 여러 번 실행될 수 있다. 순번이 겹치면 이력이 망가진다.
	s := openTemp(t)
	caID := insertCA(t, s, sampleCA(nil))

	const workers, each = 5, 20
	var (
		mu        sync.Mutex
		collected []int64
		wg        sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				var seq int64
				if err := s.Tx(func(tx *sql.Tx) error {
					var err error
					seq, err = s.AllocateSeq(tx, caID)
					return err
				}); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				collected = append(collected, seq)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(collected) != workers*each {
		t.Fatalf("개수 = %d", len(collected))
	}
	seen := map[int64]bool{}
	for _, v := range collected {
		if seen[v] {
			t.Fatalf("순번 중복: %d", v)
		}
		seen[v] = true
	}
	for i := int64(1); i <= workers*each; i++ {
		if !seen[i] {
			t.Fatalf("순번 %d 가 빠졌다", i)
		}
	}
}

func sampleCert(caID int64, serial string, overrides func(*Cert)) Cert {
	c := Cert{
		CAID: caID, Seq: 1, SerialHex: serial, CommonName: "web.example.com",
		SubjectDN: "CN=web.example.com",
		SANs:      []names.SAN{{Type: names.TypeDNS, Value: "web.example.com"}},
		Profile:   "server", KeyAlgo: "rsa2048", NotBefore: Now(),
		NotAfter: "2030-01-01T00:00:00Z", Fingerprint: "aaaa", BundlePath: "b.zip",
		BundleSHA256: "bbbb", HasPrivateKey: true, Source: "generated", Status: "valid",
	}
	if overrides != nil {
		overrides(&c)
	}
	return c
}

func insertCert(t *testing.T, s *Store, c Cert) int64 {
	t.Helper()
	var id int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var err error
		id, err = s.InsertCert(tx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSerialUniquenessIsTheLastDefence(t *testing.T) {
	s := openTemp(t)
	caID := insertCA(t, s, sampleCA(nil))
	insertCert(t, s, sampleCert(caID, "deadbeef", nil))

	err := s.Tx(func(tx *sql.Tx) error {
		_, err := s.InsertCert(tx, sampleCert(caID, "deadbeef", func(c *Cert) { c.Seq = 2 }))
		return err
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Errorf("serial 중복이 거부되지 않았다: %v", err)
	}
}

func TestResolveCertByIDSerialAndCN(t *testing.T) {
	s := openTemp(t)
	caID := insertCA(t, s, sampleCA(nil))
	id := insertCert(t, s, sampleCert(caID, "0a1b2c3d", nil))

	for _, ref := range []string{"1", "0a1b2c3d", "0A1B2C3D", "0a:1b:2c:3d", "web.example.com"} {
		c, err := s.ResolveCert(ref)
		if err != nil || c.ID != id {
			t.Errorf("ResolveCert(%q) 실패: %v", ref, err)
		}
	}
	if _, err := s.ResolveCert("nothing"); !certerr.IsKind(err, certerr.KindNotFound) {
		t.Error("없는 참조가 통과했다")
	}
}

func TestListFilters(t *testing.T) {
	s := openTemp(t)
	caID := insertCA(t, s, sampleCA(nil))
	insertCert(t, s, sampleCert(caID, "aa01", nil))
	insertCert(t, s, sampleCert(caID, "aa02", func(c *Cert) {
		c.Seq = 2
		c.CommonName = "api.example.com"
		c.SANs = []names.SAN{{Type: names.TypeIP, Value: "10.0.0.5"}}
		c.NotAfter = "2026-01-01T00:00:00Z"
		c.Status = "revoked"
		c.PublicSHA256 = "pub-a"
	}))

	check := func(label string, f CertFilter, want int) {
		got, err := s.ListCerts(f)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if len(got) != want {
			t.Errorf("%s = %d건, 기대 %d건", label, len(got), want)
		}
	}
	check("ca", CertFilter{CAID: &caID}, 2)
	check("status", CertFilter{Status: "revoked"}, 1)
	check("search cn", CertFilter{Search: "api"}, 1)
	// SAN 도 검색 대상이다(IP 로만 아는 서비스를 찾아야 한다).
	check("search san", CertFilter{Search: "10.0.0.5"}, 1)
	check("public", CertFilter{PublicSHA: "pub-a"}, 1)

	revoked, err := s.RevokedForCA(caID)
	if err != nil || len(revoked) != 1 {
		t.Errorf("폐기 목록 = %d, %v", len(revoked), err)
	}
}

func TestKeyCRUDAndUsage(t *testing.T) {
	s := openTemp(t)
	var keyID int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var err error
		keyID, err = s.InsertKey(tx, Key{
			Name: "web-key", Algo: "rsa2048", Path: "keys/web-key.key",
			PublicSHA256: "pub-web", Source: "generated",
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// 같은 이름 / 같은 공개키는 거부되어야 한다.
	err := s.Tx(func(tx *sql.Tx) error {
		_, err := s.InsertKey(tx, Key{Name: "web-key", Algo: "rsa2048", Path: "x",
			PublicSHA256: "pub-other", Source: "generated"})
		return err
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Error("이름 중복이 거부되지 않았다")
	}
	err = s.Tx(func(tx *sql.Tx) error {
		_, err := s.InsertKey(tx, Key{Name: "other", Algo: "rsa2048", Path: "x",
			PublicSHA256: "pub-web", Source: "generated"})
		return err
	})
	if !certerr.IsKind(err, certerr.KindConflict) {
		t.Error("공개키 중복이 거부되지 않았다")
	}

	caID := insertCA(t, s, sampleCA(func(c *CA) { c.KeyID = &keyID }))
	insertCert(t, s, sampleCert(caID, "cc01", func(c *Cert) { c.KeyID = &keyID }))

	cas, certs, err := s.KeyUsage(keyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 || len(certs) != 1 {
		t.Errorf("사용처 = CA %v, 인증서 %v", cas, certs)
	}
}

func TestAuditRoundtrip(t *testing.T) {
	s := openTemp(t)
	if err := s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, "cli", "tester", "cert.issue", "web.example.com", true,
			map[string]any{"days": 397})
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.RecentAudit(5)
	if err != nil || len(entries) != 1 {
		t.Fatalf("감사 로그 = %d, %v", len(entries), err)
	}
	if entries[0].Action != "cert.issue" || !entries[0].OK {
		t.Errorf("감사 내용이 다르다: %+v", entries[0])
	}
}
