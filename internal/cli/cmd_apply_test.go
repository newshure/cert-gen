package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/store"
)

// userFormatFile 은 사용자가 준 tests/src 와 같은 형식이다 — CA 블록 + leaf 블록(--- 구분).
const userFormatFile = `
[ req ]
default_bits            = 4096
distinguished_name      = req_distinguished_name
x509_extensions         = v3_ca
prompt                  = no

[ v3_ca ]
basicConstraints        = critical, CA:TRUE, pathlen:0
keyUsage                = critical, keyCertSign, cRLSign

[ req_distinguished_name ]
countryName             = KR
organizationName        = HaeDong Inc.
commonName              = HaeDong Root CA

---

[ req ]
default_bits            = 2048
distinguished_name      = req_distinguished_name
req_extensions          = v3_req
prompt                  = no

[ v3_req ]
basicConstraints        = CA:FALSE
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth, clientAuth
subjectAltName          = @alt_names

[ alt_names ]
DNS.1   = example.com
DNS.2   = *.example.com
IP.1    = 192.0.2.10

[ req_distinguished_name ]
countryName             = KR
organizationName        = haedong Inc.
commonName              = example.com
`

func applyApp(t *testing.T) (*App, string) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	if err := fsops.EnsureDir(cfg.DataDir, fsops.ModeDir); err != nil {
		t.Fatal(err)
	}
	app := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}, dataFlag: cfg.DataDir}
	// 테스트 편의: 패스프레이즈 없이 CA 를 만든다.
	path := filepath.Join(t.TempDir(), "pki.cnf")
	if err := os.WriteFile(path, []byte(userFormatFile), 0o600); err != nil {
		t.Fatal(err)
	}
	return app, path
}

func TestApplyCreatesCAAndIssuesLeaf(t *testing.T) {
	app, path := applyApp(t)
	if err := app.dispatch([]string{"apply", path, "--no-passphrase"}); err != nil {
		t.Fatalf("apply 실패: %v", err)
	}
	defer app.store.Close()

	cas, err := app.store.ListCAs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 || cas[0].CommonName != "HaeDong Root CA" {
		t.Fatalf("CA = %+v", cas)
	}
	// default_bits 4096 → rsa4096
	if cas[0].KeyAlgo != "rsa4096" {
		t.Errorf("CA 키 = %q, 기대 rsa4096", cas[0].KeyAlgo)
	}
	certs, err := app.store.ListCerts(store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("인증서 수 = %d", len(certs))
	}
	leaf := certs[0]
	if leaf.CommonName != "example.com" || leaf.Profile != "server+client" {
		t.Errorf("leaf = %+v", leaf)
	}
	if leaf.KeyAlgo != "rsa2048" {
		t.Errorf("leaf 키 = %q, 기대 rsa2048", leaf.KeyAlgo)
	}
	// leaf 는 CA 아래에 발급돼야 한다.
	if leaf.CAID != cas[0].ID {
		t.Errorf("leaf 가 다른 CA 에 붙었다: %d", leaf.CAID)
	}
	// SAN: CN 자동 포함 + 와일드카드 + IP
	var sawWild, sawIP bool
	for _, s := range leaf.SANs {
		if s.Value == "*.example.com" {
			sawWild = true
		}
		if s.Value == "192.0.2.10" {
			sawIP = true
		}
	}
	if !sawWild || !sawIP {
		t.Errorf("SAN = %+v", leaf.SANs)
	}
}

func TestApplyIsIdempotentForCA(t *testing.T) {
	// 다시 돌려도 CA 가 중복 생성되지 않아야 한다(선언적 실행).
	app, path := applyApp(t)
	if err := app.dispatch([]string{"apply", path, "--no-passphrase"}); err != nil {
		t.Fatal(err)
	}
	app.store.Close()
	app.store = nil

	app2 := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}, dataFlag: app.dataFlag}
	if err := app2.dispatch([]string{"apply", path, "--no-passphrase"}); err != nil {
		t.Fatal(err)
	}
	defer app2.store.Close()

	cas, err := app2.store.ListCAs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Errorf("CA 가 중복 생성됐다: %d개", len(cas))
	}
	// leaf 는 두 번 발급돼 2건이어야 한다(발급은 멱등이 아니다 — 매번 새 serial).
	certs, _ := app2.store.ListCerts(store.CertFilter{})
	if len(certs) != 2 {
		t.Errorf("인증서 수 = %d, 기대 2", len(certs))
	}
}

func TestApplyDryRunChangesNothing(t *testing.T) {
	app, path := applyApp(t)
	if err := app.dispatch([]string{"apply", path, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if app.store != nil {
		// dry-run 은 DB 를 열 수는 있다. 내용이 비어야 한다.
		cas, _ := app.store.ListCAs("")
		if len(cas) != 0 {
			t.Errorf("dry-run 이 CA 를 만들었다: %d", len(cas))
		}
		app.store.Close()
	}
	out := app.Out.W.(*bytes.Buffer).String()
	if !strings.Contains(out, "CA 생성") || !strings.Contains(out, "example.com") {
		t.Errorf("계획이 표시되지 않았다:\n%s", out)
	}
}

func TestApplyRefusesEmptyArg(t *testing.T) {
	app := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}}
	if err := app.dispatch([]string{"apply"}); err == nil {
		t.Error("파일 없이 통과했다")
	}
}

func TestApplyLeafOnlyNeedsExistingCA(t *testing.T) {
	// CA 블록이 없는 파일은 기존 CA 가 하나면 그 아래로 발급해야 한다.
	app, _ := applyApp(t)
	leafOnly := filepath.Join(t.TempDir(), "leaf.cnf")
	content := `[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = solo.hd.local
[v3]
subjectAltName = DNS:solo.hd.local
extendedKeyUsage = serverAuth
`
	if err := os.WriteFile(leafOnly, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// CA 가 없으면 거부.
	if err := app.dispatch([]string{"apply", leafOnly}); err == nil {
		if app.store != nil {
			app.store.Close()
			app.store = nil
		}
		t.Fatal("CA 없이 leaf 발급이 통과했다")
	}
	if app.store != nil {
		app.store.Close()
		app.store = nil
	}

	// CA 를 하나 만든 뒤면 통과.
	app2 := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}, dataFlag: app.dataFlag}
	if err := app2.dispatch([]string{"ca", "create", "--cn", "HD Root CA", "--no-passphrase"}); err != nil {
		t.Fatal(err)
	}
	app2.store.Close()

	app3 := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}, dataFlag: app.dataFlag}
	if err := app3.dispatch([]string{"apply", leafOnly}); err != nil {
		t.Fatalf("기존 CA 아래 발급 실패: %v", err)
	}
	defer app3.store.Close()
	certs, _ := app3.store.ListCerts(store.CertFilter{})
	if len(certs) != 1 || certs[0].CommonName != "solo.hd.local" {
		t.Errorf("발급 결과 = %+v", certs)
	}
}

func TestApplyMultipleFiles(t *testing.T) {
	// "각각 파일": CA 파일 하나 + leaf 파일 둘. 명령행 순서대로 이어 붙는다.
	app, _ := applyApp(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caFile := write("ca.cnf", `[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[v3_ca]
basicConstraints = critical, CA:TRUE
[dn]
CN = HD Root CA`)
	webFile := write("web.cnf", `[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = DNS:web.hd.local
[dn]
CN = web.hd.local`)
	apiFile := write("api.cnf", `[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = DNS:api.hd.local
[dn]
CN = api.hd.local`)

	if err := app.dispatch([]string{"apply", caFile, webFile, apiFile, "--no-passphrase"}); err != nil {
		t.Fatalf("여러 파일 apply 실패: %v", err)
	}
	defer app.store.Close()

	cas, _ := app.store.ListCAs("")
	if len(cas) != 1 {
		t.Fatalf("CA 수 = %d", len(cas))
	}
	certs, _ := app.store.ListCerts(store.CertFilter{})
	if len(certs) != 2 {
		t.Fatalf("인증서 수 = %d, 기대 2 (서버·클라이언트)", len(certs))
	}
	// 둘 다 같은 CA 아래여야 한다.
	for _, c := range certs {
		if c.CAID != cas[0].ID {
			t.Errorf("%s 가 다른 CA 에 붙었다", c.CommonName)
		}
	}
}

func TestApplyRejectsMultipleCABlocks(t *testing.T) {
	// 제약: apply 한 번은 CA 하나만 만든다(1 CA / 1회). CA 블록이 둘이면 거부해야 한다.
	app, _ := applyApp(t)
	path := filepath.Join(t.TempDir(), "two-ca.cnf")
	content := `[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[v3_ca]
basicConstraints = critical, CA:TRUE
[dn]
CN = Internal CA
---
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[v3_ca]
basicConstraints = critical, CA:TRUE
[dn]
CN = Partner CA
---
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = DNS:web.internal
[dn]
CN = web.internal`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	err := app.dispatch([]string{"apply", path, "--no-passphrase"})
	if app.store != nil {
		app.store.Close()
		app.store = nil
	}
	if err == nil {
		t.Fatal("CA 블록 둘이 통과했다")
	}
	if !strings.Contains(err.Error(), "1 CA") {
		t.Errorf("오류가 1 CA 제약을 말하지 않는다: %v", err)
	}
	// 거부했으면 아무 CA 도 만들어지지 않았어야 한다(파싱 단계에서 멈춘다).
	app2 := &App{Out: Out{W: &bytes.Buffer{}, Err: &bytes.Buffer{}}, dataFlag: app.dataFlag}
	if err := app2.open(false); err == nil {
		defer app2.store.Close()
		cas, _ := app2.store.ListCAs("")
		if len(cas) != 0 {
			t.Errorf("거부했는데 CA 가 %d개 만들어졌다", len(cas))
		}
	}
}

func TestApplyOneCAManyLeaves(t *testing.T) {
	// 핵심 모델: 1 CA : N 서버·클라이언트. CA 하나에 leaf 여럿.
	app, _ := applyApp(t)
	path := filepath.Join(t.TempDir(), "one-ca.cnf")
	content := `[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[v3_ca]
basicConstraints = critical, CA:TRUE
[dn]
CN = HD Root CA
---
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = DNS:web.hd.local
[dn]
CN = web.hd.local
---
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = DNS:agent.hd.local
[dn]
CN = agent.hd.local
---
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[v3]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:both.hd.local
[dn]
CN = both.hd.local`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.dispatch([]string{"apply", path, "--no-passphrase"}); err != nil {
		t.Fatalf("1 CA + leaf 셋 apply 실패: %v", err)
	}
	defer app.store.Close()

	cas, _ := app.store.ListCAs("")
	if len(cas) != 1 {
		t.Fatalf("CA 수 = %d, 기대 1", len(cas))
	}
	certs, _ := app.store.ListCerts(store.CertFilter{})
	if len(certs) != 3 {
		t.Fatalf("인증서 수 = %d, 기대 3", len(certs))
	}
	// 전부 같은 CA 아래.
	for _, c := range certs {
		if c.CAID != cas[0].ID {
			t.Errorf("%s 가 다른 CA 에 붙었다", c.CommonName)
		}
	}
	// 서버·클라이언트·양쪽이 다 있어야 한다.
	profiles := map[string]bool{}
	for _, c := range certs {
		profiles[c.Profile] = true
	}
	for _, want := range []string{"server", "client", "server+client"} {
		if !profiles[want] {
			t.Errorf("%s 프로필 인증서가 없다", want)
		}
	}
}

func TestApplyFileCAAndFlagCAConflict(t *testing.T) {
	// 파일이 CA 를 만들라는데 --ca 로 다른 CA 를 가리키면 의도가 충돌한다.
	app, path := applyApp(t) // 이 파일은 CA 블록을 포함한다
	err := app.dispatch([]string{"apply", path, "--ca", "something", "--no-passphrase"})
	if app.store != nil {
		app.store.Close()
		app.store = nil
	}
	if err == nil {
		t.Fatal("파일 CA + --ca 충돌이 통과했다")
	}
}

func TestApplyMissingFileReported(t *testing.T) {
	app, path := applyApp(t)
	// 여러 파일 중 하나가 없으면 명확히 실패해야 한다.
	err := app.dispatch([]string{"apply", path, filepath.Join(t.TempDir(), "nope.cnf"), "--no-passphrase"})
	if err == nil {
		if app.store != nil {
			app.store.Close()
		}
		t.Fatal("없는 파일이 통과했다")
	}
}
