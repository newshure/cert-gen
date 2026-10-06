package csr

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
)

func TestCreateProducesVerifiableCSR(t *testing.T) {
	out, err := Create(CreateOptions{
		Subject:   names.Subject{CommonName: "web.hd.local", Organization: "HD", Country: "KR"},
		SANValues: []string{"dns:api.hd.local", "ip:10.0.0.5"},
		KeyAlgo:   "ec-p256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Request.CheckSignature(); err != nil {
		t.Fatalf("CSR 서명이 올바르지 않다: %v", err)
	}
	if out.Request.Subject.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", out.Request.Subject.CommonName)
	}
	// CN 이 SAN 에 자동 포함되어야 한다.
	if !contains(out.Request.DNSNames, "web.hd.local") {
		t.Errorf("CN 이 SAN 에 없다: %v", out.Request.DNSNames)
	}
	if !contains(out.Request.DNSNames, "api.hd.local") {
		t.Errorf("지정한 SAN 이 없다: %v", out.Request.DNSNames)
	}
	if len(out.Request.IPAddresses) != 1 {
		t.Errorf("IP SAN = %v", out.Request.IPAddresses)
	}
	// 개인키는 우리 쪽에 남는다. CSR 만 나가고 키는 안 나간다는 게 CSR 을 쓰는 이유다.
	if out.Key == nil || len(out.KeyPEM) == 0 {
		t.Fatal("개인키가 없다")
	}
	if !keys.PublicMatches(out.Key, out.Request.PublicKey) {
		t.Error("CSR 의 공개키와 개인키가 짝이 아니다")
	}
	// 기본은 평문 키다. 암호화하면 서버가 기동할 때마다 패스프레이즈를 묻는다.
	if out.KeyEncrypted || strings.Contains(string(out.KeyPEM), "ENCRYPTED") {
		t.Error("기본값이 암호화된 키다")
	}
	if block, _ := pem.Decode(out.CSRPEM); block == nil || block.Type != pemTypeCSR {
		t.Errorf("CSR PEM 헤더가 잘못됐다")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestCreateRequiresSAN(t *testing.T) {
	// SAN 없는 CSR 을 제출하고 며칠 기다린 뒤 알게 되는 편이 훨씬 비싸다.
	_, err := Create(CreateOptions{
		Subject: names.Subject{CommonName: "Payment Gateway Client"}, KeyAlgo: "ec-p256",
	})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("SAN 없는 비호스트명 CN 이 통과했다: %v", err)
	}
}

func TestCreateUsesCurveAppropriateHash(t *testing.T) {
	// 해시 표를 우리가 들고 다니지 않고 Go 에 맡겼다. 그 결과가 맞는지 확인한다.
	cases := map[string]x509.SignatureAlgorithm{
		"ec-p256": x509.ECDSAWithSHA256,
		"ec-p384": x509.ECDSAWithSHA384,
		"rsa2048": x509.SHA256WithRSA,
		"ed25519": x509.PureEd25519,
	}
	for algo, want := range cases {
		out, err := Create(CreateOptions{
			Subject: names.Subject{CommonName: "web.hd.local"}, KeyAlgo: algo,
		})
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if out.Request.SignatureAlgorithm != want {
			t.Errorf("%s 서명 알고리즘 = %v, 기대 %v", algo, out.Request.SignatureAlgorithm, want)
		}
	}
}

func TestCreateEncryptsKeyWhenAsked(t *testing.T) {
	out, err := Create(CreateOptions{
		Subject: names.Subject{CommonName: "web.hd.local"}, KeyAlgo: "ec-p256",
		Passphrase: "key-passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.KeyEncrypted || !strings.Contains(string(out.KeyPEM), "ENCRYPTED") {
		t.Error("패스프레이즈를 줬는데 암호화되지 않았다")
	}
	back, err := keys.FromPEM(out.KeyPEM, "key-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !keys.PublicMatches(back, out.Request.PublicKey) {
		t.Error("암호화된 키를 되읽었더니 짝이 아니다")
	}
}

func TestCreateUsesExistingKey(t *testing.T) {
	signer, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Create(CreateOptions{
		Subject: names.Subject{CommonName: "web.hd.local"}, ExistingKey: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !keys.PublicMatches(signer, out.Request.PublicKey) {
		t.Error("지정한 키가 쓰이지 않았다")
	}
}

func TestOpenSSLReadsOurCSR(t *testing.T) {
	// 교차 검증: 외부 CA 에 제출할 파일이므로 openssl 이 읽고 서명을 확인해야 한다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	out, err := Create(CreateOptions{
		Subject:   names.Subject{CommonName: "web.hd.local", Organization: "HD"},
		SANValues: []string{"dns:api.hd.local", "ip:10.0.0.5"},
		KeyAlgo:   "rsa2048",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "req.csr")
	if err := os.WriteFile(path, out.CSRPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// -verify 는 CSR 의 자기서명을 확인한다.
	if res, err := exec.Command(openssl, "req", "-in", path, "-noout", "-verify").CombinedOutput(); err != nil {
		t.Fatalf("openssl 이 CSR 서명을 확인하지 못했다: %v\n%s", err, res)
	}
	text, err := exec.Command(openssl, "req", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	for _, want := range []string{"web.hd.local", "DNS:api.hd.local", "IP Address:10.0.0.5"} {
		if !strings.Contains(body, want) {
			t.Errorf("openssl 출력에 %q 가 없다:\n%s", want, body)
		}
	}
}

// --- 외부 CSR 해석 ------------------------------------------------------------

func makeCSR(t *testing.T, algo string, sans ...string) []byte {
	t.Helper()
	out, err := Create(CreateOptions{
		Subject:   names.Subject{CommonName: "web.hd.local", Organization: "HD"},
		SANValues: sans, KeyAlgo: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.CSRPEM
}

func TestParseAcceptsPEM(t *testing.T) {
	parsed, err := Parse(makeCSR(t, "ec-p256", "dns:api.hd.local"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", parsed.CommonName)
	}
	if parsed.KeyAlgo != "ec-p256" {
		t.Errorf("키 알고리즘 = %q", parsed.KeyAlgo)
	}
	if len(parsed.SANs) != 2 {
		t.Errorf("SAN = %v", parsed.SANs)
	}
	if len(parsed.PEM) == 0 {
		t.Error("정규화된 PEM 이 비었다")
	}
}

func TestParseAcceptsDER(t *testing.T) {
	// 바이너리 붙여넣기가 깨진 경우를 구제하는 보조 경로.
	block, _ := pem.Decode(makeCSR(t, "ec-p256", "dns:api.hd.local"))
	parsed, err := Parse(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", parsed.CommonName)
	}
	// DER 로 받아도 PEM 으로 정규화해 돌려준다(번들에 넣을 형식).
	if !strings.Contains(string(parsed.PEM), "BEGIN CERTIFICATE REQUEST") {
		t.Error("PEM 으로 정규화되지 않았다")
	}
}

func TestParseRejectsBadSignature(t *testing.T) {
	// 서명을 확인하지 않으면 남의 공개키로 아무 이름의 인증서를 받아 갈 수 있다.
	block, _ := pem.Decode(makeCSR(t, "ec-p256", "dns:api.hd.local"))
	der := append([]byte{}, block.Bytes...)
	// 서명 바이트는 끝쪽에 있다.
	der[len(der)-5] ^= 0xff
	_, err := Parse(pem.EncodeToMemory(&pem.Block{Type: pemTypeCSR, Bytes: der}))
	if err == nil {
		t.Fatal("서명이 깨진 CSR 이 통과했다")
	}
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("오류 종류 = %v", err)
	}
}

func TestParseRejectsNonCSRPEM(t *testing.T) {
	// 인증서나 개인키를 잘못 준 경우. 무엇을 줬는지 알려 줘야 사용자가 고칠 수 있다.
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not really")})
	_, err := Parse(data)
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("인증서 PEM 이 CSR 로 통과했다: %v", err)
	}
	if !strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("오류가 무엇을 받았는지 말하지 않는다: %v", err)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("hello")); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("쓰레기 입력이 통과했다: %v", err)
	}
}

func TestParseLiftsCNToSANWithWarning(t *testing.T) {
	// SAN 없는 CSR 을 그대로 발급하면 쓸 수 없는 인증서가 나간다. CN 을 올리고 알린다.
	template := &x509.CertificateRequest{}
	signer, err := keys.Generate("ec-p256")
	if err != nil {
		t.Fatal(err)
	}
	template.Subject.CommonName = "web.hd.local"
	der, err := x509.CreateCertificateRequest(nil, template, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(pem.EncodeToMemory(&pem.Block{Type: pemTypeCSR, Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.SANs) != 1 || parsed.SANs[0].Value != "web.hd.local" {
		t.Errorf("CN 이 SAN 으로 올라가지 않았다: %v", parsed.SANs)
	}
	if len(parsed.Warnings) == 0 {
		t.Error("SAN 없음에 대한 경고가 없다")
	}
}

func TestParseWarnsOnRequestedExtensions(t *testing.T) {
	// 조용히 무시하면 요청자는 자기가 넣은 확장이 반영됐다고 믿는다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "req.conf")
	// basicConstraints CA:TRUE 를 요청하는 CSR 을 openssl 로 만든다.
	if err := os.WriteFile(conf, []byte(`
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = evil.hd.local
[ext]
basicConstraints = critical,CA:TRUE
subjectAltName = DNS:evil.hd.local
`), 0o600); err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(dir, "evil.csr")
	keyPath := filepath.Join(dir, "evil.key")
	if out, err := exec.Command(openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", csrPath, "-config", conf).CombinedOutput(); err != nil {
		t.Fatalf("테스트용 CSR 생성 실패: %v\n%s", err, out)
	}
	parsed, err := ParseFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(parsed.Warnings, " ")
	if !strings.Contains(joined, "basicConstraints") {
		t.Errorf("CA:TRUE 요청에 경고가 없다: %v", parsed.Warnings)
	}
	// 경고만 하고 거부하지는 않는다. 확장을 버리고 서명하는 것이 정상 경로다.
	if parsed.CommonName != "evil.hd.local" {
		t.Errorf("CN = %q", parsed.CommonName)
	}
}

func TestParseWarnsOnWeakKey(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	dir := t.TempDir()
	csrPath := filepath.Join(dir, "weak.csr")
	keyPath := filepath.Join(dir, "weak.key")
	// 1024비트. 폐쇄망 레거시 장비가 실제로 이런 것을 내놓는다 — 거부하지 않고 알린다.
	if out, err := exec.Command(openssl, "req", "-new", "-newkey", "rsa:1024", "-nodes",
		"-keyout", keyPath, "-out", csrPath, "-subj", "/CN=old.hd.local").CombinedOutput(); err != nil {
		t.Skipf("openssl 이 1024비트 키를 거부했다(정책): %s", out)
	}
	parsed, err := ParseFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(parsed.Warnings, " "), "2048") {
		t.Errorf("약한 키 경고가 없다: %v", parsed.Warnings)
	}
}

func TestParseFileMissing(t *testing.T) {
	if _, err := ParseFile(filepath.Join(t.TempDir(), "nope.csr")); err == nil {
		t.Error("없는 파일이 통과했다")
	}
}
