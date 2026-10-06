package osslconf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/profiles"
)

func parseString(t *testing.T, cnf string) Spec {
	t.Helper()
	spec, err := Parse([]byte(cnf))
	if err != nil {
		t.Fatalf("파싱 실패: %v\n--- 설정 ---\n%s", err, cnf)
	}
	return spec
}

func hasSAN(spec Spec, want string) bool {
	for _, s := range spec.SANValues {
		if s == want {
			return true
		}
	}
	return false
}

func TestPromptNoWithInlineSAN(t *testing.T) {
	spec := parseString(t, `
[req]
distinguished_name = dn
req_extensions = v3
prompt = no

[dn]
CN = web.hd.local
O  = HaeDong
C  = KR

[v3]
subjectAltName = DNS:web.hd.local, IP:10.0.0.5
extendedKeyUsage = serverAuth
`)
	if spec.Subject.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", spec.Subject.CommonName)
	}
	if spec.Subject.Organization != "HaeDong" || spec.Subject.Country != "KR" {
		t.Errorf("DN = %+v", spec.Subject)
	}
	if !hasSAN(spec, "dns:web.hd.local") || !hasSAN(spec, "ip:10.0.0.5") {
		t.Errorf("SAN = %v", spec.SANValues)
	}
	if spec.Profile != profiles.Server {
		t.Errorf("프로필 = %q, 기대 server", spec.Profile)
	}
}

func TestAltNamesSectionReference(t *testing.T) {
	spec := parseString(t, `
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = api.hd.local
[v3]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth
[alt_names]
DNS.1 = api.hd.local
DNS.2 = api2.hd.local
IP.1  = 10.0.0.6
email = ops@hd.local
`)
	// @alt_names 참조가 풀려야 한다.
	for _, want := range []string{"dns:api.hd.local", "dns:api2.hd.local", "ip:10.0.0.6", "email:ops@hd.local"} {
		if !hasSAN(spec, want) {
			t.Errorf("SAN 에 %q 가 없다: %v", want, spec.SANValues)
		}
	}
	// serverAuth + clientAuth → server+client
	if spec.Profile != profiles.ServerClient {
		t.Errorf("프로필 = %q, 기대 server+client", spec.Profile)
	}
}

func TestPromptModeUsesDefault(t *testing.T) {
	// prompt 모드: 평문은 프롬프트 문구이고 _default 가 값이다.
	spec := parseString(t, `
[req]
distinguished_name = dn
[dn]
commonName = Common Name
commonName_default = web.hd.local
0.organizationName = Organization Name
0.organizationName_default = HaeDong
countryName = Country (2 letter code)
countryName_default = KR
`)
	if spec.Subject.CommonName != "web.hd.local" {
		t.Errorf("CN = %q (프롬프트 문구를 값으로 잘못 읽음?)", spec.Subject.CommonName)
	}
	if spec.Subject.Organization != "HaeDong" {
		t.Errorf("O = %q", spec.Subject.Organization)
	}
	if spec.Subject.Country != "KR" {
		t.Errorf("C = %q", spec.Subject.Country)
	}
}

func TestLongFormDNAttributes(t *testing.T) {
	spec := parseString(t, `
[req]
distinguished_name = dn
prompt = no
[dn]
commonName = web.hd.local
organizationName = HaeDong
organizationalUnitName = IT
stateOrProvinceName = Seoul
localityName = Gangnam
emailAddress = ops@hd.local
`)
	s := spec.Subject
	if s.CommonName != "web.hd.local" || s.Organization != "HaeDong" ||
		s.OrganizationalUnit != "IT" || s.State != "Seoul" ||
		s.Locality != "Gangnam" || s.Email != "ops@hd.local" {
		t.Errorf("긴 형식 매핑 실패: %+v", s)
	}
}

func TestCABlockIsClassified(t *testing.T) {
	// CA:TRUE 블록은 CA 설정으로 분류한다. pathlen 과 root-ca 프로필을 뽑는다.
	spec := parseString(t, `
[req]
default_bits = 4096
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = HD Root CA
C  = KR
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
`)
	if !spec.IsCA {
		t.Error("CA:TRUE 블록이 CA 로 분류되지 않았다")
	}
	if spec.Profile != profiles.RootCA {
		t.Errorf("프로필 = %q, 기대 root-ca", spec.Profile)
	}
	if spec.PathLen == nil || *spec.PathLen != 0 {
		t.Errorf("pathlen = %v, 기대 0", spec.PathLen)
	}
	if spec.KeyAlgo != "rsa4096" {
		t.Errorf("default_bits 4096 → %q, 기대 rsa4096", spec.KeyAlgo)
	}
	// CA 블록에서 keyCertSign 은 당연하므로 경고하지 않는다.
	if strings.Contains(strings.Join(spec.Warnings, " "), "keyUsage") {
		t.Errorf("CA 블록인데 keyUsage 를 경고했다: %v", spec.Warnings)
	}
}

func TestLeafBlockIsNotCA(t *testing.T) {
	spec := parseString(t, `
[req]
default_bits = 2048
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = web.hd.local
[v3]
basicConstraints = CA:FALSE
subjectAltName = DNS:web.hd.local
extendedKeyUsage = serverAuth
`)
	if spec.IsCA {
		t.Error("CA:FALSE 블록이 CA 로 분류됐다")
	}
	if spec.KeyAlgo != "rsa2048" {
		t.Errorf("default_bits 2048 → %q", spec.KeyAlgo)
	}
	if spec.Profile != profiles.Server {
		t.Errorf("프로필 = %q", spec.Profile)
	}
}

func TestParseBlocksSplitsOnDashes(t *testing.T) {
	// 사용자 파일 형식: CA 블록 + leaf 블록을 --- 로 구분.
	specs, err := ParseBlocks([]byte(`
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = HD Root CA
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0

---

[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = web.hd.local
[v3]
basicConstraints = CA:FALSE
subjectAltName = DNS:web.hd.local
extendedKeyUsage = serverAuth
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("블록 수 = %d, 기대 2", len(specs))
	}
	if !specs[0].IsCA || specs[0].Subject.CommonName != "HD Root CA" {
		t.Errorf("블록 0 = %+v", specs[0])
	}
	if specs[1].IsCA || specs[1].Subject.CommonName != "web.hd.local" {
		t.Errorf("블록 1 = %+v", specs[1])
	}
}

func TestKeyUsageAndUnknownEKUWarned(t *testing.T) {
	// 반영하지 않는 확장은 조용히 버리지 않고 알린다.
	spec := parseString(t, `
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = web.hd.local
[v3]
subjectAltName = DNS:web.hd.local
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, codeSigning, 1.3.6.1.5.5.7.3.8
`)
	joined := strings.Join(spec.Warnings, " ")
	if !strings.Contains(joined, "keyUsage") {
		t.Errorf("keyUsage 경고가 없다: %v", spec.Warnings)
	}
	if !strings.Contains(joined, "codesigning") && !strings.Contains(joined, "codeSigning") {
		t.Errorf("알 수 없는 EKU 경고가 없다: %v", spec.Warnings)
	}
	// serverAuth 가 있으므로 프로필은 server 로 추론된다.
	if spec.Profile != profiles.Server {
		t.Errorf("프로필 = %q", spec.Profile)
	}
}

func TestMissingCNRejected(t *testing.T) {
	_, err := Parse([]byte(`
[req]
distinguished_name = dn
prompt = no
[dn]
O = HaeDong
`))
	if err == nil {
		t.Fatal("CN 없는 설정이 통과했다")
	}
	if !strings.Contains(err.Error(), "CN") {
		t.Errorf("오류가 원인을 말하지 않는다: %v", err)
	}
}

func TestMissingDNSectionRejected(t *testing.T) {
	_, err := Parse([]byte("[req]\nprompt = no\n"))
	if err == nil {
		t.Fatal("DN 섹션 없는 설정이 통과했다")
	}
}

func TestCommentsAndContinuation(t *testing.T) {
	spec := parseString(t, `
# 주석 줄
[req]
distinguished_name = dn   # 줄 끝 주석
prompt = no
[dn]
CN = web.hd.local
[v3_req]
subjectAltName = DNS:a.hd.local, \
                 DNS:b.hd.local, \
                 IP:10.0.0.9
`)
	// 역슬래시 줄 이음이 풀려야 한다.
	for _, want := range []string{"dns:a.hd.local", "dns:b.hd.local", "ip:10.0.0.9"} {
		if !hasSAN(spec, want) {
			t.Errorf("줄 이음 SAN 에 %q 가 없다: %v", want, spec.SANValues)
		}
	}
}

func TestHashInQuotesNotComment(t *testing.T) {
	spec := parseString(t, `
[req]
distinguished_name = dn
prompt = no
[dn]
CN = web.hd.local
O = "Team #1"
`)
	if spec.Subject.Organization != "Team #1" {
		t.Errorf("따옴표 안 # 를 주석으로 잘랐다: %q", spec.Subject.Organization)
	}
}

func TestUnsupportedSANTypeWarned(t *testing.T) {
	spec := parseString(t, `
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = web.hd.local
[v3]
subjectAltName = DNS:web.hd.local, otherName:1.2.3;UTF8:x, RID:1.2.3.4
`)
	// 지원하는 것은 통과, 나머지는 경고.
	if !hasSAN(spec, "dns:web.hd.local") {
		t.Errorf("DNS 가 유실됐다: %v", spec.SANValues)
	}
	joined := strings.Join(spec.Warnings, " ")
	if !strings.Contains(joined, "otherName") || !strings.Contains(joined, "RID") {
		t.Errorf("지원 안 하는 SAN 경고가 없다: %v", spec.Warnings)
	}
}

func TestLineWithoutEqualsRejected(t *testing.T) {
	_, err := Parse([]byte("[dn]\nCN web.hd.local\n"))
	if err == nil {
		t.Error("'=' 없는 줄이 통과했다")
	}
}

// --- openssl 교차 검증 --------------------------------------------------------

func TestOpenSSLWrittenConfigParses(t *testing.T) {
	// 우리가 읽겠다고 한 것은 openssl 이 실제로 쓰는 형식이어야 한다.
	// openssl 로 .cnf → CSR 을 만들고, 같은 .cnf 를 우리가 읽어 결과가 일치하는지 본다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	dir := t.TempDir()
	cnf := filepath.Join(dir, "req.cnf")
	content := `[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = web.hd.local
O = HaeDong
C = KR

[v3_req]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = web.hd.local
DNS.2 = www.hd.local
IP.1 = 10.0.0.5
`
	if err := os.WriteFile(cnf, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// openssl 이 이 .cnf 를 받아들이는지 먼저 확인한다(형식이 유효한지).
	csr := filepath.Join(dir, "out.csr")
	key := filepath.Join(dir, "out.key")
	out, err := exec.Command(openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", csr, "-config", cnf).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl 이 .cnf 를 거부했다(우리 테스트 설정이 틀림): %v\n%s", err, out)
	}

	// 같은 .cnf 를 우리가 읽는다.
	spec, err := ParseFile(cnf)
	if err != nil {
		t.Fatal(err)
	}

	// openssl 이 그 .cnf 로 만든 CSR 의 SAN 과 우리가 읽은 SAN 이 일치해야 한다.
	text, err := exec.Command(openssl, "req", "-in", csr, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	for _, pair := range [][2]string{
		{"web.hd.local", "dns:web.hd.local"},
		{"www.hd.local", "dns:www.hd.local"},
		{"10.0.0.5", "ip:10.0.0.5"},
	} {
		if !strings.Contains(body, pair[0]) {
			t.Fatalf("전제 조건: openssl CSR 에 %q 가 없다", pair[0])
		}
		if !hasSAN(spec, pair[1]) {
			t.Errorf("openssl 은 %q 를 넣었는데 우리는 %q 를 못 읽었다: %v",
				pair[0], pair[1], spec.SANValues)
		}
	}
	if spec.Subject.CommonName != "web.hd.local" || spec.Subject.Organization != "HaeDong" {
		t.Errorf("DN 불일치: %+v", spec.Subject)
	}
	if spec.Profile != profiles.Server {
		t.Errorf("프로필 = %q", spec.Profile)
	}
}
