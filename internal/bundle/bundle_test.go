package bundle

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/names"
)

func sampleContent() Content {
	return Content{
		CertPEM:  []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"),
		CAPEM:    []byte("-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"),
		KeyPEM:   []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"),
		ChainPEM: []byte("-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"),
		Metadata: Metadata{
			Tool: "cert_gen", CommonName: "web.hd.local", SubjectDN: "CN=web.hd.local,O=HD",
			SANs:    []names.SAN{{Type: "dns", Value: "web.hd.local"}, {Type: "ip", Value: "10.0.0.5"}},
			Profile: "server", KeyAlgo: "rsa2048", Serial: "AB:CD", Seq: 1,
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
			CASlug: "hd-root-ca", CACommonName: "hd Root CA",
		},
	}
}

func writeSample(t *testing.T, c Content) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.zip")
	digest, err := Write(path, "web-hd-local-ab12cd34", c)
	if err != nil {
		t.Fatal(err)
	}
	return path, digest
}

func TestWriteRoundTrip(t *testing.T) {
	content := sampleContent()
	path, digest := writeSample(t, content)

	if len(digest) != 64 {
		t.Fatalf("sha256 길이 = %d", len(digest))
	}
	members, err := Members(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{MemberKey, MemberCert, MemberChain, MemberFullchain, MemberCA, MemberMetadata, MemberUsage} {
		if _, ok := members[want]; !ok {
			t.Errorf("번들에 %s 가 없다", want)
		}
	}
	// CSR 을 주지 않았으면 만들지 않는다. 빈 파일이 들어가면 "CSR 경유 발급" 과 구분이 안 된다.
	if _, ok := members[MemberCSR]; ok {
		t.Error("CSR 을 주지 않았는데 request.csr 이 생겼다")
	}
	if string(members[MemberCert]) != string(content.CertPEM) {
		t.Error("cert.pem 내용이 다르다")
	}
	if string(members[MemberKey]) != string(content.KeyPEM) {
		t.Error("privkey.pem 내용이 다르다")
	}
	// fullchain = leaf + chain. 순서가 뒤집히면 nginx 가 거부한다.
	wantFull := string(content.CertPEM) + string(content.ChainPEM)
	if got := string(members[MemberFullchain]); got != wantFull {
		t.Errorf("fullchain 이 leaf+chain 이 아니다:\n%s", got)
	}
	// Root 는 fullchain 에 들어가면 안 된다(클라이언트가 이미 신뢰해야 한다).
	if strings.Contains(string(members[MemberFullchain]), "ROOT") {
		t.Error("fullchain 에 Root CA 가 들어갔다")
	}
}

func TestWriteSkipsEmptyOptionalMembers(t *testing.T) {
	// CSR 서명 건: 개인키가 없다. 번들에 빈 privkey.pem 이 생기면 받는 쪽이
	// "키가 있는데 깨졌다" 로 오해한다.
	content := sampleContent()
	content.KeyPEM = nil
	content.ChainPEM = nil
	content.CSRPEM = []byte("-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----\n")

	path, _ := writeSample(t, content)
	members, err := Members(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := members[MemberKey]; ok {
		t.Error("개인키가 없는데 privkey.pem 이 생겼다")
	}
	if _, ok := members[MemberChain]; ok {
		t.Error("체인이 없는데 chain.pem 이 생겼다")
	}
	if _, ok := members[MemberCSR]; !ok {
		t.Error("request.csr 이 없다")
	}
	// 체인이 없어도 fullchain 은 있어야 한다(leaf 단독).
	if got := string(members[MemberFullchain]); got != string(content.CertPEM) {
		t.Errorf("체인 없는 fullchain 이 leaf 와 다르다: %q", got)
	}
}

func TestPrivkeyCarriesTightModeInZip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ACL — zip 모드 비트가 의미 없다")
	}
	path, _ := writeSample(t, sampleContent())
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	found := false
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, MemberKey) {
			continue
		}
		found = true
		// unzip 이 이 비트를 복원한다. 0600 이 아니면 받는 쪽에서 개인키가 월드 리더블로 풀린다.
		if perm := f.Mode().Perm(); perm != 0o600 {
			t.Errorf("zip 안 privkey.pem 모드 = %o, 기대 600", perm)
		}
	}
	if !found {
		t.Fatal("zip 에서 privkey.pem 을 찾지 못했다")
	}
}

func TestWriteIsReproducible(t *testing.T) {
	// 같은 입력이면 같은 바이트가 나와야 한다. 타임스탬프가 흘러 들어가면 번들 sha256 이
	// 매번 바뀌어 "백업이 변했는지" 를 판단할 수 없다.
	dir := t.TempDir()
	content := sampleContent()
	first, err := Write(filepath.Join(dir, "a.zip"), "pfx", content)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Write(filepath.Join(dir, "b.zip"), "pfx", content)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("같은 입력인데 sha256 이 다르다: %s vs %s", first, second)
	}
}

func TestWriteRefusesExisting(t *testing.T) {
	path, _ := writeSample(t, sampleContent())
	// 덮어쓰기를 허용하면 발급 id 가 겹쳤을 때 이전 개인키가 조용히 사라진다.
	if _, err := Write(path, "pfx", sampleContent()); err == nil {
		t.Error("기존 번들을 덮어썼다")
	}
}

func TestVerifyDigestDetectsTampering(t *testing.T) {
	path, digest := writeSample(t, sampleContent())
	if err := VerifyDigest(path, digest); err != nil {
		t.Fatalf("정상 번들이 거부됐다: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(path, digest); err == nil {
		t.Error("변조된 번들이 통과했다")
	}
}

func TestExtractTo(t *testing.T) {
	path, _ := writeSample(t, sampleContent())
	dest := filepath.Join(t.TempDir(), "out")
	written, err := ExtractTo(path, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) < 7 {
		t.Errorf("추출 파일 수 = %d", len(written))
	}
	keyPath := filepath.Join(dest, MemberKey)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("추출된 개인키 권한 = %o, 기대 600", perm)
		}
	}
	certPath := filepath.Join(dest, MemberCert)
	if _, err := os.Stat(certPath); err != nil {
		t.Error("cert.pem 이 추출되지 않았다")
	}
}

func TestMembersRejectsPathTraversal(t *testing.T) {
	// 우리가 만들지 않은 번들도 읽는다(백업 복원·외부 전달). 멤버 이름에 ../ 가 있으면
	// 추출 시 번들 밖으로 써질 수 있다. Members 는 디렉터리 부분을 버린다.
	path := filepath.Join(t.TempDir(), "evil.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../../../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("pwned"))
	zw.Close()
	f.Close()

	members, err := Members(path)
	if err != nil {
		t.Fatal(err)
	}
	for name := range members {
		if strings.ContainsAny(name, `/\`) || name == ".." {
			t.Errorf("멤버 이름에 경로가 남았다: %q", name)
		}
	}
}

func TestExtractToRejectsPathTraversal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evil.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("sub/../../escape.pem")
	w.Write([]byte("x"))
	zw.Close()
	f.Close()

	dest := filepath.Join(t.TempDir(), "out")
	written, err := ExtractTo(path, dest)
	if err != nil {
		// 거부도 올바른 처리다.
		return
	}
	for _, p := range written {
		rel, relErr := filepath.Rel(dest, p)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("추출 경로가 대상 디렉터리를 벗어났다: %s", p)
		}
	}
}

func TestMetadataIsValidJSON(t *testing.T) {
	path, _ := writeSample(t, sampleContent())
	members, err := Members(path)
	if err != nil {
		t.Fatal(err)
	}
	var back Metadata
	if err := json.Unmarshal(members[MemberMetadata], &back); err != nil {
		t.Fatalf("metadata.json 파싱 실패: %v", err)
	}
	if back.CommonName != "web.hd.local" || back.Profile != "server" {
		t.Errorf("메타데이터가 다르다: %+v", back)
	}
	if len(back.SANs) != 2 || back.SANs[1].Value != "10.0.0.5" {
		t.Errorf("SAN 이 유실됐다: %+v", back.SANs)
	}
}

func TestUsageTextMentionsEveryConsumer(t *testing.T) {
	// USAGE.txt 는 번들을 받은 사람이 제일 먼저 읽는 파일이다. 소비자 하나가 빠지면
	// 그 사람은 다시 물어보게 된다.
	text := UsageText(sampleContent().Metadata)
	for _, want := range []string{"nginx", "fullchain.pem", "privkey.pem", "ca.crt", "kubectl", "keytool"} {
		if !strings.Contains(text, want) {
			t.Errorf("USAGE.txt 에 %q 안내가 없다", want)
		}
	}
	if !strings.Contains(text, "web.hd.local") {
		t.Error("USAGE.txt 에 CN 이 없다")
	}
}

func TestRelPathShape(t *testing.T) {
	got := RelPath(42, "*.hd.local", "0ab1cd2ef3", "2027")
	if filepath.Base(filepath.Dir(got)) != "2027" {
		t.Errorf("연도 디렉터리가 없다: %s", got)
	}
	if !strings.HasSuffix(got, ".zip") {
		t.Errorf(".zip 이 아니다: %s", got)
	}
	// 와일드카드 CN 이 파일명에 * 로 들어가면 셸이 글롭으로 먹는다.
	if strings.Contains(got, "*") {
		t.Errorf("경로에 와일드카드 문자가 남았다: %s", got)
	}
	if !strings.Contains(filepath.Base(got), "42-") {
		t.Errorf("경로에 인증서 id 가 없다: %s", got)
	}
}
