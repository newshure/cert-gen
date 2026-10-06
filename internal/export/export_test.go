package export

import (
	"crypto"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/issue"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

const caPass = "test-ca-passphrase"

// fixture 는 실제로 발급한 인증서 한 건을 변환 입력으로 돌려준다. 손으로 만든 재료가 아니라
// 발급 경로를 그대로 통과한 것이어야 변환이 실제로 쓸 수 있는지 알 수 있다.
func fixture(t *testing.T) (config.Config, store.Cert, Input) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Cert.DefaultKeyAlgo = "rsa2048" // p12/JKS 소비자 호환 기본값 그대로
	cfg.CA.DefaultKeyAlgo = "ec-p384"
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
	res, err := issue.Issue(cfg, s, issue.Options{
		Material: material, Subject: names.Subject{CommonName: "web.hd.local", Organization: "HD"},
		SANValues: []string{"ip:10.0.0.5"}, Frontend: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := FromBundle(cfg, res.Record, "")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, res.Record, in
}

func TestFromBundleLoadsEverything(t *testing.T) {
	_, rec, in := fixture(t)
	if in.Cert == nil || in.Cert.Subject.CommonName != "web.hd.local" {
		t.Fatalf("인증서를 읽지 못했다: %+v", in.Cert)
	}
	if !in.HasKey() {
		t.Error("번들에 개인키가 있는데 읽지 못했다")
	}
	if in.CA == nil || !in.CA.IsCA {
		t.Error("ca.crt 를 읽지 못했다")
	}
	if in.Label != rec.CommonName {
		t.Errorf("라벨 = %q", in.Label)
	}
	// 읽어 온 키가 인증서의 짝인지. 아니면 뒤의 변환이 전부 쓸모없다.
	if !keys.PublicMatches(in.Key, in.Cert.PublicKey) {
		t.Error("번들에서 읽은 키와 인증서가 짝이 아니다")
	}
}

func TestFromBundleRejectsTamperedBundle(t *testing.T) {
	cfg, rec, _ := fixture(t)
	path := filepath.Join(cfg.DataDir, rec.BundlePath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// 변조된 번들로 키스토어를 만들어 배포하면 어디서 틀어졌는지 추적할 수 없다.
	if _, err := FromBundle(cfg, rec, ""); err == nil {
		t.Error("변조된 번들이 변환 입력으로 통과했다")
	}
}

func TestP12RoundTrip(t *testing.T) {
	_, _, in := fixture(t)
	res, err := P12(in, Options{Password: "correct-horse-battery-staple"})
	if err != nil {
		t.Fatal(err)
	}
	_, cert, chain, err := pkcs12.DecodeChain(res.Data, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("되읽기 실패: %v", err)
	}
	if cert.Subject.CommonName != "web.hd.local" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if !cert.Equal(in.Cert) {
		t.Error("p12 안 인증서가 원본과 다르다")
	}
	// p12 는 그 자체로 신뢰 경로를 완성해야 Java 가 체인을 세운다 → Root 포함.
	found := false
	for _, c := range chain {
		if c.Equal(in.CA) {
			found = true
		}
	}
	if !found {
		t.Error("p12 체인에 Root CA 가 없다")
	}
	if res.Filename != "keystore.p12" {
		t.Errorf("파일명 = %s", res.Filename)
	}
}

func TestP12UsesModern2023Algorithms(t *testing.T) {
	// 의존성이 올라도 산출물 호환 범위가 조용히 바뀌지 않아야 한다. openssl 이 보는
	// 알고리즘으로 고정 여부를 확인한다.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	_, _, in := fixture(t)
	res, err := P12(in, Options{Password: "correct-horse-battery-staple"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.p12")
	if err := os.WriteFile(path, res.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(openssl, "pkcs12", "-in", path, "-info", "-noout",
		"-passin", "pass:correct-horse-battery-staple").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl 이 p12 를 열지 못했다: %v\n%s", err, out)
	}
	body := string(out)
	if !strings.Contains(body, "AES-256-CBC") {
		t.Errorf("AES-256-CBC 가 아니다 — Modern2023 고정이 깨졌다:\n%s", body)
	}
	if strings.Contains(body, "RC2") || strings.Contains(body, "3DES") {
		t.Errorf("기본값에 약한 알고리즘이 들어갔다:\n%s", body)
	}
}

func TestP12LegacyIsOptInAndWarns(t *testing.T) {
	_, _, in := fixture(t)
	res, err := P12(in, Options{Password: "correct-horse-battery-staple", Legacy: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pkcs12.DecodeChain(res.Data, "correct-horse-battery-staple"); err != nil {
		t.Fatalf("legacy p12 되읽기 실패: %v", err)
	}
	// 약한 알고리즘을 쓴다는 사실을 숨기면 안 된다.
	if !strings.Contains(strings.Join(res.Warnings, " "), "legacy") {
		t.Errorf("legacy 경고가 없다: %v", res.Warnings)
	}
}

func TestP12WarnsOnWeakPassword(t *testing.T) {
	_, _, in := fixture(t)
	short, err := P12(in, Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(short.Warnings) == 0 {
		t.Error("짧은 비밀번호에 경고가 없다")
	}
	empty, err := P12(in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// 빈 암호를 막지는 않는다(파일 권한으로만 보호하는 운용이 실제로 있다) — 대신 알린다.
	if len(empty.Warnings) == 0 {
		t.Error("빈 비밀번호에 경고가 없다")
	}
	long, err := P12(in, Options{Password: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if len(long.Warnings) != 0 {
		t.Errorf("충분한 비밀번호에 불필요한 경고가 붙었다: %v", long.Warnings)
	}
}

func TestJKSRoundTrip(t *testing.T) {
	_, _, in := fixture(t)
	const pass = "changeit-please"
	res, err := JKS(in, Options{Password: pass, Alias: "web"})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(strings.NewReader(string(res.Data)), []byte(pass)); err != nil {
		t.Fatalf("JKS 되읽기 실패: %v", err)
	}
	entry, err := ks.GetPrivateKeyEntry("web", []byte(pass))
	if err != nil {
		t.Fatalf("개인키 항목을 읽지 못했다: %v", err)
	}
	// 체인의 첫 항목이 leaf 여야 Java 가 인증서를 올바로 제시한다.
	if len(entry.CertificateChain) < 2 {
		t.Fatalf("체인 길이 = %d, leaf+CA 가 들어가야 한다", len(entry.CertificateChain))
	}
	leaf, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.Equal(in.Cert) {
		t.Error("JKS 체인의 첫 인증서가 leaf 가 아니다")
	}
	// 개인키가 실제로 그 인증서의 짝인지
	parsed, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		t.Fatalf("JKS 안 개인키를 파싱할 수 없다: %v", err)
	}
	stored, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatalf("JKS 안 개인키가 서명 키가 아니다: %T", parsed)
	}
	if !keys.PublicMatches(stored, leaf.PublicKey) {
		t.Error("JKS 안 키와 인증서가 짝이 아니다")
	}
	if len(res.Warnings) == 0 {
		t.Error("JKS 가 레거시라는 안내가 없다")
	}
}

func TestJKSRequiresSixCharPassword(t *testing.T) {
	_, _, in := fixture(t)
	// Java 가 강제하는 하한이다. 통과시키면 keytool 로 다시 열지 못하는 파일이 나간다.
	for _, pass := range []string{"", "12345"} {
		if _, err := JKS(in, Options{Password: pass}); !certerr.IsKind(err, certerr.KindValidation) {
			t.Errorf("비밀번호 %q 가 거부되지 않았다: %v", pass, err)
		}
	}
	if _, err := JKS(in, Options{Password: "123456"}); err != nil {
		t.Errorf("6자 비밀번호가 거부됐다: %v", err)
	}
}

func TestJKSAliasDefaultsToLowercasedCN(t *testing.T) {
	// JKS 는 별칭을 소문자로 정규화한다. 미리 맞춰 두지 않으면 keytool -list 결과와
	// 우리가 안내한 별칭이 어긋난다.
	_, _, in := fixture(t)
	in.Label = "Web.HD.Local"
	const pass = "changeit-please"
	res, err := JKS(in, Options{Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(strings.NewReader(string(res.Data)), []byte(pass)); err != nil {
		t.Fatal(err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 1 || aliases[0] != "web.hd.local" {
		t.Errorf("별칭 = %v, 기대 [web.hd.local]", aliases)
	}
}

func TestKeytoolReadsOurJKS(t *testing.T) {
	// 교차 검증의 핵심. 우리가 쓴 JKS 를 Java 자신이 읽어야 keytool 의존을 떼어낸 게 맞다.
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		t.Skip("keytool 없음 — JDK 미설치")
	}
	_, _, in := fixture(t)
	const pass = "changeit-please"
	res, err := JKS(in, Options{Password: pass, Alias: "web"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keystore.jks")
	if err := os.WriteFile(path, res.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keytool, "-list", "-v", "-keystore", path,
		"-storetype", "JKS", "-storepass", pass).CombinedOutput()
	if err != nil {
		t.Fatalf("keytool 이 우리 JKS 를 읽지 못했다: %v\n%s", err, out)
	}
	body := string(out)
	for _, want := range []string{"web", "PrivateKeyEntry", "web.hd.local"} {
		if !strings.Contains(body, want) {
			t.Errorf("keytool 출력에 %q 가 없다:\n%s", want, body)
		}
	}
}

func TestKeytoolReadsOurP12(t *testing.T) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		t.Skip("keytool 없음 — JDK 미설치")
	}
	_, _, in := fixture(t)
	const pass = "correct-horse-battery-staple"
	res, err := P12(in, Options{Password: pass, Alias: "web"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keystore.p12")
	if err := os.WriteFile(path, res.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keytool, "-list", "-keystore", path,
		"-storetype", "PKCS12", "-storepass", pass).CombinedOutput()
	if err != nil {
		t.Fatalf("keytool 이 우리 p12 를 읽지 못했다: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PrivateKeyEntry") {
		t.Errorf("p12 에 개인키 항목이 없다:\n%s", out)
	}
}

func TestJKSIsReproducible(t *testing.T) {
	_, _, in := fixture(t)
	// 같은 입력이면 같은 바이트. 생성 시각이 흘러 들어가면 재배포 때마다 파일이 달라져
	// "바뀐 게 있나" 를 판단할 수 없다. (JKS 는 암호화에 난수 솔트를 쓰므로 키 항목까지
	// 동일하진 않다 — 여기서는 생성 시각이 고정되었는지만 본다.)
	const pass = "changeit-please"
	first, err := JKS(in, Options{Password: pass, Alias: "web"})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(strings.NewReader(string(first.Data)), []byte(pass)); err != nil {
		t.Fatal(err)
	}
	entry, err := ks.GetPrivateKeyEntry("web", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if !entry.CreationTime.Equal(jksEpoch) {
		t.Errorf("생성 시각이 고정되지 않았다: %s", entry.CreationTime)
	}
}

func TestTrustStores(t *testing.T) {
	_, _, in := fixture(t)
	p12res, err := TrustStoreP12(in, Options{Password: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pkcs12.DecodeTrustStore(p12res.Data, "0123456789abcdef")
	if err != nil {
		t.Fatalf("신뢰 저장소 되읽기 실패: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(in.CA) {
		t.Error("신뢰 저장소에 Root CA 가 없다")
	}
	// 신뢰 저장소에는 개인키가 들어가면 안 된다. 들어가면 배포 대상이 CA 가 된다.
	if _, _, err := pkcs12.Decode(p12res.Data, "0123456789abcdef"); err == nil {
		t.Error("신뢰 저장소에서 개인키가 나왔다")
	}

	jksres, err := TrustStoreJKS(in, Options{Password: "changeit"})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(strings.NewReader(string(jksres.Data)), []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 1 {
		t.Fatalf("별칭 수 = %d", len(aliases))
	}
	if !ks.IsTrustedCertificateEntry(aliases[0]) {
		t.Error("JKS 신뢰 저장소 항목이 trusted 가 아니다")
	}
	if ks.IsPrivateKeyEntry(aliases[0]) {
		t.Error("JKS 신뢰 저장소에 개인키가 들어갔다")
	}
}

func TestExportsWithoutKeyAreRejected(t *testing.T) {
	// CSR 서명 건은 개인키가 없다. 빈 키스토어를 만들어 주면 받는 쪽이 한참 뒤에 깨닫는다.
	_, _, in := fixture(t)
	in.Key = nil
	if _, err := P12(in, Options{Password: "0123456789abcdef"}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("개인키 없이 p12 가 만들어졌다: %v", err)
	}
	if _, err := JKS(in, Options{Password: "changeit"}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("개인키 없이 JKS 가 만들어졌다: %v", err)
	}
	if _, err := KeyPEM(in, ""); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("개인키 없이 키 PEM 이 만들어졌다: %v", err)
	}
	// 인증서만 필요한 포맷은 여전히 되어야 한다.
	if der := DER(in); len(der.Data) == 0 {
		t.Error("개인키가 없다고 DER 변환까지 막혔다")
	}
}

func TestDERIsParseable(t *testing.T) {
	_, _, in := fixture(t)
	res := DER(in)
	back, err := x509.ParseCertificate(res.Data)
	if err != nil {
		t.Fatalf("DER 파싱 실패: %v", err)
	}
	if !back.Equal(in.Cert) {
		t.Error("DER 왕복에서 인증서가 변했다")
	}
}

func TestFullchainExcludesRoot(t *testing.T) {
	_, _, in := fixture(t)
	res := FullchainPEM(in)
	// Root 를 넣으면 핸드셰이크마다 쓸데없는 바이트를 보낸다. 신뢰는 클라이언트 쪽 몫이다.
	if strings.Count(string(res.Data), "BEGIN CERTIFICATE") != 1 {
		t.Errorf("Root 직접 발급의 fullchain 에 인증서가 1개가 아니다:\n%s", res.Data)
	}
	parsed, err := ca.LoadChain(res.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed[0].Equal(in.Cert) {
		t.Error("fullchain 의 첫 인증서가 leaf 가 아니다")
	}
}

func TestKeyPEMEncryptionWarns(t *testing.T) {
	_, _, in := fixture(t)
	plain, err := KeyPEM(in, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain.Data), "ENCRYPTED") {
		t.Error("패스프레이즈 없이 암호화됐다")
	}
	if len(plain.Warnings) != 0 {
		t.Errorf("평문 키에 불필요한 경고: %v", plain.Warnings)
	}
	enc, err := KeyPEM(in, "secret-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enc.Data), "ENCRYPTED") {
		t.Error("암호화되지 않았다")
	}
	// 암호화된 키를 서버에 쓰면 기동 때마다 묻는다는 사실을 알려야 한다.
	if len(enc.Warnings) == 0 {
		t.Error("암호화된 키에 기동 경고가 없다")
	}
}

// --- 외부 파일 입력 -----------------------------------------------------------

func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFromFilesAcceptsExternalPEM(t *testing.T) {
	// 실무에서 가장 잦은 변환: 남이 준 PEM 을 p12 로.
	_, _, src := fixture(t)
	dir := t.TempDir()
	keyPEM, err := keys.ToPEM(src.Key, "")
	if err != nil {
		t.Fatal(err)
	}
	certPath := writePEM(t, dir, "cert.pem", certbuild.CertPEM(src.Cert))
	keyPath := writePEM(t, dir, "key.pem", keyPEM)
	caPath := writePEM(t, dir, "ca.crt", certbuild.CertPEM(src.CA))

	in, err := FromFiles(ExternalFiles{CertPath: certPath, KeyPath: keyPath, CAPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if in.Label != "web.hd.local" {
		t.Errorf("라벨 = %q", in.Label)
	}
	res, err := P12(in, Options{Password: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if _, cert, _, err := pkcs12.DecodeChain(res.Data, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	} else if !cert.Equal(src.Cert) {
		t.Error("외부 파일 경유 p12 의 인증서가 다르다")
	}
}

func TestFromFilesRejectsMismatchedKey(t *testing.T) {
	// 짝이 아닌 키로 만든 키스토어는 파일로는 멀쩡해 보이고 서버를 올릴 때야 실패한다.
	_, _, src := fixture(t)
	other, err := keys.Generate("rsa2048")
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := keys.ToPEM(other, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writePEM(t, dir, "cert.pem", certbuild.CertPEM(src.Cert))
	keyPath := writePEM(t, dir, "other.pem", otherPEM)

	_, err = FromFiles(ExternalFiles{CertPath: certPath, KeyPath: keyPath})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("짝이 아닌 키가 통과했다: %v", err)
	}
	if !strings.Contains(err.Error(), "짝") {
		t.Errorf("오류 문구가 원인을 말하지 않는다: %v", err)
	}
}

func TestFromFilesRejectsNonCAAsCA(t *testing.T) {
	_, _, src := fixture(t)
	dir := t.TempDir()
	certPath := writePEM(t, dir, "cert.pem", certbuild.CertPEM(src.Cert))
	// leaf 를 CA 라고 주면 거부해야 한다. 받아들이면 신뢰 저장소에 leaf 가 들어간다.
	_, err := FromFiles(ExternalFiles{CertPath: certPath, CAPath: certPath})
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("leaf 를 CA 로 받아들였다: %v", err)
	}
}

func TestFromFilesRequiresCert(t *testing.T) {
	if _, err := FromFiles(ExternalFiles{}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("인증서 없이 통과했다: %v", err)
	}
}

func TestFromFilesHandlesEncryptedKey(t *testing.T) {
	_, _, src := fixture(t)
	dir := t.TempDir()
	encPEM, err := keys.ToPEM(src.Key, "key-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	certPath := writePEM(t, dir, "cert.pem", certbuild.CertPEM(src.Cert))
	keyPath := writePEM(t, dir, "key.pem", encPEM)

	// 패스프레이즈 없이는 '재입력 유도' 종류의 오류여야 한다. 설정 문제와 섞이면
	// 사용자가 무엇을 고쳐야 할지 모른다.
	_, err = FromFiles(ExternalFiles{CertPath: certPath, KeyPath: keyPath})
	if !certerr.IsKind(err, certerr.KindKeyUnlock) {
		t.Fatalf("암호화된 키에 keyunlock 오류가 아니다: %v", err)
	}
	in, err := FromFiles(ExternalFiles{CertPath: certPath, KeyPath: keyPath, Passphrase: "key-passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	if !in.HasKey() {
		t.Error("패스프레이즈를 줬는데 키를 읽지 못했다")
	}
}
