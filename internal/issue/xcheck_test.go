package issue

// openssl 교차 검증. 우리 검증기(crypto/x509)가 통과시킨 것을 외부 도구도 통과시켜야 한다.
// 같은 코드로 만들고 같은 코드로 검증하면 서로의 버그를 가려 준다.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/names"
)

func opensslPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl 없음")
	}
	return path
}

func TestOpenSSLVerifiesIssuedCert(t *testing.T) {
	openssl := opensslPath(t)
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local", "ip:10.0.0.5", "dns:*.hd.local")

	dir := t.TempDir()
	if _, err := bundle.ExtractTo(res.BundlePath, dir); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, bundle.MemberCA)
	certPath := filepath.Join(dir, bundle.MemberCert)

	out, err := exec.Command(openssl, "verify", "-CAfile", caPath, certPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify 실패: %v\n%s", err, out)
	}

	// SAN·확장이 실제로 DER 에 들어갔는지 openssl 의 눈으로 확인한다.
	text, err := exec.Command(openssl, "x509", "-in", certPath, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	for _, want := range []string{
		"DNS:web.hd.local", "DNS:*.hd.local", "IP Address:10.0.0.5",
		"CA:FALSE", "TLS Web Server Authentication",
		"X509v3 Subject Key Identifier", "X509v3 Authority Key Identifier",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("openssl 출력에 %q 가 없다", want)
		}
	}
	if strings.Contains(body, "TLS Web Client Authentication") {
		t.Error("server 프로필에 clientAuth 가 들어갔다")
	}

	// 개인키와 인증서가 실제 짝인지: 모듈러스/공개키 지문 비교
	keyPub, err := exec.Command(openssl, "pkey", "-in", filepath.Join(dir, bundle.MemberKey), "-pubout").Output()
	if err != nil {
		t.Fatal(err)
	}
	certPub, err := exec.Command(openssl, "x509", "-in", certPath, "-noout", "-pubkey").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(keyPub)) != strings.TrimSpace(string(certPub)) {
		t.Error("번들의 개인키와 인증서가 짝이 아니다")
	}
}

func TestOpenSSLRejectsCertFromOtherCA(t *testing.T) {
	// 음성 통제: 교차 검증이 무엇이든 통과시키는 게 아님을 확인한다.
	openssl := opensslPath(t)
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local")

	dir := t.TempDir()
	if _, err := bundle.ExtractTo(res.BundlePath, dir); err != nil {
		t.Fatal(err)
	}
	// 전혀 다른 CA 를 신뢰 기준으로 준다.
	cfg2, s2, m2 := setup(t)
	_ = cfg2
	_ = s2
	otherCA := filepath.Join(dir, "other-ca.crt")
	if err := os.WriteFile(otherCA, certbuild.CertPEM(m2.Root()), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(openssl, "verify", "-CAfile", otherCA,
		filepath.Join(dir, bundle.MemberCert)).CombinedOutput(); err == nil {
		t.Errorf("다른 CA 로 검증이 통과했다:\n%s", out)
	}
}

func TestOpenSSLSeesFullchainOrder(t *testing.T) {
	// nginx 는 fullchain 의 첫 인증서를 leaf 로 취급한다. 순서가 뒤집히면 핸드셰이크가 깨진다.
	openssl := opensslPath(t)
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local")

	dir := t.TempDir()
	if _, err := bundle.ExtractTo(res.BundlePath, dir); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(openssl, "x509", "-in", filepath.Join(dir, bundle.MemberFullchain),
		"-noout", "-subject").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "web.hd.local") {
		t.Errorf("fullchain 의 첫 인증서가 leaf 가 아니다: %s", out)
	}
}

func TestIssuedSANMatchesStoredRecord(t *testing.T) {
	// DB 기록과 실제 DER 이 어긋나면 "목록에는 맞는데 서버가 거부" 가 된다.
	cfg, s, m := setup(t)
	res := issueOne(t, cfg, s, m, "web.hd.local", "dns:api.hd.local", "ip:10.0.0.5", "email:ops@hd.local")

	dnsFromCert := map[string]bool{}
	for _, d := range res.Cert.DNSNames {
		dnsFromCert[d] = true
	}
	for _, san := range res.Record.SANs {
		switch san.Type {
		case names.TypeDNS:
			if !dnsFromCert[san.Value] {
				t.Errorf("DB 의 DNS SAN %q 가 인증서에 없다", san.Value)
			}
		case names.TypeIP:
			found := false
			for _, ip := range res.Cert.IPAddresses {
				if ip.String() == san.Value {
					found = true
				}
			}
			if !found {
				t.Errorf("DB 의 IP SAN %q 가 인증서에 없다", san.Value)
			}
		case names.TypeEmail:
			found := false
			for _, e := range res.Cert.EmailAddresses {
				if e == san.Value {
					found = true
				}
			}
			if !found {
				t.Errorf("DB 의 email SAN %q 가 인증서에 없다", san.Value)
			}
		}
	}
	if res.Record.Fingerprint != certbuild.Fingerprint(res.Cert) {
		t.Error("DB 지문과 실제 인증서 지문이 다르다")
	}
}
