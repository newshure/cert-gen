package certbuild

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
)

func buildCA(t *testing.T, algo string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := keys.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := names.BuildSubject(names.Subject{CommonName: "test Root CA", Organization: "HD"})
	nb, na, _ := ValidityWindow(3650, 5)
	serial, _ := NewSerial()
	p, _ := profiles.Get(profiles.RootCA)
	cert, _, err := Build(Request{
		Subject: subject, PublicKey: key.Public(), Signer: key,
		Profile: p, Serial: serial, NotBefore: nb, NotAfter: na,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestSerialRoundtrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		s, err := NewSerial()
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 {
			t.Fatal("serial 이 양수가 아니다")
		}
		// RFC 5280: 20옥텟 이하
		if s.BitLen() > 159 {
			t.Fatalf("serial 이 159비트를 넘는다: %d", s.BitLen())
		}
		hex := SerialHex(s)
		if len(hex)%2 != 0 {
			t.Fatalf("hex 길이가 홀수다: %q", hex)
		}
		back, err := SerialFromHex(hex)
		if err != nil || back.Cmp(s) != 0 {
			t.Fatalf("왕복 실패: %v", err)
		}
		if back2, _ := SerialFromHex(FormatColons(hex)); back2.Cmp(s) != 0 {
			t.Fatal("콜론 표기 왕복 실패")
		}
	}
}

func TestFormatColons(t *testing.T) {
	if got := FormatColons("aabbcc"); got != "aa:bb:cc" {
		t.Errorf("= %q", got)
	}
}

func TestValidityWindowBackdates(t *testing.T) {
	// 시계가 틀어진 장비에서 "아직 유효하지 않음" 을 피해야 한다.
	nb, na, err := ValidityWindow(397, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !nb.Before(time.Now()) {
		t.Error("notBefore 가 과거가 아니다")
	}
	if na.Sub(nb) < 396*24*time.Hour {
		t.Error("유효기간이 짧다")
	}
	if _, _, err := ValidityWindow(0, 5); err == nil {
		t.Error("0일이 통과했다")
	}
}

func TestCAIsSelfSignedWithExpectedExtensions(t *testing.T) {
	cert, _ := buildCA(t, "ec-p384")
	if cert.Issuer.String() != cert.Subject.String() {
		t.Error("자기서명이 아니다")
	}
	if !cert.IsCA {
		t.Error("CA:TRUE 가 아니다")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("pathLen 이 0 이 아니다: %d", cert.MaxPathLen)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("keyCertSign·cRLSign 이 없다")
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Error("SKI 가 없다")
	}
}

func TestLeafLinksToCAAndVerifies(t *testing.T) {
	caCert, caKey := buildCA(t, "ec-p384")
	leafKey, _ := keys.Generate("rsa2048")
	subject, _ := names.BuildSubject(names.Subject{CommonName: "web.example.com"})
	sans, _ := names.BuildSANs("web.example.com", []string{"10.0.0.5", "*.web.example.com"})
	nb, na, _ := ValidityWindow(397, 5)
	serial, _ := NewSerial()
	p, _ := profiles.GetLeaf(profiles.Server)

	leaf, _, err := Build(Request{
		Subject: subject, Issuer: caCert, PublicKey: leafKey.Public(), Signer: caKey,
		Profile: p, Serial: serial, NotBefore: nb, NotAfter: na, SANs: sans,
	})
	if err != nil {
		t.Fatal(err)
	}

	// AKI 가 CA 의 SKI 를 가리켜야 한다.
	if string(leaf.AuthorityKeyId) != string(caCert.SubjectKeyId) {
		t.Error("AKI 가 CA SKI 와 다르다")
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "web.example.com" {
		t.Errorf("DNS SAN 이 다르다: %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IP SAN 이 다르다: %v", leaf.IPAddresses)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "web.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("체인 검증 실패: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "wrong.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("호스트명 불일치가 통과했다")
	}
}

func TestLeafWithoutSANIsRejected(t *testing.T) {
	caCert, caKey := buildCA(t, "ec-p384")
	leafKey, _ := keys.Generate("rsa2048")
	subject, _ := names.BuildSubject(names.Subject{CommonName: "My Service"})
	nb, na, _ := ValidityWindow(397, 5)
	serial, _ := NewSerial()
	p, _ := profiles.GetLeaf(profiles.Server)

	if _, _, err := Build(Request{
		Subject: subject, Issuer: caCert, PublicKey: leafKey.Public(), Signer: caKey,
		Profile: p, Serial: serial, NotBefore: nb, NotAfter: na,
	}); err == nil {
		t.Error("SAN 없는 leaf 가 통과했다")
	}
}

func TestEd25519CASigns(t *testing.T) {
	// Ed25519 는 해시를 지정하면 안 되는 경로다.
	cert, _ := buildCA(t, "ed25519")
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("서명 알고리즘 = %v", cert.SignatureAlgorithm)
	}
}
