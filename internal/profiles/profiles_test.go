package profiles

import (
	"crypto/x509"
	"testing"

	"github.com/newshure/cert-gen/internal/keys"
)

// 이 값이 틀리면 "어떤 클라이언트에서만 실패" 로 돌아오고 원인을 찾기 어렵다. 기대값을 고정한다.
func TestRootCAProfile(t *testing.T) {
	p, err := Get(RootCA)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsCA {
		t.Error("CA 가 아니다")
	}
	// pathLen=0 — 이 CA 아래에 또 CA 를 두지 않는다(중간 CA 생성은 범위 밖).
	if p.PathLen != 0 {
		t.Errorf("pathLen = %d, 기대 0", p.PathLen)
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	if p.KeyUsage != want {
		t.Errorf("keyUsage = %b, 기대 %b", p.KeyUsage, want)
	}
	if len(p.ExtKeyUsage) != 0 {
		t.Error("CA 에 EKU 가 붙었다")
	}
	if p.RequiresSAN {
		t.Error("CA 에 SAN 을 요구한다")
	}
}

func TestLeafProfiles(t *testing.T) {
	cases := map[string][]x509.ExtKeyUsage{
		Server:       {x509.ExtKeyUsageServerAuth},
		Client:       {x509.ExtKeyUsageClientAuth},
		ServerClient: {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for name, wantEKU := range cases {
		p, err := GetLeaf(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.IsCA {
			t.Errorf("%s 가 CA 다", name)
		}
		if !p.RequiresSAN {
			t.Errorf("%s 에 SAN 이 필수가 아니다", name)
		}
		if len(p.ExtKeyUsage) != len(wantEKU) {
			t.Errorf("%s EKU 개수 = %d, 기대 %d", name, len(p.ExtKeyUsage), len(wantEKU))
			continue
		}
		for i := range wantEKU {
			if p.ExtKeyUsage[i] != wantEKU[i] {
				t.Errorf("%s EKU[%d] 불일치", name, i)
			}
		}
	}
}

func TestKeyEnciphermentDroppedForNonRSA(t *testing.T) {
	// keyEncipherment 는 RSA 키 전송용 비트다. EC/Ed25519 에 켜면 의미가 없고 경고를 만든다.
	p, _ := GetLeaf(Server)

	rsaKey, _ := keys.Generate("rsa2048")
	if KeyUsageFor(p, rsaKey.Public())&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA 에서 keyEncipherment 가 빠졌다")
	}
	for _, algo := range []string{"ec-p256", "ec-p384", "ed25519"} {
		k, err := keys.Generate(algo)
		if err != nil {
			t.Fatal(err)
		}
		if KeyUsageFor(p, k.Public())&x509.KeyUsageKeyEncipherment != 0 {
			t.Errorf("%s 에 keyEncipherment 가 켜져 있다", algo)
		}
	}
}

func TestCAProfileCannotBeUsedForLeaf(t *testing.T) {
	if _, err := GetLeaf(RootCA); err == nil {
		t.Error("CA 프로필로 leaf 를 발급할 수 있다")
	}
	if _, err := Get("nope"); err == nil {
		t.Error("없는 프로필이 통과했다")
	}
}
