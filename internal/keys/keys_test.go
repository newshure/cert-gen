package keys

import (
	"crypto"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
)

func TestRoundtripAllAlgorithms(t *testing.T) {
	for _, spec := range Specs {
		key, err := Generate(spec.Name)
		if err != nil {
			t.Fatalf("%s 생성: %v", spec.Name, err)
		}
		// 이름이 왕복해야 DB 컬럼·CLI 인자·설정이 같은 어휘를 쓸 수 있다.
		if got := AlgoOf(key); got != spec.Name {
			t.Errorf("AlgoOf = %q, 기대 %q", got, spec.Name)
		}

		encrypted, err := ToPEM(key, "secret")
		if err != nil {
			t.Fatalf("%s 암호화 직렬화: %v", spec.Name, err)
		}
		if !IsEncryptedPEM(encrypted) {
			t.Errorf("%s: 암호화 PEM 으로 인식되지 않는다", spec.Name)
		}
		back, err := FromPEM(encrypted, "secret")
		if err != nil {
			t.Fatalf("%s 되읽기: %v", spec.Name, err)
		}
		if !PublicMatches(back, key.Public()) {
			t.Errorf("%s: 왕복 후 공개키가 다르다", spec.Name)
		}

		plain, err := ToPEM(key, "")
		if err != nil {
			t.Fatal(err)
		}
		if IsEncryptedPEM(plain) {
			t.Errorf("%s: 평문인데 암호화로 보인다", spec.Name)
		}
		if _, err := FromPEM(plain, ""); err != nil {
			t.Errorf("%s 평문 되읽기: %v", spec.Name, err)
		}
	}
}

func TestSignatureHashMatchesCurve(t *testing.T) {
	rsaKey, _ := Generate("rsa2048")
	if SignatureHash(rsaKey) != crypto.SHA256 {
		t.Error("rsa2048 은 SHA-256 이어야 한다")
	}
	p384, _ := Generate("ec-p384")
	if SignatureHash(p384) != crypto.SHA384 {
		t.Error("ec-p384 는 SHA-384 여야 한다")
	}
	// Ed25519 는 해시를 지정하면 안 된다.
	ed, _ := Generate("ed25519")
	if SignatureHash(ed) != 0 {
		t.Error("ed25519 는 해시가 0 이어야 한다")
	}
}

func TestWrongAndMissingPassphraseAreDistinguishable(t *testing.T) {
	// 패스프레이즈 문제와 파일 문제를 섞으면 사용자가 무엇을 고쳐야 할지 알 수 없다.
	key, _ := Generate("ec-p256")
	pem, _ := ToPEM(key, "right")

	_, err := FromPEM(pem, "wrong")
	if err == nil || !strings.Contains(err.Error(), "올바르지 않") {
		t.Errorf("틀린 패스프레이즈 오류가 다르다: %v", err)
	}
	if !certerr.IsKind(err, certerr.KindKeyUnlock) {
		t.Error("KindKeyUnlock 이 아니다")
	}

	_, err = FromPEM(pem, "")
	if err == nil || !strings.Contains(err.Error(), "암호화되어 있습니다") {
		t.Errorf("패스프레이즈 누락 오류가 다르다: %v", err)
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	if _, err := Generate("rsa1024"); err == nil {
		t.Error("rsa1024 가 통과했다")
	}
}

func TestPublicMatchesDetectsMismatch(t *testing.T) {
	a, _ := Generate("ec-p256")
	b, _ := Generate("ec-p256")
	if PublicMatches(a, b.Public()) {
		t.Error("다른 키가 일치로 나왔다")
	}
}

func TestPublicDigestIsStable(t *testing.T) {
	key, _ := Generate("rsa2048")
	d1, err := PublicDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := PublicDigest(key.Public())
	if d1 != d2 || len(d1) != 64 {
		t.Errorf("지문이 불안정하거나 길이가 다르다: %q", d1)
	}
}

func TestPublicPEMAcceptsPrivateKeyToo(t *testing.T) {
	// 시그니처가 any 라서 개인키를 넘기는 실수가 쉽게 난다. 그 경우에도 공개키가 나와야
	// 하고, 무엇보다 **개인키가 섞여 나가면 안 된다.**
	for _, algo := range []string{"rsa2048", "ec-p256", "ed25519"} {
		signer, err := Generate(algo)
		if err != nil {
			t.Fatal(err)
		}
		fromPrivate, err := PublicPEM(signer)
		if err != nil {
			t.Fatalf("%s: 개인키로 호출 실패: %v", algo, err)
		}
		fromPublic, err := PublicPEM(signer.Public())
		if err != nil {
			t.Fatalf("%s: 공개키로 호출 실패: %v", algo, err)
		}
		if string(fromPrivate) != string(fromPublic) {
			t.Errorf("%s: 개인키/공개키 입력의 결과가 다르다", algo)
		}
		if strings.Contains(string(fromPrivate), "PRIVATE") {
			t.Fatalf("%s: 공개키 출력에 개인키가 섞였다", algo)
		}
		if !strings.Contains(string(fromPrivate), "BEGIN PUBLIC KEY") {
			t.Errorf("%s: PUBLIC KEY 헤더가 없다", algo)
		}
	}
}
