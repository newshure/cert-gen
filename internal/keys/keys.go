// Package keys — 개인키 생성·직렬화·로드.
//
// 알고리즘을 문자열 하나로 다룬다(rsa2048, ec-p384, ed25519). 설정·CLI 인자·DB 컬럼이
// 모두 같은 어휘를 쓰게 해서 사용자가 본 이름과 저장된 이름이 어긋나지 않게 한다.
//
// 저장은 항상 PKCS#8 PEM 이다. 암호화는 PBES2(AES-256-CBC + HMAC-SHA256)를 쓴다.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/youmark/pkcs8"
)

// Spec 은 지원하는 알고리즘 하나다.
type Spec struct {
	Name string
	// Label 은 화면·드롭다운용 짧은 이름. 길면 좁은 열에서 줄바꿈되어 폼이 늘어난다.
	Label string
	// Hash 는 이 키로 서명할 때 쓸 해시. Ed25519 는 알고리즘에 내장되어 있어 0 이다.
	Hash crypto.Hash
	// Note 는 선택에 참고할 설명. 도움말에서만 쓴다.
	Note string
}

// Described 는 설명을 붙인 이름이다(CLI 도움말용).
func (s Spec) Described() string {
	if s.Note == "" {
		return s.Label
	}
	return s.Label + " — " + s.Note
}

// Specs 의 순서가 CLI --help 와 TUI 선택 목록의 순서가 된다.
var Specs = []Spec{
	{Name: "rsa2048", Label: "RSA 2048", Hash: crypto.SHA256, Note: "호환성 최우선"},
	{Name: "rsa3072", Label: "RSA 3072", Hash: crypto.SHA256},
	{Name: "rsa4096", Label: "RSA 4096", Hash: crypto.SHA256, Note: "생성이 느리다. CA 용"},
	{Name: "ec-p256", Label: "ECDSA P-256", Hash: crypto.SHA256},
	{Name: "ec-p384", Label: "ECDSA P-384", Hash: crypto.SHA384},
	{Name: "ed25519", Label: "Ed25519", Note: "구형 클라이언트 미지원"},
}

// Names 는 선택 가능한 알고리즘 이름들이다.
func Names() []string {
	out := make([]string, 0, len(Specs))
	for _, s := range Specs {
		out = append(out, s.Name)
	}
	return out
}

// SpecFor 는 이름으로 알고리즘을 찾는다.
func SpecFor(algo string) (Spec, error) {
	want := strings.ToLower(strings.TrimSpace(algo))
	for _, s := range Specs {
		if s.Name == want {
			return s, nil
		}
	}
	return Spec{}, certerr.Validationf(
		"지원하지 않는 키 알고리즘입니다: %q (사용 가능: %s)", algo, strings.Join(Names(), ", "))
}

// Generate 는 새 개인키를 만든다.
func Generate(algo string) (crypto.Signer, error) {
	spec, err := SpecFor(algo)
	if err != nil {
		return nil, err
	}
	switch spec.Name {
	case "rsa2048", "rsa3072", "rsa4096":
		bits := map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}[spec.Name]
		return rsa.GenerateKey(rand.Reader, bits)
	case "ec-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
}

// AlgoOf 는 키 객체에서 알고리즘 이름을 되읽는다(외부 CA 를 가져왔을 때 필요).
func AlgoOf(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return curveName(k.Curve)
	case *ecdsa.PublicKey:
		return curveName(k.Curve)
	case ed25519.PrivateKey, ed25519.PublicKey:
		return "ed25519"
	}
	return "unknown"
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "ec-p256"
	case elliptic.P384():
		return "ec-p384"
	case elliptic.P521():
		return "ec-p521"
	}
	return "ec-" + strings.ToLower(c.Params().Name)
}

// SignatureHash 는 서명에 쓸 해시다. Ed25519 는 0 을 돌려줘야 한다(지정하면 안 된다).
// 알 수 없는 곡선(외부 CA)은 SHA-256 으로 떨어뜨린다 — 서명 자체는 성립한다.
func SignatureHash(key any) crypto.Hash {
	if _, ok := key.(ed25519.PrivateKey); ok {
		return 0
	}
	algo := AlgoOf(key)
	for _, s := range Specs {
		if s.Name == algo {
			return s.Hash
		}
	}
	return crypto.SHA256
}

// PublicBits 는 공개키의 비트 수다. 곡선 키는 곡선 크기를 돌려준다.
//
// 외부에서 온 CSR·인증서의 키 강도를 판단할 때 쓴다. 모르는 종류는 0 이다 — 0 을 "약하다"
// 로 읽으면 안 되고, "판단할 수 없다" 로 읽어야 한다.
func PublicBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

const (
	pemTypePlain     = "PRIVATE KEY"
	pemTypeEncrypted = "ENCRYPTED PRIVATE KEY"
)

// MarshalPKCS8 은 개인키를 평문 PKCS#8 DER 로 직렬화한다.
//
// JKS 가 이 형식을 그대로 담는다(PEM 이 아니라 DER). PEM 으로 한 번 감쌌다가 다시 벗기는
// 왕복을 피하려고 따로 둔다.
func MarshalPKCS8(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, certerr.WrapState(err, "개인키를 직렬화할 수 없습니다: %v", err)
	}
	return der, nil
}

// ToPEM 은 PKCS#8 PEM 으로 직렬화한다. passphrase 가 비어 있지 않으면 암호화한다.
func ToPEM(key crypto.Signer, passphrase string) ([]byte, error) {
	if passphrase == "" {
		der, err := MarshalPKCS8(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: pemTypePlain, Bytes: der}), nil
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte(passphrase), nil)
	if err != nil {
		return nil, certerr.WrapState(err, "개인키를 암호화할 수 없습니다: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeEncrypted, Bytes: der}), nil
}

// FromPEM 은 개인키 PEM 을 읽는다.
//
// 패스프레이즈 문제와 그 외 문제를 구분해서 돌려준다. 프런트엔드가 '재입력 유도' 와
// '설정·파일 문제' 를 섞어 보여주면 사용자가 무엇을 고쳐야 할지 알 수 없다.
func FromPEM(data []byte, passphrase string) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, certerr.KeyUnlockf("개인키 PEM 을 해석할 수 없습니다")
	}

	encrypted := IsEncryptedPEM(data)
	switch {
	case encrypted && passphrase == "":
		return nil, certerr.KeyUnlockf("개인키가 암호화되어 있습니다. 패스프레이즈가 필요합니다")
	case !encrypted && passphrase != "":
		return nil, certerr.KeyUnlockf("개인키가 암호화되어 있지 않은데 패스프레이즈가 지정되었습니다")
	}

	var (
		parsed any
		err    error
	)
	if encrypted {
		parsed, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
		if err != nil {
			return nil, certerr.WrapKeyUnlock(err, "패스프레이즈가 올바르지 않거나 개인키 형식이 잘못되었습니다")
		}
	} else {
		parsed, err = parsePlain(block)
		if err != nil {
			return nil, certerr.WrapKeyUnlock(err,
				"개인키를 읽을 수 없습니다 (암호화되어 있다면 패스프레이즈가 필요합니다)")
		}
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, certerr.Validationf("인증서 서명에 쓸 수 없는 키 종류입니다: %T", parsed)
	}
	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return signer, nil
	}
	return nil, certerr.Validationf("인증서 서명에 쓸 수 없는 키 종류입니다: %T", signer)
}

// parsePlain 은 PKCS#8 을 우선 보고, 구형 포맷(PKCS#1·SEC1)도 받아 준다.
// 외부에서 가져온 CA 키가 구형인 경우가 흔하다.
func parsePlain(block *pem.Block) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("PKCS#8·PKCS#1·SEC1 어느 것으로도 읽히지 않습니다")
}

// IsEncryptedPEM 은 헤더만 보고 암호화 여부를 판단한다(프롬프트를 띄울지 결정용).
func IsEncryptedPEM(data []byte) bool {
	text := string(data)
	return strings.Contains(text, pemTypeEncrypted) || strings.Contains(text, "Proc-Type: 4,ENCRYPTED")
}

// PublicMatches 는 키-인증서 짝을 확인한다. 공개키 DER 바이트를 직접 비교한다.
func PublicMatches(key crypto.Signer, pub any) bool {
	a, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return false
	}
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	return string(a) == string(b)
}

// PublicDigest 는 공개키(SubjectPublicKeyInfo DER)의 SHA256 이다.
//
// 개인키 자체를 해싱하지 않는다 — 저장할 필요가 없고, 저장하면 유출 시 오프라인 대조에
// 쓰일 수 있다. 공개키 지문만으로 "같은 키인가" 판정에 충분하다.
func PublicDigest(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", certerr.WrapState(err, "공개키를 직렬화할 수 없습니다: %v", err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum), nil
}

// PublicPEM 은 공개키 PEM 이다(key show --public).
func PublicPEM(key any) ([]byte, error) {
	// 개인키를 넘겨도 공개키를 뽑아 쓴다. 시그니처가 any 라서 개인키를 넘기는 실수가
	// 쉽게 나는데, 그러면 "unsupported public key type: *ecdsa.PrivateKey" 라는
	// 원인을 짐작하기 어려운 오류가 난다. 여기서 흡수한다.
	pub := key
	if signer, ok := key.(crypto.Signer); ok {
		pub = signer.Public()
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, certerr.WrapState(err, "공개키를 직렬화할 수 없습니다: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
