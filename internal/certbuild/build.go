// Package certbuild — 인증서 조립·서명의 공용 경로.
//
// CA 자기서명과 leaf 서명을 각각 조립하면 SKI/AKI 연결이나 유효기간 계산이 두 곳에서
// 갈라진다. 확장 세트만 profiles 에서 받아오고 조립은 여기 한 곳에서 한다.
package certbuild

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
)

// NewSerial 은 RFC 5280 을 만족하는 serial 을 만든다.
//
// 직접 바이트를 조립하지 않는다 — '양수, 20옥텟 이하, 충분한 엔트로피' 를 손으로 맞추면
// 최상위 비트(음수화)와 길이 상한에서 틀리기 쉽다. 159비트 난수가 그 조건을 모두 만족한다.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, certerr.WrapState(err, "serial 을 만들 수 없습니다: %v", err)
	}
	// 0 은 쓰지 않는다(RFC 는 양수를 요구한다).
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

// SerialHex 는 DB·표시용 정규형이다: 소문자 hex, 짝수 길이(옥텟 경계).
func SerialHex(serial *big.Int) string {
	text := fmt.Sprintf("%x", serial)
	if len(text)%2 != 0 {
		return "0" + text
	}
	return text
}

// SerialFromHex 는 hex 표기를 되돌린다. `aa:bb` 콜론 표기와 `0x` 접두어도 받는다.
func SerialFromHex(text string) (*big.Int, error) {
	cleaned := ""
	for _, r := range text {
		if r != ':' {
			cleaned += string(r)
		}
	}
	if len(cleaned) > 2 && (cleaned[:2] == "0x" || cleaned[:2] == "0X") {
		cleaned = cleaned[2:]
	}
	value, ok := new(big.Int).SetString(cleaned, 16)
	if !ok {
		return nil, certerr.Validationf("serial 을 해석할 수 없습니다: %q", text)
	}
	return value, nil
}

// FormatColons 는 `openssl x509 -text` 와 같은 `aa:bb:cc` 표기다.
// 사람이 눈으로 대조할 때 쓴다.
func FormatColons(hexText string) string {
	out := make([]byte, 0, len(hexText)+len(hexText)/2)
	for i := 0; i < len(hexText); i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		end := i + 2
		if end > len(hexText) {
			end = len(hexText)
		}
		out = append(out, hexText[i:end]...)
	}
	return string(out)
}

// ShortSerial 은 파일명에 쓰는 축약형(앞 8자)이다.
func ShortSerial(hexText string) string {
	if len(hexText) <= 8 {
		return hexText
	}
	return hexText[:8]
}

// ValidityWindow 는 유효기간 창을 만든다.
//
// 시작 시각을 조금 과거로 당긴다. 시계가 몇 분 틀어진 장비에서 갓 발급한 인증서가
// "아직 유효하지 않음" 으로 거부되는 일을 막는다.
func ValidityWindow(days, backdateMinutes int) (time.Time, time.Time, error) {
	if days < 1 {
		return time.Time{}, time.Time{}, certerr.Validationf("유효기간은 1일 이상이어야 합니다: %d", days)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return now.Add(-time.Duration(backdateMinutes) * time.Minute), now.AddDate(0, 0, days), nil
}

// Request 는 인증서 하나를 만드는 데 필요한 모든 것이다.
type Request struct {
	Subject   pkix.Name
	Issuer    *x509.Certificate // nil 이면 자기서명
	PublicKey crypto.PublicKey
	Signer    crypto.Signer
	Profile   profiles.Profile
	Serial    *big.Int
	NotBefore time.Time
	NotAfter  time.Time
	SANs      []names.SAN
}

// Build 는 확장을 붙여 인증서를 만들고 서명한다.
func Build(req Request) (*x509.Certificate, []byte, error) {
	if req.Profile.RequiresSAN && len(req.SANs) == 0 {
		// leaf 에 SAN 이 없으면 현대 클라이언트가 전부 거부한다. 발급 시점에 막는 편이 낫다.
		return nil, nil, certerr.Validationf(
			"%s 에는 SAN 이 최소 1개 필요합니다 (CN 폴백은 RFC 6125 이후 폐기되었습니다)",
			req.Profile.Label)
	}

	dns, ips, uris, emails, err := names.Split(req.SANs)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          req.Serial,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  req.Profile.IsCA,
		KeyUsage:              profiles.KeyUsageFor(req.Profile, req.PublicKey),
		ExtKeyUsage:           req.Profile.ExtKeyUsage,
		DNSNames:              dns,
		IPAddresses:           ips,
		URIs:                  uris,
		EmailAddresses:        emails,
	}
	if req.Profile.IsCA {
		tmpl.MaxPathLen = req.Profile.PathLen
		// pathLen=0 을 '제한 없음' 이 아니라 '0' 으로 넣으려면 이 플래그가 필요하다.
		tmpl.MaxPathLenZero = req.Profile.PathLen == 0
	}

	// SKI 는 Go 가 CA 인증서에 자동으로 넣지만, leaf 에도 넣어 두면 체인 추적이 쉬워진다.
	ski, err := subjectKeyID(req.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	tmpl.SubjectKeyId = ski

	parent := tmpl
	if req.Issuer != nil {
		parent = req.Issuer
		// AKI 는 Go 가 parent.SubjectKeyId 에서 자동으로 넣는다.
		// 발급자에 SKI 가 없는 구형 CA 면 공개키로 직접 만들어 준다.
		if len(parent.SubjectKeyId) == 0 {
			if id, idErr := subjectKeyID(parent.PublicKey); idErr == nil {
				tmpl.AuthorityKeyId = id
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, req.PublicKey, req.Signer)
	if err != nil {
		return nil, nil, certerr.WrapState(err, "인증서를 서명할 수 없습니다: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, certerr.WrapState(err, "만든 인증서를 되읽을 수 없습니다: %v", err)
	}
	return cert, der, nil
}

// subjectKeyID 는 RFC 5280 권고(공개키 비트열의 SHA-1)가 아니라 SHA-256 앞 20바이트를 쓴다.
// SKI 는 식별자일 뿐 보안 속성이 아니지만, 굳이 SHA-1 을 새로 넣을 이유가 없다.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, certerr.WrapState(err, "공개키를 직렬화할 수 없습니다: %v", err)
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// Fingerprint 는 인증서의 SHA-256 지문이다(소문자 hex).
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// SigningHashNote 는 서명 해시 선택을 설명용으로 노출한다(진단 출력).
func SigningHashNote(signer crypto.Signer) string {
	h := keys.SignatureHash(signer)
	if h == 0 {
		return "알고리즘 내장"
	}
	return h.String()
}

// CertPEM 은 인증서 PEM 이다.
func CertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// ChainPEM 은 여러 인증서를 이어 붙인 PEM 이다.
func ChainPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, CertPEM(c)...)
	}
	return out
}
