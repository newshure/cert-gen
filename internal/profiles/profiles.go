// Package profiles — 발급 프로필. 확장(extension) 세트의 단일 출처.
//
// 손으로 설정을 쓰면 basicConstraints / keyUsage / extendedKeyUsage 를 매번 다르게 적게 되고,
// 그 차이가 "어떤 클라이언트에서만 실패" 로 돌아온다. 표로 고정하고 발급 코드가 여기서만
// 확장을 받아가게 해서 그 변동을 없앤다.
//
// 중간 CA 생성은 범위 밖이다(Root → leaf 1단계). 따라서 root-ca 의 pathLen 은 0 이다.
package profiles

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
)

const (
	RootCA       = "root-ca"
	Server       = "server"
	Client       = "client"
	ServerClient = "server+client"
)

// Leaf 는 leaf 발급 화면·CLI 에 노출되는 프로필이다(CA 프로필은 CA 생성 경로 전용).
var Leaf = []string{Server, Client, ServerClient}

// Profile 은 한 용도의 확장 세트다.
type Profile struct {
	Name string
	// Label 은 상세·출력용 전체 이름.
	Label string
	// Short 는 좁은 드롭다운용. 길면 줄바꿈되어 폼이 한 줄씩 늘어난다.
	Short string
	IsCA  bool
	// PathLen 은 basicConstraints 의 pathLenConstraint. CA 가 아니면 의미 없다.
	PathLen int
	// KeyUsage 는 RSA 기준이다. EC/Ed25519 는 KeyUsageFor 가 걸러 준다.
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	// RequiresSAN: leaf 는 SAN 이 필수다(CN 폴백은 RFC 6125 이후 폐기되었다).
	RequiresSAN bool
}

// MenuLabel 은 좁은 화면용 이름이다.
func (p Profile) MenuLabel() string {
	if p.Short != "" {
		return p.Short
	}
	return p.Label
}

var all = map[string]Profile{
	RootCA: {
		Name:  RootCA,
		Label: "Root CA",
		Short: "Root CA",
		IsCA:  true,
		// 0 = 이 CA 아래에 또 다른 CA 를 둘 수 없다. 중간 CA 를 만들지 않는 설계와 일치한다.
		PathLen:     0,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		RequiresSAN: false,
	},
	Server: {
		Name:        Server,
		Label:       "서버 인증서 (TLS serverAuth)",
		Short:       "서버 (serverAuth)",
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		RequiresSAN: true,
	},
	Client: {
		Name:        Client,
		Label:       "클라이언트 인증서 (mTLS clientAuth)",
		Short:       "클라이언트 (clientAuth)",
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		RequiresSAN: true,
	},
	ServerClient: {
		Name:        ServerClient,
		Label:       "서버 + 클라이언트 (양방향 TLS)",
		Short:       "서버+클라이언트",
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		RequiresSAN: true,
	},
}

// Get 은 이름으로 프로필을 찾는다.
func Get(name string) (Profile, error) {
	p, ok := all[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Profile{}, certerr.Validationf(
			"지원하지 않는 프로필입니다: %q (사용 가능: %s)", name, strings.Join(Leaf, ", "))
	}
	return p, nil
}

// GetLeaf 는 leaf 용 프로필만 받는다. CA 프로필로 leaf 를 발급하려는 시도를 막는다.
func GetLeaf(name string) (Profile, error) {
	p, err := Get(name)
	if err != nil {
		return Profile{}, err
	}
	if p.IsCA {
		return Profile{}, certerr.Validationf("%s 은 CA 프로필입니다. leaf 발급에는 쓸 수 없습니다", p.Name)
	}
	return p, nil
}

// KeyUsageFor 는 키 종류에 맞게 조정한 KeyUsage 다.
//
// EC/Ed25519 키에 keyEncipherment 를 넣으면 의미가 없다(RSA 키 전송 전용 비트).
// 일부 검사기가 경고하고, 실무에서 "왜 경고가 뜨나" 를 다시 조사하게 되므로 제거한다.
func KeyUsageFor(p Profile, pub any) x509.KeyUsage {
	usage := p.KeyUsage
	switch pub.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		usage &^= x509.KeyUsageKeyEncipherment
	}
	return usage
}

// Label 은 이름에 해당하는 표시 문자열이다. 모르는 이름은 그대로 돌려준다.
func Label(name string) string {
	if p, ok := all[name]; ok {
		return p.Label
	}
	return name
}
