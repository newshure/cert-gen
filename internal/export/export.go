// Package export — 발급 결과를 다른 포맷으로 변환한다.
//
// 변환 대상은 두 가지다. 우리 발급 이력(번들)과 **외부 파일**이다. 실무에서 가장 잦은 변환이
// "남이 준 PEM 을 p12 로" 이므로 이력 기반만 지원하면 기능이 반쪽이 된다. 두 입력을 Input
// 하나로 모아 이후 경로를 공유한다.
//
// PKCS#12·JKS 모두 Go 로 직접 쓴다. keytool(OpenJDK) 을 부르지 않으므로 JDK 가 없는 서버에서도
// 동작하고, 비밀번호가 외부 프로세스의 argv 로 새지 않는다.
package export

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/keys"
)

// Format 은 지원하는 출력 포맷이다.
type Format string

const (
	FormatPEM   Format = "pem"
	FormatDER   Format = "der"
	FormatP12   Format = "p12"
	FormatJKS   Format = "jks"
	FormatK8s   Format = "k8s"
	FormatTrust Format = "truststore" // CA 만 담은 신뢰 저장소
)

// Formats 는 사용자에게 보여 줄 순서대로의 전체 목록이다.
var Formats = []Format{FormatPEM, FormatDER, FormatP12, FormatJKS, FormatK8s, FormatTrust}

// Input 은 변환할 재료다. 번들에서 꺼냈든 외부 파일에서 읽었든 여기로 수렴한다.
type Input struct {
	Cert  *x509.Certificate
	Chain []*x509.Certificate // leaf 제외, 상위 순서
	CA    *x509.Certificate   // Root. 신뢰 등록·truststore 용
	Key   crypto.Signer       // 없을 수 있다(CSR 서명 건, 인증서만 변환)
	// Label 은 별칭 기본값을 만들 때 쓴다(보통 CN).
	Label string
}

// HasKey 는 개인키를 포함한 포맷으로 내보낼 수 있는지다.
func (in Input) HasKey() bool { return in.Key != nil }

// chainWithCA 는 p12/JKS 에 넣을 상위 인증서 목록이다.
//
// Root 를 포함한다. PEM 의 fullchain 과 다른 판단인데, 이유가 있다. fullchain 은 서버가
// 핸드셰이크에 보내는 것이라 Root 를 넣으면 매 연결마다 쓸데없이 바이트를 쓴다. p12/JKS 는
// 보통 그 자체로 신뢰 경로를 완성해야 하는 키스토어라 Root 가 있어야 Java 가 체인을 세운다.
func (in Input) chainWithCA() []*x509.Certificate {
	out := append([]*x509.Certificate{}, in.Chain...)
	if in.CA != nil && !containsCert(out, in.CA) && !in.CA.Equal(in.Cert) {
		out = append(out, in.CA)
	}
	return out
}

func containsCert(list []*x509.Certificate, want *x509.Certificate) bool {
	for _, c := range list {
		if c.Equal(want) {
			return true
		}
	}
	return false
}

// Options 는 변환 옵션이다.
type Options struct {
	Password string
	Alias    string
	// Legacy 는 구형 소비자(Java 8, 옛 Windows)를 위해 약한 알고리즘을 쓴다.
	Legacy bool
}

func (o Options) alias(fallback string) string {
	if o.Alias != "" {
		return o.Alias
	}
	if fallback == "" {
		return "cert"
	}
	// JKS 별칭은 소문자로 정규화된다. 미리 맞춰 두면 keytool -list 결과와 어긋나지 않는다.
	return strings.ToLower(fallback)
}

// Result 는 변환 산출물이다. 파일로 쓰는 일은 호출자(CLI/TUI)가 한다.
type Result struct {
	Data     []byte
	Filename string
	Warnings []string
}

// --- PEM / DER ---------------------------------------------------------------

// CertPEM 은 leaf 인증서 하나다.
func CertPEM(in Input) Result {
	return Result{Data: certbuild.CertPEM(in.Cert), Filename: "cert.pem"}
}

// FullchainPEM 은 leaf + 상위 체인이다. Root 는 넣지 않는다(클라이언트가 신뢰해야 한다).
func FullchainPEM(in Input) Result {
	data := certbuild.CertPEM(in.Cert)
	if len(in.Chain) > 0 {
		data = append(data, certbuild.ChainPEM(in.Chain)...)
	}
	return Result{Data: data, Filename: "fullchain.pem"}
}

// KeyPEM 은 개인키다. passphrase 가 비면 평문 PKCS#8 이다.
func KeyPEM(in Input, passphrase string) (Result, error) {
	if !in.HasKey() {
		return Result{}, certerr.Validationf("이 인증서에는 개인키가 없습니다(CSR 서명 건)")
	}
	data, err := keys.ToPEM(in.Key, passphrase)
	if err != nil {
		return Result{}, err
	}
	res := Result{Data: data, Filename: "privkey.pem"}
	if passphrase != "" {
		res.Warnings = append(res.Warnings,
			"암호화된 개인키입니다. 서버(nginx·Tomcat 등)에 쓰면 기동할 때마다 패스프레이즈를 묻습니다")
	}
	return res, nil
}

// DER 은 인증서의 DER 바이트다. 변환이 아니라 그냥 원본이다.
func DER(in Input) Result {
	return Result{Data: in.Cert.Raw, Filename: "cert.der"}
}

// --- PKCS#12 -----------------------------------------------------------------

// P12 는 개인키 + 인증서 + 체인을 하나의 PKCS#12 로 묶는다.
func P12(in Input, opts Options) (Result, error) {
	if !in.HasKey() {
		return Result{}, certerr.Validationf(
			"PKCS#12 에는 개인키가 필요합니다. 이 인증서에는 개인키가 없습니다(CSR 서명 건)")
	}

	// Modern2023 으로 **고정**한다. 라이브러리의 Modern 별칭은 버전이 오르면 가리키는 대상이
	// 바뀌도록 설계돼 있어서, 의존성만 올려도 산출물의 호환 범위가 조용히 달라진다.
	// Modern2023 = PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC → OpenSSL 1.1.1+, Java 12+.
	encoder := pkcs12.Modern2023
	var warnings []string
	if opts.Legacy {
		// Java 8 이나 옛 Windows 가 상대일 때만. 약한 알고리즘이라는 사실을 숨기지 않는다.
		encoder = pkcs12.LegacyDES
		warnings = append(warnings,
			"legacy 모드: 3DES·SHA-1 을 씁니다. 구형 Java 8·Windows 호환용이며 암호 강도가 낮습니다")
	}
	warnings = append(warnings, passwordWarnings(opts.Password, opts.Legacy)...)

	data, err := encoder.Encode(in.Key, in.Cert, in.chainWithCA(), opts.Password)
	if err != nil {
		return Result{}, certerr.WrapState(err, "PKCS#12 생성 실패: %v", err)
	}
	return Result{Data: data, Filename: "keystore.p12", Warnings: warnings}, nil
}

// TrustStoreP12 는 CA 만 담은 PKCS#12 신뢰 저장소다. 클라이언트 쪽에 배포한다.
func TrustStoreP12(in Input, opts Options) (Result, error) {
	ca := in.CA
	if ca == nil {
		return Result{}, certerr.Validationf("신뢰 저장소를 만들 CA 인증서가 없습니다")
	}
	encoder := pkcs12.Modern2023
	if opts.Legacy {
		encoder = pkcs12.LegacyDES
	}
	data, err := encoder.EncodeTrustStore([]*x509.Certificate{ca}, opts.Password)
	if err != nil {
		return Result{}, certerr.WrapState(err, "신뢰 저장소 생성 실패: %v", err)
	}
	return Result{
		Data: data, Filename: "truststore.p12",
		Warnings: passwordWarnings(opts.Password, opts.Legacy),
	}, nil
}

func passwordWarnings(password string, legacy bool) []string {
	var out []string
	if password == "" {
		// 빈 암호를 막지는 않는다. 폐쇄망에서 파일 권한으로만 보호하는 운용이 실제로 있다.
		out = append(out, "비밀번호가 비어 있습니다. 파일 권한으로만 보호됩니다")
		return out
	}
	if !legacy && len(password) < 16 {
		// 반복 횟수가 2048 이라 짧은 암호는 무차별 대입을 사실상 막지 못한다.
		out = append(out, fmt.Sprintf(
			"비밀번호가 짧습니다(%d자). PKCS#12 의 KDF 반복은 2048회라 짧은 암호는 보호가 되지 않습니다. "+
				"16자 이상(예: openssl rand -hex 16)을 권합니다", len(password)))
	}
	return out
}

// --- JKS ---------------------------------------------------------------------

// jksEpoch — JKS 항목의 생성 시각. 고정해 두면 같은 입력이 같은 바이트를 낸다.
var jksEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// JKS 는 Java KeyStore 를 직접 쓴다.
//
// keytool 을 부르지 않는다. JDK 가 없는 서버에서도 되고, 비밀번호가 다른 프로세스의
// argv(/proc/<pid>/cmdline)로 노출되지 않는다.
//
// JKS 자체는 레거시다. JDK 9+ 의 기본 키스토어는 PKCS#12 이고 Java 8u60+ 도 p12 를 직접
// 읽는다. 그래도 지원하는 이유는 폐쇄망에 그것만 받는 장비·앱이 남아 있기 때문이다.
func JKS(in Input, opts Options) (Result, error) {
	if !in.HasKey() {
		return Result{}, certerr.Validationf(
			"JKS 에는 개인키가 필요합니다. 이 인증서에는 개인키가 없습니다(CSR 서명 건)")
	}
	if opts.Password == "" {
		// p12 와 달리 여기서는 거부한다. JKS 는 빈 암호로 저장해도 Java 쪽에서 읽기가
		// 일관되지 않아, 되는 줄 알고 배포했다가 기동 실패로 돌아온다.
		return Result{}, certerr.Validationf("JKS 에는 비밀번호가 필요합니다(최소 6자)")
	}
	if len(opts.Password) < 6 {
		// Java 의 keytool 이 강제하는 하한이다. 더 짧으면 keytool 로 다시 열지 못한다.
		return Result{}, certerr.Validationf("JKS 비밀번호는 6자 이상이어야 합니다(Java 제약)")
	}

	keyDER, err := keys.MarshalPKCS8(in.Key)
	if err != nil {
		return Result{}, err
	}

	chain := []keystore.Certificate{{Type: "X509", Content: in.Cert.Raw}}
	for _, c := range in.chainWithCA() {
		chain = append(chain, keystore.Certificate{Type: "X509", Content: c.Raw})
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry(opts.alias(in.Label), keystore.PrivateKeyEntry{
		CreationTime:     jksEpoch,
		PrivateKey:       keyDER,
		CertificateChain: chain,
	}, []byte(opts.Password)); err != nil {
		return Result{}, certerr.WrapState(err, "JKS 항목 생성 실패: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(opts.Password)); err != nil {
		return Result{}, certerr.WrapState(err, "JKS 생성 실패: %v", err)
	}
	return Result{
		Data: buf.Bytes(), Filename: "keystore.jks",
		Warnings: []string{
			"JKS 는 레거시 포맷입니다. JDK 9+ 의 기본 키스토어는 PKCS#12 이고 Java 8u60+ 도 " +
				"PKCS#12 를 직접 읽습니다. 가능하면 keystore.p12 를 쓰세요",
		},
	}, nil
}

// TrustStoreJKS 는 CA 만 담은 JKS 신뢰 저장소다. Java 클라이언트의 truststore 로 쓴다.
func TrustStoreJKS(in Input, opts Options) (Result, error) {
	ca := in.CA
	if ca == nil {
		return Result{}, certerr.Validationf("신뢰 저장소를 만들 CA 인증서가 없습니다")
	}
	if len(opts.Password) < 6 {
		return Result{}, certerr.Validationf("JKS 비밀번호는 6자 이상이어야 합니다(Java 제약)")
	}
	alias := opts.alias(commonNameOr(ca, "ca"))

	ks := keystore.New()
	if err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
		CreationTime: jksEpoch,
		Certificate:  keystore.Certificate{Type: "X509", Content: ca.Raw},
	}); err != nil {
		return Result{}, certerr.WrapState(err, "JKS 신뢰 항목 생성 실패: %v", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(opts.Password)); err != nil {
		return Result{}, certerr.WrapState(err, "JKS 신뢰 저장소 생성 실패: %v", err)
	}
	return Result{Data: buf.Bytes(), Filename: "truststore.jks"}, nil
}

func commonNameOr(c *x509.Certificate, fallback string) string {
	if c != nil && c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return fallback
}
