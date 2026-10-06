// Package csr — CSR 생성과 외부 CSR 해석.
//
// 두 방향이 있다. 우리가 외부 CA 에 제출할 CSR 을 만드는 쪽(Create)과, 남이 보낸 CSR 을
// 읽어 우리 CA 로 서명하는 쪽(Parse → issue.SignCSR)이다.
//
// 서명 쪽에서 지켜야 할 규칙이 하나 있다. **CSR 에 담긴 확장(extension)은 믿지 않는다.**
// CSR 은 요청자가 통제하는 입력이고, basicConstraints CA:TRUE 를 넣어 보내는 것도 막을 수
// 없다. 그대로 복사하면 leaf 를 요청한 상대에게 CA 를 발급하는 사고가 된다. 그래서 이 패키지는
// CSR 에서 **공개키·Subject·SAN 만** 꺼내고, 확장은 issue 쪽이 우리 프로필로 새로 만든다.
package csr

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
)

const pemTypeCSR = "CERTIFICATE REQUEST"

// Created 는 생성한 CSR 과 그 짝 개인키다.
type Created struct {
	CSRPEM  []byte
	KeyPEM  []byte
	Key     crypto.Signer
	Request *x509.CertificateRequest
	SANs    []names.SAN
	// KeyEncrypted 는 KeyPEM 이 암호화되었는지다.
	KeyEncrypted bool
}

// CreateOptions 는 CSR 생성 입력이다.
type CreateOptions struct {
	Subject   names.Subject
	SANValues []string
	KeyAlgo   string
	// Passphrase 가 있으면 개인키를 암호화해 저장한다. 기본은 평문이다 — 이 키는 결국
	// 서버가 읽어야 하고, 암호화하면 기동할 때마다 패스프레이즈를 묻는다.
	Passphrase string
	// ExistingKey 가 있으면 미리 만들어 둔 키로 CSR 을 만든다.
	ExistingKey crypto.Signer
}

// Create 는 외부 CA 에 제출할 CSR 과 개인키를 만든다.
//
// 개인키는 **우리 쪽에 남는다.** CSR 만 외부로 나가고 개인키는 절대 나가지 않는다는 것이
// CSR 을 쓰는 이유 자체다.
func Create(opts CreateOptions) (Created, error) {
	algo := opts.KeyAlgo
	if algo == "" {
		algo = "rsa2048"
	}
	if _, err := keys.SpecFor(algo); err != nil {
		return Created{}, err
	}

	subject, err := names.BuildSubject(opts.Subject)
	if err != nil {
		return Created{}, err
	}
	sans, err := names.BuildSANs(opts.Subject.CommonName, opts.SANValues)
	if err != nil {
		return Created{}, err
	}
	if len(sans) == 0 {
		// SAN 없는 CSR 을 받아 주는 CA 는 거의 없고, 받아 줘도 현대 클라이언트가 그 결과를
		// 거부한다. 제출하고 며칠 기다린 뒤 알게 되는 편이 훨씬 비싸다.
		return Created{}, certerr.Validationf(
			"SAN 이 없습니다. CN(%q)이 호스트명 형식이 아니면 SAN 을 최소 1개 지정해야 합니다",
			opts.Subject.CommonName)
	}

	signer := opts.ExistingKey
	if signer == nil {
		signer, err = keys.Generate(algo)
		if err != nil {
			return Created{}, err
		}
	}

	dns, ips, uris, emails, err := names.Split(sans)
	if err != nil {
		return Created{}, err
	}
	// SignatureAlgorithm 을 지정하지 않는다. Go 가 키 종류와 곡선 크기에 맞는 해시를
	// 고른다(P-384 면 SHA-384, Ed25519 면 내장). 우리가 표를 들고 다니면 그 표가 틀릴 뿐이다.
	template := &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dns,
		IPAddresses:    ips,
		URIs:           uris,
		EmailAddresses: emails,
	}
	der, err := x509.CreateCertificateRequest(nil, template, signer)
	if err != nil {
		return Created{}, certerr.WrapState(err, "CSR 을 만들 수 없습니다: %v", err)
	}
	// 만든 것을 되읽어 확인한다. 서명이 깨진 CSR 을 제출하면 거절 사유가 불명확하게 돌아온다.
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return Created{}, certerr.WrapState(err, "만든 CSR 을 되읽을 수 없습니다: %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		return Created{}, certerr.WrapState(err, "만든 CSR 의 서명이 올바르지 않습니다: %v", err)
	}

	keyPEM, err := keys.ToPEM(signer, opts.Passphrase)
	if err != nil {
		return Created{}, err
	}
	return Created{
		CSRPEM:       pem.EncodeToMemory(&pem.Block{Type: pemTypeCSR, Bytes: der}),
		KeyPEM:       keyPEM,
		Key:          signer,
		Request:      parsed,
		SANs:         sans,
		KeyEncrypted: opts.Passphrase != "",
	}, nil
}

// Parsed 는 해석한 외부 CSR 이다.
type Parsed struct {
	Request    *x509.CertificateRequest
	PEM        []byte
	CommonName string
	SANs       []names.SAN
	KeyAlgo    string
	// Warnings 는 서명을 막지는 않지만 알려야 할 사항이다.
	Warnings []string
}

// ParseFile 은 파일에서 CSR 을 읽는다.
func ParseFile(path string) (Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Parsed{}, certerr.WrapState(err, "CSR 파일을 읽을 수 없습니다: %s (%v)", path, err)
	}
	return Parse(data)
}

// Parse 는 CSR PEM(또는 DER)을 해석한다.
//
// 서명을 반드시 확인한다. 확인하지 않으면 공개키와 Subject 가 같은 주체에게서 왔다는 보장이
// 없어, 남의 공개키로 아무 이름의 인증서를 받아 갈 수 있다.
func Parse(data []byte) (Parsed, error) {
	der, normalized, err := decodeCSR(data)
	if err != nil {
		return Parsed{}, err
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return Parsed{}, certerr.Validationf("CSR 을 해석할 수 없습니다: %v", err)
	}
	if err := req.CheckSignature(); err != nil {
		return Parsed{}, certerr.Validationf(
			"CSR 서명이 올바르지 않습니다. 공개키와 Subject 가 같은 주체에게서 왔다고 "+
				"볼 수 없습니다: %v", err)
	}

	algo := keys.AlgoOf(req.PublicKey)
	if algo == "" {
		return Parsed{}, certerr.Validationf(
			"지원하지 않는 공개키 종류입니다: %T", req.PublicKey)
	}

	out := Parsed{
		Request: req, PEM: normalized,
		CommonName: req.Subject.CommonName, KeyAlgo: algo,
	}
	out.SANs, out.Warnings, err = sansFromRequest(req)
	if err != nil {
		return Parsed{}, err
	}
	if weak := weakKeyWarning(req.PublicKey); weak != "" {
		out.Warnings = append(out.Warnings, weak)
	}
	if note := extensionWarning(req); note != "" {
		out.Warnings = append(out.Warnings, note)
	}
	return out, nil
}

func decodeCSR(data []byte) (der, normalized []byte, err error) {
	// PEM 이 먼저다. 실무에서 오는 것은 거의 PEM 이고, DER 은 바이너리로 붙여넣기가 깨진
	// 경우를 구제하기 위한 보조 경로다.
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != pemTypeCSR && !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
			return nil, nil, certerr.Validationf(
				"CSR 이 아닌 PEM 입니다(%s). 인증서나 개인키를 주신 것 같습니다", block.Type)
		}
		return block.Bytes, pem.EncodeToMemory(&pem.Block{Type: pemTypeCSR, Bytes: block.Bytes}), nil
	}
	if _, parseErr := x509.ParseCertificateRequest(data); parseErr == nil {
		return data, pem.EncodeToMemory(&pem.Block{Type: pemTypeCSR, Bytes: data}), nil
	}
	return nil, nil, certerr.Validationf(
		"CSR 을 읽을 수 없습니다. PEM(-----BEGIN CERTIFICATE REQUEST-----) 또는 DER 이어야 합니다")
}

// sansFromRequest 는 CSR 의 SAN 을 우리 표현으로 옮긴다.
//
// CSR 에 SAN 이 없고 CN 이 호스트명이면 CN 을 SAN 으로 올린다. CN-only 인증서는 현대
// 클라이언트가 거부하므로, 그대로 발급하면 쓸 수 없는 인증서가 나간다.
func sansFromRequest(req *x509.CertificateRequest) ([]names.SAN, []string, error) {
	var (
		values   []string
		warnings []string
	)
	for _, d := range req.DNSNames {
		values = append(values, names.TypeDNS+":"+d)
	}
	for _, ip := range req.IPAddresses {
		values = append(values, names.TypeIP+":"+ip.String())
	}
	for _, u := range req.URIs {
		values = append(values, names.TypeURI+":"+u.String())
	}
	for _, e := range req.EmailAddresses {
		values = append(values, names.TypeEmail+":"+e)
	}

	if len(values) == 0 {
		if req.Subject.CommonName == "" {
			return nil, nil, certerr.Validationf("CSR 에 SAN 도 CN 도 없습니다")
		}
		warnings = append(warnings,
			"CSR 에 SAN 이 없어 CN 을 SAN 으로 사용합니다. CN 만 있는 인증서는 현대 "+
				"클라이언트가 거부하므로, 의도한 이름이 맞는지 확인하세요")
	}

	sans, err := names.BuildSANs(req.Subject.CommonName, values)
	if err != nil {
		return nil, nil, err
	}
	return sans, warnings, nil
}

func weakKeyWarning(pub crypto.PublicKey) string {
	bits := keys.PublicBits(pub)
	if bits > 0 && bits < 2048 {
		// 거부하지는 않는다. 폐쇄망 레거시 장비가 1024비트 키를 내놓는 경우가 실제로 있고,
		// 그 판단은 운영자 몫이다. 다만 모른 채로 지나가게 하지는 않는다.
		return "요청된 공개키가 2048비트 미만입니다. 최신 클라이언트와 OS 정책이 거부할 수 있습니다"
	}
	return ""
}

// extensionWarning 은 CSR 이 확장을 요청했을 때 그것을 쓰지 않는다는 사실을 알린다.
//
// 조용히 무시하면 요청자는 자기가 넣은 EKU 가 반영됐다고 믿는다.
func extensionWarning(req *x509.CertificateRequest) string {
	for _, attr := range req.Extensions {
		switch {
		case attr.Id.Equal(oidBasicConstraints):
			return "CSR 이 basicConstraints 를 요청했습니다. 무시하고 우리 프로필을 적용합니다 " +
				"(CSR 의 확장을 믿으면 leaf 요청자에게 CA 를 발급하는 사고가 가능합니다)"
		case attr.Id.Equal(oidKeyUsage), attr.Id.Equal(oidExtKeyUsage):
			return "CSR 이 keyUsage/EKU 를 요청했습니다. 무시하고 발급 프로필의 값을 사용합니다"
		}
	}
	return ""
}

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)
