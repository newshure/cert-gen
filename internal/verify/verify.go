// Package verify — 발급한 인증서가 실제로 쓸 수 있는지 확인한다.
//
// 우리가 만든 것을 우리 코드로만 검증하면 서로의 버그를 가려 준다. 그래서 두 가지를 한다.
// Go 의 crypto/x509 로 검증하고, openssl 이 있으면 같은 판단을 openssl 에게도 물어 본다.
// 두 결과가 엇갈리면 그 사실 자체를 보고한다 — 어느 쪽이 맞는지 우리가 정하지 않는다.
//
// 검사는 통과/실패로 끝내지 않고 **무엇을 확인했는지** 를 항목으로 남긴다. "검증 실패" 한
// 줄은 고칠 단서를 주지 않는다.
package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/crl"
	"github.com/newshure/cert-gen/internal/export"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/store"
)

// Status 는 검사 하나의 결과다.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	// StatusSkip 은 확인할 수 없었다는 뜻이다. 통과와 구분해야 한다 — 확인하지 못한 것을
	// 통과로 보여 주면 사용자가 검증됐다고 믿는다.
	StatusSkip Status = "skip"
)

// Check 는 검사 항목 하나다.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// Report 는 검증 결과 전체다.
type Report struct {
	Checks []Check
	// Hostname 은 검사에 쓴 호스트명이다(비어 있으면 호스트명 검사를 하지 않았다).
	Hostname string
}

// OK 는 실패한 검사가 없는지다. 경고와 skip 은 실패가 아니다.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

// Failures 는 실패한 검사들이다.
func (r Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			out = append(out, c)
		}
	}
	return out
}

// Counts 는 상태별 개수다(요약 표시용).
func (r Report) Counts() map[Status]int {
	out := map[Status]int{}
	for _, c := range r.Checks {
		out[c.Status]++
	}
	return out
}

func (r *Report) add(name string, status Status, format string, args ...any) {
	r.Checks = append(r.Checks, Check{
		Name: name, Status: status, Detail: fmt.Sprintf(format, args...),
	})
}

// Options 는 검증 옵션이다.
type Options struct {
	// Hostname 이 있으면 SAN 매칭을 확인한다. 서버 인증서의 진짜 용도가 이것이다.
	Hostname string
	// CheckRevocation 이 true 면 CA 의 CRL 을 읽어 폐기 여부를 본다.
	CheckRevocation bool
	// CrossCheckOpenSSL 이 true 면 openssl 에게 같은 판단을 물어 본다.
	CrossCheckOpenSSL bool
	// Now 를 주면 그 시각 기준으로 유효기간을 본다(테스트용).
	Now time.Time
	// CARecord 는 CRL 을 찾기 위한 발급 CA 다. CheckRevocation 과 함께 쓴다.
	// export.Input 에 넣지 않는 이유: Input 은 암호 재료이고 이것은 DB 레코드다.
	CARecord *store.CA
}

// Run 은 인증서를 검증한다.
func Run(cfg config.Config, in export.Input, opts Options) (Report, error) {
	if in.Cert == nil {
		return Report{}, certerr.Validationf("검증할 인증서가 없습니다")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	report := Report{Hostname: opts.Hostname}

	checkValidity(&report, in.Cert, now)
	checkKeyPair(&report, in)
	checkChain(&report, in, now)
	checkHostname(&report, in.Cert, opts.Hostname)
	checkProfileSanity(&report, in.Cert)
	checkRevocation(&report, cfg, in, opts)
	crossCheckOpenSSL(&report, cfg, in, opts)

	return report, nil
}

func checkValidity(r *Report, cert *x509.Certificate, now time.Time) {
	const name = "유효기간"
	switch {
	case now.Before(cert.NotBefore):
		r.add(name, StatusFail, "아직 유효하지 않습니다 (notBefore: %s)",
			cert.NotBefore.Format(time.RFC3339))
	case now.After(cert.NotAfter):
		r.add(name, StatusFail, "만료되었습니다 (notAfter: %s, %d일 경과)",
			cert.NotAfter.Format(time.RFC3339), int(now.Sub(cert.NotAfter).Hours()/24))
	default:
		remaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		// 30일은 갱신을 준비할 시간이다. 더 짧으면 경고로 올린다.
		status := StatusPass
		if remaining <= 30 {
			status = StatusWarn
		}
		r.add(name, status, "%d일 남음 (만료: %s)", remaining, cert.NotAfter.Format("2006-01-02"))
	}
}

func checkKeyPair(r *Report, in export.Input) {
	const name = "키-인증서 짝"
	if !in.HasKey() {
		// CSR 서명 건은 개인키가 없다. 확인할 수 없는 것은 skip 이다.
		r.add(name, StatusSkip, "개인키가 없습니다(CSR 서명 건이거나 인증서만 주어졌습니다)")
		return
	}
	if keys.PublicMatches(in.Key, in.Cert.PublicKey) {
		r.add(name, StatusPass, "개인키가 인증서의 공개키와 일치합니다")
		return
	}
	// 이것이 틀리면 서버는 기동하지 못한다. 파일로는 멀쩡해 보이므로 꼭 확인해야 한다.
	r.add(name, StatusFail, "개인키가 인증서와 짝이 아닙니다")
}

func checkChain(r *Report, in export.Input, now time.Time) {
	const name = "체인 검증"
	if in.CA == nil {
		r.add(name, StatusSkip, "신뢰 기준이 될 CA 인증서가 주어지지 않았습니다")
		return
	}
	cert := in.Cert
	roots := x509.NewCertPool()
	roots.AddCert(in.CA)
	intermediates := x509.NewCertPool()
	for _, c := range in.Chain {
		if !c.Equal(in.CA) {
			intermediates.AddCert(c)
		}
	}

	// AKI/SKI 를 **먼저** 본다. 체인이 실패할 때 원인을 알려 주는 항목이 바로 이것인데,
	// 체인 검사 뒤에 두고 실패 시 early return 하면 가장 필요한 순간에 단서가 사라진다.
	switch {
	case len(cert.AuthorityKeyId) == 0:
		r.add("AKI/SKI", StatusWarn, "인증서에 Authority Key Identifier 가 없습니다")
	case len(in.CA.SubjectKeyId) == 0:
		r.add("AKI/SKI", StatusWarn, "CA 인증서에 Subject Key Identifier 가 없습니다")
	case !bytes.Equal(cert.AuthorityKeyId, in.CA.SubjectKeyId):
		r.add("AKI/SKI", StatusFail,
			"인증서의 AKI 가 CA 의 SKI 와 다릅니다 — 이 CA 가 발급한 인증서가 아닙니다")
	default:
		r.add("AKI/SKI", StatusPass, "AKI 가 CA 의 SKI 와 일치합니다")
	}

	// KeyUsages 를 비워 두면 Go 가 ServerAuth 를 요구한다. client 전용 인증서가 그 때문에
	// 실패하면 원인을 오해하게 되므로, 인증서가 가진 EKU 를 기준으로 본다.
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: usagesFor(cert),
	})
	if err != nil {
		r.add(name, StatusFail, "CA 로 체인을 세울 수 없습니다: %v", err)
		return
	}
	r.add(name, StatusPass, "CA(%s)까지 체인이 연결됩니다 (길이 %d)",
		in.CA.Subject.CommonName, len(chains[0]))
}

// usagesFor 는 검증에 쓸 EKU 목록이다.
func usagesFor(cert *x509.Certificate) []x509.ExtKeyUsage {
	if len(cert.ExtKeyUsage) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	return cert.ExtKeyUsage
}

func checkHostname(r *Report, cert *x509.Certificate, hostname string) {
	const name = "호스트명 매칭"
	if hostname == "" {
		r.add(name, StatusSkip, "확인할 호스트명이 주어지지 않았습니다")
		return
	}
	if err := cert.VerifyHostname(hostname); err != nil {
		r.add(name, StatusFail, "%q 가 SAN 과 맞지 않습니다: %v (SAN: %s)",
			hostname, err, sanSummary(cert))
		return
	}
	r.add(name, StatusPass, "%q 가 SAN 과 일치합니다", hostname)
}

func sanSummary(cert *x509.Certificate) string {
	var parts []string
	parts = append(parts, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		parts = append(parts, ip.String())
	}
	for _, e := range cert.EmailAddresses {
		parts = append(parts, e)
	}
	for _, u := range cert.URIs {
		parts = append(parts, u.String())
	}
	if len(parts) == 0 {
		return "없음"
	}
	return strings.Join(parts, ", ")
}

// checkProfileSanity 는 "체인은 서는데 클라이언트가 거부하는" 흔한 원인들을 본다.
func checkProfileSanity(r *Report, cert *x509.Certificate) {
	// CN 이 SAN 에 없는 인증서는 체인 검증을 통과하고도 브라우저가 거부한다.
	if cn := cert.Subject.CommonName; cn != "" && looksLikeHostname(cn) {
		if err := cert.VerifyHostname(cn); err != nil {
			r.add("CN in SAN", StatusFail,
				"CN(%q)이 SAN 에 없습니다. 현대 클라이언트는 CN 을 보지 않으므로 거부됩니다", cn)
		} else {
			r.add("CN in SAN", StatusPass, "CN 이 SAN 에 포함되어 있습니다")
		}
	}

	if cert.IsCA {
		r.add("basicConstraints", StatusWarn, "CA:TRUE 입니다 — leaf 인증서로 쓸 수 없습니다")
	} else {
		r.add("basicConstraints", StatusPass, "CA:FALSE (leaf)")
	}

	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		r.add("EKU", StatusWarn, "EKU 가 없습니다. 용도를 제한하지 않은 인증서입니다")
	} else {
		r.add("EKU", StatusPass, "%s", ekuSummary(cert))
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		// TLS 핸드셰이크는 digitalSignature 를 쓴다. 없으면 엄격한 구현이 거부한다.
		r.add("keyUsage", StatusWarn, "digitalSignature 가 없습니다. TLS 에서 거부될 수 있습니다")
	} else {
		r.add("keyUsage", StatusPass, "digitalSignature 포함")
	}

	// 키 강도는 종류별로 기준이 다르다. RSA 2048 과 EC 256 은 둘 다 충분한데 비트 수만
	// 비교하면 EC 가 전부 약한 키로 잡힌다.
	if note := keyStrengthNote(cert.PublicKey); note != "" {
		r.add("키 강도", StatusWarn, "%s", note)
	} else {
		r.add("키 강도", StatusPass, "%s", keys.AlgoOf(cert.PublicKey))
	}
}

// keyStrengthNote 는 약한 키일 때 설명을 돌려준다. 충분하면 빈 문자열이다.
func keyStrengthNote(pub any) string {
	bits := keys.PublicBits(pub)
	switch pub.(type) {
	case *rsa.PublicKey:
		if bits < 2048 {
			return fmt.Sprintf("RSA %d비트입니다. 2048비트 미만은 최신 정책이 거부합니다", bits)
		}
	case *ecdsa.PublicKey:
		// P-224 이하. P-256 은 RSA 3072 에 상응하므로 경고 대상이 아니다.
		if bits < 256 {
			return fmt.Sprintf("ECDSA %d비트 곡선입니다. P-256 이상을 권합니다", bits)
		}
	case ed25519.PublicKey:
		// 고정 강도다. 판단할 것이 없다.
	default:
		return fmt.Sprintf("키 종류를 판단할 수 없습니다: %T", pub)
	}
	return ""
}

func looksLikeHostname(cn string) bool {
	if net.ParseIP(cn) != nil {
		return true
	}
	_, err := names.ValidateDNS(cn)
	return err == nil
}

func ekuSummary(cert *x509.Certificate) string {
	labels := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth: "serverAuth",
		x509.ExtKeyUsageClientAuth: "clientAuth",
		x509.ExtKeyUsageAny:        "any",
	}
	var parts []string
	for _, eku := range cert.ExtKeyUsage {
		if label, ok := labels[eku]; ok {
			parts = append(parts, label)
		} else {
			parts = append(parts, fmt.Sprintf("eku(%d)", eku))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		parts = append(parts, oid.String())
	}
	return strings.Join(parts, ", ")
}

func checkRevocation(r *Report, cfg config.Config, in export.Input, opts Options) {
	const name = "폐기 확인"
	if !opts.CheckRevocation {
		return
	}
	if opts.CARecord == nil {
		r.add(name, StatusSkip, "CA 레코드를 모르므로 CRL 을 찾을 수 없습니다")
		return
	}
	list, err := crl.Load(cfg, *opts.CARecord)
	if err != nil {
		// CRL 이 없는 것은 실패가 아니다. 아직 만들지 않았을 수 있다.
		r.add(name, StatusSkip, "%v", err)
		return
	}
	revoked, err := crl.IsRevoked(list, in.CA, in.Cert)
	if err != nil {
		r.add(name, StatusFail, "%v", err)
		return
	}
	if revoked {
		r.add(name, StatusFail, "이 인증서는 폐기되었습니다 (CRL #%s)", list.Number)
		return
	}
	r.add(name, StatusPass, "CRL #%s 에 없습니다 (다음 갱신: %s)",
		list.Number, list.NextUpdate.Format("2006-01-02"))
}

// crossCheckOpenSSL 은 같은 판단을 openssl 에게 물어 본다.
//
// 우리 코드로 만들고 우리 코드로만 검증하면 서로의 버그를 가려 준다. 두 결과가 엇갈리면
// 그 사실을 보고한다 — 어느 쪽이 맞는지 우리가 정하지 않는다.
func crossCheckOpenSSL(r *Report, cfg config.Config, in export.Input, opts Options) {
	const name = "openssl 교차 검증"
	if !opts.CrossCheckOpenSSL {
		return
	}
	if in.CA == nil {
		r.add(name, StatusSkip, "신뢰 기준이 될 CA 인증서가 없습니다")
		return
	}
	bin := cfg.Tools.OpenSSL
	if bin == "" {
		bin = "openssl"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		r.add(name, StatusSkip, "openssl 을 찾을 수 없습니다(%s)", bin)
		return
	}

	dir, err := os.MkdirTemp("", "cert-gen-verify-")
	if err != nil {
		r.add(name, StatusSkip, "임시 디렉터리를 만들 수 없습니다: %v", err)
		return
	}
	defer os.RemoveAll(dir)

	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(caPath, certbuild.CertPEM(in.CA), 0o600); err != nil {
		r.add(name, StatusSkip, "임시 파일을 쓸 수 없습니다: %v", err)
		return
	}
	if err := os.WriteFile(certPath, certbuild.CertPEM(in.Cert), 0o600); err != nil {
		r.add(name, StatusSkip, "임시 파일을 쓸 수 없습니다: %v", err)
		return
	}

	args := []string{"verify", "-CAfile", caPath}
	if len(in.Chain) > 0 {
		chainPath := filepath.Join(dir, "chain.pem")
		if err := os.WriteFile(chainPath, certbuild.ChainPEM(in.Chain), 0o600); err == nil {
			args = append(args, "-untrusted", chainPath)
		}
	}
	args = append(args, certPath)

	out, runErr := exec.Command(path, args...).CombinedOutput()
	ours := r.chainPassed()
	theirs := runErr == nil

	switch {
	case theirs && ours:
		r.add(name, StatusPass, "openssl 도 검증을 통과시킵니다")
	case !theirs && !ours:
		r.add(name, StatusPass, "openssl 도 같은 이유로 거부합니다: %s", oneLine(out))
	default:
		// 엇갈리면 그것이 가장 중요한 정보다.
		r.add(name, StatusFail,
			"우리 검증(%v)과 openssl(%v)의 판단이 다릅니다: %s", ours, theirs, oneLine(out))
	}
}

func (r Report) chainPassed() bool {
	for _, c := range r.Checks {
		if c.Name == "체인 검증" {
			return c.Status == StatusPass
		}
	}
	return false
}

func oneLine(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return "(출력 없음)"
	}
	return strings.Join(strings.Fields(text), " ")
}
