// Package names — Subject DN 조립과 SAN 파싱.
//
// SAN 을 "타입을 골라 입력" 시키지 않고 **값만 받아 자동 판별**한다. 손으로 쓰는 설정에서
// 가장 자주 틀리는 부분이 DNS:/IP: 를 잘못 붙이는 것이고, IP 를 DNS 로 넣으면 브라우저가
// 조용히 거부한다. 필요하면 dns:/ip: 접두어로 명시할 수 있다.
//
// CN 은 **항상 SAN 에도 넣는다.** CN 만 있는 인증서는 현대 클라이언트가 거부한다
// (RFC 6125 이후 CN 폴백 폐기). 이것을 선택으로 두면 "왜 브라우저가 거부하나" 를 또
// 디버깅하게 된다.
package names

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/newshure/cert-gen/internal/certerr"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// SAN 타입. DB(sans_json)와 CLI 접두어가 같은 어휘를 쓴다.
const (
	TypeDNS   = "dns"
	TypeIP    = "ip"
	TypeURI   = "uri"
	TypeEmail = "email"
)

var sanTypes = map[string]bool{TypeDNS: true, TypeIP: true, TypeURI: true, TypeEmail: true}

// 라벨 하나의 규칙(LDH: letter/digit/hyphen). 와일드카드는 별도로 처리한다.
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// SAN 은 SAN 항목 하나다.
type SAN struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Display 는 `DNS:a.example.com` 형태다.
func (s SAN) Display() string { return strings.ToUpper(s.Type) + ":" + s.Value }

// Subject 는 Subject DN 구성 요소다. CN 만 필수다.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	Email              string
}

// idnaProfile 은 인증서에 넣을 A-label 변환용이다. 조회(Lookup)보다 관대한
// Registration 프로파일을 쓰지 않는 이유는, 인증서에 들어가는 이름은 조회에 쓰이기 때문이다.
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false))

// Slugify 는 파일시스템·CLI 식별자용 slug 다.
//
// CA 디렉터리명과 번들 파일명에 쓴다. 와일드카드(*)와 점을 바꿔 셸에서 글로빙되거나
// 숨김 파일이 되는 사고를 막는다.
func Slugify(text, fallback string) string {
	decomposed := norm.NFKD.String(text)
	var b strings.Builder
	for _, r := range decomposed {
		if r > unicode.MaxASCII {
			continue // ASCII 가 아닌 것은 버린다(파일명은 ASCII 로 유지한다)
		}
		b.WriteRune(r)
	}
	s := strings.ToLower(b.String())
	s = strings.ReplaceAll(s, "*", "wildcard")
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return fallback
	}
	return s
}

// ValidateDNS 는 DNS 이름을 검증하고 정규화한다(소문자, IDNA A-label, 끝점 제거).
func ValidateDNS(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host == "" {
		return "", certerr.Validationf("빈 DNS 이름입니다")
	}
	if len(host) > 253 {
		return "", certerr.Validationf("DNS 이름이 253자를 넘습니다: %.40s...", host)
	}

	labels := strings.Split(host, ".")
	wildcard := labels[0] == "*"
	if wildcard {
		// 와일드카드는 최좌측 레이블 하나만, 그 아래로 레이블이 2개 이상 있어야 한다.
		// `*.com` 은 클라이언트가 거부하므로 발급 자체를 막는다.
		if len(labels) < 3 {
			return "", certerr.Validationf("와일드카드는 최소 3개 레이블이 필요합니다(예: *.example.com): %q", value)
		}
		labels = labels[1:]
	}
	for _, l := range labels {
		if strings.Contains(l, "*") {
			return "", certerr.Validationf("와일드카드는 최좌측 레이블 하나만 허용합니다: %q", value)
		}
	}

	out := make([]string, 0, len(labels)+1)
	if wildcard {
		out = append(out, "*")
	}
	for _, l := range labels {
		ascii := l
		if !isASCII(l) {
			converted, err := idnaProfile.ToASCII(l)
			if err != nil {
				return "", certerr.WrapValidation(err, "호스트명을 ASCII(IDNA)로 변환할 수 없습니다: %q", l)
			}
			ascii = converted
		}
		if !labelRe.MatchString(ascii) {
			return "", certerr.Validationf("DNS 레이블이 올바르지 않습니다: %q (전체: %q)", l, value)
		}
		out = append(out, ascii)
	}
	return strings.Join(out, "."), nil
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// ParseSAN 은 한 줄을 SAN 으로 바꾼다. `type:value` 접두어가 있으면 그것을 따르고 없으면 추론한다.
func ParseSAN(raw string) (SAN, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return SAN{}, certerr.Validationf("빈 SAN 항목입니다")
	}

	explicit := ""
	if head, tail, found := strings.Cut(text, ":"); found {
		if sanTypes[strings.ToLower(head)] {
			explicit = strings.ToLower(head)
			text = strings.TrimSpace(tail)
			if text == "" {
				return SAN{}, certerr.Validationf("SAN 값이 비어 있습니다: %q", raw)
			}
		}
	}

	switch {
	case explicit == TypeIP || (explicit == "" && looksLikeIP(text)):
		value, err := parseIP(text)
		if err != nil {
			return SAN{}, err
		}
		return SAN{Type: TypeIP, Value: value}, nil
	case explicit == TypeEmail || (explicit == "" && strings.Contains(text, "@")):
		return SAN{Type: TypeEmail, Value: text}, nil
	case explicit == TypeURI || (explicit == "" && strings.Contains(text, "://")):
		if _, err := url.Parse(text); err != nil {
			return SAN{}, certerr.WrapValidation(err, "URI 가 올바르지 않습니다: %q", text)
		}
		return SAN{Type: TypeURI, Value: text}, nil
	default:
		value, err := ValidateDNS(text)
		if err != nil {
			return SAN{}, err
		}
		return SAN{Type: TypeDNS, Value: value}, nil
	}
}

func looksLikeIP(text string) bool {
	if net.ParseIP(text) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(text)
	return err == nil
}

func parseIP(text string) (string, error) {
	if ip := net.ParseIP(text); ip != nil {
		return ip.String(), nil
	}
	// 네트워크 표기도 받아 둔다. SAN 에서는 드물지만 내부 서비스 인증서에 쓰이는 경우가 있다.
	if _, network, err := net.ParseCIDR(text); err == nil {
		return network.String(), nil
	}
	return "", certerr.Validationf("IP 주소가 올바르지 않습니다: %q", text)
}

// BuildSANs 는 CN 을 선두에 포함한 SAN 목록을 만든다(중복 제거, 입력 순서 유지).
//
// 입력 한 줄에 쉼표로 여러 개를 적는 것도 받는다(TUI 의 여러 줄 입력과 CLI 의 반복 옵션을
// 같은 함수로 처리하기 위함).
func BuildSANs(commonName string, raw []string) ([]SAN, error) {
	var out []SAN
	seen := map[string]bool{}

	add := func(s SAN) {
		key := s.Type + ":" + s.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}

	if cn := strings.TrimSpace(commonName); cn != "" {
		// CN 이 호스트명이 아닌 경우(예: "hd Root CA")는 SAN 에 넣지 않는다.
		if s, err := ParseSAN(cn); err == nil {
			add(s)
		}
	}

	for _, line := range raw {
		for _, piece := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r'
		}) {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			s, err := ParseSAN(piece)
			if err != nil {
				return nil, err
			}
			add(s)
		}
	}
	return out, nil
}

// Split 은 SAN 목록을 x509 템플릿에 넣을 네 갈래로 나눈다.
func Split(sans []SAN) (dns []string, ips []net.IP, uris []*url.URL, emails []string, err error) {
	for _, s := range sans {
		switch s.Type {
		case TypeDNS:
			dns = append(dns, s.Value)
		case TypeIP:
			if ip := net.ParseIP(s.Value); ip != nil {
				ips = append(ips, ip)
				continue
			}
			// CIDR 표기는 네트워크 주소로 넣는다.
			if _, network, cidrErr := net.ParseCIDR(s.Value); cidrErr == nil {
				ips = append(ips, network.IP)
				continue
			}
			return nil, nil, nil, nil, certerr.Validationf("IP SAN 을 해석할 수 없습니다: %q", s.Value)
		case TypeURI:
			u, parseErr := url.Parse(s.Value)
			if parseErr != nil {
				return nil, nil, nil, nil, certerr.WrapValidation(parseErr, "URI SAN 을 해석할 수 없습니다: %q", s.Value)
			}
			uris = append(uris, u)
		case TypeEmail:
			emails = append(emails, s.Value)
		}
	}
	return dns, ips, uris, emails, nil
}

// Summary 는 목록 표시용 요약이다.
func Summary(sans []SAN, limit int) string {
	parts := make([]string, 0, len(sans))
	for _, s := range sans {
		parts = append(parts, s.Display())
	}
	if len(parts) <= limit {
		return strings.Join(parts, ", ")
	}
	return strings.Join(parts[:limit], ", ") + fmt.Sprintf(" (+%d)", len(parts)-limit)
}

// BuildSubject 는 Subject DN 을 만든다.
func BuildSubject(spec Subject) (pkix.Name, error) {
	cn := strings.TrimSpace(spec.CommonName)
	if cn == "" {
		return pkix.Name{}, certerr.Validationf("CN(common name)은 필수입니다")
	}
	if len(cn) > 64 {
		return pkix.Name{}, certerr.Validationf("CN 은 64자를 넘을 수 없습니다: %d자", len(cn))
	}

	name := pkix.Name{CommonName: cn}
	if spec.Country != "" {
		code := strings.ToUpper(strings.TrimSpace(spec.Country))
		if len(code) != 2 || !isAlpha(code) {
			return pkix.Name{}, certerr.Validationf("국가 코드는 2자 영문이어야 합니다(ISO 3166-1): %q", spec.Country)
		}
		name.Country = []string{code}
	}
	if v := strings.TrimSpace(spec.State); v != "" {
		name.Province = []string{v}
	}
	if v := strings.TrimSpace(spec.Locality); v != "" {
		name.Locality = []string{v}
	}
	if v := strings.TrimSpace(spec.Organization); v != "" {
		name.Organization = []string{v}
	}
	if v := strings.TrimSpace(spec.OrganizationalUnit); v != "" {
		name.OrganizationalUnit = []string{v}
	}
	return name, nil
}

func isAlpha(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// DNString 은 DB·표시용 RFC4514 표기다.
//
// Go 의 pkix.Name.String() 은 RFC2253 순서(CN 이 앞)를 따르므로 아래에서
// rfc4514_string() 과 같은 결과가 나온다.
func DNString(name pkix.Name) string { return name.String() }
