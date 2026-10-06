// Package osslconf — openssl 설정 파일(.cnf)에서 발급 입력을 읽는다.
//
// openssl req -config 가 쓰는 형식의 하위 집합을 해석한다. 목적은 **기존 openssl 자산을
// 그대로 활용** 하는 것이다 — 손으로 쌓아 둔 DN·SAN 을 다시 타이핑하지 않게 한다.
//
// 설계에서 딱 하나 분명히 할 것: **DN 과 SAN 은 데이터이므로 그대로 쓰고, 확장(keyUsage·
// EKU·basicConstraints)은 그대로 복사하지 않는다.** 대신 EKU 에서 프로필을 추론하고, 우리가
// 반영하지 않는 요청은 경고로 알린다. 이유는 cert-gen 의 전체 설계가 "확장은 프로필이 통제해
// 실수를 구조적으로 막는다" 이기 때문이다. .cnf 는 CSR 과 달리 운영자가 쓴 파일이라 더
// 믿을 만하지만, 확장을 자유롭게 덮어쓰게 하면 그 안전장치가 사라진다.
//
// 지원하지 않는 것(만나면 경고하고 건너뛴다): $var 치환, .include, otherName/RID/dirName SAN.
// 폐쇄망 사내 자산에서 실제로 쓰이는 범위를 넘어선다.
package osslconf

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
)

// NL 은 줄바꿈이다.
const NL = "\n"

// Spec 은 .cnf 에서 뽑아낸 발급 입력이다.
type Spec struct {
	Subject names.Subject
	// SANValues 는 우리 표현("dns:x")이다. BuildSANs 에 그대로 넘긴다.
	SANValues []string
	// Profile 은 EKU 에서 추론한 값이다. 추론하지 못하면 빈 문자열이다(호출자가 기본을 쓴다).
	// CA 블록이면 "root-ca" 다.
	Profile string
	// IsCA 는 basicConstraints CA:TRUE 인 블록이다. CA 생성용 설정이라는 뜻이다.
	IsCA bool
	// KeyAlgo 는 default_bits 에서 추론한 키 알고리즘이다("rsa4096" 등). 없으면 빈 문자열.
	KeyAlgo string
	// PathLen 은 CA 블록의 pathlen 이다(없으면 nil).
	PathLen *int64
	// Warnings 는 반영하지 않은 요청·지원하지 않는 항목이다. 조용히 무시하면 사용자는
	// 자기가 적은 것이 적용됐다고 믿는다.
	Warnings []string
}

// ParseFile 은 .cnf 파일을 읽어 Spec 으로 만든다.
func ParseFile(path string) (Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return Spec{}, certerr.WrapState(err, "설정 파일을 열 수 없습니다: %s (%v)", path, err)
	}
	defer f.Close()
	cfg, err := parse(bufio.NewScanner(f))
	if err != nil {
		return Spec{}, err
	}
	return cfg.toSpec()
}

// ParseBlocks 는 '---' 로 구분된 여러 블록을 읽는다.
//
// 한 파일에 CA 설정과 그 아래 발급할 leaf 설정들을 함께 두는 형식이다. openssl 자체는
// 여러 블록을 모르지만, "이 PKI 를 이렇게 만들어라" 를 한 파일로 적는 쪽이 운영에 편하다.
// 구분선은 **그 줄 전체가 ---(3개 이상)** 인 줄이다.
func ParseBlocks(data []byte) ([]Spec, error) {
	var (
		specs []Spec
		buf   []string
	)
	flush := func() error {
		text := strings.TrimSpace(strings.Join(buf, NL))
		buf = nil
		if text == "" {
			return nil
		}
		spec, err := Parse([]byte(text))
		if err != nil {
			return err
		}
		specs = append(specs, spec)
		return nil
	}
	for _, line := range strings.Split(string(data), NL) {
		if isSeparator(line) {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		buf = append(buf, line)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, certerr.Validationf("설정 블록이 없습니다")
	}
	return specs, nil
}

// ParseBlocksFile 은 파일에서 여러 블록을 읽는다.
func ParseBlocksFile(path string) ([]Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, certerr.WrapState(err, "설정 파일을 열 수 없습니다: %s (%v)", path, err)
	}
	return ParseBlocks(data)
}

// isSeparator 는 블록 구분선(--- 이상)인지다.
func isSeparator(line string) bool {
	t := strings.TrimSpace(line)
	if len(t) < 3 {
		return false
	}
	for _, r := range t {
		if r != '-' {
			return false
		}
	}
	return true
}

// Parse 는 바이트에서 읽는다(테스트·stdin 용).
func Parse(data []byte) (Spec, error) {
	cfg, err := parse(bufio.NewScanner(strings.NewReader(string(data))))
	if err != nil {
		return Spec{}, err
	}
	return cfg.toSpec()
}

// --- INI 파싱 ----------------------------------------------------------------

// config 는 섹션 → (키 → 값) 이다. 키 순서를 보존한다(SAN 의 DNS.1, DNS.2 순서가 중요하다).
type config struct {
	sections map[string]*section
}

type section struct {
	keys   []string
	values map[string]string
}

func newSection() *section { return &section{values: map[string]string{}} }

func (s *section) set(key, value string) {
	if _, ok := s.values[key]; !ok {
		s.keys = append(s.keys, key)
	}
	s.values[key] = value
}

func parse(sc *bufio.Scanner) (*config, error) {
	cfg := &config{sections: map[string]*section{}}
	// openssl 은 섹션 밖의 키도 허용한다(default 섹션). 그 자리를 "" 로 둔다.
	current := newSection()
	cfg.sections[""] = current

	var pending string // 역슬래시 줄 이음
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := stripComment(raw)

		// 역슬래시로 끝나면 다음 줄과 잇는다(openssl 이 허용한다).
		if strings.HasSuffix(line, "\\") {
			pending += strings.TrimSuffix(line, "\\")
			continue
		}
		line = strings.TrimSpace(pending + line)
		pending = ""
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name := strings.TrimSpace(strings.Trim(line, "[]"))
			if name == "" {
				return nil, certerr.Validationf("%d행: 섹션 이름이 비어 있습니다", lineNo)
			}
			sec, ok := cfg.sections[name]
			if !ok {
				sec = newSection()
				cfg.sections[name] = sec
			}
			current = sec
			continue
		}

		eq := strings.Index(line, "=")
		if eq < 0 {
			// openssl 설정에서 '=' 없는 줄은 오류다. 조용히 넘기면 오타를 못 잡는다.
			return nil, certerr.Validationf("%d행: '=' 가 없습니다: %q", lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		value := unquote(strings.TrimSpace(line[eq+1:]))
		current.set(key, value)
	}
	if err := sc.Err(); err != nil {
		return nil, certerr.WrapState(err, "설정을 읽을 수 없습니다: %v", err)
	}
	return cfg, nil
}

// stripComment 는 따옴표 밖의 # 를 제거한다.
func stripComment(line string) string {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func (c *config) section(name string) *section { return c.sections[name] }

func (c *config) value(sectionName, key string) (string, bool) {
	sec := c.sections[sectionName]
	if sec == nil {
		return "", false
	}
	v, ok := sec.values[key]
	return v, ok
}

// --- Spec 매핑 ---------------------------------------------------------------

func (c *config) toSpec() (Spec, error) {
	var spec Spec

	// 1. [req] 에서 DN·확장 섹션을 찾는다. openssl 의 관례다.
	//    없으면 흔히 쓰는 이름을 차례로 시도한다.
	reqSection := firstSection(c, "req")
	dnName := pointerOr(c, reqSection, "distinguished_name", "dn", "req_distinguished_name")

	dnSec := c.section(dnName)
	if dnSec == nil {
		return Spec{}, certerr.Validationf(
			"DN 섹션을 찾을 수 없습니다 ([req] distinguished_name 또는 [dn]/[req_distinguished_name])")
	}
	spec.Subject = mapSubject(dnSec)
	if spec.Subject.CommonName == "" {
		return Spec{}, certerr.Validationf("설정에 CN(commonName)이 없습니다")
	}

	// 2. 확장 섹션. CSR 용 req_extensions 와 자기서명용 x509_extensions 둘 다 본다.
	extName := pointerOr(c, reqSection, "req_extensions", "x509_extensions")
	if extName == "" {
		extName = firstExistingSection(c, "v3_req", "v3_ca", "usr_cert", "server_cert")
	}
	extSec := c.section(extName)

	// 3. SAN. 확장 섹션의 subjectAltName 을 본다. 없으면 흔한 alt_names 섹션도 시도한다.
	sans, sanWarns := mapSAN(c, extSec)
	spec.SANValues = sans
	spec.Warnings = append(spec.Warnings, sanWarns...)

	// 4. default_bits → 키 알고리즘.
	if bits, ok := c.value(reqSection, "default_bits"); ok {
		switch strings.TrimSpace(bits) {
		case "2048":
			spec.KeyAlgo = "rsa2048"
		case "3072":
			spec.KeyAlgo = "rsa3072"
		case "4096":
			spec.KeyAlgo = "rsa4096"
		default:
			spec.Warnings = append(spec.Warnings,
				"default_bits="+strings.TrimSpace(bits)+" 는 매핑하지 않습니다(설정 기본 키를 씁니다)")
		}
	}

	// 5. CA 블록인지 분류하고, 아니면 프로필을 추론한다.
	if isCABlock(extSec) {
		spec.IsCA = true
		spec.Profile = profiles.RootCA
		spec.PathLen = parsePathLen(extSec)
		// CA 블록에서 keyCertSign/cRLSign 은 당연하므로 경고하지 않는다.
	} else {
		profile, profWarns := inferProfile(extSec)
		spec.Profile = profile
		spec.Warnings = append(spec.Warnings, profWarns...)
	}

	return spec, nil
}

// isCABlock 은 basicConstraints 에 CA:TRUE 가 있는지다.
func isCABlock(extSec *section) bool {
	if extSec == nil {
		return false
	}
	return strings.Contains(strings.ToUpper(extSec.values["basicConstraints"]), "CA:TRUE")
}

// parsePathLen 은 basicConstraints 의 pathlen 을 읽는다(없으면 nil).
func parsePathLen(extSec *section) *int64 {
	if extSec == nil {
		return nil
	}
	bc := strings.ToLower(extSec.values["basicConstraints"])
	idx := strings.Index(bc, "pathlen:")
	if idx < 0 {
		return nil
	}
	rest := bc[idx+len("pathlen:"):]
	n := int64(0)
	count := 0
	for _, r := range strings.TrimSpace(rest) {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int64(r-'0')
		count++
	}
	if count == 0 {
		return nil
	}
	return &n
}

// firstSection 은 대소문자·언더스코어 변형을 흡수해 섹션 이름을 돌려준다.
func firstSection(c *config, candidates ...string) string {
	for _, name := range candidates {
		if c.section(name) != nil {
			return name
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// pointerOr 는 섹션의 포인터 키(다른 섹션 이름을 값으로 갖는)를 따라간다.
func pointerOr(c *config, inSection string, keys ...string) string {
	for _, key := range keys {
		if v, ok := c.value(inSection, key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	// 포인터가 없으면 관례적 섹션 이름 자체를 후보로 본다.
	for _, key := range keys {
		if c.section(key) != nil {
			return key
		}
	}
	return ""
}

func firstExistingSection(c *config, names ...string) string {
	for _, n := range names {
		if c.section(n) != nil {
			return n
		}
	}
	return ""
}

// dnAliases 는 openssl 의 DN 속성 이름(짧은·긴 형태)을 Subject 필드로 잇는다.
var dnAliases = map[string]string{
	"cn": "cn", "commonname": "cn",
	"c": "c", "countryname": "c",
	"st": "st", "stateorprovincename": "st",
	"l": "l", "localityname": "l",
	"o": "o", "organizationname": "o",
	"ou": "ou", "organizationalunitname": "ou",
	"emailaddress": "email", "email": "email",
}

func mapSubject(sec *section) names.Subject {
	// openssl 은 두 형식을 쓴다.
	//   prompt=no:   "CN = web.hd.local"              ← 평문이 값
	//   prompt 모드: "commonName = Common Name"        ← 프롬프트 문구(값 아님)
	//                "commonName_default = web.hd.local"  ← 이쪽이 값
	// 그리고 중복 허용을 위해 "0.O", "1.O" 처럼 숫자 접두어를 붙인다.
	//
	// 규칙 하나로 둘을 다 흡수한다: **_default 가 있으면 그것이 값, 없으면 평문이 값.**
	// prompt 플래그를 따로 볼 필요가 없다 — prompt=no 파일에는 _default 가 없고, prompt
	// 파일에는 있다.
	plain := map[string]string{}
	deflt := map[string]string{}
	for _, rawKey := range sec.keys {
		key := rawKey
		if dot := strings.Index(key, "."); dot > 0 && isAllDigits(key[:dot]) {
			key = key[dot+1:]
		}
		target := plain
		if strings.HasSuffix(strings.ToLower(key), "_default") {
			key = key[:len(key)-len("_default")]
			target = deflt
		}
		field, ok := dnAliases[strings.ToLower(key)]
		if !ok {
			continue
		}
		if value := strings.TrimSpace(sec.values[rawKey]); value != "" {
			target[field] = value
		}
	}
	pick := func(field string) string {
		if v, ok := deflt[field]; ok {
			return v
		}
		return plain[field]
	}
	return names.Subject{
		CommonName:         pick("cn"),
		Country:            pick("c"),
		State:              pick("st"),
		Locality:           pick("l"),
		Organization:       pick("o"),
		OrganizationalUnit: pick("ou"),
		Email:              pick("email"),
	}
}

func mapSAN(c *config, extSec *section) ([]string, []string) {
	var warnings []string

	// subjectAltName 값을 찾는다. 확장 섹션이 없으면 alt_names 섹션을 직접 시도한다.
	var sanValue string
	if extSec != nil {
		sanValue = extSec.values["subjectAltName"]
	}
	var altSec *section
	switch {
	case strings.HasPrefix(strings.TrimSpace(sanValue), "@"):
		// @alt_names → 섹션 참조
		altSec = c.section(strings.TrimSpace(sanValue)[1:])
		if altSec == nil {
			warnings = append(warnings, fmt.Sprintf(
				"subjectAltName 이 가리키는 섹션 %q 가 없습니다", strings.TrimSpace(sanValue)[1:]))
		}
	case sanValue != "":
		// 인라인: "DNS:a, IP:b"
		return parseInlineSAN(sanValue)
	default:
		// 명시적 참조가 없어도 관례적 alt_names 섹션이 있으면 쓴다.
		altSec = c.section("alt_names")
	}

	if altSec == nil {
		return nil, warnings
	}
	return parseSANSection(altSec, warnings)
}

// parseInlineSAN 은 "DNS:a, IP:b, email:c" 를 우리 표현으로 바꾼다.
func parseInlineSAN(value string) ([]string, []string) {
	var (
		out      []string
		warnings []string
	)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		colon := strings.Index(item, ":")
		if colon < 0 {
			warnings = append(warnings, fmt.Sprintf("SAN 항목에 타입이 없습니다: %q", item))
			continue
		}
		mapped, ok := mapSANType(item[:colon], strings.TrimSpace(item[colon+1:]))
		if !ok {
			warnings = append(warnings, fmt.Sprintf("지원하지 않는 SAN 타입입니다: %q", item))
			continue
		}
		out = append(out, mapped)
	}
	return out, warnings
}

// parseSANSection 은 [alt_names] 의 DNS.1, IP.1, email, URI.2 … 를 읽는다.
func parseSANSection(sec *section, warnings []string) ([]string, []string) {
	// 키 순서를 보존하되, 같은 타입 안에서는 번호 순으로 둔다(DNS.1 before DNS.2).
	keys := append([]string{}, sec.keys...)
	sort.SliceStable(keys, func(i, j int) bool { return sanKeyLess(keys[i], keys[j]) })

	var out []string
	for _, key := range keys {
		base := key
		if dot := strings.Index(key, "."); dot > 0 {
			base = key[:dot]
		}
		mapped, ok := mapSANType(base, strings.TrimSpace(sec.values[key]))
		if !ok {
			warnings = append(warnings, fmt.Sprintf("지원하지 않는 SAN 타입입니다: %q", key))
			continue
		}
		out = append(out, mapped)
	}
	return out, warnings
}

func mapSANType(osslType, value string) (string, bool) {
	if value == "" {
		return "", false
	}
	switch strings.ToUpper(strings.TrimSpace(osslType)) {
	case "DNS":
		return names.TypeDNS + ":" + value, true
	case "IP", "IP ADDRESS":
		return names.TypeIP + ":" + value, true
	case "EMAIL":
		return names.TypeEmail + ":" + value, true
	case "URI":
		return names.TypeURI + ":" + value, true
	default:
		// otherName, RID, dirName 등은 지원하지 않는다.
		return "", false
	}
}

// inferProfile 은 extendedKeyUsage 에서 프로필을 추론하고, 반영하지 않는 확장을 경고한다.
func inferProfile(extSec *section) (string, []string) {
	if extSec == nil {
		return "", nil
	}
	var warnings []string
	eku := strings.ToLower(extSec.values["extendedKeyUsage"])
	hasServer := strings.Contains(eku, "serverauth")
	hasClient := strings.Contains(eku, "clientauth")

	// 우리가 반영하지 않는 keyUsage/EKU 요청은 알린다. 조용히 프로필로 바꾸면 사용자는
	// 자기가 적은 확장이 그대로 들어갔다고 믿는다.
	if ku := extSec.values["keyUsage"]; ku != "" {
		warnings = append(warnings,
			"설정의 keyUsage 는 프로필이 결정하므로 그대로 반영되지 않습니다: "+strings.TrimSpace(ku))
	}
	if other := unknownEKU(eku); other != "" {
		warnings = append(warnings,
			"프로필로 표현되지 않는 EKU 가 있습니다(무시): "+other)
	}

	switch {
	case hasServer && hasClient:
		return profiles.ServerClient, warnings
	case hasServer:
		return profiles.Server, warnings
	case hasClient:
		return profiles.Client, warnings
	default:
		// 추론 불가. 호출자가 기본 프로필을 쓴다.
		return "", warnings
	}
}

// unknownEKU 는 serverAuth·clientAuth 외의 EKU 를 돌려준다(경고용).
func unknownEKU(eku string) string {
	var extra []string
	for _, token := range strings.Split(eku, ",") {
		t := strings.TrimSpace(token)
		switch t {
		case "", "serverauth", "clientauth":
		default:
			extra = append(extra, t)
		}
	}
	return strings.Join(extra, ", ")
}

func sanKeyLess(a, b string) bool {
	ta, na := splitSANKey(a)
	tb, nb := splitSANKey(b)
	if ta != tb {
		return ta < tb
	}
	return na < nb
}

func splitSANKey(key string) (string, int) {
	if dot := strings.Index(key, "."); dot > 0 {
		n := 0
		fmt.Sscanf(key[dot+1:], "%d", &n)
		return key[:dot], n
	}
	return key, 0
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
