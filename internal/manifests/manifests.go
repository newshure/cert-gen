// Package manifests — 인증서를 소비하는 쪽의 설정을 생성한다.
//
// YAML 라이브러리를 쓰지 않고 직접 만든다. 이유는 하나다. 여기서 나오는 파일은 사람이
// 저장소에 커밋하고 나중에 읽는 것이라 **주석과 키 순서가 내용만큼 중요하다.** YAML 덤퍼는
// 둘 다 보존하지 않는다(맵을 알파벳 순으로 재배열하고 주석을 버린다).
//
// 대신 값 인용(quoting)을 직접 책임져야 한다. base64 는 안전한 문자만 나오지만 이름·호스트명은
// 사용자 입력이므로 YAML 특수문자를 검사한다.
package manifests

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/newshure/cert-gen/internal/certerr"
)

// NamespaceToken 은 워크스페이스 컨벤션이다. deploy.sh 가 렌더링한다.
const NamespaceToken = "__NAMESPACE__"

// SecretOptions 는 kubernetes.io/tls Secret 생성 입력이다.
type SecretOptions struct {
	Name      string
	Namespace string
	// UseToken 이면 namespace 에 __NAMESPACE__ 토큰을 넣는다(워크스페이스 컨벤션).
	UseToken bool
	// FullchainPEM 은 leaf + 상위 체인이다. tls.crt 에 들어간다.
	FullchainPEM []byte
	KeyPEM       []byte
	// CAPEM 이 있고 IncludeCA 면 ca.crt 키를 추가한다. mTLS 클라이언트 검증에 쓴다.
	CAPEM     []byte
	IncludeCA bool
	// Labels 는 추가 라벨이다. 워크스페이스 컨벤션은 app=<component>.
	Labels map[string]string
}

// 리소스 이름 규칙(RFC 1123 라벨). 틀리면 kubectl apply 가 거부하므로 미리 잡는다.
var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// 인용 없이 써도 안전한 스칼라. 여기서 벗어나면 따옴표로 감싼다.
var plainScalarRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// YAML 1.1 이 불리언·null 로 해석하는 말들. 인용하지 않으면 문자열이 아닌 것이 된다.
var yamlReserved = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true,
	"null": true, "y": true, "n": true, "~": true,
}

func validateName(kind, value string) error {
	if value == "" {
		return certerr.Validationf("%s 이름이 비어 있습니다", kind)
	}
	if len(value) > 253 {
		return certerr.Validationf("%s 이름이 253자를 넘습니다", kind)
	}
	if !dnsLabelRE.MatchString(value) {
		return certerr.Validationf(
			"%s 이름 %q 이 Kubernetes 규칙에 맞지 않습니다 "+
				"(소문자·숫자·'-' 만, 양끝은 영숫자)", kind, value)
	}
	return nil
}

// TLSSecret 은 kubernetes.io/tls Secret YAML 을 만든다.
func TLSSecret(opts SecretOptions) ([]byte, error) {
	if err := validateName("Secret", opts.Name); err != nil {
		return nil, err
	}
	namespace := opts.Namespace
	if opts.UseToken {
		namespace = NamespaceToken
	} else if namespace != "" {
		if err := validateName("Namespace", namespace); err != nil {
			return nil, err
		}
	}
	if len(opts.FullchainPEM) == 0 {
		return nil, certerr.Validationf("tls.crt 에 넣을 인증서가 없습니다")
	}
	if len(opts.KeyPEM) == 0 {
		// 개인키 없는 tls Secret 은 Ingress 가 거부한다. 빈 값으로 만들어 주면
		// apply 는 성공하고 트래픽이 흐를 때 실패한다.
		return nil, certerr.Validationf(
			"tls.key 에 넣을 개인키가 없습니다. kubernetes.io/tls Secret 에는 개인키가 필수입니다")
	}

	var b strings.Builder
	b.WriteString("# cert_gen 생성. kubectl apply -f 로 적용합니다.\n")
	if opts.UseToken {
		b.WriteString("# 네임스페이스는 " + NamespaceToken + " 토큰입니다 — deploy.sh 가 렌더링합니다.\n")
	}
	b.WriteString("apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", opts.Name)
	if namespace != "" {
		fmt.Fprintf(&b, "  namespace: %s\n", namespace)
	}
	if len(opts.Labels) > 0 {
		b.WriteString("  labels:\n")
		for _, k := range sortedKeys(opts.Labels) {
			fmt.Fprintf(&b, "    %s: %s\n", k, yamlScalar(opts.Labels[k]))
		}
	}
	b.WriteString("data:\n")
	// 키 순서를 tls.crt → tls.key → ca.crt 로 고정한다. 읽는 사람이 매번 같은 자리에서
	// 같은 것을 찾게 된다.
	writeB64(&b, "tls.crt", opts.FullchainPEM)
	writeB64(&b, "tls.key", opts.KeyPEM)
	if opts.IncludeCA {
		if len(opts.CAPEM) == 0 {
			return nil, certerr.Validationf("--with-ca 를 지정했지만 CA 인증서가 없습니다")
		}
		// ca.crt 는 표준 키가 아니다. Ingress 가 mTLS 클라이언트 검증에 쓴다.
		b.WriteString("  # ca.crt 는 kubernetes.io/tls 표준 키가 아닙니다.\n")
		b.WriteString("  # nginx Ingress 의 mTLS(auth-tls-secret)가 이 키를 읽습니다.\n")
		writeB64(&b, "ca.crt", opts.CAPEM)
	}
	return []byte(b.String()), nil
}

// writeB64 는 base64 를 64자로 접어 쓴다.
//
// 한 줄로 쓰면 수천 자가 되어 diff 가 쓸모없어진다. kubectl 은 둘 다 받는다.
func writeB64(b *strings.Builder, key string, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	fmt.Fprintf(b, "  %s: >-\n", key)
	for len(encoded) > 0 {
		n := 64
		if len(encoded) < n {
			n = len(encoded)
		}
		fmt.Fprintf(b, "    %s\n", encoded[:n])
		encoded = encoded[n:]
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// 라벨은 알파벳 순으로 고정한다. 맵 순회 순서는 Go 가 무작위화하므로, 정렬하지 않으면
	// 같은 입력이 실행할 때마다 다른 파일을 내고 diff 가 쓸모없어진다.
	sort.Strings(out)
	return out
}

// yamlScalar 는 YAML 스칼라를 안전하게 인용한다.
//
// 사용자 입력이 들어오는 자리다. 인용하지 않으면 `*`, `{`, `yes` 같은 값이 YAML 문법으로
// 해석되어 매니페스트가 조용히 다른 뜻이 된다.
func yamlScalar(value string) string {
	if value == "" {
		return `""`
	}
	if plainScalarRE.MatchString(value) && !yamlReserved[strings.ToLower(value)] {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// IngressOptions 는 Ingress 스니펫 입력이다.
type IngressOptions struct {
	Name       string
	Namespace  string
	UseToken   bool
	Host       string
	SecretName string
	Service    string
	Port       int
	Path       string
	// SSLRedirect 는 HTTP → HTTPS 리다이렉트다.
	SSLRedirect bool
}

// Ingress 는 nginx IngressClass 용 Ingress YAML 을 만든다.
func Ingress(opts IngressOptions) ([]byte, error) {
	if err := validateName("Ingress", opts.Name); err != nil {
		return nil, err
	}
	if err := validateName("Secret", opts.SecretName); err != nil {
		return nil, err
	}
	if err := validateName("Service", opts.Service); err != nil {
		return nil, err
	}
	if opts.Host == "" {
		return nil, certerr.Validationf("Ingress 호스트가 비어 있습니다")
	}
	if opts.Port <= 0 || opts.Port > 65535 {
		return nil, certerr.Validationf("서비스 포트가 올바르지 않습니다: %d", opts.Port)
	}
	namespace := opts.Namespace
	if opts.UseToken {
		namespace = NamespaceToken
	} else if namespace != "" {
		if err := validateName("Namespace", namespace); err != nil {
			return nil, err
		}
	}
	path := opts.Path
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	b.WriteString("# cert_gen 생성. 위 Secret 을 먼저 apply 하세요.\n")
	b.WriteString("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", opts.Name)
	if namespace != "" {
		fmt.Fprintf(&b, "  namespace: %s\n", namespace)
	}
	b.WriteString("  annotations:\n")
	fmt.Fprintf(&b, "    nginx.ingress.kubernetes.io/ssl-redirect: %q\n", boolString(opts.SSLRedirect))
	b.WriteString("spec:\n  ingressClassName: nginx\n  tls:\n")
	fmt.Fprintf(&b, "    - hosts:\n        - %s\n      secretName: %s\n",
		yamlScalar(opts.Host), opts.SecretName)
	b.WriteString("  rules:\n")
	fmt.Fprintf(&b, "    - host: %s\n      http:\n        paths:\n", yamlScalar(opts.Host))
	fmt.Fprintf(&b, "          - path: %s\n            pathType: Prefix\n", yamlScalar(path))
	fmt.Fprintf(&b, "            backend:\n              service:\n                name: %s\n",
		opts.Service)
	fmt.Fprintf(&b, "                port:\n                  number: %d\n", opts.Port)
	return []byte(b.String()), nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// NginxOptions 는 nginx server 블록 입력이다.
type NginxOptions struct {
	Host     string
	CertPath string
	KeyPath  string
	// CRLPath 가 있으면 ssl_crl 을 넣는다.
	CRLPath string
	// CAPath 가 있으면 클라이언트 인증(mTLS)을 설정한다.
	CAPath       string
	ProxyPass    string
	ListenPort   int
	HTTPRedirect bool
}

// NginxServerBlock 은 nginx 설정 스니펫을 만든다.
func NginxServerBlock(opts NginxOptions) ([]byte, error) {
	if opts.Host == "" {
		return nil, certerr.Validationf("호스트명이 비어 있습니다")
	}
	if opts.CertPath == "" || opts.KeyPath == "" {
		return nil, certerr.Validationf("인증서와 개인키 경로가 필요합니다")
	}
	port := opts.ListenPort
	if port == 0 {
		port = 443
	}

	var b strings.Builder
	b.WriteString("# cert_gen 생성.\n")
	b.WriteString("# ssl_certificate 에는 fullchain(leaf + 상위 체인)을 넣습니다.\n")
	b.WriteString("# cert.pem(leaf 단독)을 넣으면 중간 CA 가 있는 경우 체인이 끊깁니다.\n")
	if opts.HTTPRedirect {
		b.WriteString("\nserver {\n    listen 80;\n")
		fmt.Fprintf(&b, "    server_name %s;\n", opts.Host)
		b.WriteString("    return 301 https://$host$request_uri;\n}\n")
	}
	b.WriteString("\nserver {\n")
	fmt.Fprintf(&b, "    listen %d ssl;\n", port)
	fmt.Fprintf(&b, "    listen [::]:%d ssl;\n", port)
	b.WriteString("    http2 on;\n")
	fmt.Fprintf(&b, "    server_name %s;\n\n", opts.Host)
	fmt.Fprintf(&b, "    ssl_certificate     %s;\n", opts.CertPath)
	fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", opts.KeyPath)
	b.WriteString("    ssl_protocols       TLSv1.2 TLSv1.3;\n")
	b.WriteString("    ssl_session_cache   shared:SSL:10m;\n")
	if opts.CAPath != "" {
		b.WriteString("\n    # 클라이언트 인증(mTLS). 'optional' 로 두면 거부하지 않고 넘긴다.\n")
		fmt.Fprintf(&b, "    ssl_client_certificate %s;\n", opts.CAPath)
		b.WriteString("    ssl_verify_client      on;\n")
	}
	if opts.CRLPath != "" {
		b.WriteString("\n    # 폐기 목록. CRL 을 갱신하면 nginx 를 reload 해야 반영된다.\n")
		fmt.Fprintf(&b, "    ssl_crl %s;\n", opts.CRLPath)
	}
	if opts.ProxyPass != "" {
		fmt.Fprintf(&b, "\n    location / {\n        proxy_pass %s;\n", opts.ProxyPass)
		b.WriteString("        proxy_set_header Host              $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP         $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}

// ProxyManagerNote 는 Nginx Proxy Manager 적용 안내다.
//
// NPM 은 설정 파일을 손으로 넣는 것이 아니라 UI 에 붙여넣는 방식이라, 생성할 파일이 없다.
// 대신 무엇을 어디에 넣는지 알려 준다.
func ProxyManagerNote(host string) string {
	return strings.Join([]string{
		"Nginx Proxy Manager 적용",
		"",
		"  SSL Certificates → Add SSL Certificate → Custom",
		"    Certificate Key : privkey.pem",
		"    Certificate     : fullchain.pem   (cert.pem 이 아니다 — 체인이 끊긴다)",
		"    Intermediate    : 비워 둔다 (fullchain 에 이미 포함)",
		"",
		"  Proxy Hosts → " + host + " → SSL 탭에서 위 인증서를 선택",
		"",
		"  주의: NPM 이 TLS 를 종료하므로 백엔드까지의 구간은 평문이다.",
		"        백엔드도 TLS 로 감싸려면 Proxy Host 의 scheme 을 https 로 둔다.",
	}, "\n")
}
