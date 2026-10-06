package manifests

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newshure/cert-gen/internal/certerr"
)

var (
	fullchain = []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n")
	keyPEM    = []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n")
	caPEM     = []byte("-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n")
)

func baseSecret() SecretOptions {
	return SecretOptions{
		Name: "web-tls", Namespace: "databases",
		FullchainPEM: fullchain, KeyPEM: keyPEM, CAPEM: caPEM,
	}
}

// kubectlDryRun 은 생성한 매니페스트를 kubectl 의 클라이언트 측 검증에 통과시킨다.
//
// 손으로 YAML 을 만들기로 했으니, 실제 Kubernetes 스키마가 받아들이는지 외부 도구로
// 확인해야 한다. 우리 눈으로 읽어 보는 것은 검증이 아니다.
func kubectlDryRun(t *testing.T, docs ...[]byte) {
	t.Helper()
	bin, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl 없음")
	}
	var joined []byte
	for i, d := range docs {
		if i > 0 {
			joined = append(joined, []byte("---\n")...)
		}
		joined = append(joined, d...)
	}
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, joined, 0o600); err != nil {
		t.Fatal(err)
	}
	// --dry-run=client 는 클러스터에 접속하지 않고 스키마만 본다.
	out, err := exec.Command(bin, "apply", "--dry-run=client", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl 이 매니페스트를 거부했다: %v\n%s\n--- 매니페스트 ---\n%s",
			err, out, joined)
	}
}

func TestTLSSecretPassesKubectlValidation(t *testing.T) {
	data, err := TLSSecret(baseSecret())
	if err != nil {
		t.Fatal(err)
	}
	kubectlDryRun(t, data)
}

func TestTLSSecretRoundTripsBase64(t *testing.T) {
	data, err := TLSSecret(baseSecret())
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeSecretData(t, string(data))
	if string(fields["tls.crt"]) != string(fullchain) {
		t.Errorf("tls.crt 왕복 실패:\n%q", fields["tls.crt"])
	}
	if string(fields["tls.key"]) != string(keyPEM) {
		t.Errorf("tls.key 왕복 실패:\n%q", fields["tls.key"])
	}
	// IncludeCA 를 주지 않았으면 ca.crt 가 없어야 한다.
	if _, ok := fields["ca.crt"]; ok {
		t.Error("요청하지 않은 ca.crt 가 들어갔다")
	}
}

// decodeSecretData 는 생성한 YAML 의 data 블록을 되읽는다. 접힌 base64 를 다시 이어 붙인다.
func decodeSecretData(t *testing.T, yaml string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	var current string
	var buf strings.Builder
	flush := func() {
		if current == "" {
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(buf.String())
		if err != nil {
			t.Fatalf("%s 의 base64 가 깨졌다: %v", current, err)
		}
		out[current] = decoded
		current, buf = "", strings.Builder{}
	}
	inData := false
	for _, line := range strings.Split(yaml, "\n") {
		if strings.HasPrefix(line, "data:") {
			inData = true
			continue
		}
		if !inData {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, ": >-") {
			flush()
			current = strings.TrimSuffix(trimmed, ": >-")
			continue
		}
		if !strings.HasPrefix(line, "    ") {
			break // data 블록을 벗어났다
		}
		buf.WriteString(trimmed)
	}
	flush()
	return out
}

func TestTLSSecretIncludesCAWhenAsked(t *testing.T) {
	opts := baseSecret()
	opts.IncludeCA = true
	data, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeSecretData(t, string(data))
	if string(fields["ca.crt"]) != string(caPEM) {
		t.Errorf("ca.crt 왕복 실패: %q", fields["ca.crt"])
	}
	// ca.crt 는 표준 키가 아니다. 왜 넣는지 파일에 남아야 나중에 읽는 사람이 안다.
	if !strings.Contains(string(data), "표준 키가 아닙니다") {
		t.Error("ca.crt 가 비표준이라는 주석이 없다")
	}
	kubectlDryRun(t, data)
}

func TestTLSSecretRejectsIncludeCAWithoutCA(t *testing.T) {
	opts := baseSecret()
	opts.IncludeCA = true
	opts.CAPEM = nil
	if _, err := TLSSecret(opts); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("CA 없이 --with-ca 가 통과했다: %v", err)
	}
}

func TestTLSSecretRequiresKey(t *testing.T) {
	// 개인키 없는 tls Secret 은 apply 는 성공하고 트래픽이 흐를 때 실패한다.
	opts := baseSecret()
	opts.KeyPEM = nil
	err := TLSSecret2Err(t, opts)
	if !certerr.IsKind(err, certerr.KindValidation) {
		t.Fatalf("개인키 없이 통과했다: %v", err)
	}
	if !strings.Contains(err.Error(), "필수") {
		t.Errorf("오류가 이유를 말하지 않는다: %v", err)
	}
}

func TLSSecret2Err(t *testing.T, opts SecretOptions) error {
	t.Helper()
	_, err := TLSSecret(opts)
	return err
}

func TestTLSSecretRejectsBadNames(t *testing.T) {
	// kubectl apply 가 거부할 이름을 미리 잡는다. 여기서 막지 않으면 사용자가
	// 파일을 만들고 적용할 때야 알게 된다.
	for _, name := range []string{"", "Web-TLS", "web_tls", "-web", "web-", "웹"} {
		opts := baseSecret()
		opts.Name = name
		if _, err := TLSSecret(opts); !certerr.IsKind(err, certerr.KindValidation) {
			t.Errorf("잘못된 이름 %q 가 통과했다", name)
		}
	}
	for _, ns := range []string{"Databases", "data_bases"} {
		opts := baseSecret()
		opts.Namespace = ns
		if _, err := TLSSecret(opts); !certerr.IsKind(err, certerr.KindValidation) {
			t.Errorf("잘못된 네임스페이스 %q 가 통과했다", ns)
		}
	}
}

func TestTLSSecretNamespaceToken(t *testing.T) {
	// 워크스페이스 컨벤션: deploy.sh 가 렌더링한다.
	opts := baseSecret()
	opts.UseToken = true
	opts.Namespace = "ignored"
	data, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "namespace: "+NamespaceToken) {
		t.Errorf("토큰이 들어가지 않았다:\n%s", data)
	}
	if strings.Contains(string(data), "ignored") {
		t.Error("토큰 모드인데 지정한 네임스페이스가 남았다")
	}
	// 토큰이 들어간 파일은 kubectl 이 거부하는 것이 정상이다 — 렌더링 전이므로.
	// 따라서 여기서는 dry-run 을 하지 않는다. 대신 치환하면 통과해야 한다.
	rendered := strings.ReplaceAll(string(data), NamespaceToken, "databases")
	kubectlDryRun(t, []byte(rendered))
}

func TestTLSSecretLabelsAreSortedAndQuoted(t *testing.T) {
	opts := baseSecret()
	opts.Labels = map[string]string{"zone": "dmz", "app": "web", "managed": "yes"}
	data, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	// 맵 순회는 Go 가 무작위화한다. 정렬하지 않으면 실행마다 다른 파일이 나와 diff 가 깨진다.
	appIdx := strings.Index(body, "app: web")
	managedIdx := strings.Index(body, "managed:")
	zoneIdx := strings.Index(body, "zone: dmz")
	if !(appIdx < managedIdx && managedIdx < zoneIdx) {
		t.Errorf("라벨이 정렬되지 않았다:\n%s", body)
	}
	// "yes" 는 YAML 1.1 에서 불리언이다. 인용하지 않으면 문자열이 아닌 것이 된다.
	if !strings.Contains(body, `managed: "yes"`) {
		t.Errorf("YAML 예약어가 인용되지 않았다:\n%s", body)
	}
	kubectlDryRun(t, data)
}

func TestTLSSecretIsDeterministic(t *testing.T) {
	opts := baseSecret()
	opts.Labels = map[string]string{"app": "web", "zone": "dmz", "tier": "edge"}
	first, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := TLSSecret(opts)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("같은 입력이 다른 출력을 냈다 (%d회차)", i)
		}
	}
}

func TestTLSSecretKeyOrderIsFixed(t *testing.T) {
	// tls.crt → tls.key → ca.crt. 읽는 사람이 매번 같은 자리에서 같은 것을 찾게 한다.
	opts := baseSecret()
	opts.IncludeCA = true
	data, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	crt := strings.Index(body, "tls.crt:")
	key := strings.Index(body, "tls.key:")
	ca := strings.Index(body, "ca.crt:")
	if !(crt < key && key < ca) {
		t.Errorf("data 키 순서가 고정되지 않았다:\n%s", body)
	}
}

func TestBase64IsFolded(t *testing.T) {
	// 한 줄로 쓰면 수천 자가 되어 diff 가 쓸모없어진다.
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'A'
	}
	opts := baseSecret()
	opts.FullchainPEM = big
	data, err := TLSSecret(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 80 {
			t.Errorf("80자를 넘는 줄이 있다 (%d자)", len(line))
		}
	}
	// 접어도 되읽을 수 있어야 한다.
	fields := decodeSecretData(t, string(data))
	if string(fields["tls.crt"]) != string(big) {
		t.Error("접은 base64 왕복 실패")
	}
	kubectlDryRun(t, data)
}

// --- Ingress -----------------------------------------------------------------

func baseIngress() IngressOptions {
	return IngressOptions{
		Name: "web-ingress", Namespace: "databases", Host: "web.hd.local",
		SecretName: "web-tls", Service: "web-svc", Port: 8080, SSLRedirect: true,
	}
}

func TestIngressPassesKubectlValidation(t *testing.T) {
	data, err := Ingress(baseIngress())
	if err != nil {
		t.Fatal(err)
	}
	kubectlDryRun(t, data)
}

func TestSecretAndIngressApplyTogether(t *testing.T) {
	// 실제 사용 형태: 한 파일에 둘을 넣어 apply 한다.
	secret, err := TLSSecret(baseSecret())
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := Ingress(baseIngress())
	if err != nil {
		t.Fatal(err)
	}
	kubectlDryRun(t, secret, ingress)
}

func TestIngressContents(t *testing.T) {
	data, err := Ingress(baseIngress())
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"ingressClassName: nginx", "secretName: web-tls",
		"host: web.hd.local", "number: 8080", "pathType: Prefix",
		`nginx.ingress.kubernetes.io/ssl-redirect: "true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Ingress 에 %q 가 없다:\n%s", want, body)
		}
	}
}

func TestIngressRejectsBadInput(t *testing.T) {
	cases := map[string]func(*IngressOptions){
		"호스트 없음":  func(o *IngressOptions) { o.Host = "" },
		"포트 0":    func(o *IngressOptions) { o.Port = 0 },
		"포트 초과":   func(o *IngressOptions) { o.Port = 70000 },
		"잘못된 이름":  func(o *IngressOptions) { o.Name = "Web" },
		"잘못된 서비스": func(o *IngressOptions) { o.Service = "web_svc" },
		"잘못된 시크릿": func(o *IngressOptions) { o.SecretName = "" },
	}
	for label, mutate := range cases {
		opts := baseIngress()
		mutate(&opts)
		if _, err := Ingress(opts); !certerr.IsKind(err, certerr.KindValidation) {
			t.Errorf("%s 이 통과했다: %v", label, err)
		}
	}
}

// --- nginx -------------------------------------------------------------------

func TestNginxServerBlock(t *testing.T) {
	data, err := NginxServerBlock(NginxOptions{
		Host: "web.hd.local", CertPath: "/etc/ssl/fullchain.pem", KeyPath: "/etc/ssl/privkey.pem",
		ProxyPass: "http://127.0.0.1:8080", HTTPRedirect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"listen 443 ssl", "server_name web.hd.local",
		"ssl_certificate     /etc/ssl/fullchain.pem",
		"ssl_certificate_key /etc/ssl/privkey.pem",
		"TLSv1.2 TLSv1.3", "proxy_pass http://127.0.0.1:8080",
		"return 301 https://$host$request_uri",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("nginx 설정에 %q 가 없다:\n%s", want, body)
		}
	}
	// 가장 흔한 실수를 파일에 적어 둔다.
	if !strings.Contains(body, "fullchain") || !strings.Contains(body, "체인이 끊깁니다") {
		t.Error("fullchain 을 써야 한다는 주석이 없다")
	}
	// 요청하지 않은 mTLS·CRL 설정이 들어가면 nginx 가 기동에 실패한다.
	if strings.Contains(body, "ssl_verify_client") || strings.Contains(body, "ssl_crl") {
		t.Error("요청하지 않은 mTLS/CRL 설정이 들어갔다")
	}
}

func TestNginxMTLSAndCRL(t *testing.T) {
	data, err := NginxServerBlock(NginxOptions{
		Host: "web.hd.local", CertPath: "/c.pem", KeyPath: "/k.pem",
		CAPath: "/ca.crt", CRLPath: "/crl/root.crl",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "ssl_client_certificate /ca.crt") {
		t.Errorf("mTLS 설정이 없다:\n%s", body)
	}
	if !strings.Contains(body, "ssl_crl /crl/root.crl") {
		t.Errorf("CRL 설정이 없다:\n%s", body)
	}
	// CRL 갱신 후 reload 가 필요하다는 사실은 운영에서 꼭 물어보게 되는 지점이다.
	if !strings.Contains(body, "reload") {
		t.Error("CRL 갱신 시 reload 안내가 없다")
	}
}

func TestNginxRejectsMissingPaths(t *testing.T) {
	if _, err := NginxServerBlock(NginxOptions{Host: "h"}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("경로 없이 통과했다: %v", err)
	}
	if _, err := NginxServerBlock(NginxOptions{CertPath: "/c", KeyPath: "/k"}); !certerr.IsKind(err, certerr.KindValidation) {
		t.Errorf("호스트 없이 통과했다: %v", err)
	}
}

func TestNginxConfigIsAcceptedByNginx(t *testing.T) {
	// nginx 가 있으면 생성한 설정을 nginx -t 로 검증한다. 우리가 읽어 보는 것보다 강하다.
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx 없음")
	}
	dir := t.TempDir()
	// nginx -t 는 인증서 파일의 존재를 확인한다. 더미를 놓는다.
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	for path, data := range map[string][]byte{certPath: fullchain, keyPath: keyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	block, err := NginxServerBlock(NginxOptions{
		Host: "web.hd.local", CertPath: certPath, KeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "nginx.conf")
	full := "events {}\nhttp {\n" + string(block) + "\n}\n"
	if err := os.WriteFile(conf, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	out, runErr := exec.Command(bin, "-t", "-c", conf, "-p", dir).CombinedOutput()
	// 더미 PEM 이라 인증서 로드 단계에서 실패하는 것은 정상이다. **문법 오류**만 잡는다.
	body := string(out)
	for _, syntaxErr := range []string{"unknown directive", "invalid parameter", "unexpected"} {
		if strings.Contains(body, syntaxErr) {
			t.Errorf("nginx 가 문법 오류를 보고했다: %v\n%s\n--- 설정 ---\n%s", runErr, body, full)
		}
	}
}

func TestProxyManagerNote(t *testing.T) {
	note := ProxyManagerNote("web.hd.local")
	for _, want := range []string{"web.hd.local", "fullchain.pem", "privkey.pem"} {
		if !strings.Contains(note, want) {
			t.Errorf("NPM 안내에 %q 가 없다", want)
		}
	}
	// NPM 에서 cert.pem 을 넣는 실수가 가장 잦다.
	if !strings.Contains(note, "cert.pem 이 아니다") {
		t.Error("cert.pem 을 넣지 말라는 경고가 없다")
	}
}

func TestYAMLScalarQuoting(t *testing.T) {
	cases := map[string]string{
		"web":          "web",
		"web.hd.local": "web.hd.local",
		"":             `""`,
		"yes":          `"yes"`,
		"no":           `"no"`,
		"true":         `"true"`,
		"null":         `"null"`,
		"*.hd.local":   `"*.hd.local"`,
		"a: b":         `"a: b"`,
		`say "hi"`:     `"say \"hi\""`,
		"{tpl}":        `"{tpl}"`,
	}
	for input, want := range cases {
		if got := yamlScalar(input); got != want {
			t.Errorf("yamlScalar(%q) = %q, 기대 %q", input, got, want)
		}
	}
}
