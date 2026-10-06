// Package bundle — 발급 결과 zip 번들.
//
// 한 번 발급한 결과를 "파일 여러 개" 가 아니라 **하나의 묶음**으로 보관한다. 이유는 두 가지다.
// 개인키·인증서·체인이 흩어지면 어느 키가 어느 인증서의 짝인지 잃어버리고, 서버에 올릴 때
// 필요한 조합(fullchain.pem 등)을 매번 다시 만들게 된다.
//
// zip 안의 privkey.pem 에는 0600 권한을 심어 둔다. unzip 이 그 권한을 복원하므로, 받은 쪽에서
// chmod 를 잊어도 개인키가 0644 로 풀리지 않는다.
package bundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/names"
)

// 번들 멤버 이름. 외부(문서·사용자)가 아는 이름이므로 상수로 고정한다.
const (
	MemberKey       = "privkey.pem"
	MemberCert      = "cert.pem"
	MemberChain     = "chain.pem"
	MemberFullchain = "fullchain.pem"
	MemberCA        = "ca.crt"
	MemberCSR       = "request.csr"
	MemberMetadata  = "metadata.json"
	MemberUsage     = "USAGE.txt"
)

// maxMemberBytes — 번들 멤버 하나의 상한. PEM·메타데이터뿐이라 실제로는 수 KB 다.
const maxMemberBytes = 16 << 20

// Metadata 는 번들에 함께 넣는 발급 정보다. 사람이 읽고 스크립트가 파싱한다.
type Metadata struct {
	Tool         string      `json:"tool"`
	CommonName   string      `json:"common_name"`
	SubjectDN    string      `json:"subject_dn"`
	SANs         []names.SAN `json:"sans"`
	Profile      string      `json:"profile"`
	KeyAlgo      string      `json:"key_algo"`
	Serial       string      `json:"serial"`
	Seq          int64       `json:"seq"`
	Fingerprint  string      `json:"fingerprint_sha256"`
	PublicSHA256 string      `json:"public_sha256"`
	NotBefore    string      `json:"not_before"`
	NotAfter     string      `json:"not_after"`
	CASlug       string      `json:"ca_slug"`
	CACommonName string      `json:"ca_common_name"`
	CAExternal   bool        `json:"ca_external"`
	Note         string      `json:"note,omitempty"`
}

// Content 는 번들에 들어갈 내용이다. 없는 항목은 비워 두면 파일을 만들지 않는다.
type Content struct {
	CertPEM  []byte
	CAPEM    []byte
	Metadata Metadata
	KeyPEM   []byte
	ChainPEM []byte
	CSRPEM   []byte
	// Extra 는 변환 산출물을 번들에 함께 넣을 때 쓴다(현재는 쓰지 않는다).
	Extra map[string][]byte
}

// FullchainPEM 은 leaf + 상위 체인이다. nginx·Nginx Proxy Manager 가 그대로 먹는 형태다.
//
// Root CA 는 체인에 넣지 않는 것이 관례다(클라이언트가 이미 신뢰하고 있어야 한다).
// 자가서명 환경에서는 ca.crt 를 따로 신뢰 등록하는 것이 정답이므로 여기서도 넣지 않는다.
func (c Content) FullchainPEM() []byte {
	out := make([]byte, 0, len(c.CertPEM)+len(c.ChainPEM))
	out = append(out, c.CertPEM...)
	return append(out, c.ChainPEM...)
}

// Write 는 번들을 원자적으로 쓰고 sha256 을 돌려준다.
//
// 이미 있는 경로는 거부한다. 번들 경로에는 새로 발급된 인증서 id 가 들어가므로 충돌 자체가
// 이상 신호다. 조용히 덮어쓰면 그 자리에 있던 개인키가 복구 불가능하게 사라진다.
func Write(path, prefix string, c Content) (string, error) {
	if fsops.Exists(path) {
		return "", certerr.Conflictf("번들이 이미 있습니다: %s", path)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name string, data []byte, secret bool) error {
		header := &zip.FileHeader{
			Name:   prefix + "/" + name,
			Method: zip.Deflate,
			// 재현 가능한 번들: 같은 입력이면 같은 바이트가 나오게 시각을 고정한다.
			Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		// unzip 이 권한을 복원하도록 모드를 심는다. 개인키가 0644 로 풀리는 사고를 막는다.
		if secret {
			header.SetMode(0o600)
		} else {
			header.SetMode(0o644)
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			return certerr.WrapState(err, "번들 항목을 만들 수 없습니다: %s (%v)", name, err)
		}
		if _, err := w.Write(data); err != nil {
			return certerr.WrapState(err, "번들 항목을 쓸 수 없습니다: %s (%v)", name, err)
		}
		return nil
	}

	if len(c.KeyPEM) > 0 {
		if err := add(MemberKey, c.KeyPEM, true); err != nil {
			return "", err
		}
	}
	if err := add(MemberCert, c.CertPEM, false); err != nil {
		return "", err
	}
	if len(c.ChainPEM) > 0 {
		if err := add(MemberChain, c.ChainPEM, false); err != nil {
			return "", err
		}
	}
	if err := add(MemberFullchain, c.FullchainPEM(), false); err != nil {
		return "", err
	}
	if err := add(MemberCA, c.CAPEM, false); err != nil {
		return "", err
	}
	if len(c.CSRPEM) > 0 {
		if err := add(MemberCSR, c.CSRPEM, false); err != nil {
			return "", err
		}
	}
	metaJSON, err := json.MarshalIndent(c.Metadata, "", "  ")
	if err != nil {
		return "", certerr.WrapState(err, "메타데이터를 직렬화할 수 없습니다: %v", err)
	}
	if err := add(MemberMetadata, metaJSON, false); err != nil {
		return "", err
	}
	if err := add(MemberUsage, []byte(UsageText(c.Metadata)), false); err != nil {
		return "", err
	}
	for name, data := range c.Extra {
		secret := strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".jks") ||
			strings.HasSuffix(name, ".key")
		if err := add(name, data, secret); err != nil {
			return "", err
		}
	}

	if err := zw.Close(); err != nil {
		return "", certerr.WrapState(err, "번들을 닫을 수 없습니다: %v", err)
	}
	data := buf.Bytes()
	if err := fsops.WriteAtomic(path, data, fsops.ModeSecret); err != nil {
		return "", err
	}
	return fsops.SHA256Bytes(data), nil
}

// Members 는 번들 내용을 {파일명: 바이트} 로 읽는다(디렉터리 접두어는 제거).
func Members(path string) (map[string][]byte, error) {
	if !fsops.IsFile(path) {
		return nil, certerr.Statef("번들 파일이 없습니다: %s", path)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, certerr.WrapState(err, "번들을 열 수 없습니다(손상): %s (%v)", path, err)
	}
	defer zr.Close()

	out := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		name := f.Name
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		rc, err := f.Open()
		if err != nil {
			return nil, certerr.WrapState(err, "번들 항목을 읽을 수 없습니다: %s (%v)", name, err)
		}
		// 선언된 크기(f.UncompressedSize64)를 믿고 버퍼를 잡지 않는다. zip 헤더는 내용과
		// 어긋날 수 있고, 우리가 만들지 않은 번들도 읽게 된다. 멤버당 상한을 둔다.
		data, err := io.ReadAll(io.LimitReader(rc, maxMemberBytes+1))
		rc.Close()
		if err != nil {
			return nil, certerr.WrapState(err, "번들 항목을 읽을 수 없습니다: %s (%v)", name, err)
		}
		if len(data) > maxMemberBytes {
			return nil, certerr.Statef("번들 항목이 너무 큽니다(%s, 상한 %d바이트)", name, maxMemberBytes)
		}
		out[name] = data
	}
	return out, nil
}

// VerifyDigest 는 번들 무결성을 확인한다.
func VerifyDigest(path, expected string) error {
	actual, err := fsops.SHA256File(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return certerr.Statef(
			"번들 무결성 불일치: %s\n  기대: %s\n  실제: %s", path, expected, actual)
	}
	return nil
}

// ExtractTo 는 번들을 디렉터리에 풀어 놓는다(개인키는 0600 으로).
func ExtractTo(path, dest string) ([]string, error) {
	members, err := Members(path)
	if err != nil {
		return nil, err
	}
	if err := fsops.EnsureDir(dest, 0o700); err != nil {
		return nil, err
	}
	// 순서를 고정해 출력이 매번 같게 나오게 한다.
	order := []string{MemberKey, MemberCert, MemberChain, MemberFullchain, MemberCA,
		MemberCSR, MemberMetadata, MemberUsage}
	var written []string
	seen := map[string]bool{}
	writeOne := func(name string) error {
		data, ok := members[name]
		if !ok || seen[name] {
			return nil
		}
		seen[name] = true
		secret := name == MemberKey || strings.HasSuffix(name, ".key") ||
			strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".jks")
		mode := fsops.ModePublic
		if secret {
			mode = fsops.ModeSecret
		}
		target := filepath.Join(dest, name)
		if err := fsops.WriteAtomic(target, data, mode); err != nil {
			return err
		}
		written = append(written, target)
		return nil
	}
	for _, name := range order {
		if err := writeOne(name); err != nil {
			return nil, err
		}
	}
	for name := range members {
		if err := writeOne(name); err != nil {
			return nil, err
		}
	}
	return written, nil
}

// UsageText 는 받은 쪽이 바로 적용할 수 있는 안내다. 번들 안에 같이 넣는다.
func UsageText(m Metadata) string {
	sanParts := make([]string, 0, len(m.SANs))
	for _, s := range m.SANs {
		sanParts = append(sanParts, s.Display())
	}
	secretName := strings.NewReplacer(".", "-", "*", "wildcard").Replace(m.CommonName)

	return fmt.Sprintf(`cert_gen 발급 번들
================

CN         : %s
SAN        : %s
발급 CA    : %s
유효기간   : %s ~ %s
serial     : %s
지문(SHA256): %s

파일
----
%-16s 개인키 (PKCS#8 PEM). 외부로 유출되면 인증서를 폐기해야 한다.
%-16s 이 서비스의 인증서
%-16s 상위 CA 체인 (Root CA 는 제외. 비어 있으면 Root 가 직접 발급한 것)
%-16s cert.pem + chain.pem. 서버 설정에는 보통 이 파일을 쓴다
%-16s Root CA 인증서. **클라이언트에 신뢰 등록할 대상**

자가서명 체인이므로 접속하는 쪽에 ca.crt 를 신뢰 등록해야 한다
------------------------------------------------------------
Rocky/RHEL   : sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
Debian/Ubuntu: sudo cp ca.crt /usr/local/share/ca-certificates/ca.crt && sudo update-ca-certificates
Windows      : certutil -addstore -f Root ca.crt
Java         : keytool -importcert -trustcacerts -alias cert-gen-ca -file ca.crt \
                 -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit
Python       : REQUESTS_CA_BUNDLE=/path/to/ca.crt  (requests/httpx)
Node.js      : NODE_EXTRA_CA_CERTS=/path/to/ca.crt
curl         : curl --cacert ca.crt https://%s/

  또는: cert-gen ca trust <slug> --apply   (현재 서버에 바로 등록)

nginx
-----
server {
    listen 443 ssl;
    server_name %s;
    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
}
# privkey.pem 은 root 소유 0600 으로 두어야 한다.

Nginx Proxy Manager
-------------------
SSL Certificates > Add SSL Certificate > Custom
  Certificate Key = privkey.pem
  Certificate     = fullchain.pem
  Intermediate    = chain.pem (비어 있으면 생략)

Kubernetes (nginx ingress)
--------------------------
kubectl create secret tls %s \
  --cert=fullchain.pem --key=privkey.pem -n <namespace>
# 또는 cert-gen export k8s <ID> 로 Secret 매니페스트를 생성한다.

Java 애플리케이션 (PKCS#12 권장)
-------------------------------
cert-gen export p12 <ID>     # JDK 9+ 기본 키스토어 형식
cert-gen export jks <ID>     # 레거시 JKS 가 꼭 필요한 경우만
`,
		m.CommonName, strings.Join(sanParts, ", "), m.CACommonName,
		m.NotBefore, m.NotAfter, m.Serial, m.Fingerprint,
		MemberKey, MemberCert, MemberChain, MemberFullchain, MemberCA,
		m.CommonName, m.CommonName, secretName)
}

// RelPath 는 번들 파일의 data_dir 기준 상대경로다.
//
// 파일명에 id·CN·serial 앞 8자를 넣어 사람이 디렉터리만 봐도 구분할 수 있게 한다.
func RelPath(certID int64, commonName, serialHex, year string) string {
	stem := fmt.Sprintf("%d-%s-%s", certID, names.Slugify(commonName, "cert"), shortSerial(serialHex))
	return filepath.Join("bundles", year, stem+".zip")
}

func shortSerial(hexText string) string {
	if len(hexText) <= 8 {
		return hexText
	}
	return hexText[:8]
}

// RemoveIfExists 는 보상 트랜잭션에서 쓴다(번들을 쓴 뒤 DB 갱신이 실패한 경우).
func RemoveIfExists(path string) {
	if fsops.Exists(path) {
		_ = os.Remove(path)
	}
}
