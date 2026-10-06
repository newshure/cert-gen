package export

// 변환 입력 해석. 발급 이력(번들)과 외부 파일 두 경로를 Input 하나로 모은다.

import (
	"os"
	"path/filepath"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/store"
)

// FromBundle 은 발급 이력의 번들에서 변환 재료를 꺼낸다.
//
// 번들 지문을 먼저 확인한다. 변조·손상된 번들로 키스토어를 만들어 배포하면 어디서 틀어졌는지
// 추적할 수 없다.
func FromBundle(cfg config.Config, record store.Cert, passphrase string) (Input, error) {
	path := filepath.Join(cfg.DataDir, record.BundlePath)
	if record.BundleSHA256 != "" {
		if err := bundle.VerifyDigest(path, record.BundleSHA256); err != nil {
			return Input{}, err
		}
	}
	members, err := bundle.Members(path)
	if err != nil {
		return Input{}, err
	}

	certPEM, ok := members[bundle.MemberCert]
	if !ok {
		return Input{}, certerr.Statef("번들에 인증서가 없습니다: %s", path)
	}
	cert, err := ca.LoadCertBytes(certPEM, path)
	if err != nil {
		return Input{}, err
	}

	in := Input{Cert: cert, Label: record.CommonName}
	if chainPEM, ok := members[bundle.MemberChain]; ok && len(chainPEM) > 0 {
		in.Chain, err = ca.LoadChain(chainPEM)
		if err != nil {
			return Input{}, err
		}
	}
	if caPEM, ok := members[bundle.MemberCA]; ok && len(caPEM) > 0 {
		in.CA, err = ca.LoadCertBytes(caPEM, path)
		if err != nil {
			return Input{}, err
		}
	}
	if keyPEM, ok := members[bundle.MemberKey]; ok && len(keyPEM) > 0 {
		in.Key, err = keys.FromPEM(keyPEM, passphrase)
		if err != nil {
			return Input{}, err
		}
	}
	return in, nil
}

// ExternalFiles 는 외부 파일 입력이다. 인증서만 주고 변환하는 경우도 있어 키는 선택이다.
type ExternalFiles struct {
	CertPath  string
	KeyPath   string
	ChainPath string
	CAPath    string
	// Passphrase 는 KeyPath 가 암호화된 경우에만 쓴다.
	Passphrase string
}

// FromFiles 는 외부 PEM 파일에서 변환 재료를 읽는다.
//
// 키가 주어지면 인증서와 짝인지 확인한다. 짝이 아닌 키로 만든 키스토어는 파일로는 멀쩡해
// 보이고 서버를 올릴 때야 실패하므로, 여기서 잡는 편이 훨씬 싸다.
func FromFiles(f ExternalFiles) (Input, error) {
	if f.CertPath == "" {
		return Input{}, certerr.Validationf("변환할 인증서 파일이 필요합니다")
	}
	cert, err := ca.LoadCertFile(f.CertPath)
	if err != nil {
		return Input{}, err
	}
	in := Input{Cert: cert, Label: cert.Subject.CommonName}

	if f.ChainPath != "" {
		data, err := readFile(f.ChainPath)
		if err != nil {
			return Input{}, err
		}
		in.Chain, err = ca.LoadChain(data)
		if err != nil {
			return Input{}, err
		}
	}
	if f.CAPath != "" {
		in.CA, err = ca.LoadCertFile(f.CAPath)
		if err != nil {
			return Input{}, err
		}
		if !in.CA.IsCA {
			return Input{}, certerr.Validationf(
				"CA 로 지정한 파일이 CA 인증서가 아닙니다(CA:TRUE 아님): %s", f.CAPath)
		}
	}
	if f.KeyPath != "" {
		data, err := readFile(f.KeyPath)
		if err != nil {
			return Input{}, err
		}
		in.Key, err = keys.FromPEM(data, f.Passphrase)
		if err != nil {
			return Input{}, err
		}
		if !keys.PublicMatches(in.Key, cert.PublicKey) {
			return Input{}, certerr.Validationf(
				"개인키와 인증서가 짝이 아닙니다 (키: %s, 인증서: %s)", f.KeyPath, f.CertPath)
		}
	}
	return in, nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, certerr.WrapState(err, "파일을 읽을 수 없습니다: %s (%v)", path, err)
	}
	return data, nil
}
