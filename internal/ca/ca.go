// Package ca — CA 생성·등록·로드.
//
// 두 가지 CA 출처를 지원한다(최상위 작업 구조의 "CA 선택" 2경로).
//
//  1. cert_gen 이 만든 CA — data_dir/ca/<slug>/ 에 키·인증서를 두고 cert_gen 이 소유한다.
//  2. 외부 디렉터리의 CA — 이미 쓰고 있는 CA 를 **복사하지 않고 그 자리에서** 쓴다.
//     개인키를 data_dir 로 옮기면 "CA 가 두 곳에 있다" 는 더 나쁜 상태가 되므로 복사하지 않는다.
//     대신 발급 이력을 남기기 위해 ca 테이블에 is_external=1 로 한 번 등록하고, 두 번째
//     사용부터는 지문으로 기존 행을 재사용한다.
//
// 중간 CA 생성은 범위 밖이다. 단 외부 CA 가 중간 CA 인 경우는 그 디렉터리의 체인 파일을
// 읽어 그대로 번들에 넣는다.
package ca

import (
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
)

// 디렉터리에서 CA 를 찾을 때 먼저 보는 관례적 파일명.
var (
	preferredKeyNames   = []string{"ca.key", "ca-key.pem", "cakey.pem", "ca.key.pem"}
	preferredCertNames  = []string{"ca.crt", "ca.pem", "ca-cert.pem", "cacert.pem", "ca.cert.pem"}
	preferredChainNames = []string{"chain.pem", "ca-chain.pem", "fullchain.pem", "ca-bundle.pem"}
	keyGlobs            = []string{"*.key", "*.pem"}
	certGlobs           = []string{"*.crt", "*.cer", "*.pem"}
)

// Material 은 서명에 필요한 모든 것이다. 패스프레이즈를 푼 뒤에만 만들어진다.
type Material struct {
	Record store.CA
	Key    crypto.Signer
	Cert   *x509.Certificate
	// Chain 은 발급자 위쪽 체인(발급 CA 자신은 제외). Root CA 면 빈 목록.
	Chain []*x509.Certificate
}

// Root 는 신뢰 등록용 최상위 인증서다.
func (m Material) Root() *x509.Certificate {
	if len(m.Chain) > 0 {
		return m.Chain[len(m.Chain)-1]
	}
	return m.Cert
}

// Discovered 는 디렉터리에서 찾아낸 CA 파일들이다. 아직 개인키를 풀지 않은 상태다.
type Discovered struct {
	Dir          string
	KeyPath      string
	CertPath     string
	ChainPath    string
	Cert         *x509.Certificate
	KeyEncrypted bool
	Chain        []*x509.Certificate
}

// IsSelfSigned 는 자기서명인지 본다.
func (d Discovered) IsSelfSigned() bool { return d.Cert.Issuer.String() == d.Cert.Subject.String() }

// --- 공통 -------------------------------------------------------------------

// LoadCertFile 은 PEM 또는 DER 인증서를 읽는다.
func LoadCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, certerr.WrapValidation(err, "인증서 파일을 읽을 수 없습니다: %s (%v)", path, err)
	}
	return LoadCertBytes(data, path)
}

// LoadCertBytes 는 PEM 또는 DER 바이트를 인증서로 바꾼다.
func LoadCertBytes(data []byte, source string) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert, nil
		}
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	return nil, certerr.Validationf("인증서를 해석할 수 없습니다(PEM/DER 아님): %s", source)
}

// LoadChain 은 PEM 묶음에서 인증서를 순서대로 모두 읽는다.
func LoadChain(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, certerr.WrapValidation(err, "체인 PEM 을 해석할 수 없습니다: %v", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// IsCACert 는 basicConstraints CA:TRUE 인지 본다.
//
// basicConstraints 가 없으면 CA 로 볼 수 없다(RFC 5280). 구형 CA 라도 거부하는 편이 안전하다.
func IsCACert(cert *x509.Certificate) bool { return cert.BasicConstraintsValid && cert.IsCA }

// CommonNameOf 는 표시용 이름이다. CN 이 없는 CA 도 있어 O → DN 순으로 떨어뜨린다.
func CommonNameOf(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.String()
}

// UniqueSlug 는 slug 충돌 시 -2, -3 을 붙인다.
func UniqueSlug(s *store.Store, base string) string {
	slug := base
	for suffix := 2; ; suffix++ {
		if _, ok := s.FindCA(slug); !ok {
			return slug
		}
		slug = fmt.Sprintf("%s-%d", base, suffix)
	}
}

// ResolvePaths 는 DB 에 기록된 경로를 실제 경로로 바꾼다.
// 외부 CA 는 절대경로, 내부 CA 는 data_dir 기준이다.
func ResolvePaths(cfg config.Config, c store.CA) (keyPath, certPath, chainPath string) {
	if c.IsExternal {
		return c.KeyPath, c.CertPath, c.ChainPath
	}
	keyPath = filepath.Join(cfg.DataDir, c.KeyPath)
	certPath = filepath.Join(cfg.DataDir, c.CertPath)
	if c.ChainPath != "" {
		chainPath = filepath.Join(cfg.DataDir, c.ChainPath)
	}
	return keyPath, certPath, chainPath
}

// --- 1. cert_gen 이 만드는 Root CA -------------------------------------------

// CreateOptions 는 Root CA 생성 입력이다.
type CreateOptions struct {
	Subject    names.Subject
	KeyAlgo    string
	Days       int
	Passphrase string
	Slug       string
	// ExistingKey 가 있으면 미리 만들어 둔 키를 쓴다(키 생성과 CA 생성을 분리하는 흐름).
	ExistingKey *LoadedKey
	// RequirePassphrase 로 호출자가 설정 기본값을 덮어쓸 수 있다. CA 마다 판단이 다를 수
	// 있고, 전역 설정만으로 강제하면 "이 CA 만 패스프레이즈 없이" 가 불가능하다.
	RequirePassphrase *bool
}

// LoadedKey 는 패스프레이즈를 푼 키다. keystore 패키지가 채워 넘긴다.
type LoadedKey struct {
	Key    crypto.Signer
	Algo   string
	KeyID  *int64
	Path   string // 등록된 키면 그 경로(data_dir 기준 또는 절대경로)
	Origin string
	// Encrypted 는 그 키 파일이 암호화되어 있는지다.
	Encrypted bool
}

// CreateRoot 는 Root CA 를 만들어 저장하고 등록한다.
func CreateRoot(cfg config.Config, s *store.Store, opts CreateOptions) (store.CA, error) {
	// 등록된 키를 쓰는 경우 그 키 파일을 **복사하지 않고 참조한다.** 복사하면 key strip 으로
	// 패스프레이즈를 제거해도 CA 가 쓰는 사본은 그대로 남아 두 상태가 갈라진다.
	reusesRegistered := opts.ExistingKey != nil && opts.ExistingKey.KeyID != nil

	algo := opts.KeyAlgo
	if opts.ExistingKey != nil {
		algo = opts.ExistingKey.Algo
	} else if algo == "" {
		algo = cfg.CA.DefaultKeyAlgo
	}
	if _, err := keys.SpecFor(algo); err != nil {
		return store.CA{}, err
	}

	days := opts.Days
	if days == 0 {
		days = cfg.CA.DefaultDays
	}

	required := cfg.CA.EncryptKey
	if opts.RequirePassphrase != nil {
		required = *opts.RequirePassphrase
	}
	passphrase := opts.Passphrase
	keyEncrypted := passphrase != ""
	if reusesRegistered {
		// 키의 보호 수준은 그 키가 이미 가지고 있다. 여기서 다시 암호화하지 않는다.
		required = false
		passphrase = ""
		keyEncrypted = opts.ExistingKey.Encrypted
	}
	if required && passphrase == "" {
		return store.CA{}, certerr.Validationf(
			"CA 개인키 패스프레이즈가 필요합니다 (패스프레이즈 없이 만들려면 --no-passphrase, " +
				"또는 설정 [ca].encrypt_key = false)")
	}

	profile, err := profiles.Get(profiles.RootCA)
	if err != nil {
		return store.CA{}, err
	}
	subject, err := names.BuildSubject(opts.Subject)
	if err != nil {
		return store.CA{}, err
	}

	var signer crypto.Signer
	if opts.ExistingKey != nil {
		signer = opts.ExistingKey.Key
	} else {
		signer, err = keys.Generate(algo)
		if err != nil {
			return store.CA{}, err
		}
	}

	notBefore, notAfter, err := certbuild.ValidityWindow(days, cfg.Cert.BackdateMinutes)
	if err != nil {
		return store.CA{}, err
	}
	serial, err := certbuild.NewSerial()
	if err != nil {
		return store.CA{}, err
	}
	cert, _, err := certbuild.Build(certbuild.Request{
		Subject: subject, PublicKey: signer.Public(), Signer: signer,
		Profile: profile, Serial: serial, NotBefore: notBefore, NotAfter: notAfter,
	})
	if err != nil {
		return store.CA{}, err
	}

	base := opts.Slug
	if base == "" {
		base = opts.Subject.CommonName
	}
	slug := UniqueSlug(s, names.Slugify(base, "root-ca"))
	relDir := filepath.Join("ca", slug)

	keyRel := filepath.Join(relDir, "ca.key")
	if reusesRegistered {
		keyRel = opts.ExistingKey.Path
	}
	pathLen := int64(profile.PathLen)

	// DB 를 먼저 넣어 slug 를 선점한다(동시 실행 시 디렉터리 충돌보다 UNIQUE 제약이 정확하다).
	// 파일 쓰기가 실패하면 행을 되돌린다.
	var caID int64
	err = s.Tx(func(tx *sql.Tx) error {
		var txErr error
		caID, txErr = s.InsertCA(tx, store.CA{
			Slug: slug, CommonName: opts.Subject.CommonName,
			SubjectDN: names.DNString(subject), KeyAlgo: algo, KeyEncrypted: keyEncrypted,
			KeyPath: keyRel, CertPath: filepath.Join(relDir, "ca.crt"),
			SerialHex: certbuild.SerialHex(serial), Fingerprint: certbuild.Fingerprint(cert),
			NotBefore: notBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:  notAfter.UTC().Format("2006-01-02T15:04:05Z"),
			PathLen:   &pathLen,
			KeyID:     keyIDOf(opts.ExistingKey),
		})
		return txErr
	})
	if err != nil {
		return store.CA{}, err
	}

	absDir := filepath.Join(cfg.DataDir, relDir)
	writeErr := func() error {
		if err := fsops.EnsureDir(absDir, fsops.ModeDir); err != nil {
			return err
		}
		if !reusesRegistered {
			pemBytes, err := keys.ToPEM(signer, passphrase)
			if err != nil {
				return err
			}
			if err := fsops.WriteAtomic(filepath.Join(absDir, "ca.key"), pemBytes, fsops.ModeSecret); err != nil {
				return err
			}
		}
		return fsops.WriteAtomic(filepath.Join(absDir, "ca.crt"), certbuild.CertPEM(cert), fsops.ModePublic)
	}()
	if writeErr != nil {
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteCA(tx, caID) })
		return store.CA{}, writeErr
	}
	return s.GetCA(fmt.Sprintf("%d", caID))
}

func keyIDOf(k *LoadedKey) *int64 {
	if k == nil {
		return nil
	}
	return k.KeyID
}

// --- 2. 외부 디렉터리의 CA ---------------------------------------------------

// DiscoverInDir 는 디렉터리에서 CA 키·인증서를 찾는다.
//
// ca.key/ca.crt 같은 관례적 파일명을 먼저 보고, 없으면 디렉터리 안의 후보를 모아
// "CA:TRUE 인 인증서" 와 "개인키" 를 각각 하나로 좁힌다. 후보가 0개거나 2개 이상이면
// 추측하지 않고 거부하고, 사용자가 파일을 직접 지정할 수 있게 안내한다.
//
// 개인키가 암호화되어 있으면 이 단계에서는 공개키 대조를 할 수 없다(복호화가 필요하다).
// 짝 검증은 패스프레이즈를 받은 LoadMaterial 에서 한다.
func DiscoverInDir(dir, keyFile, certFile string) (Discovered, error) {
	if !fsops.IsDir(dir) {
		return Discovered{}, certerr.Validationf("디렉터리가 아닙니다: %s", dir)
	}

	certPath := certFile
	var err error
	if certPath == "" {
		certPath, err = pickCert(dir)
		if err != nil {
			return Discovered{}, err
		}
	}
	keyPath := keyFile
	if keyPath == "" {
		keyPath, err = pickKey(dir, certPath)
		if err != nil {
			return Discovered{}, err
		}
	}
	if !fsops.IsFile(certPath) {
		return Discovered{}, certerr.Validationf("인증서 파일이 없습니다: %s", certPath)
	}
	if !fsops.IsFile(keyPath) {
		return Discovered{}, certerr.Validationf("개인키 파일이 없습니다: %s", keyPath)
	}

	cert, err := LoadCertFile(certPath)
	if err != nil {
		return Discovered{}, err
	}
	if !IsCACert(cert) {
		return Discovered{}, certerr.Validationf(
			"CA 인증서가 아닙니다(basicConstraints CA:TRUE 아님): %s\n  subject: %s",
			certPath, cert.Subject.String())
	}

	chainPath := pickChain(dir)
	var chain []*x509.Certificate
	if chainPath != "" {
		data, readErr := os.ReadFile(chainPath)
		if readErr == nil {
			found, chainErr := LoadChain(data)
			if chainErr != nil {
				return Discovered{}, chainErr
			}
			// 체인 파일에 발급 CA 자신이 포함된 경우가 흔하다. 중복을 제거한다.
			own := certbuild.Fingerprint(cert)
			for _, c := range found {
				if certbuild.Fingerprint(c) != own {
					chain = append(chain, c)
				}
			}
		}
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return Discovered{}, certerr.WrapValidation(err, "개인키를 읽을 수 없습니다: %s (%v)", keyPath, err)
	}

	abs, _ := filepath.Abs(dir)
	return Discovered{
		Dir: abs, KeyPath: mustAbs(keyPath), CertPath: mustAbs(certPath),
		ChainPath: mustAbsOrEmpty(chainPath), Cert: cert,
		KeyEncrypted: keys.IsEncryptedPEM(keyBytes), Chain: chain,
	}, nil
}

func mustAbs(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func mustAbsOrEmpty(path string) string {
	if path == "" {
		return ""
	}
	return mustAbs(path)
}

func pickCert(dir string) (string, error) {
	for _, name := range preferredCertNames {
		candidate := filepath.Join(dir, name)
		if fsops.IsFile(candidate) {
			return candidate, nil
		}
	}
	var candidates []string
	seen := map[string]bool{}
	for _, pattern := range certGlobs {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		sort.Strings(matches)
		for _, m := range matches {
			if fsops.IsFile(m) && !seen[m] {
				seen[m] = true
				candidates = append(candidates, m)
			}
		}
	}
	// 키 파일이 .pem 으로 섞여 들어오므로 CA 인증서로 읽히는 것만 남긴다.
	var caCerts []string
	for _, path := range candidates {
		if cert, err := LoadCertFile(path); err == nil && IsCACert(cert) {
			caCerts = append(caCerts, path)
		}
	}
	switch len(caCerts) {
	case 1:
		return caCerts[0], nil
	case 0:
		return "", certerr.Validationf(
			"CA 인증서를 찾을 수 없습니다: %s\n  찾아본 이름: %s 및 %s\n  파일을 직접 지정하려면 --ca-cert 를 쓰세요",
			dir, strings.Join(preferredCertNames, ", "), strings.Join(certGlobs, ", "))
	default:
		return "", certerr.Validationf(
			"CA 인증서 후보가 여러 개입니다: %s\n%s\n  --ca-cert 로 하나를 지정하세요",
			dir, bulletList(caCerts))
	}
}

func pickKey(dir, certPath string) (string, error) {
	for _, name := range preferredKeyNames {
		candidate := filepath.Join(dir, name)
		if fsops.IsFile(candidate) {
			return candidate, nil
		}
	}
	var keylike []string
	seen := map[string]bool{}
	for _, pattern := range keyGlobs {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		sort.Strings(matches)
		for _, m := range matches {
			if !fsops.IsFile(m) || m == certPath || seen[m] {
				continue
			}
			seen[m] = true
			head := make([]byte, 4096)
			f, err := os.Open(m)
			if err != nil {
				continue
			}
			n, _ := f.Read(head)
			f.Close()
			if strings.Contains(string(head[:n]), "PRIVATE KEY") {
				keylike = append(keylike, m)
			}
		}
	}
	switch len(keylike) {
	case 1:
		return keylike[0], nil
	case 0:
		return "", certerr.Validationf(
			"CA 개인키를 찾을 수 없습니다: %s\n  찾아본 이름: %s 및 %s\n  파일을 직접 지정하려면 --ca-key 를 쓰세요",
			dir, strings.Join(preferredKeyNames, ", "), strings.Join(keyGlobs, ", "))
	default:
		return "", certerr.Validationf(
			"CA 개인키 후보가 여러 개입니다: %s\n%s\n  --ca-key 로 하나를 지정하세요",
			dir, bulletList(keylike))
	}
}

func pickChain(dir string) string {
	for _, name := range preferredChainNames {
		candidate := filepath.Join(dir, name)
		if fsops.IsFile(candidate) {
			return candidate
		}
	}
	return ""
}

func bulletList(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString("  - " + filepath.Base(p) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// AdoptExternal 은 외부 CA 를 복사 없이 등록한다. 이미 등록된 CA 면 그 행을 재사용한다.
func AdoptExternal(cfg config.Config, s *store.Store, d Discovered, slug string) (store.CA, bool, error) {
	fingerprint := certbuild.Fingerprint(d.Cert)
	if existing, ok := s.FindCAByFingerprint(fingerprint); ok {
		// 같은 CA 를 다른 경로에서 다시 지정한 경우까지 받아 준다(이동·마운트 변경).
		if existing.SourceDir != d.Dir {
			if err := s.Tx(func(tx *sql.Tx) error {
				return s.TouchCASourceDir(tx, existing.ID, d.Dir)
			}); err != nil {
				return store.CA{}, false, err
			}
			updated, err := s.GetCA(fmt.Sprintf("%d", existing.ID))
			return updated, false, err
		}
		return existing, false, nil
	}

	commonName := CommonNameOf(d.Cert)
	base := slug
	if base == "" {
		// 외부 CA 는 목록에서 한눈에 구분되게 접두어를 붙인다.
		base = "ext-" + names.Slugify(commonName, "external-ca")
	} else {
		base = names.Slugify(base, "external-ca")
	}
	chosen := UniqueSlug(s, base)

	var pathLen *int64
	if d.Cert.BasicConstraintsValid && d.Cert.MaxPathLen >= 0 {
		v := int64(d.Cert.MaxPathLen)
		pathLen = &v
	}

	var caID int64
	err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		caID, txErr = s.InsertCA(tx, store.CA{
			Slug: chosen, CommonName: commonName, SubjectDN: d.Cert.Subject.String(),
			KeyAlgo: keys.AlgoOf(d.Cert.PublicKey), KeyEncrypted: d.KeyEncrypted,
			IsExternal: true, SourceDir: d.Dir,
			KeyPath: d.KeyPath, CertPath: d.CertPath, ChainPath: d.ChainPath,
			SerialHex: certbuild.SerialHex(d.Cert.SerialNumber), Fingerprint: fingerprint,
			NotBefore: d.Cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:  d.Cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			PathLen:   pathLen,
		})
		return txErr
	})
	if err != nil {
		return store.CA{}, false, err
	}
	record, err := s.GetCA(fmt.Sprintf("%d", caID))
	return record, true, err
}

// --- 3. 기존 CA 를 data_dir 로 복사해 등록 (ca import) ------------------------

// ImportOptions 는 ca import 입력이다.
type ImportOptions struct {
	KeyFile    string
	CertFile   string
	ChainFile  string
	Passphrase string
	Slug       string
}

// ImportExisting 은 개인키를 data_dir 로 복사해 cert_gen 이 소유하도록 등록한다.
//
// AdoptExternal 과 달리 cert_gen 이 키를 들고 간다. 원본을 치우려는 경우에 쓴다.
// 복사 시점에 패스프레이즈로 키를 열어 **키-인증서 짝을 반드시 검증**한다.
func ImportExisting(cfg config.Config, s *store.Store, opts ImportOptions) (store.CA, error) {
	cert, err := LoadCertFile(opts.CertFile)
	if err != nil {
		return store.CA{}, err
	}
	if !IsCACert(cert) {
		return store.CA{}, certerr.Validationf("CA 인증서가 아닙니다(CA:TRUE 아님): %s", opts.CertFile)
	}
	keyBytes, err := os.ReadFile(opts.KeyFile)
	if err != nil {
		return store.CA{}, certerr.WrapValidation(err, "개인키를 읽을 수 없습니다: %s (%v)", opts.KeyFile, err)
	}
	signer, err := keys.FromPEM(keyBytes, opts.Passphrase)
	if err != nil {
		return store.CA{}, err
	}
	if !keys.PublicMatches(signer, cert.PublicKey) {
		return store.CA{}, certerr.Validationf(
			"개인키와 인증서가 짝이 맞지 않습니다: %s / %s", opts.KeyFile, opts.CertFile)
	}

	fingerprint := certbuild.Fingerprint(cert)
	if _, ok := s.FindCAByFingerprint(fingerprint); ok {
		return store.CA{}, certerr.Conflictf("같은 지문의 CA 가 이미 등록되어 있습니다: %.16s...", fingerprint)
	}

	var chain []*x509.Certificate
	if opts.ChainFile != "" {
		data, err := os.ReadFile(opts.ChainFile)
		if err != nil {
			return store.CA{}, certerr.WrapValidation(err, "체인을 읽을 수 없습니다: %v", err)
		}
		found, err := LoadChain(data)
		if err != nil {
			return store.CA{}, err
		}
		for _, c := range found {
			if certbuild.Fingerprint(c) != fingerprint {
				chain = append(chain, c)
			}
		}
	}

	commonName := CommonNameOf(cert)
	base := opts.Slug
	if base == "" {
		base = commonName
	}
	slug := UniqueSlug(s, names.Slugify(base, "imported-ca"))
	relDir := filepath.Join("ca", slug)
	chainRel := ""
	if len(chain) > 0 {
		chainRel = filepath.Join(relDir, "chain.pem")
	}

	var pathLen *int64
	if cert.BasicConstraintsValid && cert.MaxPathLen >= 0 {
		v := int64(cert.MaxPathLen)
		pathLen = &v
	}

	var caID int64
	err = s.Tx(func(tx *sql.Tx) error {
		var txErr error
		caID, txErr = s.InsertCA(tx, store.CA{
			Slug: slug, CommonName: commonName, SubjectDN: cert.Subject.String(),
			KeyAlgo: keys.AlgoOf(signer), KeyEncrypted: opts.Passphrase != "",
			SourceDir: filepath.Dir(mustAbs(opts.CertFile)),
			KeyPath:   filepath.Join(relDir, "ca.key"), CertPath: filepath.Join(relDir, "ca.crt"),
			ChainPath: chainRel,
			SerialHex: certbuild.SerialHex(cert.SerialNumber), Fingerprint: fingerprint,
			NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			PathLen:   pathLen,
		})
		return txErr
	})
	if err != nil {
		return store.CA{}, err
	}

	absDir := filepath.Join(cfg.DataDir, relDir)
	writeErr := func() error {
		if err := fsops.EnsureDir(absDir, fsops.ModeDir); err != nil {
			return err
		}
		// 원본의 암호화 상태를 그대로 유지한다(재암호화하면 패스프레이즈 관리가 갈라진다).
		if err := fsops.WriteAtomic(filepath.Join(absDir, "ca.key"), keyBytes, fsops.ModeSecret); err != nil {
			return err
		}
		if err := fsops.WriteAtomic(filepath.Join(absDir, "ca.crt"), certbuild.CertPEM(cert), fsops.ModePublic); err != nil {
			return err
		}
		if len(chain) > 0 {
			return fsops.WriteAtomic(filepath.Join(absDir, "chain.pem"), certbuild.ChainPEM(chain), fsops.ModePublic)
		}
		return nil
	}()
	if writeErr != nil {
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteCA(tx, caID) })
		return store.CA{}, writeErr
	}
	return s.GetCA(fmt.Sprintf("%d", caID))
}

// --- 로드 -------------------------------------------------------------------

// LoadMaterial 은 서명에 필요한 키·인증서·체인을 모두 읽는다. 짝 검증까지 여기서 한다.
func LoadMaterial(cfg config.Config, s *store.Store, c store.CA, passphrase string) (Material, error) {
	keyPath, certPath, chainPath := ResolvePaths(cfg, c)
	if !fsops.IsFile(keyPath) {
		msg := fmt.Sprintf("CA 개인키가 없습니다: %s", keyPath)
		if c.IsExternal {
			msg += fmt.Sprintf("\n  (외부 CA: %s 가 마운트되어 있는지 확인하세요)", c.SourceDir)
		}
		return Material{}, certerr.Statef("%s", msg)
	}
	if !fsops.IsFile(certPath) {
		return Material{}, certerr.Statef("CA 인증서가 없습니다: %s", certPath)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return Material{}, certerr.WrapState(err, "CA 개인키를 읽을 수 없습니다: %v", err)
	}
	signer, err := keys.FromPEM(keyBytes, passphrase)
	if err != nil {
		return Material{}, err
	}
	cert, err := LoadCertFile(certPath)
	if err != nil {
		return Material{}, err
	}
	if !keys.PublicMatches(signer, cert.PublicKey) {
		// 외부 디렉터리에서 파일을 추측해 짝지은 경우 여기서 걸린다.
		return Material{}, certerr.Validationf(
			"CA 개인키와 인증서가 짝이 맞지 않습니다: %s / %s", keyPath, certPath)
	}

	var chain []*x509.Certificate
	if chainPath != "" && fsops.IsFile(chainPath) {
		data, err := os.ReadFile(chainPath)
		if err == nil {
			found, chainErr := LoadChain(data)
			if chainErr != nil {
				return Material{}, chainErr
			}
			own := certbuild.Fingerprint(cert)
			for _, candidate := range found {
				if certbuild.Fingerprint(candidate) != own {
					chain = append(chain, candidate)
				}
			}
		}
	}
	return Material{Record: c, Key: signer, Cert: cert, Chain: chain}, nil
}
