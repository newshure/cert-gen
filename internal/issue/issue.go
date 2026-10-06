// Package issue — leaf 인증서 발급·갱신·CSR 서명.
//
// 순서가 중요하다:
//
//  1. 짧은 쓰기 트랜잭션에서 seq 할당
//  2. serial 생성 (DB 무관)
//  3. 키 생성 + 서명   ← 트랜잭션 **밖**. RSA-4096 생성에 수 초가 걸리는데 그 동안 쓰기 락을
//     잡고 있으면 동시에 실행된 다른 발급이 모두 막힌다.
//  4. 짧은 쓰기 트랜잭션에서 INSERT → 커밋
//  5. 번들 zip 쓰기. 실패하면 4 의 행을 지운다(보상 트랜잭션).
//
// 4 와 5 의 순서를 바꾸면 DB 에 없는 고아 zip 이 남는다. 지금 순서에서는 최악의 경우
// "행은 있는데 zip 이 없다" 가 되고, 그건 cert show 가 명확한 오류로 알려줄 수 있다.
package issue

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"github.com/newshure/cert-gen/internal/bundle"
	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/names"
	"github.com/newshure/cert-gen/internal/profiles"
	"github.com/newshure/cert-gen/internal/store"
)

// Result 는 발급 결과다.
type Result struct {
	Record     store.Cert
	BundlePath string
	Cert       *x509.Certificate
	// Warnings 는 치명적이지 않은 경고다. 프런트엔드가 그대로 보여 준다.
	Warnings []string
}

// Options 는 발급 입력이다.
type Options struct {
	Material  ca.Material
	Subject   names.Subject
	SANValues []string
	Profile   string
	KeyAlgo   string
	Days      int
	Note      string
	Frontend  string
	// ExistingKey 가 있으면 미리 만들어 둔 키를 쓴다(즉석 생성하지 않는다).
	ExistingKey *ca.LoadedKey
}

const timeLayout = "2006-01-02T15:04:05Z"

// CheckDays 는 유효기간을 검사한다. 상한 초과는 거부, 관례 초과는 경고다.
func CheckDays(cfg config.Config, days int) ([]string, error) {
	if days > cfg.Cert.MaxDays {
		return nil, certerr.Validationf(
			"유효기간이 상한을 넘습니다: %d일 > %d일 (설정 [cert].max_days 로 조정)",
			days, cfg.Cert.MaxDays)
	}
	if days > 397 {
		// 사설 CA 에 강제되는 규칙은 아니다. 다만 공인 CA 관례를 넘긴다는 사실은 알려 준다.
		return []string{fmt.Sprintf(
			"유효기간 %d일은 공인 CA 관례(397일)를 넘습니다. "+
				"사설 CA 에는 강제되지 않지만 일부 클라이언트가 경고할 수 있습니다", days)}, nil
	}
	return nil, nil
}

// checkCAValidity 는 CA 자체의 만료가 leaf 보다 먼저 오는지 확인한다.
//
// CA 가 먼저 만료되면 leaf 는 유효기간이 남아 있어도 검증에 실패한다. 발급 시점에 알려 주지
// 않으면 "어제까지 되던 게 왜" 로 돌아온다.
func checkCAValidity(m ca.Material, days int) ([]string, error) {
	now := time.Now()
	caExpiry := m.Cert.NotAfter
	if !caExpiry.After(now) {
		return nil, certerr.Validationf(
			"CA 인증서가 이미 만료되었습니다(%s). 이 CA 로는 발급할 수 없습니다",
			caExpiry.Format("2006-01-02"))
	}
	leafExpiry := now.AddDate(0, 0, days)
	if caExpiry.Before(leafExpiry) {
		remaining := int(caExpiry.Sub(now).Hours() / 24)
		return []string{fmt.Sprintf(
			"CA 가 leaf 보다 먼저 만료됩니다(CA: %s, 남은 %d일). "+
				"CA 만료 이후에는 이 인증서도 검증에 실패합니다",
			caExpiry.Format("2006-01-02"), remaining)}, nil
	}
	return nil, nil
}

// Issue 는 CA 로 leaf 인증서를 발급하고 번들을 만든다.
func Issue(cfg config.Config, s *store.Store, opts Options) (Result, error) {
	profileName := opts.Profile
	if profileName == "" {
		profileName = cfg.Cert.DefaultProfile
	}
	profile, err := profiles.GetLeaf(profileName)
	if err != nil {
		return Result{}, err
	}

	algo := opts.KeyAlgo
	if opts.ExistingKey != nil {
		algo = opts.ExistingKey.Algo
	} else if algo == "" {
		algo = cfg.Cert.DefaultKeyAlgo
	}
	if _, err := keys.SpecFor(algo); err != nil {
		return Result{}, err
	}

	days := opts.Days
	if days == 0 {
		days = cfg.Cert.DefaultDays
	}

	warnings, err := CheckDays(cfg, days)
	if err != nil {
		return Result{}, err
	}
	caWarnings, err := checkCAValidity(opts.Material, days)
	if err != nil {
		return Result{}, err
	}
	warnings = append(warnings, caWarnings...)

	subject, err := names.BuildSubject(opts.Subject)
	if err != nil {
		return Result{}, err
	}
	sans, err := names.BuildSANs(opts.Subject.CommonName, opts.SANValues)
	if err != nil {
		return Result{}, err
	}
	if profile.RequiresSAN && len(sans) == 0 {
		return Result{}, certerr.Validationf(
			"SAN 이 없습니다. CN(%q)이 호스트명 형식이 아니면 --san 으로 최소 1개를 지정해야 합니다",
			opts.Subject.CommonName)
	}

	return perform(cfg, s, performInput{
		material:    opts.Material,
		subjectName: subject,
		commonName:  opts.Subject.CommonName,
		sans:        sans,
		profile:     profile,
		keyAlgo:     algo,
		days:        days,
		note:        opts.Note,
		frontend:    opts.Frontend,
		warnings:    warnings,
		source:      "generated",
		existingKey: opts.ExistingKey,
	})
}

// RenewOptions 는 갱신 입력이다.
type RenewOptions struct {
	Material    ca.Material
	Record      store.Cert
	Days        int
	KeyAlgo     string
	Frontend    string
	ExistingKey *ca.LoadedKey
}

// Renew 는 기존 인증서와 같은 DN·SAN 으로 재발급한다.
//
// 기본은 **새 키**다. 키를 재사용하면 이전 인증서가 유출됐을 때 갱신의 의미가 사라진다.
// 다만 장비가 키 교체를 받지 못하는 경우가 있어, ExistingKey 로 특정 키를 지정하면 그 키로
// 발급한다(호출자가 의도를 명시한 경우에만).
//
// 이전 건은 superseded 로 표시해 목록에서 혼동되지 않게 한다(폐기와는 구분한다).
func Renew(cfg config.Config, s *store.Store, opts RenewOptions) (Result, error) {
	// DN 을 Subject 구조체로 되돌리면 지원하지 않는 속성이 유실된다.
	// 원래 인증서의 Subject 를 그대로 다시 쓴다.
	previousCert, err := loadCertFromBundle(cfg, s, opts.Record)
	if err != nil {
		return Result{}, err
	}

	profile, err := profiles.GetLeaf(opts.Record.Profile)
	if err != nil {
		return Result{}, err
	}
	algo := opts.KeyAlgo
	if opts.ExistingKey != nil {
		algo = opts.ExistingKey.Algo
	} else if algo == "" {
		algo = opts.Record.KeyAlgo
	}
	days := opts.Days
	if days == 0 {
		days = cfg.Cert.DefaultDays
	}

	warnings, err := CheckDays(cfg, days)
	if err != nil {
		return Result{}, err
	}
	caWarnings, err := checkCAValidity(opts.Material, days)
	if err != nil {
		return Result{}, err
	}
	warnings = append(warnings, caWarnings...)

	renewedFrom := opts.Record.ID
	result, err := perform(cfg, s, performInput{
		material:    opts.Material,
		subjectName: previousCert.Subject,
		commonName:  opts.Record.CommonName,
		sans:        opts.Record.SANs,
		profile:     profile,
		keyAlgo:     algo,
		days:        days,
		note:        opts.Record.Note,
		frontend:    opts.Frontend,
		warnings:    warnings,
		source:      "generated",
		existingKey: opts.ExistingKey,
		renewedFrom: &renewedFrom,
	})
	if err != nil {
		return Result{}, err
	}
	if opts.Record.Status == "valid" {
		if err := s.Tx(func(tx *sql.Tx) error {
			return s.SetCertStatus(tx, opts.Record.ID, "superseded", "", "")
		}); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func loadCertFromBundle(cfg config.Config, s *store.Store, record store.Cert) (*x509.Certificate, error) {
	path := filepath.Join(cfg.DataDir, record.BundlePath)
	members, err := bundle.Members(path)
	if err != nil {
		return nil, err
	}
	data, ok := members[bundle.MemberCert]
	if !ok {
		return nil, certerr.Statef("번들에 인증서가 없습니다: %s", path)
	}
	return ca.LoadCertBytes(data, path)
}

// SignCSROptions 는 CSR 서명 입력이다.
type SignCSROptions struct {
	Material     ca.Material
	CSR          *x509.CertificateRequest
	Profile      string
	Days         int
	OverrideSANs []string
	Note         string
	Frontend     string
	// CommonName·SANs 는 호출자(csr 패키지)가 추출해 넘긴다.
	CommonName string
	SANs       []names.SAN
	CSRPEM     []byte
}

// SignCSR 은 받은 CSR 을 우리 CA 로 서명한다.
//
// CSR 의 공개키와 Subject 는 그대로 쓰고, **확장은 우리 프로필로 덮어쓴다.** 요청자가 보낸
// 확장을 그대로 믿으면 CA 가 아닌 주체에게 CA:TRUE 를 발급하는 사고가 가능하다.
func SignCSR(cfg config.Config, s *store.Store, opts SignCSROptions) (Result, error) {
	profileName := opts.Profile
	if profileName == "" {
		profileName = cfg.Cert.DefaultProfile
	}
	profile, err := profiles.GetLeaf(profileName)
	if err != nil {
		return Result{}, err
	}
	days := opts.Days
	if days == 0 {
		days = cfg.Cert.DefaultDays
	}
	warnings, err := CheckDays(cfg, days)
	if err != nil {
		return Result{}, err
	}
	caWarnings, err := checkCAValidity(opts.Material, days)
	if err != nil {
		return Result{}, err
	}
	warnings = append(warnings, caWarnings...)

	sans := opts.SANs
	if len(opts.OverrideSANs) > 0 {
		sans, err = names.BuildSANs(opts.CommonName, opts.OverrideSANs)
		if err != nil {
			return Result{}, err
		}
	}
	if profile.RequiresSAN && len(sans) == 0 {
		return Result{}, certerr.Validationf(
			"CSR 에 SAN 이 없고 CN(%q)도 호스트명이 아닙니다. --san 으로 지정하세요", opts.CommonName)
	}

	return perform(cfg, s, performInput{
		material:    opts.Material,
		subjectName: opts.CSR.Subject,
		commonName:  opts.CommonName,
		sans:        sans,
		profile:     profile,
		keyAlgo:     keys.AlgoOf(opts.CSR.PublicKey),
		days:        days,
		note:        opts.Note,
		frontend:    opts.Frontend,
		warnings:    warnings,
		source:      "csr",
		publicKey:   opts.CSR.PublicKey,
		csrPEM:      opts.CSRPEM,
	})
}

// --- 공용 경로 ---------------------------------------------------------------

type performInput struct {
	material ca.Material
	// subjectName 은 pkix.Name 을 그대로 나른다. DN 문자열로 왕복시키면 우리가 모르는
	// 속성(예: serialNumber, 추가 OID)이 유실된다.
	subjectName pkix.Name
	commonName  string
	sans        []names.SAN
	profile     profiles.Profile
	keyAlgo     string
	days        int
	note        string
	frontend    string
	warnings    []string
	source      string
	// publicKey 가 주어지면(CSR 서명) 키를 만들지 않고 그 공개키로 서명한다.
	// 이 경우 번들에 개인키가 들어가지 않는다(요청자가 가지고 있다).
	publicKey   crypto.PublicKey
	csrPEM      []byte
	existingKey *ca.LoadedKey
	renewedFrom *int64
}

func perform(cfg config.Config, s *store.Store, in performInput) (Result, error) {
	subject := in.subjectName
	caRecord := in.material.Record

	// 1. 짧은 쓰기 트랜잭션에서 순번 할당
	var seq int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		seq, txErr = s.AllocateSeq(tx, caRecord.ID)
		return txErr
	}); err != nil {
		return Result{}, err
	}

	// 2~3. 트랜잭션 밖: 키 생성 + 서명
	var (
		leafKey crypto.Signer
		err     error
	)
	publicKey := in.publicKey
	if publicKey == nil {
		if in.existingKey != nil {
			// 미리 만들어 둔 키를 쓴다. 같은 키로 갱신하거나, 보안 담당자가 먼저 만든 키를
			// 쓰는 흐름을 지원한다.
			leafKey = in.existingKey.Key
		} else {
			leafKey, err = keys.Generate(in.keyAlgo)
			if err != nil {
				return Result{}, err
			}
		}
		publicKey = leafKey.Public()
	}

	notBefore, notAfter, err := certbuild.ValidityWindow(in.days, cfg.Cert.BackdateMinutes)
	if err != nil {
		return Result{}, err
	}
	serial, err := certbuild.NewSerial()
	if err != nil {
		return Result{}, err
	}
	cert, _, err := certbuild.Build(certbuild.Request{
		Subject: subject, Issuer: in.material.Cert, PublicKey: publicKey,
		Signer: in.material.Key, Profile: in.profile, Serial: serial,
		NotBefore: notBefore, NotAfter: notAfter, SANs: in.sans,
	})
	if err != nil {
		return Result{}, err
	}
	serialHex := certbuild.SerialHex(serial)
	publicSHA, err := keys.PublicDigest(publicKey)
	if err != nil {
		return Result{}, err
	}

	// 4. 짧은 쓰기 트랜잭션에서 등록
	var certID int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		certID, txErr = s.InsertCert(tx, store.Cert{
			CAID: caRecord.ID, Seq: seq, SerialHex: serialHex,
			CommonName: in.commonName, SubjectDN: names.DNString(subject), SANs: in.sans,
			Profile: in.profile.Name, KeyAlgo: in.keyAlgo,
			NotBefore: notBefore.UTC().Format(timeLayout), NotAfter: notAfter.UTC().Format(timeLayout),
			Fingerprint: certbuild.Fingerprint(cert), PublicSHA256: publicSHA,
			BundlePath: "", BundleSHA256: "", // 번들 경로는 id 를 포함하므로 아래에서 갱신한다
			HasPrivateKey: leafKey != nil, KeyID: keyIDOf(in.existingKey),
			Source: in.source, Status: "valid", Note: in.note, RenewedFrom: in.renewedFrom,
		})
		return txErr
	}); err != nil {
		return Result{}, err
	}

	// 5. 번들 쓰기. 실패하면 행을 되돌린다.
	rel := bundle.RelPath(certID, in.commonName, serialHex, notAfter.UTC().Format("2006"))
	bundlePath := filepath.Join(cfg.DataDir, rel)

	writeErr := func() error {
		var (
			keyPEM []byte
			err    error
		)
		if leafKey != nil {
			// 서버에 올릴 키에는 패스프레이즈를 걸지 않는다 — 걸면 nginx·Tomcat 이 부팅할
			// 때마다 패스워드를 묻고 무인 재시작이 깨진다.
			keyPEM, err = keys.ToPEM(leafKey, "")
			if err != nil {
				return err
			}
		}
		// 체인: 발급 CA 가 중간 CA 인 경우 발급 CA 자신 + 그 위쪽을 넣는다.
		// Root 가 직접 발급했다면 체인은 비운다(Root 는 ca.crt 로 따로 제공한다).
		var chainCerts []*x509.Certificate
		if len(in.material.Chain) > 0 {
			chainCerts = append(chainCerts, in.material.Cert)
			chainCerts = append(chainCerts, in.material.Chain[:len(in.material.Chain)-1]...)
		}
		var chainPEM []byte
		if len(chainCerts) > 0 {
			chainPEM = certbuild.ChainPEM(chainCerts)
		}

		meta := bundle.Metadata{
			Tool: "cert_gen", CommonName: in.commonName, SubjectDN: names.DNString(subject),
			SANs: in.sans, Profile: in.profile.Name, KeyAlgo: in.keyAlgo,
			Serial: certbuild.FormatColons(serialHex), Seq: seq,
			Fingerprint: certbuild.Fingerprint(cert), PublicSHA256: publicSHA,
			NotBefore: notBefore.UTC().Format(timeLayout), NotAfter: notAfter.UTC().Format(timeLayout),
			CASlug: caRecord.Slug, CACommonName: caRecord.CommonName,
			CAExternal: caRecord.IsExternal, Note: in.note,
		}
		prefix := fmt.Sprintf("%s-%s", names.Slugify(in.commonName, "cert"), shortHex(publicSHA))
		if err := fsops.EnsureDir(filepath.Dir(bundlePath), fsops.ModeDir); err != nil {
			return err
		}
		digest, err := bundle.Write(bundlePath, prefix, bundle.Content{
			CertPEM: certbuild.CertPEM(cert), CAPEM: certbuild.CertPEM(in.material.Root()),
			Metadata: meta, KeyPEM: keyPEM, ChainPEM: chainPEM, CSRPEM: in.csrPEM,
		})
		if err != nil {
			return err
		}
		return s.Tx(func(tx *sql.Tx) error { return s.SetBundle(tx, certID, rel, digest) })
	}()
	if writeErr != nil {
		// 번들을 못 만들었으면 발급은 없었던 것으로 되돌린다.
		bundle.RemoveIfExists(bundlePath)
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteCert(tx, certID) })
		return Result{}, writeErr
	}

	action := "cert.issue"
	if in.renewedFrom != nil {
		action = "cert.renew"
	}
	_ = s.Tx(func(tx *sql.Tx) error {
		detail := map[string]any{
			"ca": caRecord.Slug, "ca_external": caRecord.IsExternal,
			"profile": in.profile.Name, "key_algo": in.keyAlgo, "days": in.days,
			"serial": serialHex, "source": in.source,
		}
		if in.renewedFrom != nil {
			detail["renewed_from"] = *in.renewedFrom
		}
		return s.Audit(tx, in.frontend, "", action, in.commonName, true, detail)
	})

	record, err := s.GetCert(certID)
	if err != nil {
		return Result{}, err
	}
	return Result{Record: record, BundlePath: bundlePath, Cert: cert, Warnings: in.warnings}, nil
}

func keyIDOf(k *ca.LoadedKey) *int64 {
	if k == nil {
		return nil
	}
	return k.KeyID
}

func shortHex(text string) string {
	if len(text) <= 8 {
		return text
	}
	return text[:8]
}
