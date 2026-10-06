// Package crl — 인증서 폐기와 CRL 생성.
//
// 폐기는 두 부분이다. 우리 DB 의 상태를 바꾸는 것과, 그 사실을 **검증하는 쪽이 알 수 있게**
// CRL 로 내보내는 것이다. 앞만 하고 뒤를 빠뜨리면 "폐기했다" 는 기록만 남고 폐기된 인증서는
// 계속 통한다. 그래서 Revoke 는 DB 변경 후 CRL 재생성까지 한 흐름으로 처리한다.
//
// 한 가지 한계를 분명히 해 둔다. 우리가 발급하는 인증서에는 CRL 배포 지점(CDP)이 들어 있지
// 않다. 폐쇄망에 CRL 을 서비스할 HTTP 지점을 전제할 수 없기 때문이다. 따라서 CRL 은
// **검증하는 쪽이 파일을 직접 받아 쓰는** 용도다(nginx 의 ssl_crl, Java 의 PKIXParameters 등).
package crl

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certbuild"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/store"
)

// Reason 은 RFC 5280 의 폐기 사유다.
type Reason struct {
	Name  string
	Code  int
	Label string
}

// Reasons 의 순서가 CLI 도움말과 TUI 선택 목록의 순서가 된다.
//
// RFC 5280 §5.3.1 의 reasonCode 다. 6(certificateHold)은 뺐다 — "보류" 는 해제를 전제하는
// 상태인데 우리는 해제 경로를 만들지 않으므로, 넣으면 되돌릴 수 없는 보류가 된다.
// 7 은 미사용(RFC 가 할당하지 않았다), 8(removeFromCRL)은 델타 CRL 전용이다.
var Reasons = []Reason{
	{Name: "unspecified", Code: 0, Label: "사유 없음"},
	{Name: "keyCompromise", Code: 1, Label: "개인키 유출"},
	{Name: "cACompromise", Code: 2, Label: "CA 키 유출"},
	{Name: "affiliationChanged", Code: 3, Label: "소속·정보 변경"},
	{Name: "superseded", Code: 4, Label: "대체됨(갱신 등)"},
	{Name: "cessationOfOperation", Code: 5, Label: "운영 중단"},
	{Name: "privilegeWithdrawn", Code: 9, Label: "권한 회수"},
	{Name: "aACompromise", Code: 10, Label: "속성기관 키 유출"},
}

// ReasonNames 는 선택 가능한 사유 이름들이다.
func ReasonNames() []string {
	out := make([]string, 0, len(Reasons))
	for _, r := range Reasons {
		out = append(out, r.Name)
	}
	return out
}

// ReasonFor 는 이름으로 사유를 찾는다. 빈 이름은 unspecified 다.
func ReasonFor(name string) (Reason, error) {
	if name == "" {
		return Reasons[0], nil
	}
	for _, r := range Reasons {
		if r.Name == name {
			return r, nil
		}
	}
	return Reason{}, certerr.Validationf(
		"알 수 없는 폐기 사유입니다: %q (사용 가능: %v)", name, ReasonNames())
}

// RevokeResult 는 폐기 결과다.
type RevokeResult struct {
	Record store.Cert
	Reason Reason
	CRL    Generated
}

// Revoke 는 인증서를 폐기하고 CRL 을 다시 만든다.
func Revoke(cfg config.Config, s *store.Store, m ca.Material, record store.Cert,
	reasonName, frontend string) (RevokeResult, error) {

	reason, err := ReasonFor(reasonName)
	if err != nil {
		return RevokeResult{}, err
	}
	if record.CAID != m.Record.ID {
		// 다른 CA 의 키로는 이 인증서의 폐기를 증명할 수 없다. CRL 서명이 맞지 않는다.
		return RevokeResult{}, certerr.Validationf(
			"이 인증서는 다른 CA(%d)가 발급했습니다. 발급한 CA 로 폐기하세요", record.CAID)
	}
	switch record.Status {
	case "revoked":
		return RevokeResult{}, certerr.Conflictf(
			"이미 폐기된 인증서입니다 (%s, 사유: %s)", record.RevokedAt, record.RevokeReason)
	case "superseded":
		// 막지 않는다. 갱신으로 대체된 인증서도 키가 유출되면 폐기해야 한다.
	}

	revokedAt := store.Now()
	if err := s.Tx(func(tx *sql.Tx) error {
		return s.SetCertStatus(tx, record.ID, "revoked", revokedAt, reason.Name)
	}); err != nil {
		return RevokeResult{}, err
	}

	// DB 를 바꿨으면 CRL 도 반드시 다시 만든다. 여기서 멈추면 "폐기했다" 는 기록만 남고
	// 폐기된 인증서는 계속 통한다.
	generated, err := Generate(cfg, s, m, frontend)
	if err != nil {
		return RevokeResult{}, err
	}

	updated, err := s.GetCert(record.ID)
	if err != nil {
		return RevokeResult{}, err
	}
	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "cert.revoke", record.CommonName, true, map[string]any{
			"ca": m.Record.Slug, "serial": record.SerialHex,
			"reason": reason.Name, "reason_code": reason.Code,
		})
	})
	return RevokeResult{Record: updated, Reason: reason, CRL: generated}, nil
}

// Generated 는 생성한 CRL 이다.
type Generated struct {
	DER        []byte
	PEM        []byte
	Path       string
	Number     int64
	Count      int
	ThisUpdate time.Time
	NextUpdate time.Time
	// Entries 는 CRL 에 들어간 항목이다(표시용).
	Entries []Entry
}

// Entry 는 CRL 항목 하나다.
type Entry struct {
	SerialHex  string
	CommonName string
	RevokedAt  time.Time
	Reason     Reason
}

// Generate 는 CA 의 CRL 을 다시 만들어 파일로 쓴다.
//
// 폐기 목록이 비어 있어도 만든다. 빈 CRL 은 "폐기된 것이 없다" 는 **유효한 진술**이고,
// 검증하는 쪽은 CRL 파일이 없는 것과 비어 있는 것을 다르게 취급한다(없으면 보통 검증 실패).
func Generate(cfg config.Config, s *store.Store, m ca.Material, frontend string) (Generated, error) {
	if !m.Cert.IsCA {
		return Generated{}, certerr.Validationf("CA 인증서가 아니므로 CRL 을 만들 수 없습니다")
	}
	// CRL 서명에는 cRLSign 비트가 필요하다. 없는 CA 로 만든 CRL 은 검증하는 쪽이 거부한다.
	if m.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return Generated{}, certerr.Validationf(
			"이 CA 인증서에는 cRLSign 권한이 없어 CRL 을 만들 수 없습니다")
	}

	revoked, err := s.RevokedForCA(m.Record.ID)
	if err != nil {
		return Generated{}, err
	}

	nextDays := cfg.CA.CRLNextUpdateDays
	if nextDays <= 0 {
		nextDays = 30
	}
	thisUpdate := time.Now().UTC().Add(-time.Duration(cfg.Cert.BackdateMinutes) * time.Minute)
	nextUpdate := thisUpdate.AddDate(0, 0, nextDays)

	var (
		entries    []x509.RevocationListEntry
		shown      []Entry
		parseFails []string
	)
	for _, rec := range revoked {
		serial, err := certbuild.SerialFromHex(rec.SerialHex)
		if err != nil {
			// 한 건이 깨졌다고 CRL 전체를 포기하면 나머지 폐기가 전부 무효가 된다.
			// 건너뛰되 무엇을 건너뛰었는지는 오류로 알린다.
			parseFails = append(parseFails, rec.SerialHex)
			continue
		}
		revokedAt, err := store.ParseTime(rec.RevokedAt)
		if err != nil {
			revokedAt = thisUpdate
		}
		reason, err := ReasonFor(rec.RevokeReason)
		if err != nil {
			reason = Reasons[0]
		}
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revokedAt.UTC(),
		}
		// reasonCode 0(unspecified)은 넣지 않는다. RFC 5280 §5.3.1 이 기본값은 생략하라고
		// 한다 — 넣으면 일부 검증기가 DER 인코딩 차이로 경고한다.
		if reason.Code != 0 {
			entry.ReasonCode = reason.Code
		}
		entries = append(entries, entry)
		shown = append(shown, Entry{
			SerialHex: rec.SerialHex, CommonName: rec.CommonName,
			RevokedAt: revokedAt, Reason: reason,
		})
	}
	if len(parseFails) > 0 {
		return Generated{}, certerr.Statef(
			"폐기 목록의 serial 을 해석할 수 없습니다: %v (DB 손상 가능)", parseFails)
	}

	// CRL 번호는 단조 증가해야 한다. 검증하는 쪽이 이것으로 더 새로운 CRL 을 판별한다.
	var number int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		number, txErr = s.BumpCRLNumber(tx, m.Record.ID)
		return txErr
	}); err != nil {
		return Generated{}, err
	}

	der, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
	}, m.Cert, m.Key)
	if err != nil {
		return Generated{}, certerr.WrapState(err, "CRL 을 만들 수 없습니다: %v", err)
	}

	rel := filepath.Join("crl", m.Record.Slug+".crl")
	path := filepath.Join(cfg.DataDir, rel)
	if err := fsops.EnsureDir(filepath.Dir(path), fsops.ModeDir); err != nil {
		return Generated{}, err
	}
	// CRL 은 공개 정보다. 검증하는 쪽이 읽어야 하므로 0644 다.
	if err := fsops.WriteAtomic(path, der, fsops.ModePublic); err != nil {
		return Generated{}, err
	}

	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "crl.generate", m.Record.Slug, true, map[string]any{
			"number": number, "count": len(entries), "next_update": nextUpdate.Format(time.RFC3339),
		})
	})

	return Generated{
		DER: der, PEM: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}),
		Path: path, Number: number, Count: len(entries),
		ThisUpdate: thisUpdate, NextUpdate: nextUpdate, Entries: shown,
	}, nil
}

// Load 는 저장된 CRL 을 읽어 파싱한다.
func Load(cfg config.Config, c store.CA) (*x509.RevocationList, error) {
	path := filepath.Join(cfg.DataDir, "crl", c.Slug+".crl")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, certerr.NotFoundf("CRL 이 아직 없습니다: %s (crl generate 로 만드세요)", path)
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	list, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, certerr.WrapState(err, "CRL 을 해석할 수 없습니다: %s (%v)", path, err)
	}
	return list, nil
}

// IsRevoked 는 CRL 에 해당 인증서가 있는지 본다.
//
// CRL 의 서명을 반드시 확인한다. 확인하지 않으면 누구나 빈 CRL 을 놓아 폐기를 무효화할 수 있다.
func IsRevoked(list *x509.RevocationList, issuer *x509.Certificate, cert *x509.Certificate) (bool, error) {
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return false, certerr.Verificationf("CRL 서명이 발급 CA 와 맞지 않습니다: %v", err)
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// Describe 는 CRL 상태를 한 줄로 요약한다.
func Describe(g Generated) string {
	return fmt.Sprintf("CRL #%d — 폐기 %d건, 다음 갱신 %s",
		g.Number, g.Count, g.NextUpdate.Format("2006-01-02"))
}
