package store

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/newshure/cert-gen/internal/certerr"
)

const certColumns = `id, ca_id, seq, serial_hex, common_name, subject_dn, sans_json, profile,
	key_algo, not_before, not_after, fingerprint_sha256, public_sha256, bundle_path,
	bundle_sha256, has_private_key, key_id, source, status, revoked_at, revoke_reason,
	renewed_from, note, created_at`

func scanCert(row interface{ Scan(...any) error }) (Cert, error) {
	var (
		c            Cert
		sansJSON     string
		publicSHA    sql.NullString
		keyID        sql.NullInt64
		revokedAt    sql.NullString
		revokeReason sql.NullString
		renewedFrom  sql.NullInt64
		note         sql.NullString
		hasKey       int
	)
	err := row.Scan(&c.ID, &c.CAID, &c.Seq, &c.SerialHex, &c.CommonName, &c.SubjectDN, &sansJSON,
		&c.Profile, &c.KeyAlgo, &c.NotBefore, &c.NotAfter, &c.Fingerprint, &publicSHA,
		&c.BundlePath, &c.BundleSHA256, &hasKey, &keyID, &c.Source, &c.Status, &revokedAt,
		&revokeReason, &renewedFrom, &note, &c.CreatedAt)
	if err != nil {
		return Cert{}, err
	}
	c.SANs = unmarshalSANs(sansJSON)
	c.PublicSHA256 = fromNullString(publicSHA)
	c.KeyID = fromNullInt(keyID)
	c.RevokedAt = fromNullString(revokedAt)
	c.RevokeReason = fromNullString(revokeReason)
	c.RenewedFrom = fromNullInt(renewedFrom)
	c.Note = fromNullString(note)
	c.HasPrivateKey = hasKey != 0
	return c, nil
}

// InsertCert 는 인증서를 등록하고 id 를 돌려준다.
func (s *Store) InsertCert(tx *sql.Tx, c Cert) (int64, error) {
	sansJSON, err := marshalSANs(c.SANs)
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO certificate
		(ca_id, seq, serial_hex, common_name, subject_dn, sans_json, profile, key_algo,
		 not_before, not_after, fingerprint_sha256, public_sha256, bundle_path, bundle_sha256,
		 has_private_key, key_id, source, status, note, renewed_from, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.CAID, c.Seq, c.SerialHex, c.CommonName, c.SubjectDN, sansJSON, c.Profile, c.KeyAlgo,
		c.NotBefore, c.NotAfter, c.Fingerprint, nullString(c.PublicSHA256), c.BundlePath,
		c.BundleSHA256, boolInt(c.HasPrivateKey), nullInt(c.KeyID), c.Source, c.Status,
		nullString(c.Note), nullInt(c.RenewedFrom), Now())
	if err != nil {
		if isUniqueViolation(err, "serial") {
			// 159비트 난수 serial 의 충돌은 현실에서 일어나지 않는다. 최후 방어선이다.
			return 0, certerr.Conflictf("serial 중복: %s", c.SerialHex)
		}
		return 0, certerr.WrapConflict(err, "인증서를 등록할 수 없습니다: %v", err)
	}
	return res.LastInsertId()
}

// GetCert 는 id 로 인증서를 찾는다.
func (s *Store) GetCert(id int64) (Cert, error) {
	row := s.db.QueryRow(`SELECT `+certColumns+` FROM certificate WHERE id = ?`, id)
	c, err := scanCert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Cert{}, certerr.NotFoundf("인증서를 찾을 수 없습니다: id=%d", id)
	}
	if err != nil {
		return Cert{}, certerr.WrapState(err, "인증서를 읽을 수 없습니다: %v", err)
	}
	return c, nil
}

// ResolveCert 는 id, serial(콜론 표기 포함), CN 중 어느 것으로든 찾는다.
// CN 이 중복이면 가장 최근 것.
func (s *Store) ResolveCert(ref string) (Cert, error) {
	ref = strings.TrimSpace(ref)
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		if c, err := s.GetCert(id); err == nil {
			return c, nil
		}
	}

	normalized := strings.ToLower(strings.ReplaceAll(ref, ":", ""))
	normalized = strings.TrimPrefix(normalized, "0x")
	row := s.db.QueryRow(
		`SELECT `+certColumns+` FROM certificate WHERE lower(serial_hex) = ?`, normalized)
	if c, err := scanCert(row); err == nil {
		return c, nil
	}

	row = s.db.QueryRow(
		`SELECT `+certColumns+` FROM certificate WHERE common_name = ? ORDER BY id DESC LIMIT 1`, ref)
	if c, err := scanCert(row); err == nil {
		return c, nil
	}
	return Cert{}, certerr.NotFoundf("인증서를 찾을 수 없습니다: %s", ref)
}

// CertFilter 는 목록 조회 조건이다.
type CertFilter struct {
	CAID       *int64
	Status     string
	Search     string
	ExpiringIn *int // N일 내 만료
	Limit      int
	PublicSHA  string // 이 공개키를 담은 인증서만
}

// ListCerts 는 조건에 맞는 인증서를 최신순으로 돌려준다.
func (s *Store) ListCerts(f CertFilter) ([]Cert, error) {
	query := `SELECT ` + certColumns + ` FROM certificate WHERE 1=1`
	var args []any
	if f.CAID != nil {
		query += ` AND ca_id = ?`
		args = append(args, *f.CAID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.Search != "" {
		// CN 과 SAN 양쪽을 본다. SAN 은 JSON 문자열이라 LIKE 로 충분하다(규모가 작다).
		query += ` AND (common_name LIKE ? OR sans_json LIKE ?)`
		args = append(args, "%"+f.Search+"%", "%"+f.Search+"%")
	}
	if f.ExpiringIn != nil {
		cutoff := time.Now().UTC().AddDate(0, 0, *f.ExpiringIn).Format("2006-01-02T15:04:05Z")
		query += ` AND not_after <= ?`
		args = append(args, cutoff)
	}
	if f.PublicSHA != "" {
		query += ` AND public_sha256 = ?`
		args = append(args, f.PublicSHA)
	}
	query += ` ORDER BY id DESC`
	if f.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, f.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, certerr.WrapState(err, "인증서 목록을 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, certerr.WrapState(err, "인증서를 읽을 수 없습니다: %v", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CertsForKey 는 같은 공개키를 담은 인증서들이다(키 → 인증서 방향의 짝 조회).
func (s *Store) CertsForKey(publicSHA string) ([]Cert, error) {
	return s.ListCerts(CertFilter{PublicSHA: publicSHA})
}

// RevokedForCA 는 폐기된 인증서 목록이다(CRL 생성용).
func (s *Store) RevokedForCA(caID int64) ([]Cert, error) {
	rows, err := s.db.Query(
		`SELECT `+certColumns+` FROM certificate WHERE ca_id = ? AND status = 'revoked'
		 ORDER BY revoked_at`, caID)
	if err != nil {
		return nil, certerr.WrapState(err, "폐기 목록을 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, certerr.WrapState(err, "폐기 항목을 읽을 수 없습니다: %v", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetBundle 은 번들 경로를 채운다. 경로가 인증서 id 를 포함하므로 INSERT 직후에 넣는다.
func (s *Store) SetBundle(tx *sql.Tx, certID int64, path, sha string) error {
	_, err := tx.Exec(
		`UPDATE certificate SET bundle_path = ?, bundle_sha256 = ? WHERE id = ?`, path, sha, certID)
	if err != nil {
		return certerr.WrapState(err, "번들 경로를 기록할 수 없습니다: %v", err)
	}
	return nil
}

// SetCertPublicSHA 는 v1 시절 발급 건의 공개키 지문을 뒤늦게 채운다(lazy backfill).
func (s *Store) SetCertPublicSHA(tx *sql.Tx, certID int64, sha string) error {
	_, err := tx.Exec(`UPDATE certificate SET public_sha256 = ? WHERE id = ?`, sha, certID)
	if err != nil {
		return certerr.WrapState(err, "공개키 지문을 기록할 수 없습니다: %v", err)
	}
	return nil
}

// SetCertStatus 는 상태를 바꾼다. 폐기면 시각·사유를 함께 넣는다.
func (s *Store) SetCertStatus(tx *sql.Tx, certID int64, status, revokedAt, reason string) error {
	res, err := tx.Exec(
		`UPDATE certificate SET status = ?, revoked_at = ?, revoke_reason = ? WHERE id = ?`,
		status, nullString(revokedAt), nullString(reason), certID)
	if err != nil {
		return certerr.WrapState(err, "인증서 상태를 바꿀 수 없습니다: %v", err)
	}
	// 바뀐 행이 없으면 오류다. 조용히 성공으로 넘기면 "폐기했다" 고 보고한 뒤 실제로는
	// 아무것도 폐기되지 않은 상태가 된다.
	affected, err := res.RowsAffected()
	if err != nil {
		return certerr.WrapState(err, "상태 변경 결과를 확인할 수 없습니다: %v", err)
	}
	if affected == 0 {
		return certerr.NotFoundf("인증서를 찾을 수 없습니다: id=%d", certID)
	}
	return nil
}

// DeleteCert 는 번들 쓰기 실패 시 보상 트랜잭션용이다. 정상 경로에서는 쓰지 않는다.
func (s *Store) DeleteCert(tx *sql.Tx, certID int64) error {
	_, err := tx.Exec(`DELETE FROM certificate WHERE id = ?`, certID)
	if err != nil {
		return certerr.WrapState(err, "인증서를 지울 수 없습니다: %v", err)
	}
	return nil
}
