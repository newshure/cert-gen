package store

import (
	"database/sql"
	"errors"
	"strconv"

	"github.com/newshure/cert-gen/internal/certerr"
)

const caColumns = `id, slug, parent_id, common_name, subject_dn, key_algo, key_encrypted,
	is_external, source_dir, key_path, cert_path, chain_path, serial_hex, fingerprint_sha256,
	not_before, not_after, path_len, key_id, next_seq, crl_number, status, created_at`

func scanCA(row interface{ Scan(...any) error }) (CA, error) {
	var (
		c         CA
		parent    sql.NullInt64
		sourceDir sql.NullString
		chainPath sql.NullString
		pathLen   sql.NullInt64
		keyID     sql.NullInt64
		keyEnc    int
		external  int
	)
	err := row.Scan(&c.ID, &c.Slug, &parent, &c.CommonName, &c.SubjectDN, &c.KeyAlgo, &keyEnc,
		&external, &sourceDir, &c.KeyPath, &c.CertPath, &chainPath, &c.SerialHex, &c.Fingerprint,
		&c.NotBefore, &c.NotAfter, &pathLen, &keyID, &c.NextSeq, &c.CRLNumber, &c.Status, &c.CreatedAt)
	if err != nil {
		return CA{}, err
	}
	c.ParentID = fromNullInt(parent)
	c.SourceDir = fromNullString(sourceDir)
	c.ChainPath = fromNullString(chainPath)
	c.PathLen = fromNullInt(pathLen)
	c.KeyID = fromNullInt(keyID)
	c.KeyEncrypted = keyEnc != 0
	c.IsExternal = external != 0
	return c, nil
}

// InsertCA 는 CA 를 등록하고 id 를 돌려준다.
func (s *Store) InsertCA(tx *sql.Tx, c CA) (int64, error) {
	res, err := tx.Exec(`INSERT INTO ca
		(slug, parent_id, common_name, subject_dn, key_algo, key_encrypted, is_external,
		 source_dir, key_path, cert_path, chain_path, serial_hex, fingerprint_sha256,
		 not_before, not_after, path_len, key_id, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.Slug, nullInt(c.ParentID), c.CommonName, c.SubjectDN, c.KeyAlgo, boolInt(c.KeyEncrypted),
		boolInt(c.IsExternal), nullString(c.SourceDir), c.KeyPath, c.CertPath,
		nullString(c.ChainPath), c.SerialHex, c.Fingerprint, c.NotBefore, c.NotAfter,
		nullInt(c.PathLen), nullInt(c.KeyID), Now())
	if err != nil {
		switch {
		case isUniqueViolation(err, "ca.slug"):
			return 0, certerr.Conflictf("같은 slug 의 CA 가 이미 있습니다: %q", c.Slug)
		case isUniqueViolation(err, "fingerprint"):
			return 0, certerr.Conflictf("같은 지문의 CA 가 이미 등록되어 있습니다")
		}
		return 0, certerr.WrapConflict(err, "CA 를 등록할 수 없습니다: %v", err)
	}
	return res.LastInsertId()
}

// GetCA 는 slug 또는 id 로 CA 를 찾는다.
func (s *Store) GetCA(ref string) (CA, error) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM ca WHERE slug = ?`, ref)
	c, err := scanCA(row)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CA{}, certerr.WrapState(err, "CA 를 읽을 수 없습니다: %v", err)
	}
	if id, convErr := strconv.ParseInt(ref, 10, 64); convErr == nil {
		row := s.db.QueryRow(`SELECT `+caColumns+` FROM ca WHERE id = ?`, id)
		c, err := scanCA(row)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return CA{}, certerr.WrapState(err, "CA 를 읽을 수 없습니다: %v", err)
		}
	}
	return CA{}, certerr.NotFoundf("CA 를 찾을 수 없습니다: %s", ref)
}

// FindCA 는 없으면 ok=false 를 돌려준다.
func (s *Store) FindCA(ref string) (CA, bool) {
	c, err := s.GetCA(ref)
	return c, err == nil
}

// FindCAByFingerprint 는 같은 CA 를 두 번 등록하지 않기 위한 조회다.
//
// 사용자가 외부 디렉터리를 CA 로 지정하면 그 CA 를 한 번 등록해 두고 이후 발급 이력을 같은
// 행에 붙인다. 두 번째 사용부터는 이 조회로 기존 행을 재사용한다.
func (s *Store) FindCAByFingerprint(fingerprint string) (CA, bool) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM ca WHERE fingerprint_sha256 = ?`, fingerprint)
	c, err := scanCA(row)
	return c, err == nil
}

// ListCAs 는 등록된 CA 목록이다. status 가 비어 있으면 전부.
func (s *Store) ListCAs(status string) ([]CA, error) {
	query := `SELECT ` + caColumns + ` FROM ca`
	args := []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, certerr.WrapState(err, "CA 목록을 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, certerr.WrapState(err, "CA 를 읽을 수 없습니다: %v", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AllocateSeq 는 CA 안에서 사람이 읽을 발급 순번을 하나 할당한다(쓰기 트랜잭션 안에서 호출).
//
// 호출자가 BEGIN IMMEDIATE 로 쓰기 락을 이미 잡고 있으므로 SELECT→UPDATE 로 나눠도 다른
// 프로세스가 사이에 끼어들 수 없다.
func (s *Store) AllocateSeq(tx *sql.Tx, caID int64) (int64, error) {
	var current int64
	if err := tx.QueryRow(`SELECT next_seq FROM ca WHERE id = ?`, caID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, certerr.NotFoundf("CA id=%d 가 없습니다", caID)
		}
		return 0, certerr.WrapState(err, "순번을 읽을 수 없습니다: %v", err)
	}
	if _, err := tx.Exec(`UPDATE ca SET next_seq = ? WHERE id = ?`, current+1, caID); err != nil {
		return 0, certerr.WrapState(err, "순번을 올릴 수 없습니다: %v", err)
	}
	return current, nil
}

// BumpCRLNumber 는 CRL 번호를 1 올려 돌려준다.
func (s *Store) BumpCRLNumber(tx *sql.Tx, caID int64) (int64, error) {
	var current int64
	if err := tx.QueryRow(`SELECT crl_number FROM ca WHERE id = ?`, caID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, certerr.NotFoundf("CA id=%d 가 없습니다", caID)
		}
		return 0, certerr.WrapState(err, "CRL 번호를 읽을 수 없습니다: %v", err)
	}
	next := current + 1
	if _, err := tx.Exec(`UPDATE ca SET crl_number = ? WHERE id = ?`, next, caID); err != nil {
		return 0, certerr.WrapState(err, "CRL 번호를 올릴 수 없습니다: %v", err)
	}
	return next, nil
}

// TouchCASourceDir 는 외부 CA 의 위치가 바뀐 경우 마지막으로 쓴 경로를 갱신한다.
func (s *Store) TouchCASourceDir(tx *sql.Tx, caID int64, dir string) error {
	_, err := tx.Exec(`UPDATE ca SET source_dir = ? WHERE id = ?`, dir, caID)
	if err != nil {
		return certerr.WrapState(err, "CA 경로를 갱신할 수 없습니다: %v", err)
	}
	return nil
}

// DeleteCA 는 등록 직후 파일 쓰기가 실패한 경우의 보상 트랜잭션용이다.
// 정상 경로에서는 쓰지 않는다.
func (s *Store) DeleteCA(tx *sql.Tx, caID int64) error {
	_, err := tx.Exec(`DELETE FROM ca WHERE id = ?`, caID)
	if err != nil {
		return certerr.WrapState(err, "CA 를 지울 수 없습니다: %v", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
