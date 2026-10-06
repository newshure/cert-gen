package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/newshure/cert-gen/internal/certerr"
)

const keyColumns = `id, name, algo, encrypted, path, public_sha256, source, note, created_at`

func scanKey(row interface{ Scan(...any) error }) (Key, error) {
	var (
		k         Key
		note      sql.NullString
		encrypted int
	)
	err := row.Scan(&k.ID, &k.Name, &k.Algo, &encrypted, &k.Path, &k.PublicSHA256,
		&k.Source, &note, &k.CreatedAt)
	if err != nil {
		return Key{}, err
	}
	k.Note = fromNullString(note)
	k.Encrypted = encrypted != 0
	return k, nil
}

// InsertKey 는 개인키를 등록하고 id 를 돌려준다.
func (s *Store) InsertKey(tx *sql.Tx, k Key) (int64, error) {
	res, err := tx.Exec(`INSERT INTO private_key
		(name, algo, encrypted, path, public_sha256, source, note, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		k.Name, k.Algo, boolInt(k.Encrypted), k.Path, k.PublicSHA256, k.Source,
		nullString(k.Note), Now())
	if err != nil {
		switch {
		case isUniqueViolation(err, "name"):
			return 0, certerr.Conflictf("같은 이름의 키가 이미 있습니다: %q", k.Name)
		case isUniqueViolation(err, "public_sha256"):
			return 0, certerr.Conflictf("같은 공개키의 키가 이미 등록되어 있습니다")
		}
		return 0, certerr.WrapConflict(err, "키를 등록할 수 없습니다: %v", err)
	}
	return res.LastInsertId()
}

// GetKey 는 이름 또는 id 로 키를 찾는다.
func (s *Store) GetKey(ref string) (Key, error) {
	row := s.db.QueryRow(`SELECT `+keyColumns+` FROM private_key WHERE name = ?`, ref)
	k, err := scanKey(row)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Key{}, certerr.WrapState(err, "키를 읽을 수 없습니다: %v", err)
	}
	if id, convErr := strconv.ParseInt(ref, 10, 64); convErr == nil {
		row := s.db.QueryRow(`SELECT `+keyColumns+` FROM private_key WHERE id = ?`, id)
		if k, err := scanKey(row); err == nil {
			return k, nil
		}
	}
	return Key{}, certerr.NotFoundf("키를 찾을 수 없습니다: %s", ref)
}

// GetKeyByID 는 id 로 찾는다(인증서의 key_id 를 따라갈 때).
func (s *Store) GetKeyByID(id int64) (Key, bool) {
	row := s.db.QueryRow(`SELECT `+keyColumns+` FROM private_key WHERE id = ?`, id)
	k, err := scanKey(row)
	return k, err == nil
}

// FindKeyByPublic 은 같은 공개키가 이미 등록되어 있는지 본다.
func (s *Store) FindKeyByPublic(publicSHA string) (Key, bool) {
	row := s.db.QueryRow(`SELECT `+keyColumns+` FROM private_key WHERE public_sha256 = ?`, publicSHA)
	k, err := scanKey(row)
	return k, err == nil
}

// ListKeys 는 등록된 키 목록이다.
func (s *Store) ListKeys() ([]Key, error) {
	rows, err := s.db.Query(`SELECT ` + keyColumns + ` FROM private_key ORDER BY id`)
	if err != nil {
		return nil, certerr.WrapState(err, "키 목록을 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, certerr.WrapState(err, "키를 읽을 수 없습니다: %v", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetKeyEncrypted 는 암호화 여부를 바꾼다(key strip / passphrase).
func (s *Store) SetKeyEncrypted(tx *sql.Tx, keyID int64, encrypted bool) error {
	_, err := tx.Exec(`UPDATE private_key SET encrypted = ? WHERE id = ?`, boolInt(encrypted), keyID)
	if err != nil {
		return certerr.WrapState(err, "키 상태를 바꿀 수 없습니다: %v", err)
	}
	return nil
}

// KeyUsage 는 이 키를 쓰는 (CA slug 목록, 인증서 설명 목록)이다. 삭제 가능 여부 판정에 쓴다.
func (s *Store) KeyUsage(keyID int64) (cas []string, certs []string, err error) {
	rows, err := s.db.Query(`SELECT slug FROM ca WHERE key_id = ?`, keyID)
	if err != nil {
		return nil, nil, certerr.WrapState(err, "키 사용처를 읽을 수 없습니다: %v", err)
	}
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			rows.Close()
			return nil, nil, certerr.WrapState(err, "키 사용처를 읽을 수 없습니다: %v", err)
		}
		cas = append(cas, slug)
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT id, common_name FROM certificate WHERE key_id = ?`, keyID)
	if err != nil {
		return nil, nil, certerr.WrapState(err, "키 사용처를 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id int64
			cn string
		)
		if err := rows.Scan(&id, &cn); err != nil {
			return nil, nil, certerr.WrapState(err, "키 사용처를 읽을 수 없습니다: %v", err)
		}
		certs = append(certs, fmt.Sprintf("#%d %s", id, cn))
	}
	return cas, certs, rows.Err()
}

// DeleteKey 는 키 행을 지운다(파일 삭제는 호출자가 한다).
func (s *Store) DeleteKey(tx *sql.Tx, keyID int64) error {
	_, err := tx.Exec(`DELETE FROM private_key WHERE id = ?`, keyID)
	if err != nil {
		return certerr.WrapState(err, "키를 지울 수 없습니다: %v", err)
	}
	return nil
}
