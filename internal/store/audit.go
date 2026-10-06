package store

import (
	"database/sql"
	"encoding/json"

	"github.com/newshure/cert-gen/internal/certerr"
)

// Audit 은 감사 로그를 남긴다. detail 은 nil 이어도 된다.
func (s *Store) Audit(tx *sql.Tx, frontend, osUser, action, target string, ok bool, detail map[string]any) error {
	var detailJSON any
	if len(detail) > 0 {
		data, err := json.Marshal(detail)
		if err == nil {
			detailJSON = string(data)
		}
	}
	_, err := tx.Exec(`INSERT INTO audit (at, frontend, os_user, action, target, detail_json, ok)
		VALUES (?,?,?,?,?,?,?)`,
		Now(), frontend, nullString(osUser), action, nullString(target), detailJSON, boolInt(ok))
	if err != nil {
		return certerr.WrapState(err, "감사 로그를 남길 수 없습니다: %v", err)
	}
	return nil
}

// RecentAudit 은 최근 감사 로그다.
func (s *Store) RecentAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, at, frontend, os_user, action, target, detail_json, ok
		 FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, certerr.WrapState(err, "감사 로그를 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e                      AuditEntry
			osUser, target, detail sql.NullString
			okInt                  int
		)
		if err := rows.Scan(&e.ID, &e.At, &e.Frontend, &osUser, &e.Action, &target, &detail, &okInt); err != nil {
			return nil, certerr.WrapState(err, "감사 로그를 읽을 수 없습니다: %v", err)
		}
		e.OSUser = fromNullString(osUser)
		e.Target = fromNullString(target)
		e.Detail = fromNullString(detail)
		e.OK = okInt != 0
		out = append(out, e)
	}
	return out, rows.Err()
}
