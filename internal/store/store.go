// Package store — SQLite 저장 계층. 스키마·마이그레이션·CRUD.
//
// 발급 이력과 serial 의 단일 출처다. 파일시스템(CA 키, 번들 zip)은 여기 기록된 상대경로를
// 따라가는 종속 자원이며, **DB 커밋이 성공한 다음에** 파일을 쓴다(역순이면 고아 파일이 남는다).
//
// 동시 실행 전제: CLI 가 여러 번 동시에 호출될 수 있다. 쓰기는 BEGIN IMMEDIATE 로 직렬화하고
// busy_timeout 으로 대기한다. 키 생성·서명 같은 긴 CPU 작업은 트랜잭션 **바깥에서** 한다.
//
// SQLite 는 modernc.org/sqlite(순수 Go)를 쓴다. cgo 를 쓰면 정적 링크가 깨지고 glibc 에
// 묶인다 — 단일 바이너리 요구와 정면으로 충돌한다.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/names"
	_ "modernc.org/sqlite"
)

// Now 는 DB 에 넣는 시각 형식이다. 문자열 정렬 = 시간 정렬이 되도록 고정한다.
func Now() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// ParseTime 은 DB 의 시각 문자열을 되돌린다.
func ParseTime(text string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05Z", text)
}

// Store 는 DB 연결 소유자다.
type Store struct {
	db   *sql.DB
	Path string
}

// Open 은 DB 를 연다. create 가 false 이고 파일이 없으면 거부한다.
func Open(path string, create bool) (*Store, error) {
	if !create {
		if _, err := os.Stat(path); err != nil {
			return nil, certerr.Statef("DB 가 없습니다: %s (먼저 `cert-gen init` 을 실행하세요)", path)
		}
	} else if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, certerr.WrapState(err, "DB 디렉터리를 만들 수 없습니다: %v", err)
	}

	// PRAGMA 는 연결마다 적용되어야 하므로 DSN 으로 건다.
	// _txlock=immediate: Begin() 이 BEGIN IMMEDIATE 를 내도록 한다(read-then-write 경쟁 제거).
	// synchronous=FULL: CA 키·발급 이력은 재생성이 불가능하다. 쓰기 성능보다 내구성을 택한다.
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=synchronous(FULL)" +
		"&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, certerr.WrapState(err, "DB 를 열 수 없습니다: %s (%v)", path, err)
	}
	// 한 프로세스 안에서 쓰기 경쟁을 만들지 않는다. 프로세스 간 경쟁은 busy_timeout 이 흡수한다.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, certerr.WrapState(err, "DB 를 열 수 없습니다: %s (%v)", path, err)
	}

	s := &Store{db: db, Path: path}
	if create {
		if err := s.ensureSchema(); err != nil {
			db.Close()
			return nil, err
		}
	} else if err := s.checkVersion(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 는 연결을 닫는다.
func (s *Store) Close() error { return s.db.Close() }

// DB 는 백업 등 저수준 접근이 필요한 곳에만 쓴다.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) ensureSchema() error {
	var name string
	err := s.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.Exec(schemaSQL); err != nil {
			return certerr.WrapState(err, "스키마를 만들 수 없습니다: %v", err)
		}
		_, err := s.db.Exec(
			`INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)`,
			strconv.Itoa(SchemaVersion))
		if err != nil {
			return certerr.WrapState(err, "스키마 버전을 기록할 수 없습니다: %v", err)
		}
		return nil
	}
	if err != nil {
		return certerr.WrapState(err, "스키마를 확인할 수 없습니다: %v", err)
	}
	return s.checkVersion()
}

func (s *Store) checkVersion() error {
	var value string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return certerr.Statef("DB 에 스키마 버전이 없습니다: %s", s.Path)
	}
	if err != nil {
		return certerr.WrapState(err, "DB 가 cert_gen 형식이 아닙니다: %s (%v)", s.Path, err)
	}
	found, convErr := strconv.Atoi(value)
	if convErr != nil {
		return certerr.Statef("스키마 버전을 읽을 수 없습니다: %q", value)
	}
	if found > SchemaVersion {
		// 더 새 버전이 만든 DB 를 구 버전이 건드리면 데이터가 깨진다. 거부가 정답이다.
		return certerr.Statef(
			"DB 스키마 버전 %d 는 이 버전(지원 %d)보다 새롭습니다. cert-gen 을 업그레이드하세요: %s",
			found, SchemaVersion, s.Path)
	}
	if found < SchemaVersion {
		return s.migrate(found)
	}
	return nil
}

// SchemaVersionOf 는 현재 DB 의 스키마 버전이다.
func (s *Store) SchemaVersionOf() (int, error) {
	var value string
	if err := s.db.QueryRow(
		`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&value); err != nil {
		return 0, certerr.WrapState(err, "스키마 버전을 읽을 수 없습니다: %v", err)
	}
	return strconv.Atoi(value)
}

// migrate 는 전진 마이그레이션이다. 기존 DB 를 버리지 않고 올린다.
// 각 단계는 멱등하게 쓴다(중간에 끊겨도 다시 실행할 수 있어야 한다).
func (s *Store) migrate(from int) error {
	if from < 2 {
		// v2: 키를 1급 자원으로 승격. private_key 테이블 + key_id·public_sha256 참조.
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS private_key (
			   id            INTEGER PRIMARY KEY AUTOINCREMENT,
			   name          TEXT    NOT NULL UNIQUE,
			   algo          TEXT    NOT NULL,
			   encrypted     INTEGER NOT NULL DEFAULT 0,
			   path          TEXT    NOT NULL,
			   public_sha256 TEXT    NOT NULL UNIQUE,
			   source        TEXT    NOT NULL DEFAULT 'generated',
			   note          TEXT,
			   created_at    TEXT    NOT NULL)`,
			`CREATE INDEX IF NOT EXISTS idx_key_name ON private_key(name)`,
		}
		for _, stmt := range stmts {
			if _, err := s.db.Exec(stmt); err != nil {
				return certerr.WrapState(err, "마이그레이션 실패(v2): %v", err)
			}
		}
		for _, spec := range []struct{ table, column, ddl string }{
			{"ca", "key_id", "INTEGER REFERENCES private_key(id)"},
			{"certificate", "key_id", "INTEGER REFERENCES private_key(id)"},
			{"certificate", "public_sha256", "TEXT"},
		} {
			has, err := s.hasColumn(spec.table, spec.column)
			if err != nil {
				return err
			}
			if !has {
				_, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s",
					spec.table, spec.column, spec.ddl))
				if err != nil {
					return certerr.WrapState(err, "마이그레이션 실패(%s.%s): %v", spec.table, spec.column, err)
				}
			}
		}
		if _, err := s.db.Exec(
			`UPDATE schema_meta SET value = ? WHERE key = 'schema_version'`,
			strconv.Itoa(SchemaVersion)); err != nil {
			return certerr.WrapState(err, "스키마 버전을 올릴 수 없습니다: %v", err)
		}
	}
	return nil
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, certerr.WrapState(err, "테이블 정보를 읽을 수 없습니다: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name, ctyp string
			notNull    int
			dflt       sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &ctyp, &notNull, &dflt, &pk); err != nil {
			return false, certerr.WrapState(err, "테이블 정보를 읽을 수 없습니다: %v", err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Tx 는 쓰기 트랜잭션을 돌린다. BEGIN IMMEDIATE 로 즉시 쓰기 락을 잡아 경쟁을 없앤다.
// fn 이 오류를 돌려주면 롤백한다.
func (s *Store) Tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return certerr.WrapState(err, "트랜잭션을 시작할 수 없습니다: %v", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return certerr.WrapState(err, "트랜잭션을 커밋할 수 없습니다: %v", err)
	}
	return nil
}

// --- 공용 보조 ---------------------------------------------------------------

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func fromNullString(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}

func fromNullInt(v sql.NullInt64) *int64 {
	if v.Valid {
		value := v.Int64
		return &value
	}
	return nil
}

func marshalSANs(sans []names.SAN) (string, error) {
	if sans == nil {
		sans = []names.SAN{}
	}
	data, err := json.Marshal(sans)
	if err != nil {
		return "", certerr.WrapState(err, "SAN 을 직렬화할 수 없습니다: %v", err)
	}
	return string(data), nil
}

func unmarshalSANs(text string) []names.SAN {
	var out []names.SAN
	if text == "" {
		return out
	}
	_ = json.Unmarshal([]byte(text), &out)
	return out
}

// isUniqueViolation 은 UNIQUE 제약 위반인지 본다.
func isUniqueViolation(err error, hints ...string) bool {
	if err == nil {
		return false
	}
	text := strings.ToUpper(err.Error())
	if !strings.Contains(text, "UNIQUE") {
		return false
	}
	if len(hints) == 0 {
		return true
	}
	for _, h := range hints {
		if strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(h)) {
			return true
		}
	}
	return false
}
