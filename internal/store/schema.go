package store

// SchemaVersion 은 현재 스키마 버전이다.
//
// 스키마 버전을 올릴 때는 이전 상태 디렉터리를 그대로 열 수 있도록 전진 마이그레이션만 더한다.
const SchemaVersion = 2

// schemaSQL 은 새 DB 를 만들 때 쓴다. 기존 DB 는 migrate() 가 올린다.
const schemaSQL = `
CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE private_key (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  name               TEXT    NOT NULL UNIQUE,
  algo               TEXT    NOT NULL,
  encrypted          INTEGER NOT NULL DEFAULT 0,
  path               TEXT    NOT NULL,
  -- 공개키(SubjectPublicKeyInfo DER)의 SHA256. 같은 키를 두 번 등록하지 않기 위한 식별자이며
  -- 개인키 자체의 해시가 아니다(개인키 해시는 저장하지 않는다).
  public_sha256      TEXT    NOT NULL UNIQUE,
  source             TEXT    NOT NULL DEFAULT 'generated',
  note               TEXT,
  created_at         TEXT    NOT NULL
);

CREATE TABLE ca (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  slug               TEXT    NOT NULL UNIQUE,
  parent_id          INTEGER REFERENCES ca(id),
  common_name        TEXT    NOT NULL,
  subject_dn         TEXT    NOT NULL,
  key_algo           TEXT    NOT NULL,
  key_encrypted      INTEGER NOT NULL DEFAULT 1,
  -- is_external=1 이면 key_path/cert_path 는 data_dir 밖의 절대경로이고 개인키를 복사하지
  -- 않는다(사용자가 지정한 디렉터리의 CA 를 그 자리에서 쓰는 경우).
  is_external        INTEGER NOT NULL DEFAULT 0,
  source_dir         TEXT,
  key_path           TEXT    NOT NULL,
  cert_path          TEXT    NOT NULL,
  chain_path         TEXT,
  serial_hex         TEXT    NOT NULL,
  fingerprint_sha256 TEXT    NOT NULL UNIQUE,
  not_before         TEXT    NOT NULL,
  not_after          TEXT    NOT NULL,
  path_len           INTEGER,
  -- 미리 만들어 둔 키를 쓴 경우 그 키를 가리킨다(NULL = CA 생성 시 즉석 생성).
  key_id             INTEGER REFERENCES private_key(id),
  next_seq           INTEGER NOT NULL DEFAULT 1,
  crl_number         INTEGER NOT NULL DEFAULT 0,
  status             TEXT    NOT NULL DEFAULT 'active',
  created_at         TEXT    NOT NULL
);

CREATE TABLE certificate (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  ca_id              INTEGER NOT NULL REFERENCES ca(id),
  seq                INTEGER NOT NULL,
  serial_hex         TEXT    NOT NULL,
  common_name        TEXT    NOT NULL,
  subject_dn         TEXT    NOT NULL,
  sans_json          TEXT    NOT NULL,
  profile            TEXT    NOT NULL,
  key_algo           TEXT    NOT NULL,
  not_before         TEXT    NOT NULL,
  not_after          TEXT    NOT NULL,
  fingerprint_sha256 TEXT    NOT NULL,
  -- 이 인증서가 담고 있는 공개키의 SHA256. private_key.public_sha256 과 같으면 그 키의 짝이다.
  -- 앞 8자를 '쌍 토큰' 으로 표시해 목록에서 눈으로 맞출 수 있게 한다.
  public_sha256      TEXT,
  bundle_path        TEXT    NOT NULL,
  bundle_sha256      TEXT    NOT NULL,
  has_private_key    INTEGER NOT NULL DEFAULT 1,
  key_id             INTEGER REFERENCES private_key(id),
  source             TEXT    NOT NULL,
  status             TEXT    NOT NULL DEFAULT 'valid',
  revoked_at         TEXT,
  revoke_reason      TEXT,
  renewed_from       INTEGER REFERENCES certificate(id),
  note               TEXT,
  created_at         TEXT    NOT NULL,
  UNIQUE (ca_id, serial_hex)
);

CREATE INDEX idx_cert_cn     ON certificate(common_name);
CREATE INDEX idx_cert_expiry ON certificate(not_after);
CREATE INDEX idx_cert_ca     ON certificate(ca_id, status);

CREATE TABLE audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          TEXT NOT NULL,
  frontend    TEXT NOT NULL,
  os_user     TEXT,
  action      TEXT NOT NULL,
  target      TEXT,
  detail_json TEXT,
  ok          INTEGER NOT NULL
);

CREATE INDEX idx_audit_at ON audit(at);
CREATE INDEX idx_key_name ON private_key(name);
`
