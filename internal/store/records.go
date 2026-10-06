package store

import "github.com/newshure/cert-gen/internal/names"

// CA 는 등록된 CA 하나다.
type CA struct {
	ID           int64
	Slug         string
	ParentID     *int64
	CommonName   string
	SubjectDN    string
	KeyAlgo      string
	KeyEncrypted bool
	// IsExternal 이면 KeyPath/CertPath 는 data_dir 밖의 절대경로이고 개인키를 복사하지 않았다.
	IsExternal  bool
	SourceDir   string
	KeyPath     string
	CertPath    string
	ChainPath   string
	SerialHex   string
	Fingerprint string
	NotBefore   string
	NotAfter    string
	PathLen     *int64
	KeyID       *int64
	NextSeq     int64
	CRLNumber   int64
	Status      string
	CreatedAt   string
}

// IsRoot 는 상위 CA 가 없는지 본다.
func (c CA) IsRoot() bool { return c.ParentID == nil }

// Cert 는 발급한 인증서 하나다.
type Cert struct {
	ID            int64
	CAID          int64
	Seq           int64
	SerialHex     string
	CommonName    string
	SubjectDN     string
	SANs          []names.SAN
	Profile       string
	KeyAlgo       string
	NotBefore     string
	NotAfter      string
	Fingerprint   string
	PublicSHA256  string
	BundlePath    string
	BundleSHA256  string
	HasPrivateKey bool
	KeyID         *int64
	Source        string
	Status        string
	RevokedAt     string
	RevokeReason  string
	RenewedFrom   *int64
	Note          string
	CreatedAt     string
}

// Key 는 미리 만들어 둔 개인키다. CA·leaf 발급에서 골라 쓸 수 있다.
type Key struct {
	ID           int64
	Name         string
	Algo         string
	Encrypted    bool
	Path         string
	PublicSHA256 string
	Source       string
	Note         string
	CreatedAt    string
}

// AuditEntry 는 감사 로그 한 줄이다.
type AuditEntry struct {
	ID       int64
	At       string
	Frontend string
	OSUser   string
	Action   string
	Target   string
	Detail   string
	OK       bool
}
