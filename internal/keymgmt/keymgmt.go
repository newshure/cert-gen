// Package keymgmt — 개인키를 먼저 만들어 두고, CA 생성·인증서 발급에서 그것을 고르는 흐름.
//
// 키 생성을 발급에서 떼어 내는 이유가 두 가지다.
//
// 하나는 책임 분리다. 키를 만드는 사람과 인증서를 받는 사람이 다를 수 있다. 키를 먼저
// 만들어 두면 발급 때 그 키를 지정하기만 하면 된다.
//
// 다른 하나는 키 재사용이다. 장비가 키 교체를 받지 못하는 경우(하드코딩된 키 지문, 수동
// 배포 절차)가 실제로 있다. 그런 경우 같은 키로 인증서만 갱신해야 한다.
//
// 쌍 추적: 키와 인증서는 둘 다 공개키 SHA-256 의 앞 8자리를 '쌍 토큰' 으로 보여 준다.
// 목록에서 어느 키가 어느 인증서의 짝인지 눈으로 맞출 수 있어야 하기 때문이다.
package keymgmt

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/newshure/cert-gen/internal/ca"
	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/keys"
	"github.com/newshure/cert-gen/internal/store"
)

// PairToken 은 키-인증서 쌍을 눈으로 맞추기 위한 짧은 토큰이다.
//
// 공개키 SubjectPublicKeyInfo DER 의 SHA-256 앞 8자리다. 개인키와 인증서 어느 쪽에서도
// 같은 값이 나오므로, 둘을 나란히 놓고 비교할 수 있다.
func PairToken(publicSHA256 string) string {
	if len(publicSHA256) < 8 {
		return publicSHA256
	}
	return publicSHA256[:8]
}

// Info 는 키 하나와 그 사용처다.
type Info struct {
	Key store.Key
	// UsedByCAs / UsedByCerts 는 이 키를 쓰는 대상이다. 삭제 가능 여부를 여기서 판단한다.
	UsedByCAs   []string
	UsedByCerts []string
}

// PairToken 은 목록 표시용이다.
func (i Info) PairToken() string { return PairToken(i.Key.PublicSHA256) }

// InUse 는 쓰이는 중인지다.
func (i Info) InUse() bool { return len(i.UsedByCAs) > 0 || len(i.UsedByCerts) > 0 }

// UsageText 는 사용처를 한 줄로 요약한다.
func (i Info) UsageText() string {
	if !i.InUse() {
		return "미사용"
	}
	var parts []string
	if n := len(i.UsedByCAs); n > 0 {
		parts = append(parts, fmt.Sprintf("CA %d", n))
	}
	if n := len(i.UsedByCerts); n > 0 {
		parts = append(parts, fmt.Sprintf("인증서 %d", n))
	}
	return strings.Join(parts, ", ")
}

// CreateOptions 는 키 생성 입력이다.
type CreateOptions struct {
	Name string
	Algo string
	// Passphrase 가 비어 있으면 평문으로 저장한다.
	//
	// 기본을 평문으로 두는 이유: 이 키는 결국 서버가 읽어야 하고, 암호화하면 nginx·Tomcat 이
	// 기동할 때마다 패스프레이즈를 묻는다. CA 키는 반대로 암호화가 기본이다.
	Passphrase string
	Note       string
	Frontend   string
}

// Create 는 개인키를 만들어 상태 디렉터리에 등록한다.
func Create(cfg config.Config, s *store.Store, opts CreateOptions) (Info, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return Info{}, certerr.Validationf("키 이름이 필요합니다")
	}
	if err := validateName(name); err != nil {
		return Info{}, err
	}
	algo := opts.Algo
	if algo == "" {
		algo = cfg.Cert.DefaultKeyAlgo
	}
	if _, err := keys.SpecFor(algo); err != nil {
		return Info{}, err
	}

	signer, err := keys.Generate(algo)
	if err != nil {
		return Info{}, err
	}
	publicSHA, err := keys.PublicDigest(signer.Public())
	if err != nil {
		return Info{}, err
	}
	// 같은 공개키가 이미 있으면 거기서 멈춘다. 우연히 겹칠 확률은 없으므로, 이것이 걸리면
	// 호출 쪽 논리에 문제가 있다는 신호다.
	if existing, ok := s.FindKeyByPublic(publicSHA); ok {
		return Info{}, certerr.Conflictf(
			"같은 공개키의 키가 이미 등록되어 있습니다: %q", existing.Name)
	}

	pemData, err := keys.ToPEM(signer, opts.Passphrase)
	if err != nil {
		return Info{}, err
	}
	rel := filepath.Join("keys", name+".key")
	abs := filepath.Join(cfg.DataDir, rel)
	if fsops.Exists(abs) {
		return Info{}, certerr.Conflictf("키 파일이 이미 있습니다: %s", abs)
	}

	// DB 를 먼저 넣어 이름을 선점한다. 파일을 먼저 쓰면 이름 충돌로 INSERT 가 실패했을 때
	// 주인 없는 키 파일이 남는다.
	var keyID int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		keyID, txErr = s.InsertKey(tx, store.Key{
			Name: name, Algo: algo, Encrypted: opts.Passphrase != "",
			Path: rel, PublicSHA256: publicSHA, Source: "generated", Note: opts.Note,
		})
		return txErr
	}); err != nil {
		return Info{}, err
	}

	if err := fsops.EnsureDir(filepath.Dir(abs), fsops.ModeDir); err != nil {
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteKey(tx, keyID) })
		return Info{}, err
	}
	if err := fsops.WriteAtomic(abs, pemData, fsops.ModeSecret); err != nil {
		// 보상 삭제. 행만 남으면 "목록에는 있는데 파일이 없는" 유령이 된다.
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteKey(tx, keyID) })
		return Info{}, err
	}

	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, opts.Frontend, "", "key.create", name, true, map[string]any{
			"algo": algo, "encrypted": opts.Passphrase != "", "pair": PairToken(publicSHA),
		})
	})
	return Get(cfg, s, fmt.Sprintf("%d", keyID))
}

// validateName 은 파일명으로 쓸 수 있는 이름인지 본다.
//
// 이름이 경로가 되므로 구분자와 상위 참조를 막아야 한다. 막지 않으면 "../../etc/x" 같은
// 이름으로 상태 디렉터리 밖에 파일을 쓸 수 있다.
func validateName(name string) error {
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return certerr.Validationf(
			"키 이름에 경로 구분자나 '..' 를 쓸 수 없습니다: %q", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return certerr.Validationf(
				"키 이름에 쓸 수 없는 문자가 있습니다: %q (영숫자와 - _ . 만)", name)
		}
	}
	return nil
}

// Import 는 외부 개인키 파일을 상태 디렉터리로 가져온다.
func Import(cfg config.Config, s *store.Store, path, name, passphrase, note, frontend string) (Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Info{}, certerr.WrapState(err, "개인키를 읽을 수 없습니다: %s (%v)", path, err)
	}
	signer, err := keys.FromPEM(data, passphrase)
	if err != nil {
		return Info{}, err
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if err := validateName(name); err != nil {
		return Info{}, err
	}
	publicSHA, err := keys.PublicDigest(signer.Public())
	if err != nil {
		return Info{}, err
	}
	if existing, ok := s.FindKeyByPublic(publicSHA); ok {
		return Info{}, certerr.Conflictf(
			"같은 공개키의 키가 이미 등록되어 있습니다: %q", existing.Name)
	}

	// 원본의 암호화 상태를 그대로 보존한다. 여기서 평문으로 풀면 사용자가 의도하지 않은
	// 보호 수준 하락이 조용히 일어난다.
	encrypted := keys.IsEncryptedPEM(data)
	rel := filepath.Join("keys", name+".key")
	abs := filepath.Join(cfg.DataDir, rel)
	if fsops.Exists(abs) {
		return Info{}, certerr.Conflictf("키 파일이 이미 있습니다: %s", abs)
	}

	var keyID int64
	if err := s.Tx(func(tx *sql.Tx) error {
		var txErr error
		keyID, txErr = s.InsertKey(tx, store.Key{
			Name: name, Algo: keys.AlgoOf(signer), Encrypted: encrypted,
			Path: rel, PublicSHA256: publicSHA, Source: "imported", Note: note,
		})
		return txErr
	}); err != nil {
		return Info{}, err
	}
	if err := fsops.EnsureDir(filepath.Dir(abs), fsops.ModeDir); err != nil {
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteKey(tx, keyID) })
		return Info{}, err
	}
	if err := fsops.WriteAtomic(abs, data, fsops.ModeSecret); err != nil {
		_ = s.Tx(func(tx *sql.Tx) error { return s.DeleteKey(tx, keyID) })
		return Info{}, err
	}
	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "key.import", name, true, map[string]any{
			"source_path": path, "encrypted": encrypted, "pair": PairToken(publicSHA),
		})
	})
	return Get(cfg, s, fmt.Sprintf("%d", keyID))
}

// List 는 등록된 키와 각 사용처를 돌려준다.
func List(cfg config.Config, s *store.Store) ([]Info, error) {
	list, err := s.ListKeys()
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(list))
	for _, k := range list {
		cas, certs, err := s.KeyUsage(k.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, Info{Key: k, UsedByCAs: cas, UsedByCerts: certs})
	}
	return out, nil
}

// Get 은 이름 또는 id 로 키를 찾는다.
func Get(cfg config.Config, s *store.Store, ref string) (Info, error) {
	k, err := s.GetKey(ref)
	if err != nil {
		return Info{}, err
	}
	cas, certs, err := s.KeyUsage(k.ID)
	if err != nil {
		return Info{}, err
	}
	return Info{Key: k, UsedByCAs: cas, UsedByCerts: certs}, nil
}

// Load 는 키를 열어 서명에 쓸 수 있는 형태로 돌려준다.
//
// ca.LoadedKey 로 돌려주므로 CA 생성(ca.CreateOptions.ExistingKey)과 발급
// (issue.Options.ExistingKey)에 그대로 넘길 수 있다.
func Load(cfg config.Config, s *store.Store, ref, passphrase string) (*ca.LoadedKey, error) {
	info, err := Get(cfg, s, ref)
	if err != nil {
		return nil, err
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, certerr.WrapState(err,
			"키 파일을 읽을 수 없습니다: %s (DB 에는 있으나 파일이 없습니다) (%v)", abs, err)
	}
	signer, err := keys.FromPEM(data, passphrase)
	if err != nil {
		return nil, err
	}
	// 파일과 DB 가 어긋나면 알려야 한다. 어긋난 채로 쓰면 쌍 토큰이 거짓이 된다.
	publicSHA, err := keys.PublicDigest(signer.Public())
	if err != nil {
		return nil, err
	}
	if publicSHA != info.Key.PublicSHA256 {
		return nil, certerr.Statef(
			"키 파일이 등록된 공개키와 다릅니다: %s (파일이 교체되었을 수 있습니다)", abs)
	}
	keyID := info.Key.ID
	return &ca.LoadedKey{
		Key: signer, Algo: info.Key.Algo, KeyID: &keyID,
		Path: info.Key.Path, Origin: "registered", Encrypted: info.Key.Encrypted,
	}, nil
}

// SetPassphrase 는 키의 패스프레이즈를 바꾼다. new 가 비어 있으면 제거한다.
//
// 제거를 지원하는 이유: 서버에 올릴 키에 패스프레이즈가 걸려 있으면 기동할 때마다 묻는다.
// 무인 재시작이 필요한 환경에서는 제거해야 한다.
func SetPassphrase(cfg config.Config, s *store.Store, ref, current, next, frontend string) (Info, error) {
	info, err := Get(cfg, s, ref)
	if err != nil {
		return Info{}, err
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	data, err := os.ReadFile(abs)
	if err != nil {
		return Info{}, certerr.WrapState(err, "키 파일을 읽을 수 없습니다: %s (%v)", abs, err)
	}
	signer, err := keys.FromPEM(data, current)
	if err != nil {
		return Info{}, err
	}
	rewritten, err := keys.ToPEM(signer, next)
	if err != nil {
		return Info{}, err
	}
	// 먼저 파일을 바꾸고 DB 를 맞춘다. 역순이면 DB 가 '암호화됨' 이라고 말하는데 파일은
	// 평문인 상태가 생길 수 있고, 그쪽이 더 위험하다(보호받는다고 오해한다).
	if err := fsops.WriteAtomic(abs, rewritten, fsops.ModeSecret); err != nil {
		return Info{}, err
	}
	if err := s.Tx(func(tx *sql.Tx) error {
		return s.SetKeyEncrypted(tx, info.Key.ID, next != "")
	}); err != nil {
		return Info{}, err
	}

	action := "key.passphrase.set"
	if next == "" {
		action = "key.passphrase.remove"
	}
	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", action, info.Key.Name, true, map[string]any{
			"encrypted": next != "",
		})
	})
	if next == "" && info.InUse() {
		// 이미 쓰이고 있는 키의 보호를 내렸다는 사실은 분명히 남겨야 한다.
		_ = s.Tx(func(tx *sql.Tx) error {
			return s.Audit(tx, frontend, "", "key.protection.lowered", info.Key.Name, true,
				map[string]any{"cas": info.UsedByCAs, "certs": info.UsedByCerts})
		})
	}
	return Get(cfg, s, ref)
}

// Delete 는 키를 지운다. 쓰이는 중이면 거부한다.
func Delete(cfg config.Config, s *store.Store, ref, frontend string) error {
	info, err := Get(cfg, s, ref)
	if err != nil {
		return err
	}
	if info.InUse() {
		// 쓰이는 키를 지우면 CA 는 서명을 못 하고 인증서는 쌍을 잃는다.
		return certerr.Conflictf(
			"이 키는 쓰이는 중이라 지울 수 없습니다 (CA: %s / 인증서: %s)",
			orNone(info.UsedByCAs), orNone(info.UsedByCerts))
	}
	abs := filepath.Join(cfg.DataDir, info.Key.Path)
	if err := s.Tx(func(tx *sql.Tx) error { return s.DeleteKey(tx, info.Key.ID) }); err != nil {
		return err
	}
	// 파일 삭제는 DB 뒤에 한다. 반대로 하면 파일만 사라지고 행이 남는다.
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return certerr.WrapState(err, "키 파일을 지울 수 없습니다: %s (%v)", abs, err)
	}
	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "key.delete", info.Key.Name, true, nil)
	})
	return nil
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "없음"
	}
	return strings.Join(list, ", ")
}

// PublicPEM 은 키의 공개키 PEM 이다. CSR 을 남이 만들어 줄 때 넘긴다.
func PublicPEM(cfg config.Config, s *store.Store, ref, passphrase string) ([]byte, error) {
	loaded, err := Load(cfg, s, ref, passphrase)
	if err != nil {
		return nil, err
	}
	return keys.PublicPEM(loaded.Key)
}
