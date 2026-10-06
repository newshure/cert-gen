// Package backup — 상태 디렉터리 전체의 백업과 복원.
//
// **백업 파일은 CA 그 자체다.** CA 개인키가 들어 있으므로, 이 파일을 가진 사람은 그 CA 로
// 무엇이든 발급할 수 있다. 그래서 0600 으로 쓰고, 외부로 보낼 때는 별도 암호화가 필요하다는
// 경고를 문서와 출력에 함께 둔다.
//
// DB 스냅샷은 파일 복사가 아니라 `VACUUM INTO` 로 뜬다. WAL 모드에서는 .sqlite3 파일만
// 복사하면 -wal 에 남은 커밋이 빠져 찢어진 스냅샷이 나온다. VACUUM INTO 는 트랜잭션
// 일관성이 보장된 단일 파일을 만든다.
//
// (SQLite 를 라이브러리로 함께 담으므로 VACUUM INTO 를 쓸 수 있는 버전이 보장된다.)
package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/newshure/cert-gen/internal/certerr"
	"github.com/newshure/cert-gen/internal/config"
	"github.com/newshure/cert-gen/internal/fsops"
	"github.com/newshure/cert-gen/internal/store"
)

// ManifestName 은 아카이브 안의 매니페스트 경로다. 반드시 **첫 항목**으로 쓴다 —
// 스트리밍으로 읽으면서 나머지를 검증하려면 먼저 나와야 한다.
const ManifestName = "manifest.json"

// DBName 은 아카이브 안의 DB 스냅샷 이름이다.
const DBName = "cert-gen.sqlite3"

// maxEntryBytes 는 아카이브 항목 하나의 상한이다.
//
// 상한을 두는 이유: 우리가 만들지 않은 아카이브도 읽는다. 압축 폭탄으로 디스크를 채우는
// 것을 막는다. 번들 zip 과 PEM 뿐이라 실제로는 수십 MB 를 넘지 않는다.
const maxEntryBytes = 512 << 20

// FileEntry 는 백업에 담긴 파일 하나다.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Manifest 는 백업 내용의 목록이자 무결성 근거다.
type Manifest struct {
	Tool          string      `json:"tool"`
	Version       string      `json:"version"`
	CreatedAt     string      `json:"created_at"`
	SchemaVersion int         `json:"schema_version"`
	SourceDataDir string      `json:"source_data_dir"`
	Counts        Counts      `json:"counts"`
	Files         []FileEntry `json:"files"`
}

// Counts 는 복원 전에 "무엇이 들어 있나" 를 보여 주기 위한 요약이다.
type Counts struct {
	CAs     int `json:"cas"`
	Certs   int `json:"certs"`
	Keys    int `json:"keys"`
	Bundles int `json:"bundles"`
}

// Result 는 백업 생성 결과다.
type Result struct {
	Path     string
	Size     int64
	SHA256   string
	Manifest Manifest
	Warnings []string
}

// 백업에 담을 디렉터리. 순서를 고정해 아카이브가 재현 가능하게 한다.
var backedUpDirs = []string{"ca", "keys", "bundles", "crl"}

// Create 는 상태 디렉터리를 tar.gz 로 묶는다.
func Create(cfg config.Config, s *store.Store, outPath, frontend string) (Result, error) {
	if outPath == "" {
		dir := cfg.BackupPath()
		if err := fsops.EnsureDir(dir, fsops.ModeDir); err != nil {
			return Result{}, err
		}
		outPath = filepath.Join(dir,
			fmt.Sprintf("cert-gen-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405")))
	}
	if fsops.Exists(outPath) {
		return Result{}, certerr.Conflictf("백업 파일이 이미 있습니다: %s", outPath)
	}

	schemaVersion, err := s.SchemaVersionOf()
	if err != nil {
		return Result{}, err
	}

	// 1. DB 를 임시 위치에 일관 스냅샷으로 뜬다.
	if err := fsops.EnsureDir(cfg.TmpDir(), fsops.ModeDir); err != nil {
		return Result{}, err
	}
	snapshot := filepath.Join(cfg.TmpDir(),
		fmt.Sprintf("backup-%d.sqlite3", time.Now().UnixNano()))
	// VACUUM INTO 는 대상이 이미 있으면 실패한다. 남아 있는 파일을 치운다.
	_ = os.Remove(snapshot)
	if _, err := s.DB().Exec(`VACUUM INTO ?`, snapshot); err != nil {
		return Result{}, certerr.WrapState(err, "DB 스냅샷을 만들 수 없습니다: %v", err)
	}
	defer os.Remove(snapshot)
	if err := fsops.Chmod(snapshot, fsops.ModeSecret); err != nil {
		return Result{}, err
	}

	// 2. 담을 파일 목록을 만든다.
	type item struct {
		archivePath string
		sourcePath  string
	}
	items := []item{{DBName, snapshot}}
	if fsops.IsFile(cfg.ConfigPath()) {
		items = append(items, item{"config.toml", cfg.ConfigPath()})
	}
	for _, dir := range backedUpDirs {
		root := filepath.Join(cfg.DataDir, dir)
		if !fsops.Exists(root) {
			continue
		}
		var found []string
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			found = append(found, p)
			return nil
		})
		if err != nil {
			return Result{}, certerr.WrapState(err, "%s 를 읽을 수 없습니다: %v", root, err)
		}
		// 정렬해 아카이브 순서를 고정한다. 순서가 흔들리면 같은 상태에서 다른 바이트가 나온다.
		sort.Strings(found)
		for _, p := range found {
			rel, err := filepath.Rel(cfg.DataDir, p)
			if err != nil {
				return Result{}, certerr.WrapState(err, "경로를 계산할 수 없습니다: %v", err)
			}
			items = append(items, item{filepath.ToSlash(rel), p})
		}
	}

	counts, err := countContents(s)
	if err != nil {
		return Result{}, err
	}
	manifest := Manifest{
		Tool: "cert_gen", Version: "1", CreatedAt: store.Now(),
		SchemaVersion: schemaVersion, SourceDataDir: cfg.DataDir, Counts: counts,
	}

	// 3. 각 파일의 해시를 미리 구해 매니페스트에 담는다. 매니페스트가 첫 항목이어야 하므로
	//    쓰기 전에 전부 알아야 한다.
	for _, it := range items {
		info, err := os.Stat(it.sourcePath)
		if err != nil {
			return Result{}, certerr.WrapState(err, "파일 정보를 읽을 수 없습니다: %v", err)
		}
		digest, err := fsops.SHA256File(it.sourcePath)
		if err != nil {
			return Result{}, err
		}
		manifest.Files = append(manifest.Files, FileEntry{
			Path: it.archivePath, Size: info.Size(),
			SHA256: digest, Mode: uint32(info.Mode().Perm()),
		})
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Result{}, certerr.WrapState(err, "매니페스트를 만들 수 없습니다: %v", err)
	}

	// 4. 아카이브를 쓴다. 백업 파일은 CA 개인키를 담으므로 0600 이다.
	tmpOut := outPath + ".partial"
	_ = os.Remove(tmpOut)
	f, err := os.OpenFile(tmpOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fsops.ModeSecret)
	if err != nil {
		return Result{}, certerr.WrapState(err, "백업 파일을 만들 수 없습니다: %s (%v)", tmpOut, err)
	}
	cleanup := func() { f.Close(); os.Remove(tmpOut) }

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	if err := writeTarFile(tw, ManifestName, manifestJSON, 0o600); err != nil {
		cleanup()
		return Result{}, err
	}
	for _, it := range items {
		mode := os.FileMode(0o600)
		for _, entry := range manifest.Files {
			if entry.Path == it.archivePath {
				mode = os.FileMode(entry.Mode)
			}
		}
		if err := copyTarFile(tw, it.archivePath, it.sourcePath, mode); err != nil {
			cleanup()
			return Result{}, err
		}
	}
	for _, closer := range []io.Closer{tw, gz, f} {
		if err := closer.Close(); err != nil {
			os.Remove(tmpOut)
			return Result{}, certerr.WrapState(err, "백업을 마무리할 수 없습니다: %v", err)
		}
	}
	if err := os.Rename(tmpOut, outPath); err != nil {
		os.Remove(tmpOut)
		return Result{}, certerr.WrapState(err, "백업 파일을 옮길 수 없습니다: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return Result{}, certerr.WrapState(err, "백업 파일을 확인할 수 없습니다: %v", err)
	}
	digest, err := fsops.SHA256File(outPath)
	if err != nil {
		return Result{}, err
	}

	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "backup.create", filepath.Base(outPath), true,
			map[string]any{"files": len(manifest.Files), "bytes": info.Size()})
	})

	return Result{
		Path: outPath, Size: info.Size(), SHA256: digest, Manifest: manifest,
		Warnings: []string{
			"이 백업에는 CA 개인키가 들어 있습니다. 파일을 가진 사람은 그 CA 로 무엇이든 " +
				"발급할 수 있습니다. 외부로 보낼 때는 별도로 암호화하세요",
		},
	}, nil
}

func countContents(s *store.Store) (Counts, error) {
	cas, err := s.ListCAs("")
	if err != nil {
		return Counts{}, err
	}
	certs, err := s.ListCerts(store.CertFilter{})
	if err != nil {
		return Counts{}, err
	}
	keys, err := s.ListKeys()
	if err != nil {
		return Counts{}, err
	}
	bundles := 0
	for _, c := range certs {
		if c.BundlePath != "" {
			bundles++
		}
	}
	return Counts{CAs: len(cas), Certs: len(certs), Keys: len(keys), Bundles: bundles}, nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte, mode os.FileMode) error {
	header := &tar.Header{
		Name: name, Mode: int64(mode), Size: int64(len(data)),
		Typeflag: tar.TypeReg,
		// 시각을 고정한다. 같은 상태에서 같은 바이트가 나오면 "백업이 변했는가" 를
		// 해시로 판단할 수 있다.
		ModTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := tw.WriteHeader(header); err != nil {
		return certerr.WrapState(err, "아카이브 항목을 만들 수 없습니다: %s (%v)", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return certerr.WrapState(err, "아카이브 항목을 쓸 수 없습니다: %s (%v)", name, err)
	}
	return nil
}

func copyTarFile(tw *tar.Writer, name, source string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return certerr.WrapState(err, "파일을 읽을 수 없습니다: %s (%v)", source, err)
	}
	return writeTarFile(tw, name, data, mode)
}

// --- 복원 --------------------------------------------------------------------

// Plan 은 복원 드라이런 보고서다.
//
// 복원은 기존 상태 디렉터리를 치우는 동작이다. 무엇이 들어오고 기존 것이 어디로 가는지
// 먼저 보여 주지 않으면 되돌릴 수 없는 일을 눈 감고 하게 된다.
type Plan struct {
	ArchivePath string
	Manifest    Manifest
	// TargetDataDir 는 복원될 위치다.
	TargetDataDir string
	// MoveExistingTo 는 기존 디렉터리가 옮겨 갈 위치다. 비어 있으면 기존 것이 없다.
	MoveExistingTo string
	// ExistingCounts 는 **덮어쓰기 전** 현재 내용이다. 무엇을 잃는지 보여 준다.
	ExistingCounts *Counts
	// Problems 는 복원을 막는 사유다. 비어 있지 않으면 Apply 가 거부한다.
	Problems []string
	Warnings []string
}

// OK 는 복원을 진행할 수 있는지다.
func (p Plan) OK() bool { return len(p.Problems) == 0 }

// Inspect 는 아카이브를 검증하고 복원 계획을 만든다. 아무것도 바꾸지 않는다.
//
// current 는 이미 열려 있는 상태 저장소다(없으면 nil). 여기서 DB 를 새로 열지 않는 이유:
// store.Open 은 필요하면 스키마 마이그레이션을 **수행한다.** 드라이런이 현재 DB 를 고치는
// 부수효과를 가지면 "아무것도 바꾸지 않는다" 가 거짓이 된다.
func Inspect(cfg config.Config, current *store.Store, archivePath string) (Plan, error) {
	plan := Plan{ArchivePath: archivePath, TargetDataDir: cfg.DataDir}

	manifest, err := readManifest(archivePath)
	if err != nil {
		return Plan{}, err
	}
	plan.Manifest = manifest

	// 1. 아카이브 내용이 매니페스트와 일치하는지 전부 확인한다.
	//    이것을 복원 전에 하는 이유: 중간에 깨진 것을 발견하면 이미 기존 디렉터리를
	//    치워 둔 상태가 되어 양쪽을 다 잃는다.
	if err := verifyContents(archivePath, manifest); err != nil {
		plan.Problems = append(plan.Problems, certerr.UserMessage(err))
	}

	// 2. 스키마 버전. 더 새로운 스키마는 우리가 읽을 수 없다.
	if manifest.SchemaVersion > store.SchemaVersion {
		plan.Problems = append(plan.Problems, fmt.Sprintf(
			"백업의 스키마 버전(%d)이 이 프로그램이 아는 버전(%d)보다 새롭습니다. "+
				"더 새 버전의 cert-gen 으로 복원하세요",
			manifest.SchemaVersion, store.SchemaVersion))
	} else if manifest.SchemaVersion < store.SchemaVersion {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"백업의 스키마 버전이 %d 입니다(현재 %d). 복원 후 자동으로 올립니다",
			manifest.SchemaVersion, store.SchemaVersion))
	}

	// 3. 기존 상태. 지우지 않고 옆으로 치운다 — 복원이 잘못됐을 때 되돌릴 길을 남긴다.
	if fsops.Exists(cfg.DataDir) {
		plan.MoveExistingTo = fmt.Sprintf("%s.bak-%s",
			strings.TrimRight(cfg.DataDir, string(filepath.Separator)),
			time.Now().UTC().Format("20060102-150405"))
		if current != nil {
			if counts, err := countContents(current); err == nil {
				plan.ExistingCounts = &counts
			}
		}
	}

	if manifest.SourceDataDir != "" && manifest.SourceDataDir != cfg.DataDir {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"백업은 %s 에서 만들어졌고 지금은 %s 에 복원됩니다. "+
				"외부 CA(is_external)의 절대경로는 그 자리에 있어야 동작합니다",
			manifest.SourceDataDir, cfg.DataDir))
	}
	plan.Warnings = append(plan.Warnings,
		"복원은 현재 상태 디렉터리를 전부 대체합니다")
	return plan, nil
}

func readManifest(archivePath string) (Manifest, error) {
	tr, closer, err := openArchive(archivePath)
	if err != nil {
		return Manifest{}, err
	}
	defer closer()

	header, err := tr.Next()
	if err != nil {
		return Manifest{}, certerr.WrapState(err,
			"백업을 읽을 수 없습니다(손상되었거나 cert-gen 백업이 아닙니다): %v", err)
	}
	if path.Clean(header.Name) != ManifestName {
		return Manifest{}, certerr.Statef(
			"cert-gen 백업이 아닙니다. 첫 항목이 %s 여야 하는데 %q 입니다",
			ManifestName, header.Name)
	}
	data, err := readLimited(tr, maxEntryBytes)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, certerr.WrapState(err, "매니페스트를 해석할 수 없습니다: %v", err)
	}
	if manifest.Tool != "cert_gen" {
		return Manifest{}, certerr.Statef(
			"cert-gen 백업이 아닙니다(tool=%q)", manifest.Tool)
	}
	if len(manifest.Files) == 0 {
		return Manifest{}, certerr.Statef("매니페스트에 파일 목록이 없습니다")
	}
	return manifest, nil
}

// verifyContents 는 아카이브의 모든 항목이 매니페스트와 일치하는지 본다.
func verifyContents(archivePath string, manifest Manifest) error {
	expected := make(map[string]FileEntry, len(manifest.Files))
	for _, entry := range manifest.Files {
		expected[entry.Path] = entry
	}

	tr, closer, err := openArchive(archivePath)
	if err != nil {
		return err
	}
	defer closer()

	seen := map[string]bool{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return certerr.WrapState(err, "백업을 읽을 수 없습니다: %v", err)
		}
		name := path.Clean(header.Name)
		if name == ManifestName {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			// 디렉터리·심볼릭 링크는 담지 않는다. 있으면 우리가 만든 것이 아니다.
			return certerr.Statef(
				"백업에 일반 파일이 아닌 항목이 있습니다: %q (유형 %c)", name, header.Typeflag)
		}
		entry, ok := expected[name]
		if !ok {
			return certerr.Statef("매니페스트에 없는 파일이 들어 있습니다: %q", name)
		}
		data, err := readLimited(tr, maxEntryBytes)
		if err != nil {
			return err
		}
		if int64(len(data)) != entry.Size {
			return certerr.Statef("%s 의 크기가 다릅니다 (기록 %d, 실제 %d)",
				name, entry.Size, len(data))
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return certerr.Statef("%s 의 내용이 매니페스트와 다릅니다(변조 또는 손상)", name)
		}
		seen[name] = true
	}
	for _, entry := range manifest.Files {
		if !seen[entry.Path] {
			return certerr.Statef("백업에 %s 가 없습니다(잘렸을 수 있습니다)", entry.Path)
		}
	}
	return nil
}

func openArchive(archivePath string) (*tar.Reader, func(), error) {
	if !fsops.IsFile(archivePath) {
		return nil, nil, certerr.NotFoundf("백업 파일이 없습니다: %s", archivePath)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, certerr.WrapState(err, "백업 파일을 열 수 없습니다: %v", err)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, certerr.WrapState(err,
			"gzip 으로 읽을 수 없습니다(손상되었거나 백업이 아닙니다): %v", err)
	}
	return tar.NewReader(gz), func() { gz.Close(); f.Close() }, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, certerr.WrapState(err, "항목을 읽을 수 없습니다: %v", err)
	}
	if int64(len(data)) > limit {
		return nil, certerr.Statef("항목이 너무 큽니다(상한 %d바이트)", limit)
	}
	return data, nil
}

// Apply 는 계획대로 복원한다.
//
// 순서가 중요하다. 검증 → 임시 위치에 전개 → 기존 것을 옆으로 치움 → 임시를 제자리로.
// 기존 것을 먼저 치우고 전개하다 실패하면 양쪽을 다 잃는다.
func Apply(cfg config.Config, current *store.Store, plan Plan, frontend string) error {
	if !plan.OK() {
		return certerr.Statef("복원할 수 없습니다: %s", strings.Join(plan.Problems, "; "))
	}

	// 열려 있는 DB 를 닫는다. 열린 채로 디렉터리를 옮기면 Windows 에서 실패하고,
	// 리눅스에서도 복원 후 그 핸들이 사라진 파일을 가리켜 이후 쿼리가 조용히 빈 결과를 낸다.
	if current != nil {
		if err := current.Close(); err != nil {
			return certerr.WrapState(err, "현재 DB 를 닫을 수 없습니다: %v", err)
		}
	}

	parent := filepath.Dir(strings.TrimRight(cfg.DataDir, string(filepath.Separator)))
	if err := fsops.EnsureDir(parent, fsops.ModeDir); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".cert-gen-restore-")
	if err != nil {
		return certerr.WrapState(err, "임시 디렉터리를 만들 수 없습니다: %v", err)
	}
	if err := fsops.Chmod(staging, fsops.ModeDir); err != nil {
		os.RemoveAll(staging)
		return err
	}
	// 실패하면 임시 위치를 치운다. 성공 경로에서는 Rename 되어 사라진다.
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(staging)
		}
	}()

	if err := extractTo(plan.ArchivePath, staging); err != nil {
		return err
	}

	// 기존 것을 옆으로 치운다. 지우지 않는다 — 복원이 잘못됐을 때 되돌릴 길을 남긴다.
	if plan.MoveExistingTo != "" {
		if err := os.Rename(cfg.DataDir, plan.MoveExistingTo); err != nil {
			return certerr.WrapState(err,
				"기존 상태 디렉터리를 옮길 수 없습니다: %s → %s (%v)",
				cfg.DataDir, plan.MoveExistingTo, err)
		}
	}
	if err := os.Rename(staging, cfg.DataDir); err != nil {
		// 되돌린다. 여기서 포기하면 상태 디렉터리가 사라진 채로 남는다.
		if plan.MoveExistingTo != "" {
			_ = os.Rename(plan.MoveExistingTo, cfg.DataDir)
		}
		return certerr.WrapState(err, "복원한 내용을 제자리로 옮길 수 없습니다: %v", err)
	}
	committed = true

	// 스키마가 오래된 백업이면 여기서 올라간다(store.Open 이 마이그레이션한다).
	s, err := store.Open(cfg.DBPath(), false)
	if err != nil {
		return certerr.WrapState(err,
			"복원한 DB 를 열 수 없습니다: %v (기존 디렉터리는 %s 에 있습니다)",
			err, plan.MoveExistingTo)
	}
	defer s.Close()
	_ = s.Tx(func(tx *sql.Tx) error {
		return s.Audit(tx, frontend, "", "backup.restore", filepath.Base(plan.ArchivePath), true,
			map[string]any{
				"files":             len(plan.Manifest.Files),
				"from_schema":       plan.Manifest.SchemaVersion,
				"moved_existing_to": plan.MoveExistingTo,
			})
	})
	return nil
}

// extractTo 는 아카이브를 디렉터리에 전개한다.
//
// 경로를 반드시 검사한다. tar 는 "../../etc/passwd" 같은 이름을 담을 수 있고(zip slip),
// 검사하지 않으면 복원이 대상 디렉터리 밖에 파일을 쓴다. 우리가 만들지 않은 아카이브도
// 읽으므로 이것은 선택이 아니다.
func extractTo(archivePath, dest string) error {
	tr, closer, err := openArchive(archivePath)
	if err != nil {
		return err
	}
	defer closer()

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return certerr.WrapState(err, "백업을 읽을 수 없습니다: %v", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(header.Name)
		if name == ManifestName {
			continue
		}
		target, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		data, err := readLimited(tr, maxEntryBytes)
		if err != nil {
			return err
		}
		if err := fsops.EnsureDir(filepath.Dir(target), fsops.ModeDir); err != nil {
			return err
		}
		// 권한을 아카이브에 기록된 대로 복원한다. 개인키가 0644 로 풀리면 안 된다.
		mode := os.FileMode(header.Mode).Perm()
		if mode == 0 {
			mode = fsops.ModeSecret
		}
		if err := fsops.WriteAtomic(target, data, mode); err != nil {
			return err
		}
	}
	return nil
}

// safeJoin 은 dest 를 벗어나지 않는 경로만 돌려준다.
func safeJoin(dest, name string) (string, error) {
	if name == "" || name == "." {
		return "", certerr.Statef("백업에 빈 경로가 있습니다")
	}
	if path.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", certerr.Statef("백업에 절대경로가 있습니다: %q", name)
	}
	target := filepath.Join(dest, filepath.FromSlash(name))
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", certerr.Statef(
			"백업이 대상 디렉터리 밖을 가리킵니다: %q (경로 탈출 시도)", name)
	}
	return target, nil
}

// Describe 는 계획을 사람이 읽는 여러 줄로 만든다.
func (p Plan) Describe() string {
	var b strings.Builder
	m := p.Manifest
	fmt.Fprintf(&b, "백업 파일   %s\n", p.ArchivePath)
	fmt.Fprintf(&b, "만든 시각   %s\n", m.CreatedAt)
	fmt.Fprintf(&b, "스키마      v%d\n", m.SchemaVersion)
	fmt.Fprintf(&b, "원본 위치   %s\n", m.SourceDataDir)
	fmt.Fprintf(&b, "내용        CA %d / 인증서 %d / 개인키 %d / 번들 %d (파일 %d개)\n",
		m.Counts.CAs, m.Counts.Certs, m.Counts.Keys, m.Counts.Bundles, len(m.Files))
	fmt.Fprintf(&b, "\n복원 위치   %s\n", p.TargetDataDir)
	if p.MoveExistingTo != "" {
		fmt.Fprintf(&b, "기존 보관   %s\n", p.MoveExistingTo)
		if c := p.ExistingCounts; c != nil {
			fmt.Fprintf(&b, "  (지금: CA %d / 인증서 %d / 개인키 %d)\n", c.CAs, c.Certs, c.Keys)
		}
	} else {
		b.WriteString("기존 상태   없음 (새로 만듭니다)\n")
	}
	return b.String()
}
