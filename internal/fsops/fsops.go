// Package fsops — 파일 쓰기 유틸.
//
// 개인키를 다루므로 **먼저 권한을 좁히고 그 다음에 내용을 쓴다.** 만든 뒤 chmod 하면
// 그 사이에 다른 프로세스가 읽을 수 있는 창이 열린다(umask 에 따라 0644 로 생성된다).
//
// 쓰기는 같은 디렉터리의 임시 파일 → rename 으로 원자적으로 교체한다. 중간에 죽어도
// 반쪽짜리 키 파일이 남지 않는다.
package fsops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/newshure/cert-gen/internal/certerr"
)

const (
	// ModeSecret — 개인키·번들. 소유자만 읽기.
	ModeSecret os.FileMode = 0o600
	// ModePublic — 인증서·체인. 공개해도 되는 자료.
	ModePublic os.FileMode = 0o644
	// ModeDir — data_dir 하위 디렉터리.
	ModeDir os.FileMode = 0o750
)

// EnsureDir 는 디렉터리를 만든다(이미 있으면 그대로).
func EnsureDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return certerr.WrapState(err, "디렉터리를 만들 수 없습니다: %s (%v)", path, err)
	}
	return nil
}

// WriteAtomic 은 같은 파일시스템의 임시 파일을 거쳐 원자적으로 교체한다.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, ModeDir); err != nil {
		return certerr.WrapState(err, "디렉터리를 만들 수 없습니다: %s (%v)", dir, err)
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp%d", filepath.Base(path), os.Getpid()))

	// O_EXCL: 남아 있는 임시 파일을 덮어쓰지 않는다(심볼릭 링크 공격 방지).
	// 권한을 **생성 시점에** 준다 — 만든 뒤 chmod 하면 그 사이에 읽힐 수 있다.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return certerr.WrapState(err, "임시 파일을 만들 수 없습니다: %s (%v)", tmp, err)
	}
	cleanup := func() { f.Close(); os.Remove(tmp) }

	if _, err := f.Write(data); err != nil {
		cleanup()
		return certerr.WrapState(err, "파일을 쓸 수 없습니다: %s (%v)", path, err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return certerr.WrapState(err, "파일을 동기화할 수 없습니다: %s (%v)", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return certerr.WrapState(err, "파일을 닫을 수 없습니다: %s (%v)", path, err)
	}
	// Windows 는 대상이 존재하면 Rename 이 실패할 수 있다. 먼저 치운다.
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return certerr.WrapState(err, "파일을 교체할 수 없습니다: %s (%v)", path, err)
	}
	// umask 가 모드를 깎았을 수 있다. 명시적으로 맞춘다.
	if err := Chmod(path, mode); err != nil {
		return err
	}
	return nil
}

// SHA256Bytes 는 바이트의 SHA-256(소문자 hex)이다.
func SHA256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256File 은 파일의 SHA-256 이다.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", certerr.WrapState(err, "파일을 읽을 수 없습니다: %s (%v)", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", certerr.WrapState(err, "파일을 읽을 수 없습니다: %s (%v)", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Exists 는 경로가 있는지 본다.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsFile 은 일반 파일인지 본다.
func IsFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// IsDir 은 디렉터리인지 본다.
func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// IsTTY 는 표준입출력이 터미널인지다.
//
// TUI 를 띄울 수 있는지 판단하는 데 쓴다. 파이프·리다이렉트 상태에서 TUI 를 띄우면
// 화면이 깨지고 입력을 받지 못해 멈춘 것처럼 보인다.
func IsTTY() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		info, err := f.Stat()
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}
