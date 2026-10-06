package fsops

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestModeStringIsOctal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ACL")
	}
	// 권한을 8진수로 지정하는 문서·명령(chmod 0750)과 눈으로 맞출 수 있어야 한다.
	// 기호 표현("rwxr-x---")이 나오면 비교가 어렵다.
	dir := t.TempDir()
	cases := map[os.FileMode]string{
		0o600: "0600",
		0o644: "0644",
		0o750: "0750",
		0o755: "0755",
	}
	for mode, want := range cases {
		path := filepath.Join(dir, want)
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got := ModeString(path); got != want {
			t.Errorf("ModeString(%04o) = %q, 기대 %q", mode, got, want)
		}
	}
	if got := ModeString(filepath.Join(dir, "nope")); got != "?" {
		t.Errorf("없는 파일 = %q, 기대 ?", got)
	}
}

func TestIsTightChecksOther(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ACL")
	}
	dir := t.TempDir()
	cases := map[os.FileMode]bool{
		0o700: true,
		0o750: true,
		0o755: false, // other 에 열려 있다
		0o751: false,
		0o640: true,
	}
	for mode, want := range cases {
		path := filepath.Join(dir, "probe")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got := IsTight(path); got != want {
			t.Errorf("IsTight(%04o) = %v, 기대 %v", mode, got, want)
		}
		os.Remove(path)
	}
}

func TestWriteAtomicSetsModeAtCreation(t *testing.T) {
	// 만든 뒤 chmod 하면 그 사이에 읽힐 수 있다. 생성 시점에 권한이 붙어야 한다.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := WriteAtomic(path, []byte("private"), ModeSecret); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if got := ModeString(path); got != "0600" {
			t.Errorf("권한 = %q, 기대 0600", got)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "private" {
		t.Errorf("내용 = %q", data)
	}
	// 임시 파일이 남지 않아야 한다.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("임시 파일이 남았다: %s", e.Name())
		}
	}
}

func TestWriteAtomicOverwrites(t *testing.T) {
	// CRL 은 매번 다시 만든다. 덮어쓰지 못하면 첫 CRL 이 영원히 남는다.
	dir := t.TempDir()
	path := filepath.Join(dir, "x.crl")
	if err := WriteAtomic(path, []byte("first"), ModePublic); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("second"), ModePublic); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Errorf("내용 = %q, 기대 second", data)
	}
}

func TestSHA256FileMatchesBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	payload := []byte("cert-gen")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if fromFile != SHA256Bytes(payload) {
		t.Errorf("파일 해시와 바이트 해시가 다르다: %s vs %s", fromFile, SHA256Bytes(payload))
	}
	if len(fromFile) != 64 {
		t.Errorf("해시 길이 = %d", len(fromFile))
	}
}
