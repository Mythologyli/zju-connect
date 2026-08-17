package keylog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls-keys.log")
	if err := os.WriteFile(path, []byte("old data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	line := "CLIENT_RANDOM 00010203 04050607\n"
	if _, err := file.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != line {
		t.Fatalf("key log = %q, want %q", data, line)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key-log permissions = %o, want 600", got)
	}
}

func TestOpenEmptyPath(t *testing.T) {
	writer, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if writer != nil {
		t.Fatalf("Open returned %T, want nil", writer)
	}
}

func TestOpenReportsError(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing", "tls-keys.log"))
	if err == nil {
		t.Fatal("Open succeeded for a missing parent directory")
	}
}
