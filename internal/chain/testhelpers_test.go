package chain

import (
	"archive/zip"
	"os"
	"testing"
)

func createMaliciousZip(t *testing.T, path string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	entry, err := writer.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	manifest, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest.Write([]byte(`{"package_id":"pkg_bad","fingerprint":"abc","created_at":"now","nodes":[],"edges":[],"entries":[{"path":"../escape.txt","size":4,"sha256":"abc"}],"event_log":{"path":"events.log","size":0,"sha256":"abc"}}`))
	eventLog, err := writer.Create("events.log")
	if err != nil {
		t.Fatal(err)
	}
	eventLog.Write(nil)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}
