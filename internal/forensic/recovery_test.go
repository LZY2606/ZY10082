package forensic

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInterruptedWriteRecoveredOnRestart(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("0123456789ABCDEF"), 400) // 6400 bytes
	bs := int64(512)
	count := (len(data) + int(bs) - 1) / int(bs)

	s, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := s.CreateSession(CreateSessionInput{
		Filename: "img.dd", TotalLength: int64(len(data)), BlockSize: bs, BlockCount: count,
		Source: Source{Origin: "rack1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// write half the blocks, then crash without seal
	for i := 0; i < count/2; i++ {
		start := int64(i) * bs
		end := start + bs
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		if _, err := s.PutBlock(sess.ID, i, bytes.NewReader(data[start:end]), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a torn temp block left behind by the interrupted process.
	bdir := filepath.Join(dir, "staging", sess.ID, "blocks")
	if err := os.WriteFile(filepath.Join(bdir, ".tmp-junk"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.GetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusRecovered {
		t.Fatalf("expected recovering, got %s", got.Status)
	}
	if len(got.Blocks) != count/2 {
		t.Fatalf("recovered blocks %d", len(got.Blocks))
	}
	// continue the upload, then seal
	for i := count / 2; i < count; i++ {
		start := int64(i) * bs
		end := start + bs
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		if _, err := s2.PutBlock(sess.ID, i, bytes.NewReader(data[start:end]), nil); err != nil {
			t.Fatal(err)
		}
	}
	art, _, err := s2.Seal(sess.ID, nil, "resume-seal")
	if err != nil {
		t.Fatalf("seal after resume: %v", err)
	}
	if art.Hashes.SHA256 != sha256hex(data) {
		t.Fatal("resumed content hash mismatch")
	}
}

func TestOldStateReadableWhenWriteFails(t *testing.T) {
	s := newTestService(t)
	data := []byte("readable old state")
	sid := makeSession(t, s, "f", data, 8)
	putBlocks(t, s, sid, data, 8)
	art, _, _ := s.Seal(sid, nil, "")

	// Force the store to fail subsequent writes by closing its file handle.
	if err := s.store.f.Close(); err != nil {
		t.Fatal(err)
	}
	s.store.f = nil

	if _, _, err := s.Transfer(TransferInput{ArtifactID: art.ID, From: "a", To: "b"}); err == nil {
		t.Fatal("expected write failure")
	}
	// Old state remains readable.
	snap := s.Snapshot()
	if len(snap.Artifacts) != 1 || snap.Artifacts[0].ID != art.ID {
		t.Fatal("old state lost after failed write")
	}
}

func TestExportImportRoundTripAndReplay(t *testing.T) {
	s1 := newTestService(t)
	data := []byte("exportable evidence payload")
	sid := makeSession(t, s1, "e.bin", data, 10)
	putBlocks(t, s1, sid, data, 10)
	root, _, _ := s1.Seal(sid, nil, "")
	der, _, _ := s1.Derive(DeriveInput{ParentID: root.ID, Tool: "sha256"})
	if _, _, err := s1.Transfer(TransferInput{ArtifactID: root.ID, From: "alice", To: "bob", Reason: "court", IdemKey: "x1"}); err != nil {
		t.Fatal(err)
	}
	pkg, rec, _, err := s1.Export([]string{root.ID}, true, "export-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ContentHash == "" {
		t.Fatal("content hash missing")
	}
	if der.ID == "" {
		t.Fatal("derive id")
	}

	// Import into a fresh store.
	dir2 := t.TempDir()
	s2, err := NewService(dir2)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s2.Import(pkg, "import-1")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Replayed || len(res.Artifacts) != 2 {
		t.Fatalf("import result %+v", res)
	}
	if res.Transfers != 1 {
		t.Fatalf("expected 1 custody imported, got %d", res.Transfers)
	}
	// Full chain verifies in the new store.
	rec2, _, err := s2.VerifyChain(VerifyInput{TargetID: der.ID, IdemKey: "iv1"})
	if err != nil || !rec2.OK {
		t.Fatalf("verify after import: %v %v", err, rec2.Errors)
	}
	// Replaying the same package must not duplicate custody events.
	res2, err := s2.Import(pkg, "import-2")
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Replayed || res2.Transfers != 1 {
		t.Fatalf("replay must return first outcome, got %+v", res2)
	}
	if n := len(s2.Snapshot().Custodies); n != 1 {
		t.Fatalf("duplicate handoffs after replay: %d", n)
	}
	// Same idempotency key returns first result too.
	res3, _ := s2.Import(pkg, "import-1")
	if !res3.Replayed {
		t.Fatal("idempotency key replay failed")
	}
}

func TestImportRejectsTamperedPackage(t *testing.T) {
	s1 := newTestService(t)
	data := []byte("tamper me")
	sid := makeSession(t, s1, "t", data, 5)
	putBlocks(t, s1, sid, data, 5)
	root, _, _ := s1.Seal(sid, nil, "")
	pkg, _, _, _ := s1.Export([]string{root.ID}, false, "e")

	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild package with a tampered blob.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		w, _ := zw.Create(f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.HasPrefix(f.Name, "blobs/") {
			b = bytes.Repeat([]byte("Z"), len(b))
		}
		w.Write(b)
	}
	zw.Close()

	s2, _ := NewService(t.TempDir())
	if _, err := s2.Import(buf.Bytes(), "imp"); err == nil {
		t.Fatal("tampered package must be rejected before registration")
	}
	if n := len(s2.Snapshot().Artifacts); n != 0 {
		t.Fatalf("nothing may register on failed import, got %d", n)
	}
}

func TestImportRejectsPathEscape(t *testing.T) {
	// Build a package whose manifest points outside the target directory.
	man := Manifest{
		PackageID: "pkg_evil", Tool: exportVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Artifacts: []ArtEntry{{
			Artifact: Artifact{ID: "art_evil", Filename: "x", Length: 1,
				Hashes: Hashes{SHA256: strings.Repeat("a", 64)}},
			BlobPath: "../../evil.bin",
		}},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	writeJSONForTest(w, man)
	zw.Close()

	s, _ := NewService(t.TempDir())
	if _, err := s.Import(buf.Bytes(), ""); err == nil {
		t.Fatal("path traversal package must be rejected")
	}
}

func TestSafePaths(t *testing.T) {
	bad := []string{"/etc/passwd", "../x", "a/../../b", "..", "a/../.."}
	for _, p := range bad {
		if safeRelPath(p) {
			t.Fatalf("path should be rejected: %q", p)
		}
		if safeZipName(p) != "" {
			t.Fatalf("zip name should be rejected: %q", p)
		}
	}
	good := []string{"manifest.json", "blobs/ab/cd/abc.bin", "events.log.json"}
	for _, p := range good {
		if !safeRelPath(p) || safeZipName(p) == "" {
			t.Fatalf("path should be allowed: %q", p)
		}
	}
}

func TestQuarantineMovesStaging(t *testing.T) {
	s := newTestService(t)
	data := []byte("quarantine-me!!")
	sid := makeSession(t, s, "q", data, 8)
	putBlocks(t, s, sid, data, 8)
	if err := s.Quarantine(sid, "bad source"); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.GetSession(sid)
	if sess.Status != StatusRejected {
		t.Fatalf("got %s", sess.Status)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "staging", sid)); !os.IsNotExist(err) {
		t.Fatal("staging dir should be moved away")
	}
}
