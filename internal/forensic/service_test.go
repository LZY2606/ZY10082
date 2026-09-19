package forensic

import (
	"bytes"
	"strings"
	"testing"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	s, err := NewService(dir)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func putBlocks(t *testing.T, s *Service, sid string, data []byte, blockSize int64) {
	t.Helper()
	for i := 0; int64(i)*blockSize < int64(len(data)); i++ {
		start := int64(i) * blockSize
		end := start + blockSize
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		res, err := s.PutBlock(sid, i, bytes.NewReader(data[start:end]), nil)
		if err != nil {
			t.Fatalf("PutBlock %d: %v", i, err)
		}
		if res.Block.Length != end-start {
			t.Fatalf("block %d length", i)
		}
	}
}

func makeSession(t *testing.T, s *Service, name string, data []byte, blockSize int64) string {
	t.Helper()
	count := (len(data) + int(blockSize) - 1) / int(blockSize)
	sess, _, err := s.CreateSession(CreateSessionInput{
		Filename: name, TotalLength: int64(len(data)), BlockSize: blockSize,
		BlockCount: count, Source: Source{Kind: "file", Origin: "unit-test", Acquirer: "tester"},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess.ID
}

func sampleData() []byte {
	var b bytes.Buffer
	b.WriteString("Forensic evidence header\n")
	b.Write(make([]byte, 4096)) // sparse zero run
	b.WriteString("SECRET-ASCII-STRING-1234\n")
	b.WriteString("trailer bytes 00")
	return b.Bytes()
}

func TestIngestSealAndHashes(t *testing.T) {
	s := newTestService(t)
	data := sampleData()
	sid := makeSession(t, s, "disk.dd", data, 1024)
	putBlocks(t, s, sid, data, 1024)
	art, replayed, err := s.Seal(sid, nil, "seal-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if replayed {
		t.Fatal("first seal should not be replay")
	}
	if art.Length != int64(len(data)) {
		t.Fatalf("length %d", art.Length)
	}
	if got := sha256hex(data); got != art.Hashes.SHA256 {
		t.Fatalf("sha256 mismatch")
	}
	if len(art.SparseRanges) == 0 {
		t.Fatal("expected sparse range for zero run")
	}
	// Blob exists and matches.
	f, _, err := s.OpenBlob(art.ID)
	if err != nil {
		t.Fatal(err)
	}
	hs, n, _ := HashReader(f)
	f.Close()
	if hs != art.Hashes || n != art.Length {
		t.Fatal("stored blob mismatch")
	}
}

func TestSealFailureKeepsLastSuccess(t *testing.T) {
	s := newTestService(t)
	data := []byte("hello world hello world")
	bs := int64(4)
	sid := makeSession(t, s, "a.bin", data, bs)
	putBlocks(t, s, sid, data, bs)

	// Declare a wrong final hash -> rejection must be recorded.
	wrong := &Hashes{SHA256: strings.Repeat("0", 64)}
	if _, _, err := s.Seal(sid, wrong, "seal-bad"); err == nil {
		t.Fatal("expected seal failure")
	}
	sess, _ := s.GetSession(sid)
	if sess.Status != StatusRejected || len(sess.Failures) != 1 {
		t.Fatalf("expected rejected with one failure, got %s %d", sess.Status, len(sess.Failures))
	}

	// Correct seal still works and acceptance does not erase the failure.
	art, _, err := s.Seal(sid, nil, "seal-good")
	if err != nil {
		t.Fatalf("correct seal: %v", err)
	}
	if art == nil {
		t.Fatal("missing artifact")
	}
	sess, _ = s.GetSession(sid)
	if sess.Status != StatusAccepted || len(sess.Failures) != 1 {
		t.Fatalf("accepted but failure history lost: %s %d", sess.Status, len(sess.Failures))
	}
}

func TestIdempotentKeyReturnsFirstResult(t *testing.T) {
	s := newTestService(t)
	in := CreateSessionInput{Filename: "x", BlockSize: 16, BlockCount: 1,
		Source: Source{Origin: "o1"}, IdemKey: "k1"}
	a, rep1, err := s.CreateSession(in)
	if err != nil || rep1 {
		t.Fatalf("first call replayed=%v err=%v", rep1, err)
	}
	b, rep2, err := s.CreateSession(in)
	if err != nil || !rep2 || a.ID != b.ID {
		t.Fatalf("second call must replay first result")
	}
	if len(s.Snapshot().Sessions) != 1 {
		t.Fatal("duplicate session created")
	}

	// Transfer idempotency.
	data := []byte("abcdefghijkl")
	sid := makeSession(t, s, "y", data, 6)
	putBlocks(t, s, sid, data, 6)
	art, _, _ := s.Seal(sid, nil, "")
	t1, r1, err := s.Transfer(TransferInput{ArtifactID: art.ID, From: "a", To: "b", IdemKey: "t1"})
	if err != nil || r1 {
		t.Fatal("first transfer")
	}
	t2, r2, _ := s.Transfer(TransferInput{ArtifactID: art.ID, From: "Z", To: "Q", IdemKey: "t1"})
	if !r2 || t1.ID != t2.ID || t2.From != "a" {
		t.Fatal("replayed transfer must return the first determined event")
	}
	if n := len(s.Snapshot().Custodies); n != 1 {
		t.Fatalf("expected 1 custody, got %d", n)
	}
}

func TestSameContentDifferentSourceNotMerged(t *testing.T) {
	s := newTestService(t)
	data := []byte("identical bytes here!!")
	bs := int64(8)
	id1 := makeSession(t, s, "same.bin", data, bs)
	id2 := makeSession(t, s, "same.bin", data, bs)
	if id1 == id2 {
		t.Fatal("sessions merged")
	}
	putBlocks(t, s, id1, data, bs)
	putBlocks(t, s, id2, data, bs)
	a1, _, _ := s.Seal(id1, nil, "")
	a2, _, _ := s.Seal(id2, nil, "")
	if a1.ID == a2.ID {
		t.Fatal("same filename/content must still create separate evidence nodes")
	}
	// bytes share the same content-addressed blob
	if a1.Hashes.SHA256 != a2.Hashes.SHA256 {
		t.Fatal("hash should be equal for identical bytes")
	}
}

func TestDerivationReproduces(t *testing.T) {
	s := newTestService(t)
	data := []byte("header\n" + strings.Repeat("\x00", 64) + "MAGICSTRING\n")
	sid := makeSession(t, s, "f", data, 32)
	putBlocks(t, s, sid, data, 32)
	root, _, _ := s.Seal(sid, nil, "")
	der, _, err := s.Derive(DeriveInput{ParentID: root.ID, Tool: "strings", Args: "min=5"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(der.Note, "strings") {
		t.Fatal(der.Note)
	}
	if der.DerivedFrom.Tool.Version == "" || der.DerivedFrom.InputRange == nil {
		t.Fatal("derivation metadata incomplete")
	}
	rec, _, err := s.VerifyChain(VerifyInput{TargetID: der.ID, IdemKey: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if !rec.OK {
		t.Fatalf("verify errors: %v", rec.Errors)
	}
}

func TestClockCorrectionNeverRewritesHistory(t *testing.T) {
	s := newTestService(t)
	before := s.Snapshot().Events
	f, _, err := s.CorrectClock("+09:00", "+00:00", "ntp", "c1")
	if err != nil {
		t.Fatal(err)
	}
	after := s.Snapshot().Events
	if len(after) != len(before)+1 {
		t.Fatal("clock correction must append exactly one event")
	}
	// historical event times unchanged: first event time untouched
	if len(before) > 0 && after[0].Time != before[0].Time {
		t.Fatal("historical event rewritten")
	}
	if f.NewOffset != "+00:00" {
		t.Fatal(f)
	}
}
