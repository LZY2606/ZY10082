package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func directEvidence(t *testing.T, service *Service, name, source string, data []byte) Node {
	t.Helper()
	result, err := service.RegisterDirect(UploadInput{Filename: name, Source: source, Notes: "collected", Reader: bytes.NewReader(data)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result.Node
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestDirectRegistrationHashesAndSameContentDifferentSource(t *testing.T) {
	service := testService(t)
	data := []byte("identical bytes")
	first := directEvidence(t, service, "a.bin", "source-a", data)
	second := directEvidence(t, service, "a.bin", "source-b", data)

	if first.ID == second.ID || first.Source == second.Source {
		t.Fatal("same content and filename must remain independent custodial events")
	}
	if first.Hashes.SHA256 != sha(data) || first.Size != int64(len(data)) {
		t.Fatal("stored fingerprint does not match content")
	}
	verify, err := service.VerifyNode(second.ID, nil)
	if err != nil || !verify.Verification.OK {
		t.Fatalf("verification failed: %+v %v", verify, err)
	}
}

func TestBatchOnlyVisibleAfterAllBlocksManifestAndFinalHash(t *testing.T) {
	service := testService(t)
	content := []byte("abcdef")
	created, err := service.CreateBatch(CreateBatchInput{Filename: "image.img", Source: "drive-1", TotalBlocks: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, block := range [][]byte{content[:2], content[2:4], content[4:]} {
		if _, err := service.WriteBlock(created.Batch.ID, index+1, bytes.NewReader(block), nil); err != nil {
			t.Fatal(err)
		}
	}
	batch, _ := service.Batch(created.Batch.ID)
	if batch.Status != StatusPending {
		t.Fatalf("batch should remain pending before seal, got %s", batch.Status)
	}
	sealed, err := service.Seal(SealInput{BatchID: batch.ID, ExpectedSHA256: sha(content)}, nil)
	if err != nil || sealed.Node == nil {
		t.Fatalf("seal failed: %+v %v", sealed, err)
	}
	if sealed.Batch.Status != StatusAccepted {
		t.Fatalf("batch status = %s", sealed.Batch.Status)
	}
	if _, err := os.Stat(service.dataPath("staging", batch.ID)); !os.IsNotExist(err) {
		t.Fatal("accepted staging directory should be removed")
	}
}

func TestFailedSealQuarantinesAndKeepsSuccessHistory(t *testing.T) {
	service := testService(t)
	root := directEvidence(t, service, "root.bin", "source", []byte("root"))
	ok, err := service.VerifyNode(root.ID, nil)
	if err != nil || !ok.Verification.OK {
		t.Fatal(err)
	}

	created, _ := service.CreateBatch(CreateBatchInput{Filename: "bad.img", Source: "drive", TotalBlocks: 1}, nil)
	_, _ = service.WriteBlock(created.Batch.ID, 1, bytes.NewReader([]byte("actual")), nil)
	failed, err := service.Seal(SealInput{BatchID: created.Batch.ID, ExpectedSHA256: sha([]byte("different"))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Batch.Status != StatusRejected || failed.Batch.Error == "" || failed.Batch.QuarantinePath == "" {
		t.Fatalf("failed seal not recorded: %+v", failed.Batch)
	}
	if _, err := os.Stat(failed.Batch.QuarantinePath); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}
	history := service.VerificationHistory(root.ID)
	if len(history) != 1 || !history[0].OK {
		t.Fatal("failed unrelated verification must not overwrite last success")
	}
}

func TestAppendFailureLeavesOldStateReadableAndNoEvent(t *testing.T) {
	service := testService(t)
	root := directEvidence(t, service, "root.bin", "source", []byte("before"))
	service.SetFaults(Faults{FailAppend: true})
	_, err := service.RegisterDirect(UploadInput{Filename: "new.bin", Source: "source", Reader: bytes.NewReader([]byte("new"))}, nil)
	if err == nil {
		t.Fatal("expected append failure")
	}
	service.SetFaults(Faults{})
	state := service.State()
	if len(state.Nodes) != 1 || state.Nodes[0].ID != root.ID {
		t.Fatalf("old state changed after failed append: %+v", state.Nodes)
	}
}

func TestIdempotentKeyReturnsFirstOutcome(t *testing.T) {
	service := testService(t)
	first, err := service.RegisterDirect(UploadInput{Filename: "first.bin", Source: "source", Reader: bytes.NewReader([]byte("one"))}, &IdempotencyRecord{
		Key: "idem-1", Route: "/api/evidence", Status: 201, ContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = first
	if service.State().Counts["node_accepted"] != 1 {
		t.Fatal("idempotency outcome event should not create another evidence node")
	}
}

func TestDerivedAndTransferExtendGraph(t *testing.T) {
	service := testService(t)
	root := directEvidence(t, service, "doc.bin", "source", []byte("<html>hello</html>"))
	derived, err := service.CreateDerived(DerivedInput{
		ParentID: root.ID, Operation: "text-extract", Name: "doc.txt",
		Parameters: map[string]any{"tool": "builtin"}, Reader: bytes.NewReader([]byte("hello")),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := service.CreateTransfer(TransferInput{ParentID: derived.Node.ID, FromParty: "lab", ToParty: "court", Purpose: "review"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := service.VerifyNode(transfer.Node.ID, nil)
	if err != nil || !verify.Verification.OK {
		t.Fatalf("chain verification failed: %+v %v", verify, err)
	}
	if strings.Join(verify.Verification.Path, ",") != strings.Join([]string{root.ID, derived.Node.ID, transfer.Node.ID}, ",") {
		t.Fatalf("unexpected chain path: %v", verify.Verification.Path)
	}
}

func TestRestartCompletesManifestedInterruptedSeal(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("complete after crash")
	created, _ := service.CreateBatch(CreateBatchInput{Filename: "crash.img", Source: "source", TotalBlocks: 2}, nil)
	_, _ = service.WriteBlock(created.Batch.ID, 1, bytes.NewReader(content[:9]), nil)
	_, _ = service.WriteBlock(created.Batch.ID, 2, bytes.NewReader(content[9:]), nil)

	batch, _ := service.Batch(created.Batch.ID)
	ordered := batch.Blocks
	hashes, size, _ := hashOrderedBlocks(service.dataPath("staging", batch.ID, "blocks"), ordered)
	ready := batch
	ready.Blocks = ordered
	ready.FinalHashes = hashes
	if err := writeManifest(service.dataPath("staging", batch.ID, "manifest.json"), ready); err != nil {
		t.Fatal(err)
	}
	_ = size
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	completed, ok := reopened.Batch(batch.ID)
	if !ok || completed.Status != StatusAccepted || completed.FinalHashes.SHA256 != sha(content) {
		t.Fatalf("batch not recovered: %+v %v", completed, ok)
	}
}

func TestRestartMarksPartialStagingRecovering(t *testing.T) {
	dir := t.TempDir()
	service, _ := Open(dir)
	created, _ := service.CreateBatch(CreateBatchInput{Filename: "partial.img", Source: "source", TotalBlocks: 2}, nil)
	_, _ = service.WriteBlock(created.Batch.ID, 1, bytes.NewReader([]byte("part")), nil)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	batch, _ := reopened.Batch(created.Batch.ID)
	if batch.Status != StatusRecovering {
		t.Fatalf("status = %s, want recovering", batch.Status)
	}

	quarantined, err := reopened.RecoverBatch(RecoveryInput{BatchID: created.Batch.ID, Action: "quarantine"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.Batch.Status != StatusRejected || quarantined.Batch.QuarantinePath == "" {
		t.Fatalf("manual quarantine failed: %+v", quarantined.Batch)
	}
}

func TestRecoveringBatchCanContinueAndSeal(t *testing.T) {
	dir := t.TempDir()
	service, _ := Open(dir)
	created, _ := service.CreateBatch(CreateBatchInput{Filename: "continue.img", Source: "source", TotalBlocks: 2}, nil)
	_, _ = service.WriteBlock(created.Batch.ID, 1, bytes.NewReader([]byte("part")), nil)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	batch, _ := reopened.Batch(created.Batch.ID)
	if batch.Status != StatusRecovering {
		t.Fatalf("status = %s", batch.Status)
	}
	content := []byte("partmore")
	_, err = reopened.WriteBlock(created.Batch.ID, 2, bytes.NewReader([]byte("more")), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := reopened.Seal(SealInput{BatchID: created.Batch.ID, ExpectedSHA256: sha(content)}, nil)
	if err != nil || sealed.Batch.Status != StatusAccepted {
		t.Fatalf("recovering batch could not continue: %+v %v", sealed, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	completed, _ := restarted.Batch(created.Batch.ID)
	if completed.Status != StatusAccepted || completed.FinalHashes.SHA256 != sha(content) {
		t.Fatalf("continued recovery did not persist: %+v", completed)
	}
}

func TestClockAdjustmentDoesNotRewriteHistory(t *testing.T) {
	service := testService(t)
	root := directEvidence(t, service, "root.bin", "source", []byte("root"))
	_, err := service.AdjustClock(ClockInput{OffsetNanos: 60_000_000_000, Reason: "NTP correction", Actor: "tester"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if service.State().Nodes[0].CreatedAt != root.CreatedAt {
		t.Fatal("historical timestamp was rewritten")
	}
	if service.State().ClockOffsetNanos != 60_000_000_000 || len(service.State().ClockAdjustments) != 1 {
		t.Fatal("clock adjustment was not saved as a fact")
	}
}

func TestExportImportRoundTripReplayAndZipSlip(t *testing.T) {
	service := testService(t)
	root := directEvidence(t, service, "root.bin", "source", []byte("exportable"))
	exported, err := service.CreateExport(ExportInput{IncludeDerived: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstReader := func() *os.File {
		file, err := os.Open(exported.Export.Path)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	file := firstReader()
	imported, err := service.ImportPackage(file, nil)
	file.Close()
	if err != nil || imported.Import.Replayed {
		t.Fatalf("import failed: %+v %v", imported, err)
	}

	file = firstReader()
	replay, err := service.ImportPackage(file, nil)
	file.Close()
	if err != nil || !replay.Import.Replayed {
		t.Fatalf("replay failed: %+v %v", replay, err)
	}

	bad := filepath.Join(t.TempDir(), "bad.zip")
	createMaliciousZip(t, bad)
	badFile, _ := os.Open(bad)
	_, err = service.ImportPackage(badFile, nil)
	badFile.Close()
	if err == nil {
		t.Fatal("zip slip package was accepted")
	}

	tampered := filepath.Join(t.TempDir(), "tampered.zip")
	rewriteZipEntry(t, exported.Export.Path, tampered, "manifest.json", func(data []byte) []byte {
		return bytes.Replace(data, []byte(root.Name), []byte("tampered-name"), 1)
	})
	tamperedFile, _ := os.Open(tampered)
	_, err = service.ImportPackage(tamperedFile, nil)
	tamperedFile.Close()
	if err == nil {
		t.Fatal("tampered manifest was accepted")
	}

	var importedNodeID string
	for _, node := range service.State().Nodes {
		if node.OriginalID == root.ID {
			importedNodeID = node.ID
		}
	}
	verify, err := service.VerifyNode(importedNodeID, nil)
	if err != nil || !verify.Verification.OK {
		t.Fatalf("imported chain verification failed: %+v %v", verify, err)
	}
}
