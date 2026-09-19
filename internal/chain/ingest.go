package chain

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

type batchManifest struct {
	Batch Batch `json:"batch"`
}

func (s *Service) RegisterDirect(input UploadInput, idempotency *IdempotencyRecord) (UploadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := safeName(input.Filename)
	if input.Source == "" {
		return UploadResult{}, validationError("source is required")
	}
	id := newID("ev")
	blobPath := s.dataPath("evidence", id+".bin")
	hashes, size, err := writeStreaming(blobPath, input.Reader)
	if err != nil {
		os.Remove(blobPath)
		return UploadResult{}, err
	}
	if err := validateRanges(input.SparseRanges, size); err != nil {
		os.Remove(blobPath)
		return UploadResult{}, err
	}
	node := Node{
		ID: id, Kind: NodeEvidence, Status: StatusAccepted, Name: name,
		Source: input.Source, Notes: input.Notes, SparseRanges: append([]Range(nil), input.SparseRanges...),
		Size: size, Hashes: hashes, CreatedAt: nowString(s.state.ClockOffsetNanos),
		BlobPath: filepath.Join("evidence", id+".bin"),
	}
	result := UploadResult{Node: node}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtDirectRegistered, DirectEvidencePayload{Node: node})
		if err != nil {
			return nil, err
		}
		node.EventID = event.ID
		return rebuildEvent(event, EvtDirectRegistered, DirectEvidencePayload{Node: node})
	})
	if err != nil {
		os.Remove(blobPath)
		return UploadResult{}, err
	}
	return committed.(UploadResult), nil
}

func (s *Service) CreateBatch(input CreateBatchInput, idempotency *IdempotencyRecord) (CreateBatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if safeName(input.Filename) == "unnamed" {
		return CreateBatchResult{}, validationError("filename is required")
	}
	if input.Source == "" {
		return CreateBatchResult{}, validationError("source is required")
	}
	if input.TotalBlocks <= 0 {
		return CreateBatchResult{}, validationError("total_blocks must be positive")
	}
	for _, item := range input.SparseRanges {
		if item.Offset < 0 || item.Length < 0 {
			return CreateBatchResult{}, validationError("invalid sparse range")
		}
	}
	at := nowString(s.state.ClockOffsetNanos)
	batch := Batch{
		ID: newID("batch"), Filename: safeName(input.Filename), Source: input.Source,
		Notes: input.Notes, SparseRanges: append([]Range(nil), input.SparseRanges...),
		TotalBlocks: input.TotalBlocks, Status: StatusPending, CreatedAt: at, UpdatedAt: at,
	}
	if err := ensureDir(s.dataPath("staging", batch.ID, "blocks")); err != nil {
		return CreateBatchResult{}, err
	}
	result := CreateBatchResult{Batch: batch}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtBatchCreated, BatchCreatedPayload{Batch: batch})
		if err != nil {
			return nil, err
		}
		return []Event{event}, nil
	})
	if err != nil {
		_ = os.RemoveAll(s.dataPath("staging", batch.ID))
		return CreateBatchResult{}, err
	}
	return committed.(CreateBatchResult), nil
}

func (s *Service) WriteBlock(batchID string, number int, reader io.Reader, idempotency *IdempotencyRecord) (BlockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch, ok := s.state.batches[batchID]
	if !ok {
		return BlockResult{}, validationError("unknown batch")
	}
	if batch.Status != StatusPending && batch.Status != StatusRecovering {
		return BlockResult{}, validationError("batch cannot accept blocks in status %s", batch.Status)
	}
	if number < 1 || number > batch.TotalBlocks {
		return BlockResult{}, validationError("block number out of range")
	}
	for _, existing := range batch.Blocks {
		if existing.Number == number {
			return BlockResult{}, validationError("block %d already written", number)
		}
	}
	blockPath := s.dataPath("staging", batchID, "blocks", blockFileName(number))
	hashes, size, err := writeStreaming(blockPath, reader)
	if err != nil {
		os.Remove(blockPath)
		return BlockResult{}, err
	}
	block := BlockInfo{Number: number, Size: size, Hashes: hashes, ReceivedAt: nowString(s.state.ClockOffsetNanos)}
	copyBatch := batch
	copyBatch.Blocks = append(copyBatch.Blocks, block)
	copyBatch.UpdatedAt = block.ReceivedAt
	result := BlockResult{Batch: copyBatch, Block: block}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtBlockWritten, BlockWrittenPayload{BatchID: batchID, Block: block})
		if err != nil {
			return nil, err
		}
		block.EventID = event.ID
		return rebuildEvent(event, EvtBlockWritten, BlockWrittenPayload{BatchID: batchID, Block: block})
	})
	if err != nil {
		os.Remove(blockPath)
		return BlockResult{}, err
	}
	return committed.(BlockResult), nil
}

func (s *Service) Seal(input SealInput, idempotency *IdempotencyRecord) (SealResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.state.batches[input.BatchID]
	if !ok {
		return SealResult{}, validationError("unknown batch")
	}
	return s.sealLocked(batch, input.ExpectedSHA256, idempotency, EvtBatchSealed, EvtBatchRejected)
}

func (s *Service) sealLocked(batch Batch, expectedSHA256 string, idempotency *IdempotencyRecord, sealedType, rejectedType string) (SealResult, error) {
	if batch.Status != StatusPending && batch.Status != StatusRecovering {
		return SealResult{}, validationError("batch is not sealable")
	}
	if expectedSHA256 == "" {
		return SealResult{}, validationError("expected_sha256 is required")
	}
	if len(batch.Blocks) != batch.TotalBlocks {
		return SealResult{}, validationError("expected %d blocks, have %d", batch.TotalBlocks, len(batch.Blocks))
	}
	ordered := make([]BlockInfo, batch.TotalBlocks)
	for _, block := range batch.Blocks {
		ordered[block.Number-1] = block
	}
	for index, block := range ordered {
		if block.Number != index+1 {
			return SealResult{}, validationError("missing block %d", index+1)
		}
	}
	hashes, size, err := hashOrderedBlocks(s.dataPath("staging", batch.ID, "blocks"), ordered)
	if err != nil {
		return SealResult{}, err
	}
	readyBatch := batch
	readyBatch.Blocks = ordered
	readyBatch.FinalHashes = hashes
	if err := writeManifest(s.dataPath("staging", batch.ID, "manifest.json"), readyBatch); err != nil {
		return SealResult{}, err
	}
	at := nowString(s.state.ClockOffsetNanos)
	if !hmacEqual(hashes.SHA256, expectedSHA256) {
		quarantineDir := s.dataPath("quarantine", batch.ID+"_"+newID("q"))
		moveError := moveAll(s.dataPath("staging", batch.ID), quarantineDir)
		if moveError != nil {
			return SealResult{}, moveError
		}
		failed := batch
		failed.Status = StatusRejected
		failed.Error = "final hash mismatch"
		failed.QuarantinePath = quarantineDir
		failed.UpdatedAt = at
		result := SealResult{Batch: failed}
		committed, err := s.commit(result, idempotency, func() ([]Event, error) {
			event, err := s.makeEvent(rejectedType, BatchRejectedPayload{BatchID: batch.ID, Status: StatusRejected, Error: failed.Error, QuarantinePath: failed.QuarantinePath, At: at})
			return []Event{event}, err
		})
		if err != nil {
			return SealResult{}, err
		}
		return committed.(SealResult), nil
	}
	if err := validateRanges(batch.SparseRanges, size); err != nil {
		return SealResult{}, err
	}
	nodeID := newID("ev")
	evidencePath := s.dataPath("evidence", nodeID+".bin")
	if err := assembleBlocks(s.dataPath("staging", batch.ID, "blocks"), ordered, evidencePath); err != nil {
		return SealResult{}, err
	}
	assembledHashes, assembledSize, err := hashFile(evidencePath)
	if err != nil || assembledHashes != hashes || assembledSize != size {
		os.Remove(evidencePath)
		return SealResult{}, validationError("assembled evidence verification failed")
	}
	node := Node{
		ID: nodeID, Kind: NodeEvidence, Status: StatusAccepted, Name: batch.Filename,
		Source: batch.Source, Notes: batch.Notes, SparseRanges: append([]Range(nil), batch.SparseRanges...),
		Size: size, Hashes: hashes, CreatedAt: at, BlobPath: filepath.Join("evidence", nodeID+".bin"),
	}
	accepted := batch
	accepted.Status = StatusAccepted
	accepted.Blocks = ordered
	accepted.NodeID = nodeID
	accepted.FinalHashes = hashes
	accepted.UpdatedAt = at
	result := SealResult{Batch: accepted, Node: &node}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(sealedType, BatchSealedPayload{Batch: accepted, Node: node})
		if err != nil {
			return nil, err
		}
		node.EventID = event.ID
		return rebuildEvent(event, sealedType, BatchSealedPayload{Batch: accepted, Node: node})
	})
	if err != nil {
		os.Remove(evidencePath)
		return SealResult{}, err
	}
	_ = os.RemoveAll(s.dataPath("staging", batch.ID))
	return committed.(SealResult), nil
}

func rebuildEvent(original Event, eventType string, payload any) ([]Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []Event{{ID: original.ID, Type: eventType, OccurredAt: original.OccurredAt, Payload: raw, PreviousHash: original.PreviousHash, Hash: eventHash(original.ID, eventType, original.OccurredAt, raw, original.PreviousHash)}}, nil
}
