package chain

import (
	"fmt"
	"os"
	"path/filepath"
)

func (s *Service) recoverStaging() error {
	entries, err := os.ReadDir(s.dataPath("staging"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		batchID := entry.Name()
		if _, ok := s.state.batches[batchID]; !ok {
			quarantine := s.dataPath("quarantine", batchID+"_unknown_"+newID("q"))
			_ = moveAll(s.dataPath("staging", batchID), quarantine)
			continue
		}
		if err := s.recoverBatch(batchID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recoverBatch(batchID string) error {
	batch := s.state.batches[batchID]
	if batch.Status == StatusAccepted || batch.Status == StatusRejected {
		if batch.Status == StatusAccepted {
			_ = os.RemoveAll(s.dataPath("staging", batchID))
		}
		return nil
	}

	manifestPath := s.dataPath("staging", batchID, "manifest.json")
	manifest, manifestErr := readManifest(manifestPath)
	if manifestErr == nil {
		if manifest.ID != batchID || len(manifest.Blocks) != manifest.TotalBlocks {
			return s.quarantineRecovery(batch, "invalid recovery manifest")
		}
		ordered := make([]BlockInfo, manifest.TotalBlocks)
		for _, block := range manifest.Blocks {
			if block.Number < 1 || block.Number > manifest.TotalBlocks || ordered[block.Number-1].Number != 0 {
				return s.quarantineRecovery(batch, "duplicate or invalid block in manifest")
			}
			ordered[block.Number-1] = block
		}
		hashes, size, err := hashOrderedBlocks(s.dataPath("staging", batchID, "blocks"), ordered)
		if err != nil || hashes != manifest.FinalHashes {
			return s.quarantineRecovery(batch, "recovery block verification failed")
		}
		if err := validateRanges(manifest.SparseRanges, size); err != nil {
			return s.quarantineRecovery(batch, err.Error())
		}
		manifest.Status = StatusPending
		_, err = s.sealLocked(manifest, manifest.FinalHashes.SHA256, nil, EvtRecoverySealed, EvtRecoveryQuarantined)
		return err
	}
	if !os.IsNotExist(manifestErr) {
		return s.quarantineRecovery(batch, "manifest unreadable")
	}

	blocks, err := readBlockDirectory(s.dataPath("staging", batchID, "blocks"))
	if err != nil {
		return s.quarantineRecovery(batch, err.Error())
	}
	known := map[int]BlockInfo{}
	for _, block := range batch.Blocks {
		known[block.Number] = block
	}
	if len(blocks) != len(known) {
		return s.markRecovering(batch)
	}
	for number, block := range known {
		observed, ok := blocks[number]
		if !ok || observed.Number != block.Number || observed.Size != block.Size || observed.Hashes != block.Hashes {
			return s.quarantineRecovery(batch, "block metadata does not match event log")
		}
	}
	if len(blocks) != batch.TotalBlocks {
		return s.markRecovering(batch)
	}

	ordered := make([]BlockInfo, batch.TotalBlocks)
	for _, block := range blocks {
		ordered[block.Number-1] = block
	}
	hashes, size, err := hashOrderedBlocks(s.dataPath("staging", batchID, "blocks"), ordered)
	if err != nil {
		return s.quarantineRecovery(batch, err.Error())
	}
	ready := batch
	ready.Blocks = ordered
	ready.FinalHashes = hashes
	ready.Status = StatusPending
	if err := validateRanges(ready.SparseRanges, size); err != nil {
		return s.quarantineRecovery(batch, err.Error())
	}
	if err := writeManifest(manifestPath, ready); err != nil {
		return err
	}
	_, err = s.sealLocked(ready, hashes.SHA256, nil, EvtRecoverySealed, EvtRecoveryQuarantined)
	return err
}

func readBlockDirectory(dir string) (map[int]BlockInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[int]BlockInfo{}, nil
		}
		return nil, err
	}
	blocks := map[int]BlockInfo{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".bin" {
			continue
		}
		number, ok := parseBlockFileName(entry.Name())
		if !ok {
			return nil, validationError("unexpected block file %s", entry.Name())
		}
		hashes, size, err := hashFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		blocks[number] = BlockInfo{Number: number, Size: size, Hashes: hashes}
	}
	return blocks, nil
}

func (s *Service) markRecovering(batch Batch) error {
	if batch.Status == StatusRecovering {
		return nil
	}
	at := nowString(s.state.ClockOffsetNanos)
	event, err := s.makeEvent(EvtRecoveryMarked, RecoveryMarkedPayload{BatchID: batch.ID, At: at})
	if err != nil {
		return err
	}
	return s.applyEvents(event)
}

func (s *Service) RecoverBatch(input RecoveryInput, idempotency *IdempotencyRecord) (RecoveryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.state.batches[input.BatchID]
	if !ok {
		return RecoveryResult{}, validationError("unknown batch")
	}
	if batch.Status != StatusPending && batch.Status != StatusRecovering {
		return RecoveryResult{}, validationError("batch is not recoverable in status %s", batch.Status)
	}
	switch input.Action {
	case "continue":
		if err := s.markRecovering(batch); err != nil {
			return RecoveryResult{}, err
		}
		batch = s.state.batches[input.BatchID]
		return RecoveryResult{Batch: batch}, nil
	case "quarantine":
		if err := s.quarantineRecovery(batch, "manual quarantine after interrupted write"); err != nil {
			return RecoveryResult{}, err
		}
		batch = s.state.batches[input.BatchID]
		return RecoveryResult{Batch: batch}, nil
	default:
		return RecoveryResult{}, validationError("action must be continue or quarantine")
	}
}

func (s *Service) quarantineRecovery(batch Batch, reason string) error {
	at := nowString(s.state.ClockOffsetNanos)
	quarantineDir := s.dataPath("quarantine", batch.ID+"_recovery_"+newID("q"))
	if err := moveAll(s.dataPath("staging", batch.ID), quarantineDir); err != nil {
		return err
	}
	event, err := s.makeEvent(EvtRecoveryQuarantined, BatchRejectedPayload{
		BatchID: batch.ID, Status: StatusRejected, Error: reason,
		QuarantinePath: quarantineDir, At: at,
	})
	if err != nil {
		return err
	}
	return s.applyEvents(event)
}

func parseBlockFileName(name string) (int, bool) {
	var number int
	if scanned, err := fmt.Sscanf(name, "block-%08d.bin", &number); err != nil || scanned != 1 {
		return 0, false
	}
	return number, true
}
