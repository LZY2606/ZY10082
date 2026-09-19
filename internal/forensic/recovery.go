package forensic

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// scanStaging runs once at startup. Pending sessions that were interrupted
// are marked recovering; blocks present only on disk are reconciled into the
// event log; staging directories without a session are quarantined.
func (s *Service) scanStaging() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stagingRoot := filepath.Join(s.dir, "staging")
	entries, err := os.ReadDir(stagingRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		if !ent.IsDir() || strings.HasPrefix(ent.Name(), ".") {
			continue
		}
		id := ent.Name()
		sess, ok := s.sess[id]
		if !ok {
			src := filepath.Join(stagingRoot, id)
			dst := filepath.Join(s.dir, "quarantine", "orphan-"+id)
			_ = os.Rename(src, dst)
			continue
		}
		if sess.Status != StatusPending {
			continue
		}
		blockDir := filepath.Join(stagingRoot, id, "blocks")
		diskBlocks := map[int]int64{}
		if bEntries, rErr := os.ReadDir(blockDir); rErr == nil {
			for _, be := range bEntries {
				if be.IsDir() || strings.HasPrefix(be.Name(), ".") || !strings.HasSuffix(be.Name(), ".blk") {
					continue
				}
				idx, fErr := strconv.Atoi(strings.TrimSuffix(be.Name(), ".blk"))
				if fErr != nil {
					continue
				}
				if info, iErr := be.Info(); iErr == nil {
					diskBlocks[idx] = info.Size()
				}
			}
		}
		// Reconcile durable blocks missing from replayed state.
		indexes := make([]int, 0, len(diskBlocks))
		for idx := range diskBlocks {
			indexes = append(indexes, idx)
		}
		sort.Ints(indexes)
		var recovered []int
		for _, idx := range indexes {
			if _, known := sess.Blocks[idx]; known {
				continue
			}
			hs, n, hErr := hashFileAt(blockPath(s.dir, id, idx))
			if hErr != nil {
				continue
			}
			bi := BlockInfo{Index: idx, Length: n, Hashes: hs}
			if _, eErr := s.emit("block_put", "", pBlockPut{SessionID: id, Block: bi}); eErr != nil {
				return eErr
			}
			sess.Blocks[idx] = bi
			recovered = append(recovered, idx)
		}
		var missing []int
		for i := 0; i < sess.BlockCount; i++ {
			if _, ok := sess.Blocks[i]; !ok {
				missing = append(missing, i)
			}
		}
		detail := fmt.Sprintf("startup recovery: %d blocks on disk, %d still missing", len(sess.Blocks), len(missing))
		if len(recovered) > 0 {
			detail += fmt.Sprintf("; reconciled blocks %v from staging", recovered)
		}
		if _, err := s.emit("recovery_note", "", pRecovery{SessionID: id, Detail: detail, Missing: missing}); err != nil {
			return err
		}
	}
	return nil
}

func hashFileAt(path string) (Hashes, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return Hashes{}, 0, err
	}
	defer f.Close()
	return HashReader(f)
}
