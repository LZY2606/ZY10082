package forensic

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// zeroDetectWriter flags fixed-size blocks that contain only zero bytes.
type zeroDetectWriter struct {
	blockSize  int64
	total      int64
	curNonZero int64
	zeros      []bool
}

func (z *zeroDetectWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		idx := int(z.total / z.blockSize)
		off := z.total % z.blockSize
		if off == 0 {
			z.zeros = append(z.zeros, true)
			z.curNonZero = 0
		}
		if b != 0 {
			z.curNonZero++
		}
		z.zeros[idx] = z.curNonZero == 0
		z.total++
	}
	return len(p), nil
}

// Seal verifies every block and the whole-stream hash; on success the batch
// becomes visible as an accepted root artifact. On failure a rejected record
// is appended without ever deleting or overwriting the last good state.
func (s *Service) Seal(sessionID string, expected *Hashes, idemKey string) (*Artifact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idemKey != "" {
		if ref, ok := s.idem[idemKey]; ok && ref.Kind == "seal" {
			if ref.ID != "" {
				a, err := s.findArtifactLocked(ref.ID)
				return a, true, err
			}
			_, err := s.findSessionLocked(sessionID)
			return nil, true, err
		}
	}
	sess, err := s.findSessionLocked(sessionID)
	if err != nil {
		return nil, false, err
	}
	if sess.Status == StatusAccepted && sess.ArtifactID != "" {
		a, _ := s.findArtifactLocked(sess.ArtifactID)
		return a, false, nil
	}
	fail := func(stage, detail string) error {
		f := CheckFailure{Time: s.now(), Stage: stage, Detail: detail, IdemKey: idemKey}
		if _, eErr := s.emit("seal_failed", "", pSealFailed{SessionID: sessionID, Failure: f}); eErr != nil {
			return eErr
		}
		if idemKey != "" {
			s.idem[idemKey] = idemRef{Kind: "seal"}
		}
		return fmt.Errorf("%w: %s: %s", ErrConflict, stage, detail)
	}
	var missing []int
	for i := 0; i < sess.BlockCount; i++ {
		if _, ok := sess.Blocks[i]; !ok {
			missing = append(missing, i)
		}
	}
	if len(missing) != 0 {
		return nil, false, fail("blocks", fmt.Sprintf("missing blocks: %v", missing))
	}
	var totalLen int64
	for i := 0; i < sess.BlockCount; i++ {
		bp := blockPath(s.dir, sessionID, i)
		f, oErr := os.Open(bp)
		if oErr != nil {
			return nil, false, fail("block_read", fmt.Sprintf("block %d: %v", i, oErr))
		}
		hs, n, hErr := HashReader(f)
		f.Close()
		if hErr != nil {
			return nil, false, fail("block_hash", fmt.Sprintf("block %d: %v", i, hErr))
		}
		want := sess.Blocks[i].Hashes
		if want != hs || n != sess.Blocks[i].Length {
			return nil, false, fail("block_hash", fmt.Sprintf("block %d corrupted on disk", i))
		}
		totalLen += n
	}
	if sess.TotalLength > 0 && totalLen != sess.TotalLength {
		return nil, false, fail("length", fmt.Sprintf("declared %d bytes but blocks total %d", sess.TotalLength, totalLen))
	}
	want := sess.Hashes
	if expected != nil {
		want = *expected
	}
	mh := newMultiHasher()
	zd := &zeroDetectWriter{blockSize: sess.BlockSize}
	dst, dErr := os.CreateTemp(s.dir, ".seal-*")
	if dErr != nil {
		return nil, false, dErr
	}
	dstName := dst.Name()
	defer os.Remove(dstName)
	for i := 0; i < sess.BlockCount; i++ {
		f, oErr := os.Open(blockPath(s.dir, sessionID, i))
		if oErr != nil {
			dst.Close()
			return nil, false, fail("block_read", oErr.Error())
		}
		if _, cErr := io.Copy(io.MultiWriter(dst, mh, zd), f); cErr != nil {
			f.Close()
			dst.Close()
			return nil, false, fail("compose", cErr.Error())
		}
		f.Close()
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return nil, false, err
	}
	dst.Close()
	got := mh.sum()
	if want.SHA256 != "" && !hashesEqualIfSet(want, got) {
		return nil, false, fail("final_hash", fmt.Sprintf("expected sha256=%s got %s", want.SHA256, got.SHA256))
	}
	finalHashes := got
	if want.SHA256 == "" {
		finalHashes = got
	}
	target := blobPath(s.dir, finalHashes)
	if err := moveFile(dstName, target); err != nil {
		return nil, false, err
	}
	sparse := sparseRangesFromZeroBlocks(zd.zeros, sess.BlockSize, totalLen)
	art := Artifact{
		ID:           newID("art"),
		Kind:         "root",
		Filename:     sess.Filename,
		Length:       totalLen,
		Hashes:       finalHashes,
		SparseRanges: sparse,
		Source:       sess.Source,
		Env:          sess.Env,
		Note:         sess.Note,
		SessionID:    sess.ID,
		CreatedAt:    s.now(),
	}
	if _, err := s.emit("sealed", idemKey, pSealed{SessionID: sessionID, ArtifactID: art.ID, Artifact: art, Sparse: sparse}); err != nil {
		return nil, false, err
	}
	if idemKey != "" {
		s.idem[idemKey] = idemRef{Kind: "seal", ID: art.ID}
	}
	out, _ := s.findArtifactLocked(art.ID)
	return out, false, nil
}

// moveFile renales src into dst, creating parent directories and syncing.
func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Quarantine isolates an unrecoverable staging session and records the fact.
func (s *Service) Quarantine(sessionID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.findSessionLocked(sessionID)
	if err != nil {
		return err
	}
	if sess.Status == StatusAccepted {
		return fmt.Errorf("%w: accepted session cannot be quarantined", ErrConflict)
	}
	src := sessionDir(s.dir, sessionID)
	dst := filepath.Join(s.dir, "quarantine", "staging-"+sessionID)
	_ = os.MkdirAll(filepath.Dir(dst), 0o755)
	if _, statErr := os.Stat(src); statErr == nil {
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	_, err = s.emit("session_quarantined", "", pQuarantined{SessionID: sessionID, Reason: reason, Time: s.now()})
	return err
}
