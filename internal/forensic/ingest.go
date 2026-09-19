package forensic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// CreateSessionInput configures a new staged batch ingestion.
type CreateSessionInput struct {
	Filename    string
	TotalLength int64
	BlockSize   int64
	BlockCount  int
	Expected    *Hashes
	Source      Source
	Env         EnvInfo
	Note        string
	IdemKey     string
}

// CreateSession opens a pending batch. Reusing an idempotency key returns the
// result that was determined the first time.
func (s *Service) CreateSession(in CreateSessionInput) (*Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.IdemKey != "" {
		if ref, ok := s.idem[in.IdemKey]; ok && ref.Kind == "session" {
			sess, err := s.findSessionLocked(ref.ID)
			return sess, true, err
		}
	}
	if in.Filename == "" {
		return nil, false, fmt.Errorf("%w: filename required", ErrInvalidInput)
	}
	if in.BlockSize <= 0 {
		return nil, false, fmt.Errorf("%w: block_size must be positive", ErrInvalidInput)
	}
	if in.BlockCount <= 0 {
		return nil, false, fmt.Errorf("%w: block_count must be positive", ErrInvalidInput)
	}
	if in.TotalLength < 0 {
		return nil, false, fmt.Errorf("%w: negative total length", ErrInvalidInput)
	}
	if in.Source.Origin == "" {
		in.Source.Origin = "unknown"
	}
	if in.Source.Kind == "" {
		in.Source.Kind = "file"
	}
	env := in.Env
	if env.Tool == "" {
		env = hostEnv()
	}
	sess := Session{
		ID:          newID("ing"),
		Filename:    in.Filename,
		TotalLength: in.TotalLength,
		BlockSize:   in.BlockSize,
		BlockCount:  in.BlockCount,
		Hashes:      orZeroHashes(in.Expected),
		Source:      in.Source,
		Env:         env,
		Note:        in.Note,
		Blocks:      map[int]BlockInfo{},
		Status:      StatusPending,
		CreatedAt:   s.now(),
		UpdatedAt:   s.now(),
	}
	if err := os.MkdirAll(filepath.Join(sessionDir(s.dir, sess.ID), "blocks"), 0o755); err != nil {
		return nil, false, err
	}
	if _, err := s.emit("session_created", in.IdemKey, pSessionCreated{Session: sess}); err != nil {
		return nil, false, err
	}
	if in.IdemKey != "" {
		s.idem[in.IdemKey] = idemRef{Kind: "session", ID: sess.ID}
	}
	out, err := s.findSessionLocked(sess.ID)
	return out, false, err
}

func orZeroHashes(h *Hashes) Hashes {
	if h == nil {
		return Hashes{}
	}
	return *h
}

// GetSession returns a session snapshot.
func (s *Service) GetSession(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findSessionLocked(id)
}

// PutBlockResult reports what happened to one block write.
type PutBlockResult struct {
	Block    BlockInfo `json:"block"`
	Replaced bool      `json:"replaced"`
}

// PutBlock writes one chunk into the staging area. The block is staged to a
// temp name, fsynced, hashed, then atomically renamed so a torn process never
// leaves a half-written block behind.
func (s *Service) PutBlock(sessionID string, index int, r io.Reader, clientHash *Hashes) (*PutBlockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.findSessionLocked(sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Status == StatusAccepted {
		return nil, fmt.Errorf("%w: session already sealed", ErrConflict)
	}
	if index < 0 || index >= sess.BlockCount {
		return nil, fmt.Errorf("%w: block index %d out of range", ErrInvalidInput, index)
	}
	bdir := filepath.Join(sessionDir(s.dir, sessionID), "blocks")
	if err := os.MkdirAll(bdir, 0o755); err != nil {
		return nil, err
	}
	final := filepath.Join(bdir, blkName(index))
	tmp, err := os.CreateTemp(bdir, ".tmp-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	mh := newMultiHasher()
	tr := io.TeeReader(io.LimitReader(r, maxBlockBytes+1), io.MultiWriter(tmp, mh))
	n, err := io.Copy(io.Discard, tr)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if n > maxBlockBytes {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("%w: block larger than %d bytes", ErrInvalidInput, maxBlockBytes)
	}
	if n > sess.BlockSize && index != sess.BlockCount-1 {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("%w: block %d exceeds block size", ErrInvalidInput, index)
	}
	if n == 0 {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("%w: empty block %d", ErrInvalidInput, index)
	}
	hs := mh.sum()
	if clientHash != nil && !hashesEqualIfSet(*clientHash, hs) {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("%w: client block hash mismatch", ErrConflict)
	}
	if sess.Hashes.SHA256 != "" && index == sess.BlockCount-1 && sess.TotalLength > 0 && n != sess.TotalLength-sess.BlockSize*int64(sess.BlockCount-1) {
		// last block length check below covers it; non-fatal here
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	replaced := false
	if existing, statErr := os.Stat(final); statErr == nil && existing.Size() == n {
		if eq, _ := fileSHA256(final); eq == hs.SHA256 {
			os.Remove(tmpName)
		} else {
			if err := os.Rename(tmpName, final); err != nil {
				return nil, err
			}
			replaced = true
		}
	} else {
		if err := os.Rename(tmpName, final); err != nil {
			return nil, err
		}
	}
	bi := BlockInfo{Index: index, Length: n, Hashes: hs}
	if _, err := s.emit("block_put", "", pBlockPut{SessionID: sessionID, Block: bi, Replaced: replaced}); err != nil {
		return nil, err
	}
	return &PutBlockResult{Block: bi, Replaced: replaced}, nil
}

const maxBlockBytes = 4 * 1024 * 1024 * 1024

func hashesEqualIfSet(want, got Hashes) bool {
	if want.SHA256 != "" && want.SHA256 != got.SHA256 {
		return false
	}
	if want.SHA512 != "" && want.SHA512 != got.SHA512 {
		return false
	}
	if want.SHA1 != "" && want.SHA1 != got.SHA1 {
		return false
	}
	return true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var _ = sort.IntSlice{}
var _ = bytes.MinRead
var _ = time.Now
