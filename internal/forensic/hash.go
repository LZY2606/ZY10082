package forensic

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
)

// multiHasher computes sha256, sha512 and sha1 in one pass.
type multiHasher struct {
	h256 hash.Hash
	h512 hash.Hash
	h1   hash.Hash
}

func newMultiHasher() *multiHasher {
	return &multiHasher{h256: sha256.New(), h512: sha512.New(), h1: sha1.New()}
}

func (m *multiHasher) Write(p []byte) (int, error) {
	m.h256.Write(p)
	m.h512.Write(p)
	m.h1.Write(p)
	return len(p), nil
}

func (m *multiHasher) sum() Hashes {
	return Hashes{
		SHA256: hex.EncodeToString(m.h256.Sum(nil)),
		SHA512: hex.EncodeToString(m.h512.Sum(nil)),
		SHA1:   hex.EncodeToString(m.h1.Sum(nil)),
	}
}

// HashReader consumes r and returns its fingerprints and byte length.
func HashReader(r io.Reader) (Hashes, int64, error) {
	m := newMultiHasher()
	n, err := io.Copy(m, r)
	if err != nil {
		return Hashes{}, 0, err
	}
	return m.sum(), n, nil
}

// HashBytes hashes an in-memory byte slice.
func HashBytes(p []byte) Hashes {
	m := newMultiHasher()
	m.Write(p)
	return m.sum()
}

// sparseRangesFromZeroBlocks merges fixed-size all-zero blocks into maximal
// contiguous ranges. blockSize must be positive.
func sparseRangesFromZeroBlocks(zero []bool, blockSize, totalLength int64) []ByteRange {
	var out []ByteRange
	for i := 0; i < len(zero); {
		if !zero[i] {
			i++
			continue
		}
		start := int64(i) * blockSize
		j := i
		for j < len(zero) && zero[j] {
			j++
		}
		end := int64(j) * blockSize
		if end > totalLength {
			end = totalLength
		}
		out = append(out, ByteRange{Start: start, End: end})
		i = j
	}
	return out
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ioLimit(r io.Reader, n int64) io.Reader { return io.LimitReader(r, n) }
