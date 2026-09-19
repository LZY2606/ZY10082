package chain

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type multiHasher struct {
	md5    hash.Hash
	sha1   hash.Hash
	sha256 hash.Hash
	sha512 hash.Hash
}

func newMultiHasher() *multiHasher {
	return &multiHasher{md5.New(), sha1.New(), sha256.New(), sha512.New()}
}

func (h *multiHasher) Write(p []byte) (int, error) {
	for _, target := range []hash.Hash{h.md5, h.sha1, h.sha256, h.sha512} {
		if _, err := target.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (h *multiHasher) hashes() Hashes {
	return Hashes{
		MD5:    hex.EncodeToString(h.md5.Sum(nil)),
		SHA1:   hex.EncodeToString(h.sha1.Sum(nil)),
		SHA256: hex.EncodeToString(h.sha256.Sum(nil)),
		SHA512: hex.EncodeToString(h.sha512.Sum(nil)),
	}
}

func hashReader(reader io.Reader) (Hashes, int64, error) {
	hasher := newMultiHasher()
	size, err := io.Copy(hasher, reader)
	if err != nil {
		return Hashes{}, 0, err
	}
	return hasher.hashes(), size, nil
}

func hashFile(path string) (Hashes, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return Hashes{}, 0, err
	}
	defer file.Close()
	return hashReader(file)
}

func sha256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

func randomID() string {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func newID(prefix string) string { return prefix + "_" + randomID() }

func nowString(offset int64) string {
	return time.Now().UTC().Add(time.Duration(offset)).Format(time.RFC3339Nano)
}

func safeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "unnamed"
	}
	return name
}

func ensureDir(path string) error { return os.MkdirAll(path, 0o750) }

func renameOrCopy(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err == nil {
		return nil
	}
	input, err := os.Open(oldPath)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(newPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		os.Remove(newPath)
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		os.Remove(newPath)
		return err
	}
	return output.Close()
}

func moveAll(oldDir, newDir string) error {
	if err := ensureDir(newDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := renameOrCopy(filepath.Join(oldDir, entry.Name()), filepath.Join(newDir, entry.Name())); err != nil {
			return err
		}
	}
	return os.RemoveAll(oldDir)
}

func validationError(format string, args ...any) error {
	return ValidationError(fmt.Sprintf(format, args...))
}

type ValidationError string

func (e ValidationError) Error() string { return string(e) }

func isValidation(err error) bool {
	var value ValidationError
	return errors.As(err, &value)
}
