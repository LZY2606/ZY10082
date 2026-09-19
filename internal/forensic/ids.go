package forensic

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
)

func newID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func sessionDir(dataDir, id string) string { return filepath.Join(dataDir, "staging", id) }
func blockPath(dataDir, sid string, i int) string {
	return filepath.Join(sessionDir(dataDir, sid), "blocks", blkName(i))
}
func blkName(i int) string {
	digits := "0000000000"
	s := itoa(i)
	if len(s) < len(digits) {
		s = digits[len(s):] + s
	}
	return s + ".blk"
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	var b [24]byte
	pos := len(b)
	for i != 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func blobPath(dataDir string, h Hashes) string {
	return filepath.Join(dataDir, "blobs", "sha256", h.SHA256[:2], h.SHA256[2:4], h.SHA256+".bin")
}

// hostEnv captures the local acquisition environment best-effort.
func hostEnv() EnvInfo {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	return EnvInfo{
		Hostname: host,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		User:     user,
		Tool:     "forensicbox",
	}
}
