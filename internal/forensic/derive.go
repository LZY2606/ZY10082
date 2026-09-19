package forensic

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// ToolVersion is the semantic identity of a built-in derivation tool.
type ToolVersion struct {
	Name    string
	Version string
}

// tool versions are fixed strings recorded on every derivation.
var toolVersions = map[string]string{
	"preview": "forensicbox-preview/1.0",
	"strings": "forensicbox-strings/1.0",
	"sha256":  "forensicbox-sha256/1.0",
	"hexdump": "forensicbox-hexdump/1.0",
	"ziplist": "forensicbox-ziplist/1.0",
}

const maxDeriveInput = 512 * 1024 * 1024
const maxDeriveOutput = 64 * 1024 * 1024

// DeriveInput asks for a new derived product from an input fragment.
type DeriveInput struct {
	ParentID string
	Tool     string
	Args     string
	Start    int64
	End      int64
	IdemKey  string
}

// openArtifactBytes opens the read-only blob of an artifact.
func (s *Service) openArtifactBytes(id string) (*os.File, Artifact, error) {
	art, err := s.findArtifactLocked(id)
	if err != nil {
		return nil, Artifact{}, err
	}
	f, err := os.Open(blobPath(s.dir, art.Hashes))
	if err != nil {
		return nil, Artifact{}, fmt.Errorf("%w: blob missing for %s", ErrNotFound, id)
	}
	return f, *art, nil
}

// Derive produces and registers a derived artifact. It never mutates the
// parent, records the tool version, arguments, input fragment and output
// fingerprint, and is idempotent per key.
func (s *Service) Derive(in DeriveInput) (*Artifact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.IdemKey != "" {
		if ref, ok := s.idem[in.IdemKey]; ok && ref.Kind == "derive" {
			a, err := s.findArtifactLocked(ref.ID)
			return a, true, err
		}
	}
	ver, ok := toolVersions[in.Tool]
	if !ok {
		return nil, false, fmt.Errorf("%w: unknown tool %q", ErrInvalidInput, in.Tool)
	}
	f, parent, err := s.openArtifactBytes(in.ParentID)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	start, end, err := resolveRange(parent.Length, in.Start, in.End)
	if err != nil {
		return nil, false, err
	}
	if end-start > maxDeriveInput {
		return nil, false, fmt.Errorf("%w: input fragment too large", ErrInvalidInput)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	lr := io.LimitReader(f, end-start)
	out, argsUsed, err := runTool(in.Tool, in.Args, lr)
	if err != nil {
		return nil, false, err
	}
	if int64(len(out)) > maxDeriveOutput {
		return nil, false, fmt.Errorf("%w: tool output too large", ErrInvalidInput)
	}
	hs := HashBytes(out)
	target := blobPath(s.dir, hs)
	if _, statErr := os.Stat(target); statErr != nil {
		if err := writeAtomic(target, out, 0o444); err != nil {
			return nil, false, err
		}
	}
	br := &ByteRange{Start: start, End: end}
	art := Artifact{
		ID:        newID("der"),
		Kind:      "derived",
		Filename:  fmt.Sprintf("%s.%s", parent.Filename, in.Tool),
		Length:    int64(len(out)),
		Hashes:    hs,
		Source:    parent.Source,
		Env:       hostEnv(),
		Note:      fmt.Sprintf("derived via %s", in.Tool),
		PackageID: parent.PackageID,
		DerivedFrom: &Derivation{
			ID:         newID("drv"),
			ParentID:   parent.ID,
			InputRange: br,
			Tool:       ToolRun{Name: in.Tool, Version: ver, Args: argsUsed, Range: br},
		},
		CreatedAt: s.now(),
	}
	if _, err := s.emit("derived", in.IdemKey, pDerived{Artifact: art}); err != nil {
		return nil, false, err
	}
	if in.IdemKey != "" {
		s.idem[in.IdemKey] = idemRef{Kind: "derive", ID: art.ID}
	}
	out2, _ := s.findArtifactLocked(art.ID)
	return out2, false, nil
}

func resolveRange(length, start, end int64) (int64, int64, error) {
	if start < 0 || end < 0 || start > length {
		return 0, 0, fmt.Errorf("%w: range outside artifact", ErrInvalidInput)
	}
	if end == 0 && start == 0 {
		end = length
	}
	if end < start {
		return 0, 0, fmt.Errorf("%w: inverted range", ErrInvalidInput)
	}
	if end > length {
		end = length
	}
	return start, end, nil
}

var stringsRe = regexp.MustCompile(`[ -~]{4,}`)

func runTool(tool, args string, r io.Reader) ([]byte, string, error) {
	switch tool {
	case "preview":
		limit := int64(4096)
		if v, n := parseLimitArg(args); n {
			limit = v
		}
		if limit > maxDeriveOutput {
			limit = maxDeriveOutput
		}
		buf := make([]byte, limit)
		n, _ := io.ReadFull(r, buf)
		return buf[:n], fmt.Sprintf("limit=%d", limit), nil
	case "strings":
		minLen := 4
		if v, n := parseMinLen(args); n {
			minLen = v
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, "", err
		}
		var lines []byte
		for _, m := range stringsRe.FindAllString(string(data), -1) {
			if len(m) >= minLen {
				lines = append(lines, m...)
				lines = append(lines, '\n')
			}
		}
		return lines, fmt.Sprintf("min=%d", minLen), nil
	case "sha256":
		hs, n, err := HashReader(r)
		if err != nil {
			return nil, "", err
		}
		return []byte(fmt.Sprintf("sha256=%s\nlength=%d\nsha512=%s\nsha1=%s\n", hs.SHA256, n, hs.SHA512, hs.SHA1)), "", nil
	case "hexdump":
		limit := int64(4096)
		if v, n := parseLimitArg(args); n {
			limit = v
		}
		data, err := io.ReadAll(io.LimitReader(r, limit))
		if err != nil {
			return nil, "", err
		}
		var b strings.Builder
		for off := 0; off < len(data); off += 16 {
			row := data[off:]
			if len(row) > 16 {
				row = row[:16]
			}
			fmt.Fprintf(&b, "%08x  ", off)
			for i := 0; i < 16; i++ {
				if i < len(row) {
					fmt.Fprintf(&b, "%02x ", row[i])
				} else {
					b.WriteString("   ")
				}
				if i == 7 {
					b.WriteByte(' ')
				}
			}
			b.WriteString(" |")
			for _, c := range row {
				if c >= 32 && c < 127 {
					b.WriteByte(c)
				} else {
					b.WriteByte('.')
				}
			}
			b.WriteString("|\n")
		}
		return []byte(b.String()), fmt.Sprintf("limit=%d", limit), nil
	case "ziplist":
		return zipList(r)
	default:
		return nil, "", fmt.Errorf("%w: unknown tool %q", ErrInvalidInput, tool)
	}
}

func parseLimitArg(args string) (int64, bool) {
	var v int64
	if _, err := fmt.Sscanf(args, "limit=%d", &v); err == nil && v > 0 {
		return v, true
	}
	return 0, false
}

func parseMinLen(args string) (int, bool) {
	var v int
	if _, err := fmt.Sscanf(args, "min=%d", &v); err == nil && v >= 1 {
		return v, true
	}
	return 0, false
}

// OpenBlob returns a reader and artifact for downloads.
func (s *Service) OpenBlob(id string) (*os.File, Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.openArtifactBytes(id)
}

var _ = bufio.NewReader
var _ = sort.IntsAreSorted
var _ = hex.EncodeToString
var _ = json.Marshal
var _ = bytes.MinRead
