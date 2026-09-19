package forensic

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ImportResult reports what a package import did.
type ImportResult struct {
	PackageID   string   `json:"package_id"`
	Replayed    bool     `json:"replayed"`
	Artifacts   []string `json:"artifacts"`
	Transfers   int      `json:"transfers"`
	ContentHash string   `json:"content_hash"`
}

// Import verifies a package fully before registering anything. Importing the
// same package again returns the first outcome and creates no new handoffs.
func (s *Service) Import(pkg []byte, idemKey string) (*ImportResult, error) {
	if int64(len(pkg)) > maxImportBytes {
		return nil, fmt.Errorf("%w: package too large", ErrInvalidInput)
	}
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return nil, fmt.Errorf("%w: not a valid package: %v", ErrInvalidInput, err)
	}
	var man Manifest
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		clean := safeZipName(f.Name)
		if clean == "" {
			return nil, fmt.Errorf("%w: illegal entry %q", ErrUnsafePath, f.Name)
		}
		files[clean] = f
	}
	mf, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("%w: manifest.json missing", ErrInvalidInput)
	}
	if err := readJSONZip(mf, &man); err != nil {
		return nil, fmt.Errorf("%w: manifest invalid: %v", ErrInvalidInput, err)
	}
	if man.PackageID == "" {
		return nil, fmt.Errorf("%w: manifest lacks package_id", ErrInvalidInput)
	}
	// Replay protection (both idempotency key and package identity).
	s.mu.Lock()
	defer s.mu.Unlock()
	if idemKey != "" {
		if ref, ok := s.idem[idemKey]; ok && ref.Kind == "import" {
			for i := range s.pkgs {
				if s.pkgs[i].ID == ref.ID {
					return s.importResultFor(s.pkgs[i], true), nil
				}
			}
		}
	}
	if pid, seen := s.pkgSeen[man.ContentHash]; seen && man.ContentHash != "" {
		for i := range s.pkgs {
			if s.pkgs[i].PackageID == pid && s.pkgs[i].Direction == "import" {
				return s.importResultFor(s.pkgs[i], true), nil
			}
		}
	}
	// Verify every listed blob exists and matches its fingerprint.
	blobs := map[string][]byte{}
	seenPaths := map[string]bool{}
	for _, e := range man.Artifacts {
		if e.Artifact.ID == "" || e.Artifact.Hashes.SHA256 == "" {
			return nil, fmt.Errorf("%w: manifest row incomplete", ErrInvalidInput)
		}
		if !safeRelPath(e.BlobPath) {
			return nil, fmt.Errorf("%w: blob path escapes package: %q", ErrUnsafePath, e.BlobPath)
		}
		zf, ok := files[e.BlobPath]
		if !ok {
			return nil, fmt.Errorf("%w: missing blob %s", ErrInvalidInput, e.BlobPath)
		}
		data, rErr := readZipAll(zf)
		if rErr != nil {
			return nil, rErr
		}
		got, n, hErr := HashReader(bytes.NewReader(data))
		if hErr != nil || n != e.Artifact.Length || !hashesEqualIfSet(e.Artifact.Hashes, got) {
			return nil, fmt.Errorf("%w: blob fingerprint mismatch for %s", ErrConflict, e.Artifact.ID)
		}
		blobs[e.BlobPath] = data
		seenPaths[e.BlobPath] = true
	}
	for name := range files {
		if name == "manifest.json" || name == "events.log.json" {
			continue
		}
		if !seenPaths[name] {
			return nil, fmt.Errorf("%w: undeclared entry %q", ErrInvalidInput, name)
		}
	}
	// Recompute payload hash and compare with the stamped content hash.
	payloadHash, err := canonicalPayloadHash(man, blobs)
	if err != nil {
		return nil, err
	}
	if man.ContentHash != "" && payloadHash != man.ContentHash {
		return nil, fmt.Errorf("%w: package content hash mismatch", ErrConflict)
	}
	// Validate foreign event log if present: events must be internally ordered
	// and reference only artifacts in the manifest.
	evFile := files["events.log.json"]
	var foreign []Event
	if evFile != nil {
		data, rErr := readZipAll(evFile)
		if rErr != nil {
			return nil, rErr
		}
		if err := json.Unmarshal(data, &foreign); err != nil {
			return nil, fmt.Errorf("%w: event log invalid: %v", ErrInvalidInput, err)
		}
	}
	knownArt := map[string]bool{}
	for _, e := range man.Artifacts {
		knownArt[e.Artifact.ID] = true
	}
	for i, ev := range foreign {
		if i > 0 && ev.Seq <= foreign[i-1].Seq {
			return nil, fmt.Errorf("%w: foreign event sequence not ordered at %d", ErrInvalidInput, i)
		}
	}

	// All verified: materialize blobs and register in one atomic event.
	arts := make([]Artifact, 0, len(man.Artifacts))
	ids := []string{}
	for _, e := range man.Artifacts {
		target := blobPath(s.dir, e.Artifact.Hashes)
		if _, statErr := os.Stat(target); statErr != nil {
			if err := writeAtomic(target, blobs[e.BlobPath], 0o444); err != nil {
				return nil, err
			}
		}
		a := e.Artifact
		a.PackageID = man.PackageID
		if a.Kind == "root" {
			a.Kind = "imported"
		}
		arts = append(arts, a)
		ids = append(ids, a.ID)
	}
	// Rebuild custody events from foreign log (transfer events only), tagged
	// with the package id so a replay never duplicates them.
	cust := s.custodyFromForeign(foreign, knownArt, man.PackageID, arts)
	rec := ExportRecord{
		ID:          newID("imp"),
		PackageID:   man.PackageID,
		ContentHash: payloadHash,
		Direction:   "import",
		ArtifactIDs: ids,
		WithDerived: man.WithDerived,
		Time:        s.now(),
		IdemKey:     idemKey,
	}
	if _, err := s.emit("package_imported", idemKey, pImported{
		PackageID: man.PackageID,
		Record:    rec,
		Artifacts: arts,
		Custodies: cust,
		Foreign:   foreign,
	}); err != nil {
		return nil, err
	}
	if idemKey != "" {
		s.idem[idemKey] = idemRef{Kind: "import", ID: rec.ID}
	}
	return &ImportResult{PackageID: man.PackageID, Replayed: false, Artifacts: ids, Transfers: len(cust), ContentHash: payloadHash}, nil
}

func (s *Service) custodyFromForeign(foreign []Event, known map[string]bool, pkgID string, arts []Artifact) []CustodyEvent {
	exists := map[string]bool{}
	for _, c := range s.cust {
		if c.PackageID == pkgID {
			exists[c.ID] = true
		}
	}
	var out []CustodyEvent
	seqs := map[string]int{}
	for _, ev := range foreign {
		if ev.Type != "transfer" {
			continue
		}
		var p pTransfer
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		c := p.Custody
		if !known[c.ArtifactID] || exists[c.ID] {
			continue
		}
		seqs[c.ArtifactID]++
		c.Seq = seqs[c.ArtifactID]
		c.PackageID = pkgID
		c.IdemKey = ""
		out = append(out, c)
		exists[c.ID] = true
	}
	return out
}

func (s *Service) importResultFor(rec ExportRecord, replayed bool) *ImportResult {
	n := 0
	for _, c := range s.cust {
		if c.PackageID == rec.PackageID {
			n++
		}
	}
	return &ImportResult{PackageID: rec.PackageID, Replayed: replayed, Artifacts: rec.ArtifactIDs, Transfers: n, ContentHash: rec.ContentHash}
}

func safeZipName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if path.IsAbs(name) {
		return ""
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) {
		return ""
	}
	return clean
}

func safeRelPath(p string) bool {
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" || path.IsAbs(p) {
		return false
	}
	clean := path.Clean(p)
	return clean != ".." && !strings.HasPrefix(clean, "../") && clean == p
}

func readZipAll(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > uint64(maxImportBytes) {
		return nil, fmt.Errorf("%w: entry too large", ErrInvalidInput)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxImportBytes+1))
}

func readJSONZip(f *zip.File, v any) error {
	data, err := readZipAll(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

var _ = filepath.Join
