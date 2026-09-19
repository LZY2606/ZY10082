package forensic

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Manifest is the machine-readable inventory inside an export package.
type Manifest struct {
	PackageID   string     `json:"package_id"`
	CreatedAt   string     `json:"created_at"`
	Tool        string     `json:"tool"`
	WithDerived bool       `json:"with_derived"`
	Artifacts   []ArtEntry `json:"artifacts"`
	Events      []Event    `json:"events"`
	ContentHash string     `json:"content_hash,omitempty"`
}

// ArtEntry is one manifest row: inventory metadata plus its blob path.
type ArtEntry struct {
	Artifact Artifact `json:"artifact"`
	BlobPath string   `json:"blob_path"`
}

const exportVersion = "forensicbox-export/1.0"
const maxImportBytes = 16 * 1024 * 1024 * 1024

// Export builds a package containing the inventory, event log and optional
// derived blobs. Repeating an idempotency key returns the first result.
func (s *Service) Export(artifactIDs []string, withDerived bool, idemKey string) ([]byte, *ExportRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idemKey != "" {
		if ref, ok := s.idem[idemKey]; ok && ref.Kind == "export" {
			for i := range s.pkgs {
				if s.pkgs[i].ID == ref.ID {
					data, gErr := os.ReadFile(s.packageFilePath(s.pkgs[i].PackageID))
					return data, &s.pkgs[i], true, gErr
				}
			}
		}
	}
	arts, err := s.collectForExportLocked(artifactIDs, withDerived)
	if err != nil {
		return nil, nil, false, err
	}
	pkgID := newID("pkg")
	man := Manifest{PackageID: pkgID, CreatedAt: s.now().Format("2006-01-02T15:04:05.000000000Z07:00"), Tool: exportVersion, WithDerived: withDerived}
	blobData := map[string][]byte{}
	for i := range arts {
		a := arts[i]
		rel := path.Join("blobs", a.Hashes.SHA256[:2], a.Hashes.SHA256[2:4], a.Hashes.SHA256+".bin")
		data, rErr := os.ReadFile(blobPath(s.dir, a.Hashes))
		if rErr != nil {
			return nil, nil, false, rErr
		}
		blobData[rel] = data
		man.Artifacts = append(man.Artifacts, ArtEntry{Artifact: a, BlobPath: rel})
	}
	for _, ev := range s.eventsRelevant(arts) {
		man.Events = append(man.Events, ev)
	}
	payloadHash, err := canonicalPayloadHash(man, blobData)
	if err != nil {
		return nil, nil, false, err
	}
	man.ContentHash = payloadHash
	pkg, err := s.buildZip(man, blobData)
	if err != nil {
		return nil, nil, false, err
	}
	ids := make([]string, 0, len(arts))
	for _, a := range arts {
		ids = append(ids, a.ID)
	}
	rec := ExportRecord{
		ID:          newID("exp"),
		PackageID:   pkgID,
		ContentHash: payloadHash,
		Direction:   "export",
		ArtifactIDs: ids,
		WithDerived: withDerived,
		Time:        s.now(),
		IdemKey:     idemKey,
	}
	savePath := s.packageFilePath(pkgID)
	if err := os.MkdirAll(filepath.Dir(savePath), 0o755); err != nil {
		return nil, nil, false, err
	}
	if err := writeAtomic(savePath, pkg, 0o644); err != nil {
		return nil, nil, false, err
	}
	if _, err := s.emit("package_exported", idemKey, pExported{Record: rec}); err != nil {
		return nil, nil, false, err
	}
	if idemKey != "" {
		s.idem[idemKey] = idemRef{Kind: "export", ID: rec.ID}
	}
	return pkg, &rec, false, nil
}

func (s *Service) packageFilePath(pkgID string) string {
	return filepath.Join(s.dir, "packages", pkgID+".fbx.zip")
}

func (s *Service) collectForExportLocked(ids []string, withDerived bool) ([]Artifact, error) {
	want := map[string]bool{}
	if len(ids) == 0 {
		for id := range s.art {
			want[id] = true
		}
	}
	for _, id := range ids {
		if _, ok := s.art[id]; !ok {
			return nil, fmt.Errorf("%w: artifact %s", ErrNotFound, id)
		}
		want[id] = true
	}
	if withDerived {
		for _, a := range s.art {
			if a.DerivedFrom != nil && want[a.DerivedFrom.ParentID] {
				want[a.ID] = true
			}
		}
	}
	// require parents
	for id := range want {
		cur := s.art[id]
		for cur.DerivedFrom != nil {
			if !want[cur.DerivedFrom.ParentID] {
				return nil, fmt.Errorf("%w: derived artifact %s needs parent %s", ErrInvalidInput, id, cur.DerivedFrom.ParentID)
			}
			cur = s.art[cur.DerivedFrom.ParentID]
		}
	}
	out := make([]Artifact, 0, len(want))
	for id := range want {
		out = append(out, *s.art[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Service) eventsRelevant(arts []Artifact) []Event {
	ids := map[string]bool{}
	for _, a := range arts {
		ids[a.ID] = true
	}
	var out []Event
	for _, ev := range s.events {
		switch ev.Type {
		case "sealed", "derived":
			out = append(out, ev)
		case "transfer", "chain_verified":
			// include custody/checks for exported artifacts
			if ev.Type == "transfer" {
				var p pTransfer
				if json.Unmarshal(ev.Payload, &p) == nil && ids[p.Custody.ArtifactID] {
					out = append(out, ev)
				}
			}
		}
	}
	return out
}

func canonicalPayloadHash(man Manifest, blobs map[string][]byte) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "pkg|%s|%s|%v\n", man.PackageID, man.Tool, man.WithDerived)
	names := make([]string, 0, len(blobs))
	for n := range blobs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "blob|%s|%d\n", n, len(blobs[n]))
		h.Write(blobs[n])
	}
	evJSON, err := json.Marshal(man.Events)
	if err != nil {
		return "", err
	}
	man2 := man
	man2.Events = nil
	man2.ContentHash = ""
	mJSON, err := json.Marshal(man2)
	if err != nil {
		return "", err
	}
	h.Write(evJSON)
	h.Write(mJSON)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Service) buildZip(man Manifest, blobs map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(blobs))
	for n := range blobs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := writeZipAt(zw, n, blobs[n]); err != nil {
			return nil, err
		}
	}
	evJSON, err := json.MarshalIndent(man.Events, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipAt(zw, "events.log.json", evJSON); err != nil {
		return nil, err
	}
	mJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipAt(zw, "manifest.json", mJSON); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeZipAt(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

var _ = io.Copy
var _ = strings.TrimSpace
