package chain

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"sort"
)

func (s *Service) CreateExport(input ExportInput, idempotency *IdempotencyRecord) (ExportOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	at := nowString(s.state.ClockOffsetNanos)
	exportID := newID("exp")
	packageID := "pkg_" + randomID()
	filePath := s.dataPath("exports", exportID+".zip")

	var selected []Node
	for _, node := range s.state.Nodes {
		if node.PackageID != "" || (!input.IncludeDerived && node.Kind == NodeDerived) {
			continue
		}
		selected = append(selected, node)
	}
	selectedIDs := map[string]bool{}
	for _, node := range selected {
		selectedIDs[node.ID] = true
	}
	var edges []Edge
	for _, edge := range s.state.Edges {
		if selectedIDs[edge.From] && selectedIDs[edge.To] {
			edges = append(edges, edge)
		}
	}

	eventData, err := os.ReadFile(s.store.Path())
	if err != nil {
		return ExportOutput{}, err
	}
	blobs := map[string][]byte{}
	var entries []PackageEntry
	for _, node := range selected {
		if node.Kind == NodeTransfer || node.BlobPath == "" {
			continue
		}
		data, err := os.ReadFile(s.dataPath(node.BlobPath))
		if err != nil {
			return ExportOutput{}, err
		}
		entryPath := path.Join("blobs", node.ID+".bin")
		blobs[entryPath] = data
		entries = append(entries, PackageEntry{Path: entryPath, Size: int64(len(data)), SHA256: sha256Bytes(data)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	manifest := PackageManifest{
		PackageID: packageID, Fingerprint: sha256Bytes(eventData), CreatedAt: at,
		IncludeDerived: input.IncludeDerived, Nodes: selected, Edges: edges, Entries: entries,
		EventLog: PackageEntry{Path: "events.log", Size: int64(len(eventData)), SHA256: sha256Bytes(eventData)},
	}
	manifest.ManifestSHA256 = manifestDigest(manifest)
	packageBytes, err := buildExportZip(manifest, eventData, blobs)
	if err != nil {
		return ExportOutput{}, err
	}
	if err := os.WriteFile(filePath, packageBytes, 0o640); err != nil {
		return ExportOutput{}, err
	}
	record := ExportRecord{
		ID: exportID, Path: filePath, SHA256: sha256Bytes(packageBytes),
		Size: int64(len(packageBytes)), IncludeDerived: input.IncludeDerived, CreatedAt: at,
	}
	result := ExportOutput{Export: record}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtExportCreated, ExportPayload{Export: record})
		if err != nil {
			return nil, err
		}
		record.EventID = event.ID
		return rebuildEvent(event, EvtExportCreated, ExportPayload{Export: record})
	})
	if err != nil {
		os.Remove(filePath)
		return ExportOutput{}, err
	}
	return committed.(ExportOutput), nil
}

func buildExportZip(manifest PackageManifest, eventData []byte, blobs map[string][]byte) ([]byte, error) {
	buffer := &bytes.Buffer{}
	writer := zip.NewWriter(buffer)
	if err := writeZipEntry(writer, "events.log", eventData); err != nil {
		return nil, err
	}
	for _, entry := range manifest.Entries {
		if err := writeZipEntry(writer, entry.Path, blobs[entry.Path]); err != nil {
			return nil, err
		}
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipEntry(writer, "manifest.json", manifestData); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeZipEntry(writer *zip.Writer, name string, data []byte) error {
	entry, err := writer.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, bytes.NewReader(data))
	return err
}

func (s *Service) ExportPath(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.state.Exports {
		if record.ID == id {
			return record.Path, true
		}
	}
	return "", false
}
