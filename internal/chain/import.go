package chain

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

func (s *Service) ImportPackage(reader io.Reader, idempotency *IdempotencyRecord) (ImportOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tempPath := s.dataPath("imports", newID("upload")+".zip.tmp")
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return ImportOutput{}, err
	}
	if _, err := io.Copy(file, reader); err != nil {
		file.Close()
		os.Remove(tempPath)
		return ImportOutput{}, err
	}
	if err := file.Close(); err != nil {
		os.Remove(tempPath)
		return ImportOutput{}, err
	}
	manifest, payload, closePackage, err := inspectPackage(tempPath)
	if err != nil {
		quarantine := s.dataPath("quarantine", newID("badpkg")+".zip")
		_ = renameOrCopy(tempPath, quarantine)
		return ImportOutput{}, err
	}
	defer closePackage()

	at := nowString(s.state.ClockOffsetNanos)
	if existing, ok := s.state.imports[manifest.Fingerprint]; ok {
		record := ImportRecord{
			ID: newID("imp"), Fingerprint: manifest.Fingerprint, Path: existing.Path,
			NodeCount: existing.NodeCount, Replayed: true, CreatedAt: at,
		}
		result := ImportOutput{Import: record}
		committed, err := s.commit(result, idempotency, func() ([]Event, error) {
			event, err := s.makeEvent(EvtImportReplayed, ReplayPayload{Import: record})
			if err != nil {
				return nil, err
			}
			record.EventID = event.ID
			return rebuildEvent(event, EvtImportReplayed, ReplayPayload{Import: record})
		})
		os.Remove(tempPath)
		if err != nil {
			return ImportOutput{}, err
		}
		return committed.(ImportOutput), nil
	}

	importID := newID("imp")
	packageDir := s.dataPath("imports", importID)
	if err := ensureDir(filepath.Join(packageDir, "blobs")); err != nil {
		os.Remove(tempPath)
		return ImportOutput{}, err
	}
	packagePath := filepath.Join(packageDir, "source.zip")
	if err := renameOrCopy(tempPath, packagePath); err != nil {
		return ImportOutput{}, err
	}

	idMapping := map[string]string{}
	blobMapping := map[string]string{}
	nodes := make([]Node, 0, len(manifest.Nodes))
	edges := make([]Edge, 0, len(manifest.Edges))
	for _, original := range manifest.Nodes {
		node := original
		newNodeID := newID(prefixForNode(original.Kind))
		idMapping[original.ID] = newNodeID
		node.ID = newNodeID
		node.OriginalID = original.ID
		node.PackageID = importID
		node.Status = StatusAccepted
		if original.BlobPath != "" {
			entryName := path.Join("blobs", newNodeID+".bin")
			node.BlobPath = path.Join("imports", importID, entryName)
			blobMapping[path.Join("blobs", path.Base(original.BlobPath))] = entryName
		}
		nodes = append(nodes, node)
	}
	if err := extractBlobs(payload, manifest, packageDir, idMapping, blobMapping); err != nil {
		_ = os.RemoveAll(packageDir)
		return ImportOutput{}, err
	}
	for _, edge := range manifest.Edges {
		from, fromOK := idMapping[edge.From]
		to, toOK := idMapping[edge.To]
		if !fromOK || !toOK {
			_ = os.RemoveAll(packageDir)
			return ImportOutput{}, validationError("edge references missing node")
		}
		edges = append(edges, Edge{From: from, To: to, Type: edge.Type})
	}
	verify := NewState()
	for _, node := range nodes {
		addNode(verify, node)
	}
	for _, edge := range edges {
		addEdge(verify, edge)
	}
	for _, node := range nodes {
		tempService := &Service{dataDir: s.dataDir, state: verify}
		if _, err := tempService.verifyChainLocked(node); err != nil {
			_ = os.RemoveAll(packageDir)
			return ImportOutput{}, err
		}
	}

	record := ImportRecord{
		ID: importID, Fingerprint: manifest.Fingerprint, Path: packagePath,
		NodeCount: len(nodes), Replayed: false, CreatedAt: at,
	}
	result := ImportOutput{Import: record, Nodes: nodes, Edges: edges}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtImportRegistered, ImportPayload{Import: record, Nodes: nodes, Edges: edges})
		if err != nil {
			return nil, err
		}
		record.EventID = event.ID
		return rebuildEvent(event, EvtImportRegistered, ImportPayload{Import: record, Nodes: nodes, Edges: edges})
	})
	if err != nil {
		_ = os.RemoveAll(packageDir)
		return ImportOutput{}, err
	}
	return committed.(ImportOutput), nil
}

func inspectPackage(packagePath string) (PackageManifest, *zip.Reader, func(), error) {
	reader, err := zip.OpenReader(packagePath)
	if err != nil {
		return PackageManifest{}, nil, nil, validationError("invalid zip package: %v", err)
	}
	closePackage := func() { _ = reader.Close() }
	manifestEntry, err := reader.Open("manifest.json")
	if err != nil {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("manifest.json missing")
	}
	defer manifestEntry.Close()
	data, err := io.ReadAll(manifestEntry)
	if err != nil {
		reader.Close()
		return PackageManifest{}, nil, nil, err
	}
	var manifest PackageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("invalid manifest json")
	}
	if manifest.PackageID == "" || manifest.Fingerprint == "" || len(manifest.Nodes) == 0 {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("manifest missing required fields")
	}
	digest := manifestDigest(manifest)
	if manifest.ManifestSHA256 == "" || manifest.ManifestSHA256 != digest {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("manifest self fingerprint mismatch")
	}
	allowedEntries := map[string]bool{"manifest.json": true, manifest.EventLog.Path: true}
	seenNodes := map[string]bool{}
	seenEntries := map[string]bool{}
	for _, node := range manifest.Nodes {
		if node.ID == "" || seenNodes[node.ID] || node.PackageID != "" || node.Status != StatusAccepted {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("invalid imported node")
		}
		seenNodes[node.ID] = true
	}
	seenEdges := map[string]bool{}
	for _, edge := range manifest.Edges {
		key := edge.From + "\x00" + edge.To + "\x00" + edge.Type
		if edge.From == "" || edge.To == "" || seenEdges[key] {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("invalid imported edge")
		}
		seenEdges[key] = true
	}
	for _, node := range manifest.Nodes {
		if node.ParentID == "" {
			if node.Kind != NodeEvidence {
				reader.Close()
				return PackageManifest{}, nil, nil, validationError("non-evidence root node is invalid")
			}
			continue
		}
		if !seenNodes[node.ParentID] {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("node parent is missing")
		}
	}
	for _, entry := range manifest.Entries {
		if !safeZipPath(entry.Path) || seenEntries[entry.Path] || entry.Size < 0 {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("unsafe package path")
		}
		seenEntries[entry.Path] = true
		allowedEntries[entry.Path] = true
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || strings.HasSuffix(file.Name, "/") {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("directory entries are not allowed")
		}
		if !safeZipPath(file.Name) {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("unsafe package path")
		}
		if !allowedEntries[file.Name] {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("unexpected package file %s", file.Name)
		}
	}
	eventEntry, err := reader.Open(manifest.EventLog.Path)
	if err != nil {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("event log missing")
	}
	eventData, err := io.ReadAll(eventEntry)
	_ = eventEntry.Close()
	if err != nil || sha256Bytes(eventData) != manifest.EventLog.SHA256 {
		reader.Close()
		return PackageManifest{}, nil, nil, validationError("event log fingerprint mismatch")
	}
	var previous string
	decoder := json.NewDecoder(bytes.NewReader(eventData))
	for {
		var event Event
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			reader.Close()
			return PackageManifest{}, nil, nil, validationError("event log invalid")
		}
		if err := event.Verify(previous); err != nil {
			reader.Close()
			return PackageManifest{}, nil, nil, err
		}
		previous = event.Hash
	}
	return manifest, &reader.Reader, closePackage, nil
}

func extractBlobs(payload *zip.Reader, manifest PackageManifest, packageDir string, idMapping map[string]string, blobMapping map[string]string) error {
	actualEntries := map[string]PackageEntry{}
	for _, zipEntry := range payload.File {
		entry, err := zipEntry.Open()
		if err != nil {
			return err
		}
		hashes, size, err := hashReader(entry)
		_ = entry.Close()
		if err != nil {
			return err
		}
		actualEntries[zipEntry.Name] = PackageEntry{Path: zipEntry.Name, Size: size, SHA256: hashes.SHA256}
	}
	for _, entry := range manifest.Entries {
		actual, ok := actualEntries[entry.Path]
		if !ok || actual.Size != entry.Size || actual.SHA256 != entry.SHA256 {
			return validationError("package entry verification failed %s", entry.Path)
		}
		entryPath := entry.Path
		if renamed, ok := blobMapping[entry.Path]; ok {
			entryPath = renamed
		}
		zipEntry, err := payload.Open(entry.Path)
		if err != nil {
			return validationError("package entry missing %s", entry.Path)
		}
		targetPath := filepath.Join(packageDir, filepath.FromSlash(entryPath))
		if err := ensureDir(filepath.Dir(targetPath)); err != nil {
			_ = zipEntry.Close()
			return err
		}
		output, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			_ = zipEntry.Close()
			return err
		}
		hasher := newMultiHasher()
		size, err := io.Copy(io.MultiWriter(output, hasher), zipEntry)
		_ = zipEntry.Close()
		closeErr := output.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("extract %s failed", entry.Path)
		}
		hashes := hasher.hashes()
		if size != entry.Size || hashes.SHA256 != entry.SHA256 {
			return validationError("package entry hash mismatch %s", entry.Path)
		}
	}
	usedEntries := map[string]bool{}
	for _, node := range manifest.Nodes {
		if node.Kind == NodeTransfer || node.BlobPath == "" {
			continue
		}
		base := path.Base(node.BlobPath)
		found := false
		for _, entry := range manifest.Entries {
			if entry.Path == path.Join("blobs", base) {
				found = true
				if usedEntries[entry.Path] {
					return validationError("blob entry referenced more than once")
				}
				usedEntries[entry.Path] = true
			}
		}
		if !found {
			return validationError("node %s blob not in manifest", node.ID)
		}
	}
	if len(usedEntries) != len(manifest.Entries) {
		return validationError("package contains unmanifest blob content")
	}
	return nil
}

func safeZipPath(value string) bool {
	clean := path.Clean(value)
	return clean == value && !path.IsAbs(clean) && clean != "." &&
		!strings.HasPrefix(clean, "../") && clean != ".." &&
		!strings.Contains(clean, "\\")
}

func prefixForNode(kind string) string {
	switch kind {
	case NodeDerived:
		return "der"
	case NodeTransfer:
		return "xfer"
	default:
		return "ev"
	}
}
