package chain

import "encoding/json"

type PackageEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type PackageManifest struct {
	PackageID      string         `json:"package_id"`
	Fingerprint    string         `json:"fingerprint"`
	CreatedAt      string         `json:"created_at"`
	IncludeDerived bool           `json:"include_derived"`
	Nodes          []Node         `json:"nodes"`
	Edges          []Edge         `json:"edges"`
	Entries        []PackageEntry `json:"entries"`
	EventLog       PackageEntry   `json:"event_log"`
	ManifestSHA256 string         `json:"manifest_sha256,omitempty"`
}

type ExportInput struct {
	IncludeDerived bool
}

type ExportOutput struct {
	Export ExportRecord `json:"export"`
}

type ImportOutput struct {
	Import ImportRecord `json:"import"`
	Nodes  []Node       `json:"nodes,omitempty"`
	Edges  []Edge       `json:"edges,omitempty"`
}

func manifestDigest(manifest PackageManifest) string {
	manifest.ManifestSHA256 = ""
	data, _ := json.Marshal(manifest)
	return sha256Bytes(data)
}
