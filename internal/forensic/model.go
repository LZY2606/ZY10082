// Package forensic implements a local, append-only chain-of-custody store
// for read-only digital evidence and its derived products.
package forensic

import "time"

// Hashes holds several cryptographic fingerprints of the same byte string.
type Hashes struct {
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	SHA1   string `json:"sha1"`
}

// ByteRange is a half-open interval [Start, End) inside a byte stream.
type ByteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// EnvInfo captures the acquisition environment.
type EnvInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	User     string `json:"user"`
	Tool     string `json:"tool"`
	Extra    string `json:"extra,omitempty"`
}

// Source describes where the evidence bytes came from. Same content from a
// different source is always a separate custody event.
type Source struct {
	Kind        string `json:"kind"` // file, image, stream
	Origin      string `json:"origin"`
	Device      string `json:"device,omitempty"`
	Path        string `json:"path,omitempty"`
	Acquirer    string `json:"acquirer,omitempty"`
	Description string `json:"description,omitempty"`
}

// SessionStatus enumerates batch ingest states.
const (
	StatusPending   = "pending"
	StatusAccepted  = "accepted"
	StatusRejected  = "rejected"
	StatusRecovered = "recovering"
)

// BlockInfo describes one written chunk of a staged batch.
type BlockInfo struct {
	Index  int    `json:"index"`
	Length int64  `json:"length"`
	Hashes Hashes `json:"hashes"`
}

// CheckFailure keeps the latest failed verification without touching success.
type CheckFailure struct {
	Time    time.Time `json:"time"`
	Stage   string    `json:"stage"`
	Detail  string    `json:"detail"`
	IdemKey string    `json:"idem_key,omitempty"`
}

// Session is a staged (possibly interrupted) batch ingestion.
type Session struct {
	ID          string            `json:"id"`
	Filename    string            `json:"filename"`
	TotalLength int64             `json:"total_length"`
	BlockSize   int64             `json:"block_size"`
	BlockCount  int               `json:"block_count"`
	Hashes      Hashes            `json:"hashes"` // final hashes declared at seal
	Source      Source            `json:"source"`
	Env         EnvInfo           `json:"env"`
	Note        string            `json:"note"`
	Blocks      map[int]BlockInfo `json:"blocks"`
	Status      string            `json:"status"`
	ArtifactID  string            `json:"artifact_id,omitempty"`
	Failures    []CheckFailure    `json:"failures,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ToolRun records exactly how a derived product was produced.
type ToolRun struct {
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Args    string     `json:"args"`
	Range   *ByteRange `json:"range,omitempty"`
}

// Derivation links a derived product back to its input fragments.
type Derivation struct {
	ID         string     `json:"id"`
	ParentID   string     `json:"parent_id"`
	InputRange *ByteRange `json:"input_range,omitempty"`
	Tool       ToolRun    `json:"tool"`
}

// Artifact is any registered read-only byte object: root evidence or derived.
type Artifact struct {
	ID           string      `json:"id"`
	Kind         string      `json:"kind"` // root, derived, imported
	Filename     string      `json:"filename"`
	Length       int64       `json:"length"`
	Hashes       Hashes      `json:"hashes"`
	SparseRanges []ByteRange `json:"sparse_ranges,omitempty"`
	Source       Source      `json:"source"`
	Env          EnvInfo     `json:"env"`
	Note         string      `json:"note"`
	SessionID    string      `json:"session_id,omitempty"`
	DerivedFrom  *Derivation `json:"derived_from,omitempty"`
	PackageID    string      `json:"package_id,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
}

// CustodyEvent is one handoff in the chain of custody.
type CustodyEvent struct {
	ID         string    `json:"id"`
	ArtifactID string    `json:"artifact_id"`
	Seq        int       `json:"seq"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Reason     string    `json:"reason"`
	IdemKey    string    `json:"idem_key,omitempty"`
	PackageID  string    `json:"package_id,omitempty"`
	Time       time.Time `json:"time"`
}

// CheckRecord is the result of a full-chain verification request.
type CheckRecord struct {
	ID       string    `json:"id"`
	TargetID string    `json:"target_id"`
	Time     time.Time `json:"time"`
	OK       bool      `json:"ok"`
	Steps    []string  `json:"steps"`
	Errors   []string  `json:"errors"`
	IdemKey  string    `json:"idem_key,omitempty"`
}

// ClockFact records a clock correction without rewriting history.
type ClockFact struct {
	ID        string    `json:"id"`
	OldOffset string    `json:"old_offset"`
	NewOffset string    `json:"new_offset"`
	Reason    string    `json:"reason"`
	Time      time.Time `json:"time"`
}

// ExportRecord tracks produced/imported packages for replay protection.
type ExportRecord struct {
	ID          string    `json:"id"`
	PackageID   string    `json:"package_id"`
	ContentHash string    `json:"content_hash"`
	Direction   string    `json:"direction"` // export, import
	ArtifactIDs []string  `json:"artifact_ids"`
	WithDerived bool      `json:"with_derived"`
	Time        time.Time `json:"time"`
	IdemKey     string    `json:"idem_key,omitempty"`
}
