package chain

import "time"

type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type Range struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

type Node struct {
	ID           string         `json:"id"`
	OriginalID   string         `json:"original_id,omitempty"`
	Kind         string         `json:"kind"`
	Status       string         `json:"status"`
	Name         string         `json:"name"`
	ParentID     string         `json:"parent_id,omitempty"`
	Source       string         `json:"source,omitempty"`
	Notes        string         `json:"notes,omitempty"`
	SparseRanges []Range        `json:"sparse_ranges,omitempty"`
	Size         int64          `json:"size,omitempty"`
	Hashes       Hashes         `json:"hashes,omitempty"`
	Operation    string         `json:"operation,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolVersion  string         `json:"tool_version,omitempty"`
	Parameters   map[string]any `json:"parameters,omitempty"`
	InputStart   *int64         `json:"input_start,omitempty"`
	InputLength  *int64         `json:"input_length,omitempty"`
	FromParty    string         `json:"from_party,omitempty"`
	ToParty      string         `json:"to_party,omitempty"`
	Purpose      string         `json:"purpose,omitempty"`
	EventID      string         `json:"event_id,omitempty"`
	CreatedAt    string         `json:"created_at"`
	PackageID    string         `json:"package_id,omitempty"`
	BlobPath     string         `json:"blob_path,omitempty"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type BlockInfo struct {
	Number     int    `json:"number"`
	Size       int64  `json:"size"`
	Hashes     Hashes `json:"hashes"`
	ReceivedAt string `json:"received_at"`
	EventID    string `json:"event_id"`
}

type Batch struct {
	ID             string      `json:"id"`
	Filename       string      `json:"filename"`
	Source         string      `json:"source"`
	Notes          string      `json:"notes,omitempty"`
	SparseRanges   []Range     `json:"sparse_ranges,omitempty"`
	TotalBlocks    int         `json:"total_blocks"`
	Status         string      `json:"status"`
	Blocks         []BlockInfo `json:"blocks"`
	NodeID         string      `json:"node_id,omitempty"`
	FinalHashes    Hashes      `json:"final_hashes,omitempty"`
	Error          string      `json:"error,omitempty"`
	QuarantinePath string      `json:"quarantine_path,omitempty"`
	CreatedAt      string      `json:"created_at"`
	UpdatedAt      string      `json:"updated_at"`
}

type Verification struct {
	ID        string   `json:"id"`
	NodeID    string   `json:"node_id"`
	OK        bool     `json:"ok"`
	Path      []string `json:"path"`
	Detail    string   `json:"detail,omitempty"`
	EventID   string   `json:"event_id"`
	CreatedAt string   `json:"created_at"`
	PackageID string   `json:"package_id,omitempty"`
}

type ClockAdjustment struct {
	ID          string `json:"id"`
	RecordedAt  string `json:"recorded_at"`
	CorrectedAt string `json:"corrected_at"`
	OffsetNanos int64  `json:"offset_nanos"`
	Reason      string `json:"reason"`
	Actor       string `json:"actor,omitempty"`
	EventID     string `json:"event_id"`
}

type ExportRecord struct {
	ID             string `json:"id"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	IncludeDerived bool   `json:"include_derived"`
	CreatedAt      string `json:"created_at"`
	EventID        string `json:"event_id"`
}

type ImportRecord struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
	NodeCount   int    `json:"node_count"`
	Replayed    bool   `json:"replayed"`
	CreatedAt   string `json:"created_at"`
	EventID     string `json:"event_id,omitempty"`
}

type IdempotencyRecord struct {
	Key         string `json:"key"`
	Route       string `json:"route"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
	CreatedAt   string `json:"created_at"`
	EventID     string `json:"event_id"`
}

type PublicState struct {
	GeneratedAt      string            `json:"generated_at"`
	ClockOffsetNanos int64             `json:"clock_offset_nanos"`
	Nodes            []Node            `json:"nodes"`
	Edges            []Edge            `json:"edges"`
	Batches          []Batch           `json:"batches"`
	Verifications    []Verification    `json:"verifications"`
	ClockAdjustments []ClockAdjustment `json:"clock_adjustments"`
	Exports          []ExportRecord    `json:"exports"`
	Imports          []ImportRecord    `json:"imports"`
	Counts           map[string]int    `json:"counts"`
}

type State struct {
	GeneratedAt      string `json:"generated_at"`
	ClockOffsetNanos int64  `json:"clock_offset_nanos"`
	Nodes            []Node
	Edges            []Edge
	Batches          []Batch
	Verifications    []Verification
	ClockAdjustments []ClockAdjustment
	Exports          []ExportRecord
	Imports          []ImportRecord

	nodes       map[string]Node
	batches     map[string]Batch
	imports     map[string]ImportRecord
	eventsByID  map[string]struct{}
	idempotency map[string]IdempotencyRecord
}

func NewState() *State {
	return &State{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		nodes:       map[string]Node{},
		batches:     map[string]Batch{},
		imports:     map[string]ImportRecord{},
		eventsByID:  map[string]struct{}{},
		idempotency: map[string]IdempotencyRecord{},
	}
}

func (s *State) Public() PublicState {
	return PublicState{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		ClockOffsetNanos: s.ClockOffsetNanos,
		Nodes:            append([]Node(nil), s.Nodes...),
		Edges:            append([]Edge(nil), s.Edges...),
		Batches:          append([]Batch(nil), s.Batches...),
		Verifications:    append([]Verification(nil), s.Verifications...),
		ClockAdjustments: append([]ClockAdjustment(nil), s.ClockAdjustments...),
		Exports:          append([]ExportRecord(nil), s.Exports...),
		Imports:          append([]ImportRecord(nil), s.Imports...),
		Counts:           s.Counts(),
	}
}
