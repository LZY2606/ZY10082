package forensic

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ---- Event payloads ------------------------------------------------------

type pSessionCreated struct {
	Session Session `json:"session"`
}
type pBlockPut struct {
	SessionID string    `json:"session_id"`
	Block     BlockInfo `json:"block"`
	Replaced  bool      `json:"replaced,omitempty"`
}
type pSealed struct {
	SessionID  string      `json:"session_id"`
	ArtifactID string      `json:"artifact_id"`
	Artifact   Artifact    `json:"artifact"`
	Sparse     []ByteRange `json:"sparse"`
}
type pSealFailed struct {
	SessionID string       `json:"session_id"`
	Failure   CheckFailure `json:"failure"`
}
type pQuarantined struct {
	SessionID string    `json:"session_id"`
	Reason    string    `json:"reason"`
	Time      time.Time `json:"time"`
}
type pRecovery struct {
	SessionID string `json:"session_id"`
	Detail    string `json:"detail"`
	Missing   []int  `json:"missing"`
}
type pDerived struct {
	Artifact Artifact `json:"artifact"`
}
type pTransfer struct {
	Custody CustodyEvent `json:"custody"`
}
type pVerified struct {
	Check CheckRecord `json:"check"`
}
type pClock struct {
	Fact ClockFact `json:"fact"`
}
type pExported struct {
	Record ExportRecord `json:"record"`
}
type pImported struct {
	PackageID string         `json:"package_id"`
	Record    ExportRecord   `json:"record"`
	Artifacts []Artifact     `json:"artifacts"`
	Custodies []CustodyEvent `json:"custodies"`
	Foreign   []Event        `json:"foreign_events"`
}

// ---- State ---------------------------------------------------------------

// State is a serializable snapshot of everything the UI needs.
type State struct {
	Artifacts  []Artifact     `json:"artifacts"`
	Sessions   []Session      `json:"sessions"`
	Custodies  []CustodyEvent `json:"custodies"`
	Checks     []CheckRecord  `json:"checks"`
	ClockFacts []ClockFact    `json:"clock_facts"`
	Packages   []ExportRecord `json:"packages"`
	Events     []Event        `json:"events"`
	Now        string         `json:"now"`
}

// Service is the application service over the event store and blob tree.
type Service struct {
	mu      sync.RWMutex
	dir     string
	store   *Store
	clock   func() time.Time
	idem    map[string]idemRef
	art     map[string]*Artifact
	sess    map[string]*Session
	cust    []CustodyEvent
	checks  []CheckRecord
	clocks  []ClockFact
	pkgs    []ExportRecord
	pkgSeen map[string]string // contentHash -> packageID
	events  []Event
	started bool
}

type idemRef struct {
	Kind string // session, seal, derive, transfer, check, clock, export, import
	ID   string
}

// NewService opens the store under dataDir, replays events and scans staging.
func NewService(dataDir string) (*Service, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "staging"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "blobs"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "quarantine"), 0o755); err != nil {
		return nil, err
	}
	st, err := OpenStore(dataDir)
	if err != nil {
		return nil, err
	}
	s := &Service{
		dir:     dataDir,
		store:   st,
		clock:   time.Now,
		idem:    map[string]idemRef{},
		art:     map[string]*Artifact{},
		sess:    map[string]*Session{},
		pkgSeen: map[string]string{},
	}
	events, err := st.ReadEvents()
	if err != nil {
		return nil, err
	}
	for i := range events {
		if err := s.apply(events[i], false); err != nil {
			return nil, fmt.Errorf("replay event %d: %w", events[i].Seq, err)
		}
	}
	s.started = true
	if err := s.scanStaging(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the event store.
func (s *Service) Close() error { return s.store.Close() }

func (s *Service) now() time.Time { return s.clock().UTC() }

func (s *Service) emit(evType, idemKey string, payload any) (Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, err
	}
	ev := Event{Type: evType, Time: s.now().Format(time.RFC3339Nano), IdemKey: idemKey, Payload: raw}
	if err := s.store.Append(&ev); err != nil {
		return Event{}, err
	}
	if err := s.apply(ev, true); err != nil {
		return Event{}, fmt.Errorf("apply durable event: %w", err)
	}
	return ev, nil
}

var payloads = map[string]func() any{
	"session_created":     func() any { return &pSessionCreated{} },
	"block_put":           func() any { return &pBlockPut{} },
	"sealed":              func() any { return &pSealed{} },
	"seal_failed":         func() any { return &pSealFailed{} },
	"session_quarantined": func() any { return &pQuarantined{} },
	"recovery_note":       func() any { return &pRecovery{} },
	"derived":             func() any { return &pDerived{} },
	"transfer":            func() any { return &pTransfer{} },
	"chain_verified":      func() any { return &pVerified{} },
	"clock_corrected":     func() any { return &pClock{} },
	"package_exported":    func() any { return &pExported{} },
	"package_imported":    func() any { return &pImported{} },
}

func (s *Service) apply(ev Event, live bool) error {
	s.events = append(s.events, ev)
	if ev.IdemKey != "" {
		// Registered explicitly by each mutator after a successful emit;
		// imported events without local key stay unmapped.
	}
	mk, ok := payloads[ev.Type]
	if !ok {
		return fmt.Errorf("unknown event type %q", ev.Type)
	}
	p := mk()
	if err := json.Unmarshal(ev.Payload, p); err != nil {
		return err
	}
	switch v := p.(type) {
	case *pSessionCreated:
		sess := v.Session
		s.sess[sess.ID] = &sess
	case *pBlockPut:
		sess := s.sess[v.SessionID]
		if sess == nil {
			return fmt.Errorf("block for missing session %s", v.SessionID)
		}
		if sess.Blocks == nil {
			sess.Blocks = map[int]BlockInfo{}
		}
		sess.Blocks[v.Block.Index] = v.Block
		sess.UpdatedAt = mustTime(ev.Time)
	case *pSealed:
		sess := s.sess[v.SessionID]
		if sess != nil {
			sess.Status = StatusAccepted
			sess.ArtifactID = v.ArtifactID
			sess.UpdatedAt = mustTime(ev.Time)
		}
		art := v.Artifact
		if art.Hashes == (Hashes{}) {
			art.Hashes = v.Artifact.Hashes
		}
		art.SparseRanges = v.Sparse
		cp := art
		s.art[art.ID] = &cp
	case *pSealFailed:
		sess := s.sess[v.SessionID]
		if sess == nil {
			return fmt.Errorf("failure for missing session %s", v.SessionID)
		}
		sess.Status = StatusRejected
		sess.Failures = append(sess.Failures, v.Failure)
		sess.UpdatedAt = mustTime(ev.Time)
	case *pQuarantined:
		sess := s.sess[v.SessionID]
		if sess != nil {
			sess.Status = StatusRejected
			sess.Failures = append(sess.Failures, CheckFailure{Time: v.Time, Stage: "quarantine", Detail: v.Reason})
			sess.UpdatedAt = v.Time
		}
	case *pRecovery:
		sess := s.sess[v.SessionID]
		if sess != nil && sess.Status == StatusPending {
			sess.Status = StatusRecovered
			sess.UpdatedAt = mustTime(ev.Time)
		}
	case *pDerived:
		art := v.Artifact
		cp := art
		s.art[art.ID] = &cp
	case *pTransfer:
		s.cust = append(s.cust, v.Custody)
	case *pVerified:
		s.checks = append(s.checks, v.Check)
	case *pClock:
		s.clocks = append(s.clocks, v.Fact)
	case *pExported:
		s.pkgs = append(s.pkgs, v.Record)
	case *pImported:
		s.pkgs = append(s.pkgs, v.Record)
		s.pkgSeen[v.Record.ContentHash] = v.PackageID
		for i := range v.Artifacts {
			art := v.Artifacts[i]
			cp := art
			s.art[art.ID] = &cp
		}
		for i := range v.Custodies {
			s.cust = append(s.cust, v.Custodies[i])
		}
	}
	return nil
}

func mustTime(rfc string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, rfc)
	if err != nil {
		return time.Now().UTC()
	}
	return t
}

// ---- Snapshot / lookups --------------------------------------------------

func sortedSessions(m map[string]*Session) []Session {
	out := make([]Session, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func sortedArtifacts(m map[string]*Artifact) []Artifact {
	out := make([]Artifact, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Snapshot returns a read-only point-in-time state copy.
func (s *Service) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cust := append([]CustodyEvent(nil), s.cust...)
	checks := append([]CheckRecord(nil), s.checks...)
	clocks := append([]ClockFact(nil), s.clocks...)
	pkgs := append([]ExportRecord(nil), s.pkgs...)
	evs := append([]Event(nil), s.events...)
	return State{
		Artifacts:  sortedArtifacts(s.art),
		Sessions:   sortedSessions(s.sess),
		Custodies:  cust,
		Checks:     checks,
		ClockFacts: clocks,
		Packages:   pkgs,
		Events:     evs,
		Now:        s.now().Format(time.RFC3339Nano),
	}
}

func (s *Service) findArtifactLocked(id string) (*Artifact, error) {
	if a, ok := s.art[id]; ok {
		cp := *a
		return &cp, nil
	}
	return nil, fmt.Errorf("%w: artifact %s", ErrNotFound, id)
}

func (s *Service) findSessionLocked(id string) (*Session, error) {
	if sess, ok := s.sess[id]; ok {
		cp := *sess
		cp.Blocks = map[int]BlockInfo{}
		for k, v := range sess.Blocks {
			cp.Blocks[k] = v
		}
		return &cp, nil
	}
	return nil, fmt.Errorf("%w: session %s", ErrNotFound, id)
}

var _ = errors.Is
