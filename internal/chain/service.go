package chain

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Faults struct {
	FailAppend bool
}

var ErrIdempotencyExists = ValidationError("idempotency key already exists")

type Service struct {
	mu      sync.Mutex
	dataDir string
	store   *EventStore
	state   *State
	faults  Faults
}

type UploadInput struct {
	Filename     string
	Source       string
	Notes        string
	SparseRanges []Range
	Reader       io.Reader
}

type UploadResult struct {
	Node Node `json:"node"`
}

type CreateBatchInput struct {
	Filename     string  `json:"filename"`
	Source       string  `json:"source"`
	Notes        string  `json:"notes"`
	SparseRanges []Range `json:"sparse_ranges"`
	TotalBlocks  int     `json:"total_blocks"`
}

type CreateBatchResult struct {
	Batch Batch `json:"batch"`
}

type BlockResult struct {
	Batch Batch     `json:"batch"`
	Block BlockInfo `json:"block"`
}

type SealInput struct {
	BatchID        string `json:"batch_id"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type SealResult struct {
	Batch Batch `json:"batch"`
	Node  *Node `json:"node,omitempty"`
}

type DerivedInput struct {
	ParentID    string         `json:"parent_id"`
	Operation   string         `json:"operation"`
	Name        string         `json:"name"`
	Parameters  map[string]any `json:"parameters"`
	InputStart  *int64         `json:"input_start"`
	InputLength *int64         `json:"input_length"`
	Reader      io.Reader      `json:"-"`
}

type DerivedResult struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

type TransferInput struct {
	ParentID  string `json:"parent_id"`
	FromParty string `json:"from_party"`
	ToParty   string `json:"to_party"`
	Purpose   string `json:"purpose"`
}

type TransferResult struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

type ClockInput struct {
	OffsetNanos int64  `json:"offset_nanos"`
	Reason      string `json:"reason"`
	Actor       string `json:"actor"`
}

type ClockResult struct {
	Adjustment ClockAdjustment `json:"adjustment"`
}

type RecoveryInput struct {
	BatchID string `json:"batch_id"`
	Action  string `json:"action"`
}

type RecoveryResult struct {
	Batch Batch `json:"batch"`
}

func Open(dataDir string) (*Service, error) {
	store, err := OpenEventStore(dataDir)
	if err != nil {
		return nil, err
	}
	events, err := store.Read()
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	state := NewState()
	if err := ApplyEvents(state, events); err != nil {
		_ = store.Close()
		return nil, err
	}
	for _, dir := range []string{"evidence", "derived", "staging", "quarantine", "imports", "exports"} {
		if err := ensureDir(filepath.Join(dataDir, dir)); err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	service := &Service{dataDir: dataDir, store: store, state: state}
	if err := service.recoverStaging(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return service, nil
}

func (s *Service) Close() error { return s.store.Close() }

func (s *Service) State() PublicState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Public()
}

func (s *Service) Batch(id string) (Batch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Batch(id)
}

func (s *Service) SetFaults(faults Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = faults
}

func (s *Service) IdempotencyLookup(key string) (IdempotencyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.idempotency[key]
	return record, ok
}

func (s *Service) RecordIdempotency(record IdempotencyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.idempotency[record.Key]; exists {
		return ErrIdempotencyExists
	}
	event, err := s.makeIdempotencyEvent(nil, record, nil)
	if err != nil {
		return err
	}
	return s.applyEvents(event)
}

func (s *Service) dataPath(parts ...string) string {
	return filepath.Join(append([]string{s.dataDir}, parts...)...)
}

func (s *Service) appendEvents(events ...Event) error {
	if s.faults.FailAppend {
		return os.ErrPermission
	}
	return s.store.AppendBatch(events)
}

func (s *Service) applyEvents(events ...Event) error {
	if err := s.appendEvents(events...); err != nil {
		return err
	}
	for _, event := range events {
		if err := ApplyEvent(s.state, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) makeEvent(eventType string, payload any) (Event, error) {
	return NewEvent(eventType, nowString(s.state.ClockOffsetNanos), payload, s.store.LastHash())
}

func (s *Service) commit(result any, idempotency *IdempotencyRecord, build func() ([]Event, error)) (any, error) {
	events, err := build()
	if err != nil {
		return nil, err
	}
	if idempotency != nil {
		idemEvent, err := s.makeIdempotencyEvent(events, *idempotency, result)
		if err != nil {
			return nil, err
		}
		events = append(events, idemEvent)
	}
	if err := s.applyEvents(events...); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) makeIdempotencyEvent(events []Event, record IdempotencyRecord, result any) (Event, error) {
	previous := s.store.LastHash()
	if len(events) > 0 {
		previous = events[len(events)-1].Hash
	}
	record.CreatedAt = nowString(s.state.ClockOffsetNanos)
	if len(record.Body) == 0 {
		body, err := json.Marshal(result)
		if err != nil {
			return Event{}, err
		}
		record.Body = body
	}
	return NewEvent(EvtIdempotentOutcome, record.CreatedAt, IdempotencyPayload{Record: record}, previous)
}

func validateRanges(ranges []Range, size int64) error {
	for _, item := range ranges {
		if item.Offset < 0 || item.Length < 0 || item.Offset+item.Length > size {
			return validationError("sparse range outside input bounds")
		}
	}
	return nil
}
