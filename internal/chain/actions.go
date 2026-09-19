package chain

import (
	"os"
	"path/filepath"
)

func (s *Service) CreateDerived(input DerivedInput, idempotency *IdempotencyRecord) (DerivedResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parent, ok := s.state.nodes[input.ParentID]
	if !ok {
		return DerivedResult{}, validationError("unknown parent node")
	}
	if parent.Status != StatusAccepted {
		return DerivedResult{}, validationError("parent node is not accepted")
	}
	if input.Operation == "" || safeName(input.Name) == "unnamed" || input.Reader == nil {
		return DerivedResult{}, validationError("operation, name and output are required")
	}
	if input.InputStart != nil && *input.InputStart < 0 {
		return DerivedResult{}, validationError("input_start cannot be negative")
	}
	if input.InputLength != nil && *input.InputLength < 0 {
		return DerivedResult{}, validationError("input_length cannot be negative")
	}
	id := newID("der")
	destination := s.dataPath("derived", id+".bin")
	hashes, size, err := writeStreaming(destination, input.Reader)
	if err != nil {
		os.Remove(destination)
		return DerivedResult{}, err
	}
	node := Node{
		ID: id, OriginalID: "", Kind: NodeDerived, Status: StatusAccepted, Name: safeName(input.Name),
		ParentID: parent.ID, Size: size, Hashes: hashes, Operation: input.Operation,
		ToolName: toolName(input.Operation), ToolVersion: toolVersion(input.Operation),
		Parameters: input.Parameters, InputStart: input.InputStart, InputLength: input.InputLength,
		CreatedAt: nowString(s.state.ClockOffsetNanos), BlobPath: filepath.Join("derived", id+".bin"),
	}
	edge := Edge{From: parent.ID, To: id, Type: "derived"}
	result := DerivedResult{Node: node, Edge: edge}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtDerivedCreated, DerivedPayload{Node: node, Edge: edge})
		if err != nil {
			return nil, err
		}
		node.EventID = event.ID
		return rebuildEvent(event, EvtDerivedCreated, DerivedPayload{Node: node, Edge: edge})
	})
	if err != nil {
		os.Remove(destination)
		return DerivedResult{}, err
	}
	return committed.(DerivedResult), nil
}

func (s *Service) CreateTransfer(input TransferInput, idempotency *IdempotencyRecord) (TransferResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parent, ok := s.state.nodes[input.ParentID]
	if !ok {
		return TransferResult{}, validationError("unknown parent node")
	}
	if parent.Status != StatusAccepted {
		return TransferResult{}, validationError("parent node is not accepted")
	}
	if input.FromParty == "" || input.ToParty == "" || input.Purpose == "" {
		return TransferResult{}, validationError("from_party, to_party and purpose are required")
	}
	id := newID("xfer")
	at := nowString(s.state.ClockOffsetNanos)
	node := Node{
		ID: id, Kind: NodeTransfer, Status: StatusAccepted, Name: "transfer-" + safeName(parent.Name),
		ParentID: parent.ID, Source: parent.Source, Size: parent.Size, Hashes: parent.Hashes,
		SparseRanges: append([]Range(nil), parent.SparseRanges...), FromParty: input.FromParty,
		ToParty: input.ToParty, Purpose: input.Purpose, CreatedAt: at, BlobPath: parent.BlobPath,
	}
	edge := Edge{From: parent.ID, To: id, Type: "transfer"}
	result := TransferResult{Node: node, Edge: edge}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtTransferCreated, TransferPayload{Node: node, Edge: edge})
		if err != nil {
			return nil, err
		}
		node.EventID = event.ID
		return rebuildEvent(event, EvtTransferCreated, TransferPayload{Node: node, Edge: edge})
	})
	if err != nil {
		return TransferResult{}, err
	}
	return committed.(TransferResult), nil
}

func (s *Service) AdjustClock(input ClockInput, idempotency *IdempotencyRecord) (ClockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if input.Reason == "" {
		return ClockResult{}, validationError("reason is required")
	}
	adjustment := ClockAdjustment{
		ID: newID("clk"), RecordedAt: nowString(s.state.ClockOffsetNanos),
		CorrectedAt: nowString(input.OffsetNanos), OffsetNanos: input.OffsetNanos,
		Reason: input.Reason, Actor: input.Actor,
	}
	result := ClockResult{Adjustment: adjustment}
	committed, err := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtClockAdjusted, ClockPayload{Adjustment: adjustment})
		if err != nil {
			return nil, err
		}
		adjustment.EventID = event.ID
		return rebuildEvent(event, EvtClockAdjusted, ClockPayload{Adjustment: adjustment})
	})
	if err != nil {
		return ClockResult{}, err
	}
	return committed.(ClockResult), nil
}

func toolName(operation string) string { return "evidencechain-builtin" }

func toolVersion(operation string) string { return "1.0.0" }
