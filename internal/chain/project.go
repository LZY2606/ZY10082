package chain

import "fmt"

func ApplyEvents(state *State, events []Event) error {
	for _, event := range events {
		if err := ApplyEvent(state, event); err != nil {
			return err
		}
	}
	return nil
}

func ApplyEvent(state *State, event Event) error {
	if _, exists := state.eventsByID[event.ID]; exists {
		return nil
	}
	state.eventsByID[event.ID] = struct{}{}

	switch event.Type {
	case EvtDirectRegistered:
		payload, err := payloadOf[DirectEvidencePayload](event)
		if err != nil {
			return err
		}
		addNode(state, payload.Node)

	case EvtBatchCreated:
		payload, err := payloadOf[BatchCreatedPayload](event)
		if err != nil {
			return err
		}
		batch := payload.Batch
		state.Batches = append(state.Batches, batch)
		state.batches[batch.ID] = batch

	case EvtBlockWritten:
		payload, err := payloadOf[BlockWrittenPayload](event)
		if err != nil {
			return err
		}
		batch, ok := state.batches[payload.BatchID]
		if !ok {
			return fmt.Errorf("missing batch %s", payload.BatchID)
		}
		batch.Blocks = append(batch.Blocks, payload.Block)
		batch.UpdatedAt = payload.Block.ReceivedAt
		state.batches[payload.BatchID] = batch
		updateBatchSlice(state, batch)

	case EvtBatchSealed, EvtRecoverySealed:
		payload, err := payloadOf[BatchSealedPayload](event)
		if err != nil {
			return err
		}
		if _, ok := state.batches[payload.Batch.ID]; ok {
			updateBatchSlice(state, payload.Batch)
		} else {
			state.Batches = append(state.Batches, payload.Batch)
		}
		state.batches[payload.Batch.ID] = payload.Batch
		addNode(state, payload.Node)

	case EvtBatchRejected, EvtRecoveryQuarantined:
		payload, err := payloadOf[BatchRejectedPayload](event)
		if err != nil {
			return err
		}
		batch, ok := state.batches[payload.BatchID]
		if !ok {
			return fmt.Errorf("missing batch %s", payload.BatchID)
		}
		batch.Status = payload.Status
		batch.Error = payload.Error
		batch.QuarantinePath = payload.QuarantinePath
		batch.UpdatedAt = payload.At
		state.batches[payload.BatchID] = batch
		updateBatchSlice(state, batch)

	case EvtDerivedCreated, EvtTransferCreated:
		if event.Type == EvtDerivedCreated {
			payload, err := payloadOf[DerivedPayload](event)
			if err != nil {
				return err
			}
			addNode(state, payload.Node)
			addEdge(state, payload.Edge)
		} else {
			payload, err := payloadOf[TransferPayload](event)
			if err != nil {
				return err
			}
			addNode(state, payload.Node)
			addEdge(state, payload.Edge)
		}

	case EvtVerification:
		payload, err := payloadOf[VerificationPayload](event)
		if err != nil {
			return err
		}
		state.Verifications = append(state.Verifications, payload.Verification)

	case EvtClockAdjusted:
		payload, err := payloadOf[ClockPayload](event)
		if err != nil {
			return err
		}
		state.ClockAdjustments = append(state.ClockAdjustments, payload.Adjustment)
		state.ClockOffsetNanos = payload.Adjustment.OffsetNanos

	case EvtExportCreated:
		payload, err := payloadOf[ExportPayload](event)
		if err != nil {
			return err
		}
		state.Exports = append(state.Exports, payload.Export)

	case EvtImportRegistered:
		payload, err := payloadOf[ImportPayload](event)
		if err != nil {
			return err
		}
		for _, node := range payload.Nodes {
			addNode(state, node)
		}
		for _, edge := range payload.Edges {
			addEdge(state, edge)
		}
		state.Imports = append(state.Imports, payload.Import)
		state.imports[payload.Import.Fingerprint] = payload.Import

	case EvtImportReplayed:
		payload, err := payloadOf[ReplayPayload](event)
		if err != nil {
			return err
		}
		state.Imports = append(state.Imports, payload.Import)

	case EvtRecoveryMarked:
		payload, err := payloadOf[RecoveryMarkedPayload](event)
		if err != nil {
			return err
		}
		batch, ok := state.batches[payload.BatchID]
		if !ok {
			return fmt.Errorf("missing batch %s", payload.BatchID)
		}
		batch.Status = StatusRecovering
		batch.UpdatedAt = payload.At
		state.batches[payload.BatchID] = batch
		updateBatchSlice(state, batch)

	case EvtIdempotentOutcome:
		payload, err := payloadOf[IdempotencyPayload](event)
		if err != nil {
			return err
		}
		state.idempotency[payload.Record.Key] = payload.Record

	default:
		return fmt.Errorf("unknown event type %s", event.Type)
	}
	return nil
}

func addNode(state *State, node Node) {
	if _, exists := state.nodes[node.ID]; exists {
		return
	}
	state.nodes[node.ID] = node
	state.Nodes = append(state.Nodes, node)
}

func addEdge(state *State, edge Edge) {
	for _, existing := range state.Edges {
		if existing == edge {
			return
		}
	}
	state.Edges = append(state.Edges, edge)
}

func updateBatchSlice(state *State, batch Batch) {
	for index := range state.Batches {
		if state.Batches[index].ID == batch.ID {
			state.Batches[index] = batch
			return
		}
	}
	state.Batches = append(state.Batches, batch)
}

func (s *State) Counts() map[string]int {
	counts := map[string]int{
		"node_pending":         0,
		"node_accepted":        0,
		"node_rejected":        0,
		"node_recovering":      0,
		"batch_pending":        0,
		"batch_accepted":       0,
		"batch_rejected":       0,
		"batch_recovering":     0,
		"verification_success": 0,
		"verification_failure": 0,
		"imports":              len(s.Imports),
		"exports":              len(s.Exports),
	}
	for _, node := range s.Nodes {
		counts["node_"+node.Status]++
	}
	for _, batch := range s.Batches {
		counts["batch_"+batch.Status]++
	}
	for _, verification := range s.Verifications {
		if verification.OK {
			counts["verification_success"]++
		} else {
			counts["verification_failure"]++
		}
	}
	return counts
}

func (s *State) Node(id string) (Node, bool) {
	node, ok := s.nodes[id]
	return node, ok
}

func (s *State) Batch(id string) (Batch, bool) {
	batch, ok := s.batches[id]
	if !ok {
		return Batch{}, false
	}
	return batch, true
}

func (s *State) Idempotency(key string) (IdempotencyRecord, bool) {
	record, ok := stateLookup(s, key)
	return record, ok
}

func stateLookup(state *State, key string) (IdempotencyRecord, bool) {
	record, ok := state.idempotency[key]
	return record, ok
}

func (s *State) ImportByFingerprint(fingerprint string) (ImportRecord, bool) {
	record, ok := s.imports[fingerprint]
	return record, ok
}
