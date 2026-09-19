package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	EvtDirectRegistered    = "evidence.direct_registered"
	EvtBatchCreated        = "batch.created"
	EvtBlockWritten        = "batch.block_written"
	EvtBatchSealed         = "batch.sealed"
	EvtBatchRejected       = "batch.rejected"
	EvtDerivedCreated      = "evidence.derived"
	EvtTransferCreated     = "evidence.transferred"
	EvtVerification        = "evidence.verified"
	EvtClockAdjusted       = "clock.adjusted"
	EvtExportCreated       = "export.created"
	EvtImportReplayed      = "import.replayed"
	EvtImportRegistered    = "import.registered"
	EvtRecoveryMarked      = "recovery.marked"
	EvtRecoverySealed      = "recovery.sealed"
	EvtRecoveryQuarantined = "recovery.quarantined"
	EvtIdempotentOutcome   = "idempotency.outcome"
)

type Event struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	OccurredAt   string          `json:"occurred_at"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash string          `json:"previous_hash"`
	Hash         string          `json:"hash"`
}

func canonicalBytes(id, eventType string, occurredAt string, payload json.RawMessage, previousHash string) []byte {
	encoded, _ := json.Marshal(struct {
		ID           string          `json:"id"`
		Type         string          `json:"type"`
		OccurredAt   string          `json:"occurred_at"`
		Payload      json.RawMessage `json:"payload"`
		PreviousHash string          `json:"previous_hash"`
	}{id, eventType, occurredAt, payload, previousHash})
	return encoded
}

func eventHash(id, eventType string, occurredAt string, payload json.RawMessage, previousHash string) string {
	sum := sha256.Sum256(canonicalBytes(id, eventType, occurredAt, payload, previousHash))
	return hex.EncodeToString(sum[:])
}

func NewEvent(eventType string, occurredAt string, payload any, previousHash string) (Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("encode event payload: %w", err)
	}
	id := "evt_" + randomID()
	hash := eventHash(id, eventType, occurredAt, raw, previousHash)
	return Event{ID: id, Type: eventType, OccurredAt: occurredAt, Payload: raw, PreviousHash: previousHash, Hash: hash}, nil
}

func (e Event) Verify(previousHash string) error {
	if e.PreviousHash != previousHash {
		return fmt.Errorf("event %s has broken previous hash", e.ID)
	}
	if e.Hash != eventHash(e.ID, e.Type, e.OccurredAt, e.Payload, e.PreviousHash) {
		return fmt.Errorf("event %s hash mismatch", e.ID)
	}
	return nil
}

func payloadOf[T any](event Event) (T, error) {
	var payload T
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return payload, fmt.Errorf("decode %s: %w", event.ID, err)
	}
	return payload, nil
}

type EventBatch struct {
	Events  []Event
	Applied func(*State)
}
