package chain

type DirectEvidencePayload struct {
	Node Node `json:"node"`
}

type BatchCreatedPayload struct {
	Batch Batch `json:"batch"`
}

type BlockWrittenPayload struct {
	BatchID string    `json:"batch_id"`
	Block   BlockInfo `json:"block"`
}

type BatchSealedPayload struct {
	Batch Batch `json:"batch"`
	Node  Node  `json:"node"`
}

type BatchRejectedPayload struct {
	BatchID        string `json:"batch_id"`
	Status         string `json:"status"`
	Error          string `json:"error"`
	QuarantinePath string `json:"quarantine_path,omitempty"`
	At             string `json:"at"`
}

type DerivedPayload struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

type TransferPayload struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

type VerificationPayload struct {
	Verification Verification `json:"verification"`
}

type ClockPayload struct {
	Adjustment ClockAdjustment `json:"adjustment"`
}

type ExportPayload struct {
	Export ExportRecord `json:"export"`
}

type ImportPayload struct {
	Import ImportRecord `json:"import"`
	Nodes  []Node       `json:"nodes"`
	Edges  []Edge       `json:"edges"`
}

type ReplayPayload struct {
	Import ImportRecord `json:"import"`
}

type RecoveryMarkedPayload struct {
	BatchID string `json:"batch_id"`
	At      string `json:"at"`
}

type IdempotencyPayload struct {
	Record IdempotencyRecord `json:"record"`
}
