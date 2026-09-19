package chain

import (
	"fmt"
	"os"
)

type VerifyResult struct {
	Verification Verification `json:"verification"`
}

func (s *Service) VerifyNode(nodeID string, idempotency *IdempotencyRecord) (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.state.nodes[nodeID]
	if !ok {
		return VerifyResult{}, validationError("unknown node")
	}
	path, err := s.verifyChainLocked(node)
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	verification := Verification{
		ID: newID("vrf"), NodeID: nodeID, OK: err == nil, Path: path,
		Detail: detail, CreatedAt: nowString(s.state.ClockOffsetNanos), PackageID: node.PackageID,
	}
	result := VerifyResult{Verification: verification}
	committed, commitErr := s.commit(result, idempotency, func() ([]Event, error) {
		event, err := s.makeEvent(EvtVerification, VerificationPayload{Verification: verification})
		if err != nil {
			return nil, err
		}
		verification.EventID = event.ID
		return rebuildEvent(event, EvtVerification, VerificationPayload{Verification: verification})
	})
	if commitErr != nil {
		return VerifyResult{}, commitErr
	}
	return committed.(VerifyResult), nil
}

func (s *Service) verifyChainLocked(target Node) ([]string, error) {
	path := []string{target.ID}
	current := target
	for {
		if current.Status != StatusAccepted {
			return path, validationError("node %s has status %s", current.ID, current.Status)
		}
		if err := s.verifyStoredNodeLocked(current); err != nil {
			return path, err
		}
		if current.ParentID == "" {
			if current.Kind != NodeEvidence {
				return path, validationError("root node %s is not evidence", current.ID)
			}
			return path, nil
		}
		parent, ok := s.state.nodes[current.ParentID]
		if !ok {
			return path, validationError("missing parent %s", current.ParentID)
		}
		if !edgeExists(s.state, parent.ID, current.ID) {
			return path, validationError("missing custody edge %s -> %s", parent.ID, current.ID)
		}
		if current.Kind == NodeTransfer {
			if current.Hashes != parent.Hashes || current.Size != parent.Size {
				return path, validationError("transfer node fingerprint differs from parent")
			}
		}
		path = append([]string{parent.ID}, path...)
		current = parent
	}
}

func (s *Service) verifyStoredNodeLocked(node Node) error {
	if node.Kind == NodeTransfer {
		return nil
	}
	if node.BlobPath == "" {
		return validationError("node %s has no stored blob", node.ID)
	}
	if node.PackageID != "" {
		blobPath := s.dataPath(node.BlobPath)
		hashes, size, err := hashFile(blobPath)
		if err != nil {
			return fmt.Errorf("imported blob unreadable: %w", err)
		}
		if hashes != node.Hashes || size != node.Size {
			return validationError("imported blob hash mismatch")
		}
		return nil
	}
	hashes, size, err := hashFile(s.dataPath(node.BlobPath))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("stored blob missing: %s", node.BlobPath)
		}
		return err
	}
	if hashes != node.Hashes || size != node.Size {
		return validationError("stored blob hash mismatch for %s", node.ID)
	}
	return nil
}

func edgeExists(state *State, from, to string) bool {
	for _, edge := range state.Edges {
		if edge.From == from && edge.To == to {
			return true
		}
	}
	return false
}

func (s *State) VerificationsForNode(nodeID string) []Verification {
	var values []Verification
	for _, verification := range s.Verifications {
		if verification.NodeID == nodeID {
			values = append(values, verification)
		}
	}
	return values
}

func (s *Service) VerificationHistory(nodeID string) []Verification {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.VerificationsForNode(nodeID)
}

func (s *Service) LastSuccessfulVerification(nodeID string) *Verification {
	history := s.VerificationHistory(nodeID)
	for index := len(history) - 1; index >= 0; index-- {
		if history[index].OK {
			value := history[index]
			return &value
		}
	}
	return nil
}
