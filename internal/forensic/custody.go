package forensic

import (
	"fmt"
	"sort"
	"time"
)

// TransferInput is one custody handoff.
type TransferInput struct {
	ArtifactID string
	From       string
	To         string
	Reason     string
	IdemKey    string
}

// Transfer appends one handoff to the artifact's custody chain.
func (s *Service) Transfer(in TransferInput) (*CustodyEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.IdemKey != "" {
		if ref, ok := s.idem[in.IdemKey]; ok && ref.Kind == "transfer" {
			for i := range s.cust {
				if s.cust[i].ID == ref.ID {
					c := s.cust[i]
					return &c, true, nil
				}
			}
		}
	}
	if _, err := s.findArtifactLocked(in.ArtifactID); err != nil {
		return nil, false, err
	}
	if in.From == "" || in.To == "" {
		return nil, false, fmt.Errorf("%w: from and to required", ErrInvalidInput)
	}
	seq := 1
	for _, c := range s.cust {
		if c.ArtifactID == in.ArtifactID && c.Seq >= seq {
			seq = c.Seq + 1
		}
	}
	ce := CustodyEvent{
		ID:         newID("ctx"),
		ArtifactID: in.ArtifactID,
		Seq:        seq,
		From:       in.From,
		To:         in.To,
		Reason:     in.Reason,
		IdemKey:    in.IdemKey,
		Time:       s.now(),
	}
	if _, err := s.emit("transfer", in.IdemKey, pTransfer{Custody: ce}); err != nil {
		return nil, false, err
	}
	if in.IdemKey != "" {
		s.idem[in.IdemKey] = idemRef{Kind: "transfer", ID: ce.ID}
	}
	out := ce
	return &out, false, nil
}

// CorrectClock records a clock correction as a standalone fact. Historical
// event times are never rewritten.
func (s *Service) CorrectClock(oldOffset, newOffset, reason, idemKey string) (*ClockFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idemKey != "" {
		if ref, ok := s.idem[idemKey]; ok && ref.Kind == "clock" {
			for i := range s.clocks {
				if s.clocks[i].ID == ref.ID {
					c := s.clocks[i]
					return &c, true, nil
				}
			}
		}
	}
	if newOffset == "" {
		return nil, false, fmt.Errorf("%w: new_offset required", ErrInvalidInput)
	}
	f := ClockFact{
		ID:        newID("clk"),
		OldOffset: oldOffset,
		NewOffset: newOffset,
		Reason:    reason,
		Time:      s.now(),
	}
	if _, err := s.emit("clock_corrected", idemKey, pClock{Fact: f}); err != nil {
		return nil, false, err
	}
	if idemKey != "" {
		s.idem[idemKey] = idemRef{Kind: "clock", ID: f.ID}
	}
	out := f
	return &out, false, nil
}

var _ = sort.IntsAreSorted
var _ = time.Now
