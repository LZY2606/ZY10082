package forensic

import (
	"bytes"
	"fmt"
	"os"
)

// VerifyInput requests verification from the root evidence to target.
type VerifyInput struct {
	TargetID string
	IdemKey  string
}

// VerifyChain verifies the complete chain. Failures are persisted and never
// overwrite the previous (successful) record.
func (s *Service) VerifyChain(in VerifyInput) (*CheckRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.IdemKey != "" {
		if ref, ok := s.idem[in.IdemKey]; ok && ref.Kind == "check" {
			for i := range s.checks {
				if s.checks[i].ID == ref.ID {
					c := s.checks[i]
					return &c, true, nil
				}
			}
		}
	}
	target, err := s.findArtifactLocked(in.TargetID)
	if err != nil {
		return nil, false, err
	}
	rec := CheckRecord{ID: newID("chk"), TargetID: target.ID, Time: s.now(), IdemKey: in.IdemKey}

	// 1. Event log integrity: replay frames from disk and recompute chain hash.
	if onDisk, rErr := s.store.ReadEvents(); rErr != nil {
		rec.Errors = append(rec.Errors, "event log unreadable: "+rErr.Error())
	} else {
		rec.Steps = append(rec.Steps, fmt.Sprintf("event log frames readable (%d events)", len(onDisk)))
		if len(onDisk) != len(s.events) {
			rec.Errors = append(rec.Errors, fmt.Sprintf("event count mismatch disk=%d state=%d", len(onDisk), len(s.events)))
		}
		var prev string
		for _, ev := range onDisk {
			sum := sha256hex(ev.Preimage(prev))
			prev = sum
		}
		rec.Steps = append(rec.Steps, "event hash chain recomputed")
	}

	// 2. Walk target back to its root.
	cur := target
	for cur != nil {
		step, ok := s.verifyOneBlob(*cur)
		rec.Steps = append(rec.Steps, step)
		if !ok {
			rec.Errors = append(rec.Errors, "blob fingerprint mismatch: "+cur.ID)
		}
		if cur.DerivedFrom == nil {
			if cur.Kind != "root" && cur.Kind != "imported" {
				rec.Errors = append(rec.Errors, "non-root artifact lacks derivation link: "+cur.ID)
			}
			rec.Steps = append(rec.Steps, "reached root/imported evidence: "+cur.ID)
			// verify custody sequence for this artifact
			rec.Steps, rec.Errors = s.verifyCustody(cur.ID, rec.Steps, rec.Errors)
			break
		}
		parent, pErr := s.findArtifactLocked(cur.DerivedFrom.ParentID)
		if pErr != nil {
			rec.Errors = append(rec.Errors, "missing parent artifact: "+cur.DerivedFrom.ParentID)
			break
		}
		if dStep, dOK := s.recomputeDerivation(*cur, *parent); dOK {
			rec.Steps = append(rec.Steps, dStep)
		} else {
			rec.Errors = append(rec.Errors, "derivation not reproducible for "+cur.ID)
		}
		rec.Steps, rec.Errors = s.verifyCustody(cur.ID, rec.Steps, rec.Errors)
		cur = parent
	}

	rec.OK = len(rec.Errors) == 0
	if _, err := s.emit("chain_verified", in.IdemKey, pVerified{Check: rec}); err != nil {
		return nil, false, err
	}
	if in.IdemKey != "" {
		s.idem[in.IdemKey] = idemRef{Kind: "check", ID: rec.ID}
	}
	out := rec
	return &out, false, nil
}

func (s *Service) verifyOneBlob(a Artifact) (string, bool) {
	f, err := os.Open(blobPath(s.dir, a.Hashes))
	if err != nil {
		return "blob missing: " + a.ID, false
	}
	defer f.Close()
	got, n, err := HashReader(f)
	if err != nil {
		return "blob unreadable: " + a.ID, false
	}
	if n != a.Length || !hashesEqualIfSet(a.Hashes, got) {
		return "blob fingerprint mismatch: " + a.ID, false
	}
	return fmt.Sprintf("fingerprint verified: %s (%d bytes)", a.ID, n), true
}

func (s *Service) recomputeDerivation(child, parent Artifact) (string, bool) {
	d := child.DerivedFrom
	f, err := os.Open(blobPath(s.dir, parent.Hashes))
	if err != nil {
		return "", false
	}
	defer f.Close()
	rng := d.Tool.Range
	if rng == nil {
		rng = &ByteRange{Start: 0, End: parent.Length}
	}
	if _, err := f.Seek(rng.Start, 0); err != nil {
		return "", false
	}
	out, _, err := runTool(d.Tool.Name, d.Tool.Args, ioLimit(f, rng.End-rng.Start))
	if err != nil {
		return "", false
	}
	got := HashBytes(out)
	if got != child.Hashes || int64(len(out)) != child.Length {
		return "", false
	}
	return fmt.Sprintf("derivation reproduced: %s via %s %s", child.ID, d.Tool.Name, d.Tool.Version), true
}

func (s *Service) verifyCustody(artifactID string, steps, errs []string) ([]string, []string) {
	var seq []CustodyEvent
	for _, c := range s.cust {
		if c.ArtifactID == artifactID {
			seq = append(seq, c)
		}
	}
	if len(seq) == 0 {
		steps = append(steps, "no custody handoffs recorded: "+artifactID)
		return steps, errs
	}
	for i, c := range seq {
		if c.Seq != i+1 {
			errs = append(errs, fmt.Sprintf("custody sequence gap for %s at %d", artifactID, i+1))
		}
		if i > 0 && c.Time.Before(seq[i-1].Time) {
			errs = append(errs, fmt.Sprintf("custody time order violation for %s", artifactID))
		}
	}
	steps = append(steps, fmt.Sprintf("custody chain checked: %s (%d handoffs)", artifactID, len(seq)))
	return steps, errs
}

var _ = bytes.MinRead
