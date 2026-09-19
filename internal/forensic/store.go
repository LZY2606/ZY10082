package forensic

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Event is one immutable, append-only state transition.
type Event struct {
	Seq     int64           `json:"seq"`
	Type    string          `json:"type"`
	Time    string          `json:"time"` // RFC3339Nano, authoritative wall time
	IdemKey string          `json:"idem_key,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// Preimage returns the canonical bytes hashed to chain consecutive events.
func (e *Event) Preimage(prevHash string) []byte {
	return []byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		e.Seq, e.Type, e.Time, e.IdemKey, prevHash, string(e.Payload)))
}

var (
	// ErrNotFound indicates a referenced entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict indicates a state or hash conflict.
	ErrConflict = errors.New("conflict")
	// ErrInvalidInput indicates malformed request data.
	ErrInvalidInput = errors.New("invalid input")
	// ErrUnsafePath indicates a path escaping its target directory.
	ErrUnsafePath = errors.New("unsafe path")
)

// frame layout: magic(4) | seq(8 BE) | payloadLen(4 BE) | crc32(4 BE) | payload
var frameMagic = []byte("FBX1")

// Store is a durable append-only event log.
type Store struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	seq     int64
	dir     string
	quarDir string
}

// OpenStore opens (or creates) the WAL at dir/events.log.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "events.log")
	s := &Store{path: logPath, dir: dir, quarDir: filepath.Join(dir, "quarantine")}
	if err := os.MkdirAll(s.quarDir, 0o755); err != nil {
		return nil, err
	}
	if err := s.recoverTail(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	s.f = f
	return s, nil
}

// Close flushes and closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Sync()
	if cErr := s.f.Close(); cErr != nil && err == nil {
		err = cErr
	}
	s.f = nil
	return err
}

func (s *Store) readAll() (events []Event, validEnd int64, err error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var off int64
	hdr := make([]byte, 20)
	for {
		if _, rErr := io.ReadFull(f, hdr); rErr != nil {
			if errors.Is(rErr, io.EOF) || errors.Is(rErr, io.ErrUnexpectedEOF) {
				break
			}
			return nil, 0, rErr
		}
		magic := hdr[0:4]
		seq := int64(binary.BigEndian.Uint64(hdr[4:12]))
		pLen := int(binary.BigEndian.Uint32(hdr[12:16]))
		crc := binary.BigEndian.Uint32(hdr[16:20])
		if string(magic) != string(frameMagic) || pLen < 0 || pLen > 64*1024*1024 {
			return nil, off, fmt.Errorf("corrupt frame header at offset %d", off)
		}
		payload := make([]byte, pLen)
		if _, rErr := io.ReadFull(f, payload); rErr != nil {
			return nil, off, fmt.Errorf("truncated frame payload at offset %d: %w", off, rErr)
		}
		if crc32.ChecksumIEEE(payload) != crc {
			return nil, off, fmt.Errorf("crc mismatch at offset %d", off)
		}
		var ev Event
		if jErr := json.Unmarshal(payload, &ev); jErr != nil {
			return nil, off, fmt.Errorf("invalid event json at offset %d: %w", off, jErr)
		}
		if ev.Seq != seq {
			return nil, off, fmt.Errorf("seq mismatch at offset %d", off)
		}
		events = append(events, ev)
		off += 20 + int64(pLen)
	}
	return events, off, nil
}

// ReadEvents replays all durable events.
func (s *Store) ReadEvents() ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events, _, err := s.readAll()
	return events, err
}

// recoverTail truncates a torn final frame and quarantines it for inspection.
func (s *Store) recoverTail() error {
	events, validEnd, err := s.readAll()
	if errors.Is(err, os.ErrNotExist) {
		s.seq = 0
		return nil
	}
	if err == nil {
		if len(events) > 0 {
			s.seq = events[len(events)-1].Seq
		}
		return nil
	}
	info, statErr := os.Stat(s.path)
	if statErr != nil {
		return statErr
	}
	bad, rErr := os.ReadFile(s.path)
	if rErr != nil {
		return rErr
	}
	if len(bad) > int(validEnd) {
		qPath := filepath.Join(s.quarDir, fmt.Sprintf("events-tail-%d.log", info.ModTime().UnixNano()))
		if wErr := os.WriteFile(qPath, bad[validEnd:], 0o644); wErr != nil {
			return wErr
		}
	}
	if tErr := os.Truncate(s.path, validEnd); tErr != nil {
		return tErr
	}
	if len(events) > 0 {
		s.seq = events[len(events)-1].Seq
	}
	return nil
}

// Append durably writes one framed event and fsyncs it.
func (s *Store) Append(ev *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errors.New("store closed")
	}
	s.seq++
	ev.Seq = s.seq
	payload, err := json.Marshal(ev)
	if err != nil {
		s.seq--
		return err
	}
	hdr := make([]byte, 20)
	copy(hdr[0:4], frameMagic)
	binary.BigEndian.PutUint64(hdr[4:12], uint64(ev.Seq))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[16:20], crc32.ChecksumIEEE(payload))
	if _, err = s.f.Write(hdr); err != nil {
		return err
	}
	if _, err = s.f.Write(payload); err != nil {
		return err
	}
	if err = s.f.Sync(); err != nil {
		return err
	}
	return nil
}
