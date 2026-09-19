package chain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type EventStore struct {
	path string
	file *os.File
	last string
}

func OpenEventStore(dataDir string) (*EventStore, error) {
	if err := ensureDir(dataDir); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "events.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, err
	}
	store := &EventStore{path: path, file: file, last: ""}
	if err := store.file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return store, nil
}

func (s *EventStore) Path() string { return s.path }

func (s *EventStore) Read() ([]Event, error) {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	var events []Event
	previous := ""
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("corrupt event log: %w", err)
		}
		if err := event.Verify(previous); err != nil {
			return nil, err
		}
		previous = event.Hash
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if _, err := s.file.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	s.last = previous
	return events, nil
}

func (s *EventStore) AppendBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	previous := s.last
	writer := bufio.NewWriterSize(s.file, 1024*1024)
	for _, event := range events {
		if event.PreviousHash != previous {
			return fmt.Errorf("event %s is not linked to current tail", event.ID)
		}
		line, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return err
		}
		previous = event.Hash
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	s.last = previous
	return nil
}

func (s *EventStore) LastHash() string { return s.last }

func (s *EventStore) Close() error { return s.file.Close() }
