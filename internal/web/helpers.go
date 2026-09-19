package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"evidencechain/internal/chain"
)

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return chain.ValidationError("invalid JSON: " + err.Error())
	}
	return nil
}

func parseRanges(value string) []chain.Range {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var ranges []chain.Range
	if err := json.Unmarshal([]byte(value), &ranges); err != nil {
		return nil
	}
	return ranges
}

func parseOptionalRange(startValue, lengthValue string) (*int64, *int64) {
	var start *int64
	var length *int64
	if value := strings.TrimSpace(startValue); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			start = &parsed
		}
	}
	if value := strings.TrimSpace(lengthValue); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			length = &parsed
		}
	}
	return start, length
}

func writeHandlerError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errIdempotencyReplayed) {
		return
	}
	var validation chain.ValidationError
	if errors.As(err, &validation) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func (s *Server) run(w http.ResponseWriter, r *http.Request, route string, runner idempotentRunner) (any, error) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return runner(nil)
	}
	lockValue, _ := s.keyLocks.LoadOrStore(key, &sync.Mutex{})
	keyLock := lockValue.(*sync.Mutex)
	keyLock.Lock()
	defer keyLock.Unlock()

	existing, ok := s.service.IdempotencyLookup(key)
	if ok {
		if existing.Route != route {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "idempotency key already used by another route"})
			return nil, errIdempotencyReplayed
		}
		w.Header().Set("Content-Type", existing.ContentType)
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(existing.Status)
		_, _ = w.Write(existing.Body)
		return nil, errIdempotencyReplayed
	}

	record := &chain.IdempotencyRecord{
		Key: key, Route: route, Status: http.StatusOK,
		ContentType: "application/json; charset=utf-8",
	}
	if strings.HasSuffix(route, "/block") || route == "/api/evidence" || route == "/api/batches" ||
		route == "/api/derive" || route == "/api/transfers" || route == "/api/clock-adjustments" ||
		route == "/api/exports" || route == "/api/imports" {
		record.Status = http.StatusCreated
	}
	result, err := func() (any, error) {
		out, serviceErr := runner(record)
		if serviceErr != nil {
			var validation chain.ValidationError
			if errors.As(serviceErr, &validation) {
				record.Status = http.StatusBadRequest
				record.Body, _ = json.Marshal(map[string]string{"error": serviceErr.Error()})
				if recordErr := s.service.RecordIdempotency(*record); recordErr != nil {
					return nil, recordErr
				}
			}
		} else {
			record.Body, _ = json.Marshal(out)
		}
		return out, serviceErr
	}()
	if err != nil {
		return nil, err
	}
	return result, nil
}

var errIdempotencyReplayed = errors.New("idempotent response replayed")
