package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"evidencechain/internal/chain"
)

func newTestServer(t *testing.T) (*chain.Service, http.Handler) {
	t.Helper()
	service, err := chain.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, NewServer(service)
}

func multipartRequest(t *testing.T, path, fieldName, fileName string, content []byte, fields map[string]string, idemKey string) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for key, value := range fields {
		_ = writer.WriteField(key, value)
	}
	file, err := writer.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	if idemKey != "" {
		request.Header.Set("Idempotency-Key", idemKey)
	}
	return request
}

func decodeBody[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode %d: %v: %s", response.Code, err, response.Body.String())
	}
	return value
}

func TestHTTPPersistedIdempotentUpload(t *testing.T) {
	service, handler := newTestServer(t)
	request := func() *http.Request {
		return multipartRequest(t, "/api/evidence", "file", "a.bin", []byte("idem-bytes"), map[string]string{
			"source": "source-a", "notes": "note",
		}, "idem-upload")
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusCreated {
		t.Fatalf("first status %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeBody[struct {
		Node chain.Node `json:"node"`
	}](t, first)

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusCreated || second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay status=%d header=%q body=%s", second.Code, second.Header().Get("Idempotent-Replayed"), second.Body.String())
	}
	secondBody := decodeBody[struct {
		Node chain.Node `json:"node"`
	}](t, second)
	if firstBody.Node.ID != secondBody.Node.ID || service.State().Counts["node_accepted"] != 1 {
		t.Fatal("repeated idempotency key created new custody event")
	}

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPIdempotentValidationFailureReplays(t *testing.T) {
	_, handler := newTestServer(t)
	request := func() *http.Request {
		return multipartRequest(t, "/api/evidence", "file", "bad.bin", []byte("x"), map[string]string{
			"source": "",
		}, "idem-bad")
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusBadRequest || strings.Contains(first.Body.String(), "Idempotent") {
		t.Fatalf("first = %d %s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusBadRequest || second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("second = %d header=%q body=%s", second.Code, second.Header().Get("Idempotent-Replayed"), second.Body.String())
	}
	if strings.TrimSpace(first.Body.String()) != strings.TrimSpace(second.Body.String()) {
		t.Fatalf("bodies differ: %s vs %s", first.Body.String(), second.Body.String())
	}
}

func TestHTTPPendingAcceptedRejectedAndRecoveryStatuses(t *testing.T) {
	_, handler := newTestServer(t)

	createRecorder := httptest.NewRecorder()
	handler.ServeHTTP(createRecorder, jsonRequest(t, http.MethodPost, "/api/batches", chain.CreateBatchInput{
		Filename: "disk.img", Source: "source", TotalBlocks: 2,
	}, ""))
	created := decodeBody[struct{ Batch chain.Batch }](t, createRecorder)

	block := multipartRequest(t, "/api/batches/"+created.Batch.ID+"/blocks", "block", "block-1", []byte("ab"), map[string]string{"number": "1"}, "")
	blockRecorder := httptest.NewRecorder()
	handler.ServeHTTP(blockRecorder, block)
	if blockRecorder.Code != http.StatusCreated {
		t.Fatal(blockRecorder.Body.String())
	}

	state := getState(t, handler)
	if state.Counts["batch_pending"] != 1 {
		t.Fatalf("pending count = %d", state.Counts["batch_pending"])
	}

	badSeal := httptest.NewRecorder()
	handler.ServeHTTP(badSeal, jsonRequest(t, http.MethodPost, "/api/batches/"+created.Batch.ID+"/seal", chain.SealInput{
		BatchID: created.Batch.ID, ExpectedSHA256: "00",
	}, ""))
	if badSeal.Code != http.StatusBadRequest {
		t.Fatalf("bad seal status = %d body=%s", badSeal.Code, badSeal.Body.String())
	}

	secondBlock := multipartRequest(t, "/api/batches/"+created.Batch.ID+"/blocks", "block", "block-2", []byte("cd"), map[string]string{"number": "2"}, "")
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, secondBlock)

	rejectSeal := httptest.NewRecorder()
	handler.ServeHTTP(rejectSeal, jsonRequest(t, http.MethodPost, "/api/batches/"+created.Batch.ID+"/seal", chain.SealInput{
		BatchID: created.Batch.ID, ExpectedSHA256: strings.Repeat("0", 64),
	}, ""))
	if rejectSeal.Code != http.StatusOK {
		t.Fatalf("reject seal status = %d body=%s", rejectSeal.Code, rejectSeal.Body.String())
	}
	state = getState(t, handler)
	if state.Counts["batch_rejected"] != 1 || state.Counts["batch_pending"] != 0 {
		t.Fatalf("statuses after rejection = %+v", state.Counts)
	}
}

func TestHTTPClockAndStaticPage(t *testing.T) {
	_, handler := newTestServer(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, jsonRequest(t, http.MethodPost, "/api/clock-adjustments", chain.ClockInput{
		OffsetNanos: 1000, Reason: "test correction",
	}, "clk-1"))
	if recorder.Code != http.StatusCreated {
		t.Fatal(recorder.Body.String())
	}
	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if home.Code != http.StatusOK || !strings.Contains(home.Body.String(), "本地证据保管链") {
		t.Fatalf("static page failed: %d", home.Code)
	}
}

func jsonRequest(t *testing.T, method, path string, body any, idemKey string) *http.Request {
	t.Helper()
	data, _ := json.Marshal(body)
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if idemKey != "" {
		request.Header.Set("Idempotency-Key", idemKey)
	}
	return request
}

func getState(t *testing.T, handler http.Handler) chain.PublicState {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	return decodeBody[chain.PublicState](t, recorder)
}
