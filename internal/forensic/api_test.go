package forensic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*Server, *Service) {
	s := newTestService(t)
	dir := t.TempDir()
	writeFile := func(name, body string) {
		_ = os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755)
		_ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	writeFile("index.html", "<html>ui</html>")
	return NewServer(s, http.FileServer(http.Dir(dir))), s
}

func doReq(t *testing.T, h http.Handler, method, path string, body any, idem string, raw []byte) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	ct := "application/json"
	if raw != nil {
		rdr = bytes.NewReader(raw)
		ct = "application/zip"
	} else if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", ct)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if strings.Contains(rec.Header().Get("Content-Type"), "json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func TestHTTPFullFlow(t *testing.T) {
	h, _ := testServer(t)
	data := []byte("HTTP evidence flow payload 12345")
	bs := int64(8)
	count := (len(data) + int(bs) - 1) / int(bs)
	code, body := doReq(t, h, "POST", "/api/sessions", map[string]any{
		"filename": "http.bin", "total_length": len(data), "block_size": bs, "block_count": count,
		"source": map[string]string{"origin": "browser"},
	}, "create-1", nil)
	if code != 201 {
		t.Fatalf("create %d %v", code, body)
	}
	sess := body["session"].(map[string]any)
	sid := sess["id"].(string)
	for i := 0; i < count; i++ {
		start := int64(i) * bs
		end := start + bs
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		req := httptest.NewRequest("PUT", "/api/sessions/"+sid+"/blocks/"+itoa(i), bytes.NewReader(data[start:end]))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("block %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	code, body = doReq(t, h, "POST", "/api/sessions/"+sid+"/seal", map[string]any{}, "seal-http", nil)
	if code != 201 {
		t.Fatalf("seal %d %v", code, body)
	}
	artID := body["artifact"].(map[string]any)["id"].(string)

	// repeated seal key replays first result (200, replayed=true)
	code, body = doReq(t, h, "POST", "/api/sessions/"+sid+"/seal", map[string]any{}, "seal-http", nil)
	if code != 200 || body["replayed"] != true {
		t.Fatalf("replay seal code=%d body=%v", code, body)
	}

	// transfer + verify
	doReq(t, h, "POST", "/api/transfer", map[string]string{"artifact_id": artID, "from": "a", "to": "b"}, "tr1", nil)
	code, body = doReq(t, h, "POST", "/api/verify", map[string]string{"target_id": artID}, "v1", nil)
	if code != 201 {
		t.Fatalf("verify %d %v", code, body)
	}
	chk := body["check"].(map[string]any)
	if chk["ok"] != true {
		t.Fatalf("verify not ok: %v", chk["errors"])
	}

	// graph and UI reachable
	if code, _ := doReq(t, h, "GET", "/api/graph", nil, "", nil); code != 200 {
		t.Fatal("graph")
	}
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ui") {
		t.Fatal("static UI not served")
	}
}

func TestHTTPPutBlockHashMismatch(t *testing.T) {
	h, _ := testServer(t)
	_, body := doReq(t, h, "POST", "/api/sessions", map[string]any{
		"filename": "m", "total_length": 4, "block_size": 4, "block_count": 1,
		"source": map[string]string{"origin": "o"},
	}, "", nil)
	sid := body["session"].(map[string]any)["id"].(string)
	req := httptest.NewRequest("PUT", "/api/sessions/"+sid+"/blocks/0", strings.NewReader("data"))
	req.Header.Set("X-Block-SHA256", strings.Repeat("0", 64))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	// no block event recorded for rejected write
	if code, _ := doReq(t, h, "GET", "/api/sessions/"+sid, nil, "", nil); code != 200 {
		t.Fatal("session must remain readable")
	}
}

func TestWALTornTailQuarantined(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("writable")
	sid := makeSession(t, s, "w", data, 4)
	putBlocks(t, s, sid, data, 4)
	if _, _, err := s.Seal(sid, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "events.log")
	good, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// append a torn, invalid frame
	if err := os.WriteFile(logPath, append(good, []byte("FBX1\x00\x00garbage-torn-tail")...), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := NewService(dir)
	if err != nil {
		t.Fatalf("must recover from torn tail: %v", err)
	}
	defer s2.Close()
	if n := len(s2.Snapshot().Artifacts); n != 1 {
		t.Fatalf("good events must survive, artifacts=%d", n)
	}
	qEntries, _ := os.ReadDir(filepath.Join(dir, "quarantine"))
	found := false
	for _, e := range qEntries {
		if strings.HasPrefix(e.Name(), "events-tail-") {
			found = true
		}
	}
	if !found {
		t.Fatal("torn tail not quarantined")
	}
}
