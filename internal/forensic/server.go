package forensic

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Server wires the service to an HTTP API.
type Server struct {
	svc *Service
	mux *http.ServeMux
}

// NewServer builds API routes and serves the web UI via webHandler.
func NewServer(svc *Service, webHandler http.Handler) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	m := s.mux
	m.HandleFunc("GET /api/state", s.handleState)
	m.HandleFunc("GET /api/events", s.handleEvents)
	m.HandleFunc("GET /api/graph", s.handleGraph)
	m.HandleFunc("POST /api/sessions", s.handleCreateSession)
	m.HandleFunc("GET /api/sessions/{id}", s.handleGetSession)
	m.HandleFunc("PUT /api/sessions/{id}/blocks/{index}", s.handlePutBlock)
	m.HandleFunc("POST /api/sessions/{id}/seal", s.handleSeal)
	m.HandleFunc("POST /api/sessions/{id}/quarantine", s.handleQuarantine)
	m.HandleFunc("GET /api/artifacts/{id}", s.handleGetArtifact)
	m.HandleFunc("GET /api/artifacts/{id}/blob", s.handleBlob)
	m.HandleFunc("POST /api/derive", s.handleDerive)
	m.HandleFunc("POST /api/transfer", s.handleTransfer)
	m.HandleFunc("POST /api/verify", s.handleVerify)
	m.HandleFunc("GET /api/checks/{id}", s.handleGetCheck)
	m.HandleFunc("POST /api/clock", s.handleClock)
	m.HandleFunc("POST /api/export", s.handleExport)
	m.HandleFunc("GET /api/packages/{id}/download", s.handlePackageDownload)
	m.HandleFunc("POST /api/import", s.handleImport)
	m.Handle("/", webHandler)
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func idemKey(r *http.Request) string { return r.Header.Get("Idempotency-Key") }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrUnsafePath):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024*1024))
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return false
	}
	return true
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.svc.Snapshot())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	st := s.svc.Snapshot()
	writeJSON(w, 200, map[string]any{"events": st.Events})
}

type createSessionReq struct {
	Filename    string  `json:"filename"`
	TotalLength int64   `json:"total_length"`
	BlockSize   int64   `json:"block_size"`
	BlockCount  int     `json:"block_count"`
	Expected    *Hashes `json:"expected"`
	Source      Source  `json:"source"`
	Env         EnvInfo `json:"env"`
	Note        string  `json:"note"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionReq
	if !decode(w, r, &req) {
		return
	}
	sess, replayed, err := s.svc.CreateSession(CreateSessionInput{
		Filename:    req.Filename,
		TotalLength: req.TotalLength,
		BlockSize:   req.BlockSize,
		BlockCount:  req.BlockCount,
		Expected:    req.Expected,
		Source:      req.Source,
		Env:         req.Env,
		Note:        req.Note,
		IdemKey:     idemKey(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"session": sess, "replayed": replayed})
}

func status(replayed bool) int {
	if replayed {
		return http.StatusOK
	}
	return http.StatusCreated
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, err := s.svc.GetSession(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, sess)
}

func (s *Server) handlePutBlock(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad block index"})
		return
	}
	var ch *Hashes
	if v := r.Header.Get("X-Block-SHA256"); v != "" {
		ch = &Hashes{SHA256: v, SHA512: r.Header.Get("X-Block-SHA512"), SHA1: r.Header.Get("X-Block-SHA1")}
	}
	res, err := s.svc.PutBlock(r.PathValue("id"), index, r.Body, ch)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

type sealReq struct {
	Expected *Hashes `json:"expected"`
}

func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	var req sealReq
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
	}
	art, replayed, err := s.svc.Seal(r.PathValue("id"), req.Expected, idemKey(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"artifact": art, "replayed": replayed})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.svc.Quarantine(r.PathValue("id"), req.Reason); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"quarantined": true})
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	_, art, err := s.svc.OpenBlob(r.PathValue("id"))
	if err != nil {
		// return metadata even if blob missing: state stays readable
		st := s.svc.Snapshot()
		for i := range st.Artifacts {
			if st.Artifacts[i].ID == r.PathValue("id") {
				writeJSON(w, 200, st.Artifacts[i])
				return
			}
		}
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, art)
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request) {
	f, art, err := s.svc.OpenBlob(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(art.Length, 10))
	w.Header().Set("Content-Disposition", contentDisposition(art.Filename))
	_, _ = io.Copy(w, f)
}

func contentDisposition(filename string) string {
	filename = strings.NewReplacer("\\", "_", "\"", "_", "\r", "_", "\n", "_").Replace(filename)
	return `attachment; filename="` + filename + `"`
}

type deriveReq struct {
	ParentID string `json:"parent_id"`
	Tool     string `json:"tool"`
	Args     string `json:"args"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
}

func (s *Server) handleDerive(w http.ResponseWriter, r *http.Request) {
	var req deriveReq
	if !decode(w, r, &req) {
		return
	}
	art, replayed, err := s.svc.Derive(DeriveInput{
		ParentID: req.ParentID, Tool: req.Tool, Args: req.Args,
		Start: req.Start, End: req.End, IdemKey: idemKey(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"artifact": art, "replayed": replayed})
}

type transferReq struct {
	ArtifactID string `json:"artifact_id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Reason     string `json:"reason"`
}

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	var req transferReq
	if !decode(w, r, &req) {
		return
	}
	c, replayed, err := s.svc.Transfer(TransferInput{
		ArtifactID: req.ArtifactID, From: req.From, To: req.To, Reason: req.Reason, IdemKey: idemKey(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"custody": c, "replayed": replayed})
}

type verifyReq struct {
	TargetID string `json:"target_id"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !decode(w, r, &req) {
		return
	}
	rec, replayed, err := s.svc.VerifyChain(VerifyInput{TargetID: req.TargetID, IdemKey: idemKey(r)})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"check": rec, "replayed": replayed})
}

func (s *Server) handleGetCheck(w http.ResponseWriter, r *http.Request) {
	st := s.svc.Snapshot()
	for i := range st.Checks {
		if st.Checks[i].ID == r.PathValue("id") {
			writeJSON(w, 200, st.Checks[i])
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "check not found"})
}

type clockReq struct {
	OldOffset string `json:"old_offset"`
	NewOffset string `json:"new_offset"`
	Reason    string `json:"reason"`
}

func (s *Server) handleClock(w http.ResponseWriter, r *http.Request) {
	var req clockReq
	if !decode(w, r, &req) {
		return
	}
	f, replayed, err := s.svc.CorrectClock(req.OldOffset, req.NewOffset, req.Reason, idemKey(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(replayed), map[string]any{"clock_fact": f, "replayed": replayed})
}

type exportReq struct {
	ArtifactIDs []string `json:"artifact_ids"`
	WithDerived bool     `json:"with_derived"`
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req exportReq
	if !decode(w, r, &req) {
		return
	}
	data, rec, replayed, err := s.svc.Export(req.ArtifactIDs, req.WithDerived, idemKey(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("X-Package-Id", rec.PackageID)
	w.Header().Set("X-Content-Hash", rec.ContentHash)
	w.Header().Set("X-Replayed", strconv.FormatBool(replayed))
	w.Header().Set("Content-Disposition", `attachment; filename="`+rec.PackageID+`.fbx.zip"`)
	_, _ = w.Write(data)
}

func (s *Server) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	st := s.svc.Snapshot()
	for _, p := range st.Packages {
		if p.PackageID == r.PathValue("id") && p.Direction == "export" {
			data, err := readPackageFile(s.svc, p.PackageID)
			if err != nil {
				writeErr(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="`+p.PackageID+`.fbx.zip"`)
			_, _ = w.Write(data)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "package not found"})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.svc.Import(data, idemKey(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, status(!res.Replayed), res)
}
