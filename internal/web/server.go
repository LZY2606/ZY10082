package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"sync"

	"evidencechain/internal/chain"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	service  *chain.Service
	mux      *http.ServeMux
	keyLocks sync.Map
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func NewServer(service *chain.Service) *Server {
	server := &Server{service: service, mux: http.NewServeMux()}
	server.routes()
	return server
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/state", s.state)
	s.mux.HandleFunc("POST /api/evidence", s.registerDirect)
	s.mux.HandleFunc("POST /api/batches", s.createBatch)
	s.mux.HandleFunc("POST /api/batches/{id}/blocks", s.writeBlock)
	s.mux.HandleFunc("POST /api/batches/{id}/seal", s.seal)
	s.mux.HandleFunc("POST /api/batches/{id}/recover", s.recoverBatch)
	s.mux.HandleFunc("POST /api/derive", s.derive)
	s.mux.HandleFunc("POST /api/transfers", s.transfer)
	s.mux.HandleFunc("POST /api/verify/{id}", s.verify)
	s.mux.HandleFunc("GET /api/nodes/{id}/verifications", s.verifications)
	s.mux.HandleFunc("POST /api/clock-adjustments", s.clock)
	s.mux.HandleFunc("POST /api/exports", s.createExport)
	s.mux.HandleFunc("GET /api/exports/{id}/download", s.downloadExport)
	s.mux.HandleFunc("POST /api/imports", s.importPackage)

	assets, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("GET /", http.FileServerFS(assets))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.service.State())
}

func (s *Server) registerDirect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	result, err := s.run(w, r, "/api/evidence", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.RegisterDirect(chain.UploadInput{
			Filename:     r.FormValue("filename"),
			Source:       r.FormValue("source"),
			Notes:        r.FormValue("notes"),
			SparseRanges: parseRanges(r.FormValue("sparse_ranges")),
			Reader:       file,
		}, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) createBatch(w http.ResponseWriter, r *http.Request) {
	var input chain.CreateBatchInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.run(w, r, "/api/batches", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.CreateBatch(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) writeBlock(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	number, err := strconv.Atoi(r.FormValue("number"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	file, _, err := r.FormFile("block")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	batchID := r.PathValue("id")
	result, err := s.run(w, r, "/api/batches/block", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.WriteBlock(batchID, number, file, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) seal(w http.ResponseWriter, r *http.Request) {
	var input chain.SealInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	input.BatchID = r.PathValue("id")
	result, err := s.run(w, r, "/api/batches/seal", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.Seal(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusOK, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) recoverBatch(w http.ResponseWriter, r *http.Request) {
	var input chain.RecoveryInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	input.BatchID = r.PathValue("id")
	result, err := s.run(w, r, "/api/batches/recover", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.RecoverBatch(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusOK, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) derive(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	file, _, err := r.FormFile("output")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	start, length := parseOptionalRange(r.FormValue("input_start"), r.FormValue("input_length"))
	var parameters map[string]any
	if raw := r.FormValue("parameters"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &parameters); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	result, err := s.run(w, r, "/api/derive", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.CreateDerived(chain.DerivedInput{
			ParentID: r.FormValue("parent_id"), Operation: r.FormValue("operation"),
			Name: r.FormValue("name"), Parameters: parameters, InputStart: start,
			InputLength: length, Reader: file,
		}, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) transfer(w http.ResponseWriter, r *http.Request) {
	var input chain.TransferInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.run(w, r, "/api/transfers", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.CreateTransfer(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	result, err := s.run(w, r, "/api/verify", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.VerifyNode(r.PathValue("id"), record)
	})
	if err == nil {
		writeJSON(w, http.StatusOK, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) verifications(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"verifications": s.service.VerificationHistory(r.PathValue("id"))})
}

func (s *Server) clock(w http.ResponseWriter, r *http.Request) {
	var input chain.ClockInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.run(w, r, "/api/clock-adjustments", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.AdjustClock(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) createExport(w http.ResponseWriter, r *http.Request) {
	var input chain.ExportInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.run(w, r, "/api/exports", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.CreateExport(input, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request) {
	path, ok := s.service.ExportPath(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("export not found"))
		return
	}
	http.ServeFile(w, r, path)
}

func (s *Server) importPackage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	file, _, err := r.FormFile("package")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	result, err := s.run(w, r, "/api/imports", func(record *chain.IdempotencyRecord) (any, error) {
		return s.service.ImportPackage(file, record)
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, result)
	} else {
		writeHandlerError(w, r, err)
	}
}

type idempotentRunner func(*chain.IdempotencyRecord) (any, error)
