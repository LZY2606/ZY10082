package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"forensicbox/internal/forensic"
)

//go:embed web/*
var webFS embed.FS

func main() {
	listen := flag.String("listen", "127.0.0.1:5212", "address to listen on")
	dataDir := flag.String("data", envOr("FORENSICBOX_DATA", "data"), "data directory")
	flag.Parse()

	absData, err := filepath.Abs(*dataDir)
	if err != nil {
		log.Fatalf("data dir: %v", err)
	}
	svc, err := forensic.NewService(absData)
	if err != nil {
		log.Fatalf("init service: %v", err)
	}
	defer svc.Close()

	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	srv := forensic.NewServer(svc, http.FileServer(http.FS(webRoot)))
	log.Printf("forensicbox listening on http://%s (data: %s)", *listen, absData)
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler()}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
