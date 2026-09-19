package main

import (
	"flag"
	"log"
	"net/http"

	"evidencechain/internal/chain"
	"evidencechain/internal/web"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5212", "HTTP listen address")
	dataDir := flag.String("data", ".evidence-data", "persistent data directory")
	flag.Parse()

	service, err := chain.Open(*dataDir)
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	defer service.Close()

	server := &http.Server{Addr: *listen, Handler: web.NewServer(service)}
	log.Printf("evidence chain listening on http://%s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
