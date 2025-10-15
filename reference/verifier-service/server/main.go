// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package provides a reference implementation of a ZKP verifier server.
// At start-up it executes the following:
//
//   - loads all avaiable circuits
//   - loads trusted CA certificates that will be used for validating the proofs.
//     Make sure you load the signing CA certificates from the issuers you expect
//     to receive the identity documents for.
//     by default certs.pm contain only a handful of certificates from known
//     issuers and test certificates from Google
//   - starts the server on the provided port (8888 by default)
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"proofs/server/v2/zk"
	"syscall"
	"time"
)

var (
	port       = flag.String("port", ":8888", "Listening port")
	certs      = flag.String("cacerts", "certs.pem", "File containing issuer CA certs")
	circuitDir = flag.String("circuit_dir", "circuits", "Directory from which to load circuits")
)

type Server struct {
	listenAddr string
	logger     *slog.Logger
}

func NewServer(listenAddr string, logger *slog.Logger) *Server {
	return &Server{
		listenAddr: listenAddr,
		logger:     logger,
	}
}

func (s *Server) healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	zk.LoadCircuits(*circuitDir)

	pem, err := os.ReadFile(*certs)
	if err != nil {
		logger.Error("could not parse cacerts file", "file", *certs, "err", err)
		os.Exit(1)
	}
	if err := zk.LoadIssuerRootCA(pem); err != nil {
		logger.Error("could not load issuer root CA", "err", err)
		os.Exit(1)
	}

	server := NewServer(*port, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/zkverify", makeHTTPHandleFunc(server.handleZKVerify))
	mux.HandleFunc("/specs", makeHTTPHandleFunc(server.handleGetZKSpecs))
	mux.HandleFunc("/healthz", server.healthzHandler)

	srv := &http.Server{
		Addr:    server.listenAddr,
		Handler: mux,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("Starting server", "addr", server.listenAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("server failed to start", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown failed", "err", err)
		os.Exit(1)
	}

	logger.Info("Server gracefully stopped")
}
