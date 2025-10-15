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

// This file contains the halnder functions for the ZK Verifier endpoints:
//
//   - /specs provide a list of ZKSpecs supported by the current version of the code.
//     The list is fixed in each version of the code, it is  hardcoded in
//     lib/circuits/mdoc/zk_spec.cc
//     The list must be used  when generating a request for a ZK Proofs to ensure
//     backwards and forward compatiblity.
//     New versions are being released ferquently and old versions get deprecated
//     when we detect they're not used in the wild anymore.
//   - /zkverify receives a proof and a session transcript in JSON format (see
//     description in the ZKVerifyRequest type below). Both of those fields are
//     BASE64-encoded. It responds with a verdict (verified or not) and a list of
//     verified claims.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"proofs/server/v2/zk"
)

type ZKVerifyRequest struct {
	// Transcript must match the one built by the mDL holder and it must be built by
	// the client library. Currently this verifier supports OpenID4VP SessionTranscript
	// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscr
	// this is a CBOR structure encoded in BASE64 JSON field
	Transcript []byte `json:"Transcript"`
	// ZKDeviceResponse is the BASE64-encoded CBOR value that Google Wallet outputs
	// when a proof is generated. Currently it follows a "preview" format similar to
	// ISO 18013-5 Second Edition. See cbor.go for the details of the format.
	ZKDeviceResponseCBOR []byte `json:"ZKDeviceResponseCBOR"`
}

type ZKVerifyResponse struct {
	Status  bool            `json:"Status"`
	Claims  zk.IssuerSigned `json:"Claims,omitempty"`
	Message string          `json:"Message,omitempty"`
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type APIError struct {
	Error string `json:"error"`
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			// Log the error
			slog.Error("handler error", "err", err, "path", r.URL.Path)
			// Send error to the client
			writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		}
	}
}

func (s *Server) handleZKVerify(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return writeJSON(w, http.StatusMethodNotAllowed, APIError{Error: "expecting a json post"})
	}

	var request ZKVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return writeJSON(w, http.StatusBadRequest, APIError{Error: "Error reading request body"})
	}

	vreq, err := zk.ProcessDeviceResponse(request.ZKDeviceResponseCBOR)
	if err != nil {
		return writeJSON(w, http.StatusBadRequest, APIError{Error: "Error processing cbor request: " + err.Error()})
	}

	vreq.Transcript = request.Transcript

	ok, err := zk.VerifyProofRequest(vreq)
	resp := ZKVerifyResponse{Status: ok, Claims: vreq.Claims}
	if err != nil {
		s.logger.Error("invalid proof", "err", err)
		resp.Message = err.Error()
	}

	return writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetZKSpecs(w http.ResponseWriter, r *http.Request) error {
	specs := zk.GetZKSpecs()
	return writeJSON(w, http.StatusOK, specs)
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
