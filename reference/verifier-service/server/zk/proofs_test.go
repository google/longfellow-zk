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

package zk

import (
	"encoding/json"
	"testing"
)

func TestVerifyProofRequest(t *testing.T) {
	// This test is limited because it cannot call the C code.
	// It can only test the Go code that prepares the data for the C functions.

	// Test with an invalid circuit ID
	req := &VerifyRequest{
		CircuitID: "invalid",
	}
	if _, err := VerifyProofRequest(req); err == nil {
		t.Error("expected an error for invalid circuit ID, but got nil")
	}

	// Test with an invalid number of attributes
	circuitMap["valid_circuit"] = &Circuit{}
	req = &VerifyRequest{
		CircuitID:    "valid_circuit",
		AttributeIDs: []string{},
	}
	if _, err := VerifyProofRequest(req); err == nil {
		t.Error("expected an error for invalid number of attributes, but got nil")
	}
}

func TestGetZKSpecs(t *testing.T) {
	specs := GetZKSpecs()
	if len(specs) == 0 {
		t.Fatal("expected some ZK specs, but got none")
	}

	encoded, err := json.Marshal(specs[0])
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(encoded, &spec); err != nil {
		t.Fatal(err)
	}
	if spec["block_enc_hash"] != float64(4151) {
		t.Errorf("block_enc_hash = %v, want 4151", spec["block_enc_hash"])
	}
	if spec["block_enc_sig"] != float64(4096) {
		t.Errorf("block_enc_sig = %v, want 4096", spec["block_enc_sig"])
	}
}
