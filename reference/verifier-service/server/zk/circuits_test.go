// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied// See the License for the specific language governing permissions and
// limitations under the License.
package zk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCircuits(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_circuits")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy circuit file
	dummyCircuit := &Circuit{
		Id: "dummy_circuit",
	}
	if err := WriteCircuit(dummyCircuit, tmpDir); err != nil {
		t.Fatalf("failed to write circuit: %v", err)
	}

	CircuitId = func(circ *Circuit) (string, error) {
		return "dummy_circuit", nil
	}

	// Load circuits from the temporary directory
	if err := LoadCircuits(tmpDir); err != nil {
		t.Fatalf("failed to load circuits: %v", err)
	}

	// Check if the circuit was loaded correctly
	if _, ok := GetCircuitByName("dummy_circuit"); !ok {
		t.Error("expected circuit to be loaded, but it wasn't")
	}
}

func TestGetCircuitByName(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_circuits")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy circuit file
	dummyCircuit := &Circuit{
		Id: "dummy_circuit",
	}
	if err := WriteCircuit(dummyCircuit, tmpDir); err != nil {
		t.Fatalf("failed to write circuit: %v", err)
	}

	CircuitId = func(circ *Circuit) (string, error) {
		return "dummy_circuit", nil
	}

	// Load circuits from the temporary directory
	if err := LoadCircuits(tmpDir); err != nil {
		t.Fatalf("failed to load circuits: %v", err)
	}

	// Test getting an existing circuit
	if _, ok := GetCircuitByName("dummy_circuit"); !ok {
		t.Error("expected to get circuit, but didn't")
	}

	// Test getting a non-existent circuit
	if _, ok := GetCircuitByName("non_existent_circuit"); ok {
		t.Error("expected not to get circuit, but did")
	}
}

// helper function WriteCircuit writes a circuit to a file in the given directory.
func WriteCircuit(c *Circuit, circuitDir string) error {
	buf := c.toBytes()
	filePath := filepath.Join(circuitDir, c.Id)
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	n, err := file.Write(buf)
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("wrote %d bytes, expected %d", n, len(buf))
	}
	return nil
}
