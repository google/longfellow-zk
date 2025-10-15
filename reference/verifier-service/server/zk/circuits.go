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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains functions to load the circuits in memory and validate them
// It scans the provided directory and attemts to read the circuits from the disk
//
// The validation is performed by calling circuit_id() function from Longfellow ZK
// library on loaded raw cirucit bytes and comparing the resulting id with expected
// one from the list of hardcoded specs in lib/circuits/mdoc/zk_spec.cc
package zk

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	circuitMap = make(map[string]*Circuit)
)

type CircuitInfo struct {
	System        string
	NumAttributes uint
}

type ZKSpec struct {
	System        string `json:"system"`
	CircuitHash   string `json:"circuit_hash"`
	NumAttributes uint   `json:"num_attributes"`
	Version       uint   `json:"version"`
}

// GetCircuitByName returns a circuit from the circuit map by its name.
func GetCircuitByName(name string) (*Circuit, bool) {
	c, ok := circuitMap[name]
	return c, ok
}

// LoadCircuits loads circuits from the given directory.
func LoadCircuits(dir string) error {
	log.Printf("Reading from dir %v", dir)
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.Contains(path, "README.md") {
			return nil // skip README file
		}
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("error reading file %s: %v", d.Name(), err)
			return nil // Skip to the next file
		}

		c := fromBytes(content)
		cid, err := CircuitId(c)
		if err != nil || cid != d.Name() {
			log.Printf("ignoring file %s: %v %s", d.Name(), err, cid)
			return nil
		}

		circuitMap[d.Name()] = c
		log.Printf("Read %s", d.Name())
		return nil
	})
}
