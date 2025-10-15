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

// This file contains all of the interface code that calls Longfellow ZK
// C++ library.
// it expect the library source code to be located in ../../install/lib
package zk

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"unsafe"
)

// #cgo LDFLAGS: -L../../install/lib -lmdoc_static -lcrypto -lzstd -lstdc++
// #cgo CFLAGS: -I../../install/include
// #include <stdlib.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <string.h>
// #include "mdoc_zk.h"
//
// /* Simple helpers to manipulate the C structs. */
//
// ZkSpecStruct* make_zkspec(size_t num) {
//    ZkSpecStruct *r = malloc(sizeof(ZkSpecStruct));
//    r->num_attributes = num;
//    return r;
// }
//
// RequestedAttribute* make_attribute(size_t len) {
//    RequestedAttribute *r = malloc(sizeof(RequestedAttribute) * len);
//    return r;
// }
//
// void set_attribute(RequestedAttribute attrs[], size_t ind, const char* namespace_id, const char* id, const uint8_t* cborvalue, size_t cborvaluelen) {
//    strncpy((char *)attrs[ind].namespace_id, namespace_id, 64);
//    strncpy((char *)attrs[ind].id, id, 32);
//    if (cborvaluelen > 64) { cborvaluelen = 64; }
//    memcpy((char *)attrs[ind].cbor_value, cborvalue, cborvaluelen);
//    attrs[ind].namespace_len = strlen(namespace_id);
//    attrs[ind].id_len = strlen(id);
//    attrs[ind].cbor_value_len = cborvaluelen;
// }
import "C"

const LONGFELLOW_V1 = "longfellow-libzk-v1"
const TIMESTAMP_LEN = 20

type Circuit struct {
	bytes         *C.uchar
	size          C.size_t
	Id            string
	NumAttributes uint
}

type VerifyRequest struct {
	System    string
	CircuitID string
	// Params, encoded in a flat structure here
	Pkx                   string
	Pky                   string
	Now                   string
	DocType               string
	AttributeNamespaceIDs []string
	AttributeIDs          []string
	AttributeCborValues   [][]byte
	Transcript            []byte
	Claims                IssuerSigned

	Proof []byte
}

func realCircuitId(circ *Circuit) (string, error) {
	cid := (*C.uchar)(C.malloc(32))
	defer C.free(unsafe.Pointer(cid))
	var cZkspec = C.make_zkspec(1)
	defer C.free(unsafe.Pointer(cZkspec))

	if C.circuit_id(cid, circ.bytes, circ.size, cZkspec) == 0 {
		return "", errors.New("circuit id failed")
	}
	gid := C.GoBytes(unsafe.Pointer(cid), C.int(32))
	return hex.EncodeToString(gid), nil
}

// Mutable dependency for testing
var CircuitId = realCircuitId

func fromBytes(bytes []byte) *Circuit {
	return &Circuit{
		bytes: (*C.uchar)(C.CBytes(bytes)),
		size:  C.size_t(len(bytes)),
	}
}

func (c *Circuit) toBytes() []byte {
	return C.GoBytes(unsafe.Pointer(c.bytes), C.int(c.size))
}

func GetZKSpecs() []ZKSpec {
	resp := make([]ZKSpec, uint(C.kNumZkSpecs))
	for i := 0; i < int(C.kNumZkSpecs); i++ {
		ss := C.kZkSpecs[i]
		resp[i] = ZKSpec{
			System:        C.GoString(ss.system),
			CircuitHash:   C.GoString(&ss.circuit_hash[0]),
			NumAttributes: uint(ss.num_attributes),
			Version:       uint(ss.version),
		}
	}
	return resp
}

func VerifyProofRequest(r *VerifyRequest) (bool, error) {

	circ, ok := GetCircuitByName(r.CircuitID)
	if !ok {
		return false, fmt.Errorf("invalid circuit id: %s", r.CircuitID)
	}
	log.Printf("loaded circuit id: %v", r.CircuitID)
	na := len(r.AttributeIDs)
	if na < 1 || na > 4 || na != len(r.AttributeCborValues) {
		return false, fmt.Errorf("invalid number of attributes: got %d, want 1-4", na)
	}

	cSystem := C.CString(LONGFELLOW_V1)
	defer C.free(unsafe.Pointer(cSystem))
	cCircuitID := C.CString(r.CircuitID)
	defer C.free(unsafe.Pointer(cCircuitID))
	cZkspec := C.find_zk_spec(cSystem, cCircuitID)
	if cZkspec == nil {
		return false, fmt.Errorf("invalid circuit spec for system %s and circuit id %s", LONGFELLOW_V1, r.CircuitID)
	}

	if cZkspec.num_attributes != C.size_t(na) {
		return false, fmt.Errorf("mismatch in number of attributes: got %d, want %d", na, cZkspec.num_attributes)
	}

	attr := C.make_attribute(C.size_t(na))
	defer C.free(unsafe.Pointer(attr))
	for i := 0; i < na; i++ {
		canamespaceid := C.CString(r.AttributeNamespaceIDs[i])
		caid := C.CString(r.AttributeIDs[i])
		cacborvalue := (*C.uchar)(C.CBytes(r.AttributeCborValues[i]))
		defer C.free(unsafe.Pointer(canamespaceid))
		defer C.free(unsafe.Pointer(caid))
		defer C.free(unsafe.Pointer(cacborvalue))
		C.set_attribute(attr, C.size_t(i), canamespaceid, caid, cacborvalue, C.size_t(len(r.AttributeCborValues[i])))
	}

	prLen := len(r.Proof)

	tr := (*C.uchar)(C.CBytes(r.Transcript))
	defer C.free(unsafe.Pointer(tr))
	trLen := len(r.Transcript)

	cNow := C.CString(r.Now)
	defer C.free(unsafe.Pointer(cNow))

	cPkX := C.CString(r.Pkx)
	defer C.free(unsafe.Pointer(cPkX))

	cPkY := C.CString(r.Pky)
	defer C.free(unsafe.Pointer(cPkY))

	cDocType := C.CString(r.DocType)
	defer C.free(unsafe.Pointer(cDocType))

	cProof := (*C.uchar)(C.CBytes(r.Proof))
	defer C.free(unsafe.Pointer(cProof))

	ret := C.run_mdoc_verifier(
		circ.bytes, circ.size,
		cPkX, cPkY,
		tr, C.size_t(trLen),
		attr, C.size_t(na),
		cNow,
		cProof, C.size_t(prLen),
		cDocType, cZkspec)

	if ret != C.MDOC_VERIFIER_SUCCESS {
		return false, fmt.Errorf("verification failure: return code %v", ret)
	}

	return true, nil
}
