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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestLoadIssuerRootCA(t *testing.T) {
	ca, _, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	if err := LoadIssuerRootCA(pemBytes); err != nil {
		t.Errorf("LoadIssuerRootCA() error = %v, wantErr %v", err, false)
	}

	if len(IssuerRoots.Subjects()) == 0 {
		t.Error("IssuerRoots should not be empty after loading a CA")
	}
}

func TestProcessDeviceResponse(t *testing.T) {
	ca, _, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := LoadIssuerRootCA(pemBytes); err != nil {
		t.Fatalf("failed to load issuer root CA: %v", err)
	}

	doc, err := createTestZkDocument()
	if err != nil {
		t.Fatalf("failed to create test zk document: %v", err)
	}

	docBytes, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to marshal zk document: %v", err)
	}

	resp := zkDeviceResponse{
		Version:     "1.0",
		ZKDocuments: [][]byte{docBytes},
		Status:      0,
	}

	respBytes, err := cbor.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal device response: %v", err)
	}

	_, err = ProcessDeviceResponse(respBytes)
	if err != nil {
		t.Errorf("ProcessDeviceResponse() error = %v, wantErr %v", err, false)
	}
}

func TestValidateRequest(t *testing.T) {
	doc, err := createTestZkDocument()
	if err != nil {
		t.Fatalf("failed to create test zk document: %v", err)
	}

	if err := validateRequest(doc); err != nil {
		t.Errorf("validateRequest() error = %v, wantErr %v", err, false)
	}

	doc.ZKSystemType.System = "invalid"
	if err := validateRequest(doc); err == nil {
		t.Error("validateRequest() error = nil, wantErr not nil")
	}
}

func TestValidateIssuerKey(t *testing.T) {
	ca, _, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := LoadIssuerRootCA(pemBytes); err != nil {
		t.Fatalf("failed to load issuer root CA: %v", err)
	}

	doc, err := createTestZkDocument()
	if err != nil {
		t.Fatalf("failed to create test zk document: %v", err)
	}

	_, _, err = validateIssuerKey(doc)
	if err != nil {
		t.Errorf("validateIssuerKey() error = %v, wantErr %v", err, false)
	}
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func createTestZkDocument() (*zkDocument, error) {
	caCert, caKey, err := generateTestCA()
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := LoadIssuerRootCA(pemBytes); err != nil {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Cert"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &zkDocument{
		DocType: "test_doctype",
		ZKSystemType: zkSpec{
			System: LONGFELLOW_V1,
			Params: zkParam{
				Version:       1,
				CircuitHash:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				NumAttributes: 1,
			},
		},
		IssuerSigned: IssuerSigned{
			"test_namespace": []zkSignedItem{
				{
					ElementIdentifier: "test_identifier",
					ElementValue:      cbor.RawMessage([]byte{0x81, 0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f}), // ["hello"]
				},
			},
		},
		MsoX5chain: chainCoseSign1{
			Unprotected: map[int][]byte{
				X5ChainIndex: cert.Raw,
			},
		},
		Timestamp: "2025-01-01T00:00:00Z",
		Proof:     []byte("test_proof"),
	}, nil
}
