package cyclonedx

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleDetections() CryptoDetections {
	return CryptoDetections{
		CatalogVersion: "2026.06.1",
		Assets: []CryptoAsset{
			{
				SPDXID: "aes", Name: "AES-256-GCM", OID: "2.16.840.1.101.3.4.1.46",
				Primitive: "ae", ParameterSetIdentifier: "256", Mode: "gcm",
				CryptoFunctions:        []string{"encrypt", "decrypt"},
				ClassicalSecurityLevel: 256, NISTQuantumSecurityLevel: 1,
				PQCStatus: PQCQuantumSafe, Standards: map[string]string{"NIST": "approved"},
				Confidence: "high", Occurrences: 3,
				Evidence: []CryptoEvidence{{Method: "source", Category: "call", Locator: "main.go:42", Snippet: "cipher.NewGCM"}},
			},
			{
				SPDXID: "rsa", Name: "RSA-2048", Primitive: "pke", ParameterSetIdentifier: "2048",
				ClassicalSecurityLevel: 112, NISTQuantumSecurityLevel: 0,
				PQCStatus: PQCQuantumVulnerable, Standards: map[string]string{"NIST": "deprecated"},
				Evidence: []CryptoEvidence{{Method: "source", Locator: "rsa.go:1"}},
			},
			{
				SPDXID: "ml-kem", Name: "ML-KEM-768", Primitive: "kem", ParameterSetIdentifier: "768",
				NISTQuantumSecurityLevel: 3, PQCStatus: PQCQuantumSafe,
				Standards: map[string]string{"NIST": "approved", "BSI": "recommended"},
			},
		},
		Libraries: []CryptoLib{
			{ID: "openssl", Name: "openssl", Provider: "OpenSSL", Languages: []string{"c"}, Purl: "pkg:generic/openssl", Confidence: "high"},
		},
		Certificates: []CryptoCert{
			{
				Name: "server.pem", Subject: "CN=example.com", Issuer: "CN=Example CA",
				NotBefore: "2024-01-01T00:00:00Z", NotAfter: "2034-01-01T00:00:00Z",
				Format: "X.509", FileExtension: ".pem",
				SignatureAlgorithm: "RSA-2048", PublicKeyAlgorithm: "RSA-2048", PublicKeyType: "public-key",
				KeySize: 2048, PQCStatus: PQCQuantumVulnerable,
				Evidence: []CryptoEvidence{{Method: "certificate", Locator: "server.pem"}},
			},
		},
	}
}

func TestBuildCBOMValidates(t *testing.T) {
	for _, spec := range []string{"1.6", "1.7"} {
		data, err := BuildCBOM(sampleDetections(), CBOMOptions{SpecVersion: spec, ToolName: "vulnetix-cbom", ToolVersion: "test"})
		if err != nil {
			t.Fatalf("BuildCBOM(%s) failed validation: %v", spec, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("output not JSON: %v", err)
		}
		if doc["specVersion"] != spec {
			t.Errorf("specVersion = %v, want %s", doc["specVersion"], spec)
		}
		s := string(data)
		for _, want := range []string{
			`"type": "cryptographic-asset"`,
			`"cryptoProperties"`,
			`"assetType": "algorithm"`,
			`"assetType": "certificate"`,
			`"assetType": "related-crypto-material"`,
			`"nistQuantumSecurityLevel": 3`,
			PropCryptoPQCStatus,
			PropCryptoStandardPrefix + "NIST",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("spec %s: output missing %q", spec, want)
			}
		}
	}
}

func TestComputeCryptoSummary(t *testing.T) {
	s := ComputeCryptoSummary(sampleDetections())
	if s.QuantumVulnerable != 2 { // RSA asset + cert
		t.Errorf("QuantumVulnerable = %d, want 2", s.QuantumVulnerable)
	}
	if s.QuantumSafe != 2 { // AES + ML-KEM
		t.Errorf("QuantumSafe = %d, want 2", s.QuantumSafe)
	}
}

func TestParseCBOMRoundTrip(t *testing.T) {
	data, err := BuildCBOM(sampleDetections(), CBOMOptions{SpecVersion: "1.7"})
	if err != nil {
		t.Fatalf("BuildCBOM: %v", err)
	}
	inv, err := ParseCBOM(data)
	if err != nil {
		t.Fatalf("ParseCBOM: %v", err)
	}
	if inv.AlgorithmCount != 3 {
		t.Errorf("AlgorithmCount = %d, want 3", inv.AlgorithmCount)
	}
	if inv.CertificateCount != 1 {
		t.Errorf("CertificateCount = %d, want 1", inv.CertificateCount)
	}
	if inv.LibraryCount != 1 {
		t.Errorf("LibraryCount = %d, want 1", inv.LibraryCount)
	}
	if inv.QuantumVulnerable != 2 {
		t.Errorf("QuantumVulnerable = %d, want 2", inv.QuantumVulnerable)
	}
}
