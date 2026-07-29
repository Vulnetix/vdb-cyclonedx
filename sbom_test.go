package cyclonedx

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSBOMCombinesPackageAIBOMAndCBOM(t *testing.T) {
	data, err := BuildSBOM(SBOMInventory{
		Packages: []SBOMPackage{{
			Name:       "left-pad",
			Version:    "1.3.0",
			Ecosystem:  "npm",
			Scope:      "production",
			SourceFile: "package-lock.json",
			SourceType: "manifest",
			IsDirect:   true,
			Hashes:     []SBOMHash{{Alg: "sha256", Content: strings.Repeat("a", 64)}},
			Signatures: []SBOMSignature{{
				Algorithm:  "sigstore",
				SourceFile: "package-lock.json.sigstore",
				TransparencyLog: &SBOMTransparencyLogEntry{
					LogID:          "rekor.example/log",
					UUID:           "abc",
					IntegratedTime: "2026-07-29T00:00:00Z",
				},
			}},
		}},
		AIDetections: &AIDetections{
			Tools: []AITool{{ID: "codex", Name: "Codex", Confidence: "high"}},
		},
		CryptoDetections: &CryptoDetections{
			Assets: []CryptoAsset{{
				SPDXID:                   "SHA-256",
				Name:                     "SHA-256",
				Primitive:                "hash",
				NISTQuantumSecurityLevel: 0,
				PQCStatus:                PQCQuantumVulnerable,
			}},
		},
	}, SBOMOptions{SpecVersion: "1.7", ToolName: "vulnetix-cdx"})
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	var doc struct {
		Components []struct {
			Type string `json:"type"`
			Name string `json:"name"`
			Purl string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Components {
		seen[c.Type+":"+c.Name] = true
	}
	for _, key := range []string{"library:left-pad", "application:Codex", "cryptographic-asset:SHA-256"} {
		if !seen[key] {
			t.Fatalf("missing %s in %s", key, data)
		}
	}
}
