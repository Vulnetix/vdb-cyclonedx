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

func TestBuildSBOMCarriesDependencyGraphAndSPDXIDs(t *testing.T) {
	data, err := BuildSBOM(SBOMInventory{
		Packages: []SBOMPackage{
			{Name: "express", Version: "4.19.2", Ecosystem: "npm", IsDirect: true, Licenses: []string{"mit"}},
			{Name: "body-parser", Version: "1.20.2", Ecosystem: "npm", Licenses: []string{"Weird Registry License"}},
			// Edge target that never becomes a component: must not appear.
			{Name: "kept", Version: "1.0.0", Ecosystem: "npm"},
		},
		Dependencies: []SBOMDependency{
			{Ref: "pkg:npm/express@4.19.2", DependsOn: []string{"pkg:npm/body-parser@1.20.2", "pkg:npm/ghost@9.9.9"}},
			{Ref: "pkg:npm/ghost@9.9.9", DependsOn: []string{"pkg:npm/kept@1.0.0"}},
		},
	}, SBOMOptions{
		CanonicalSPDXID: func(v string) string {
			if strings.EqualFold(v, "mit") {
				return "MIT"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}

	var doc struct {
		Components []struct {
			Name     string `json:"name"`
			Licenses []struct {
				License *struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	licenseOf := func(name string) (id, free string) {
		for _, c := range doc.Components {
			if c.Name == name && len(c.Licenses) == 1 && c.Licenses[0].License != nil {
				return c.Licenses[0].License.ID, c.Licenses[0].License.Name
			}
		}
		return "", ""
	}
	if id, _ := licenseOf("express"); id != "MIT" {
		t.Fatalf("express license id = %q, want MIT", id)
	}
	if id, name := licenseOf("body-parser"); id != "" || name != "Weird Registry License" {
		t.Fatalf("unrecognised license must stay free text, got id=%q name=%q", id, name)
	}

	edges := map[string][]string{}
	for _, d := range doc.Dependencies {
		edges[d.Ref] = d.DependsOn
	}
	if got := edges["pkg:npm/express@4.19.2"]; len(got) != 1 || got[0] != "pkg:npm/body-parser@1.20.2" {
		t.Fatalf("express dependsOn = %v, want only body-parser (unknown ref dropped)", got)
	}
	if _, ok := edges["pkg:npm/ghost@9.9.9"]; ok {
		t.Fatal("edge whose ref is not a component must be dropped")
	}
	if got := edges["urn:project"]; len(got) != 1 || got[0] != "pkg:npm/express@4.19.2" {
		t.Fatalf("project dependsOn = %v, want the direct dependency", got)
	}
}
