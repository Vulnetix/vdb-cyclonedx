package cyclonedx

import "testing"

func TestBuildAndParseAIBOMRoundTrip(t *testing.T) {
	det := AIDetections{
		CatalogVersion: "2026.06.4",
		Tools: []AITool{{
			ID: "claude-code", Name: "Claude Code", Vendor: "Anthropic", Confidence: "high",
			Evidence: []AIEvidence{{Method: "file", Category: "instructions", Locator: "CLAUDE.md"}},
		}},
		Libraries: []AILibrary{{
			ID: "openai", Name: "OpenAI SDK", Provider: "OpenAI",
			Languages: []string{"python"}, Purl: "pkg:pypi/openai@1.0.0", Confidence: "high",
		}},
		Models: []AIModel{{
			Name: "@cf/moonshotai/kimi-k2.7-code", Provider: "Cloudflare Workers AI",
			Family: "Workers AI", ViaSDK: "cloudflare-workers-ai", Known: true, Occurrences: 3, Confidence: "high",
			Evidence: []AIEvidence{{Method: "source", Category: "model", Locator: "run.sh:5", Snippet: "--model @cf/..."}},
		}},
	}

	data, err := BuildAIBOM(det, AIBOMOptions{
		SpecVersion: "1.7", ToolName: "vulnetix-aibom", ToolVersion: "v3.x",
		Project: &AIBOMProject{
			Name: "acme/repo", Branch: "main", Commit: "deadbeef",
			RemoteURLs: []string{"git@github.com:acme/repo.git"},
			System:     &AIBOMSystem{OS: "linux", Arch: "amd64"},
		},
	})
	if err != nil {
		t.Fatalf("BuildAIBOM (validates against schema): %v", err)
	}

	inv, err := ParseAIBOM(data)
	if err != nil {
		t.Fatalf("ParseAIBOM: %v", err)
	}
	if inv.ToolCount != 1 || inv.LibraryCount != 1 || inv.ModelCount != 1 {
		t.Fatalf("counts tools=%d sdks=%d models=%d", inv.ToolCount, inv.LibraryCount, inv.ModelCount)
	}
	if inv.RepoName != "acme/repo" || inv.BranchName != "main" || inv.CommitSha != "deadbeef" {
		t.Fatalf("git meta repo=%q branch=%q commit=%q", inv.RepoName, inv.BranchName, inv.CommitSha)
	}
	if inv.CatalogVersion != "2026.06.4" {
		t.Fatalf("catalog version = %q", inv.CatalogVersion)
	}

	var model *AIBOMComponentRow
	for i := range inv.Components {
		if inv.Components[i].Category == "model" {
			model = &inv.Components[i]
		}
	}
	if model == nil {
		t.Fatal("no model row parsed")
	}
	if model.Name != "@cf/moonshotai/kimi-k2.7-code" || model.Provider != "Cloudflare Workers AI" || model.ViaSDK != "cloudflare-workers-ai" {
		t.Fatalf("model row = %+v", model)
	}
	if model.Known == nil || !*model.Known {
		t.Fatal("model.Known should round-trip to true")
	}
	if model.Occurrences != 3 {
		t.Fatalf("model.Occurrences = %d, want 3", model.Occurrences)
	}
	if len(model.Evidence) != 1 || model.Evidence[0].Method != "source" || model.Evidence[0].Locator != "model run.sh:5" {
		t.Fatalf("model evidence = %+v", model.Evidence)
	}
}

func TestBuildAIBOMValidatesSpecVersions(t *testing.T) {
	det := AIDetections{
		Tools:  []AITool{{ID: "claude-code", Name: "Claude Code", Vendor: "Anthropic"}},
		Models: []AIModel{{Name: "gpt-4o", Provider: "OpenAI", Known: true}},
	}
	for _, spec := range []string{"1.6", "1.7"} {
		if _, err := BuildAIBOM(det, AIBOMOptions{SpecVersion: spec}); err != nil {
			t.Fatalf("BuildAIBOM(spec=%s) should validate: %v", spec, err)
		}
	}
}

func TestParseAIBOMRejectsNonCycloneDX(t *testing.T) {
	if _, err := ParseAIBOM([]byte(`{"foo":"bar"}`)); err == nil {
		t.Fatal("expected error for non-CycloneDX document")
	}
	if _, err := ParseAIBOM([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`)); err == nil {
		t.Fatal("expected error for AIBOM with no AI components")
	}
}
