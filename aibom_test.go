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

func TestBuildAndParseAIBOMInfraDataRoundTrip(t *testing.T) {
	det := AIDetections{
		Infrastructure: []AIInfra{
			{
				ID: "vllm", Name: "vLLM", Category: "inference", Version: "0.6.3", RawTag: "v0.6.3",
				Image:    "vllm/vllm-openai:v0.6.3",
				Evidence: []AIEvidence{{Method: "iac", Category: "image", Locator: "deploy.yaml:12"}},
			},
			{
				ID: "triton", Name: "NVIDIA Triton", Category: "inference", RawTag: "24.05-py3",
				Image:         "nvcr.io/nvidia/tritonserver:24.05-py3",
				ConfidenceGap: true,
				GapReason:     "version unverified: image tag '24.05-py3' is not semver-shaped",
			},
		},
		Data: []AIData{
			{
				Name: "pvc:models-pvc", Kind: "model-artifact", Source: "pvc", MountPath: "/models",
				Evidence: []AIEvidence{{Method: "iac", Category: "mount", Locator: "deploy.yaml:30"}},
			},
			{
				Name: "volume:weights", Kind: "model-artifact", Source: "unknown", MountPath: "/weights",
				ConfidenceGap: true, GapReason: "volume 'weights' has no matching volumes[] entry",
			},
		},
	}

	for _, spec := range []string{"1.6", "1.7"} {
		data, err := BuildAIBOM(det, AIBOMOptions{SpecVersion: spec})
		if err != nil {
			t.Fatalf("BuildAIBOM(spec=%s) with infra/data should validate: %v", spec, err)
		}
		inv, err := ParseAIBOM(data)
		if err != nil {
			t.Fatalf("ParseAIBOM(spec=%s): %v", spec, err)
		}
		if inv.InfraCount != 2 || inv.DataCount != 2 {
			t.Fatalf("spec=%s counts infra=%d data=%d, want 2/2", spec, inv.InfraCount, inv.DataCount)
		}
		var vllm, triton, gapData *AIBOMComponentRow
		for i := range inv.Components {
			switch {
			case inv.Components[i].InfraID == "vllm":
				vllm = &inv.Components[i]
			case inv.Components[i].InfraID == "triton":
				triton = &inv.Components[i]
			case inv.Components[i].Category == "data" && inv.Components[i].ConfidenceGap:
				gapData = &inv.Components[i]
			}
		}
		if vllm == nil || vllm.Version != "0.6.3" || vllm.ImageTag != "v0.6.3" || vllm.Image != "vllm/vllm-openai:v0.6.3" || vllm.ConfidenceGap {
			t.Fatalf("vllm row = %+v", vllm)
		}
		if vllm.Category != "inference" {
			t.Fatalf("vllm category = %q", vllm.Category)
		}
		if triton == nil || !triton.ConfidenceGap || triton.GapReason == "" || triton.Version != "" {
			t.Fatalf("triton gap row = %+v", triton)
		}
		if gapData == nil || gapData.GapReason != "volume 'weights' has no matching volumes[] entry" || gapData.MountPath != "/weights" {
			t.Fatalf("gap data row = %+v", gapData)
		}
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
