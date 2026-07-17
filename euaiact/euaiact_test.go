package euaiact

import "testing"

func find(ms []ArticleMapping, article string) *ArticleMapping {
	for i := range ms {
		if ms[i].Article == article {
			return &ms[i]
		}
	}
	return nil
}

func TestMapSatisfied(t *testing.T) {
	scan := Scan{
		RepoName: "acme/repo", CommitSha: "deadbeefcafe", ToolName: "vulnetix-aibom",
		ToolVersion: "v3.65.1", CreatedAt: 1784000000000, ComponentCount: 3,
	}
	comps := []Component{
		{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", EvidenceCount: 2},
		{Type: "application", Category: "ai-service", Name: "OpenAI API", Provider: "OpenAI", EvidenceCount: 1},
		{Type: "library", Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
	}
	ms := Map(scan, comps)
	if len(ms) != 2 {
		t.Fatalf("want 2 articles, got %d", len(ms))
	}
	a12 := find(ms, "Article 12")
	if a12 == nil || a12.Status != StatusSatisfied {
		t.Fatalf("Article 12 = %+v", a12)
	}
	if a12.Framework != Framework {
		t.Errorf("framework = %q", a12.Framework)
	}
	if len(a12.Evidence) == 0 {
		t.Error("Article 12 has no evidence")
	}
	a50 := find(ms, "Article 50")
	if a50 == nil || a50.Status != StatusSatisfied {
		t.Fatalf("Article 50 = %+v", a50)
	}
	// model + service both disclosed
	if len(a50.Evidence) != 2 {
		t.Errorf("Article 50 evidence = %d, want 2", len(a50.Evidence))
	}
}

func TestArticle12GapWithoutProvenance(t *testing.T) {
	comps := []Component{{Type: "machine-learning-model", Category: "model", Name: "m", Provider: "P", EvidenceCount: 1}}
	a12 := find(Map(Scan{ComponentCount: 1}, comps), "Article 12")
	if a12.Status != StatusGap {
		t.Fatalf("no-provenance should be a gap, got %s", a12.Status)
	}
	if len(a12.Gaps) == 0 {
		t.Error("expected a gap reason")
	}
}

func TestArticle12PartialWhenComponentLacksEvidence(t *testing.T) {
	scan := Scan{RepoName: "r", CommitSha: "abc123", ToolName: "t", CreatedAt: 1}
	comps := []Component{
		{Type: "model", Category: "model", Name: "a", Provider: "P", EvidenceCount: 1},
		{Type: "model", Category: "model", Name: "b", Provider: "P", EvidenceCount: 0},
	}
	a12 := find(Map(scan, comps), "Article 12")
	if a12.Status != StatusPartial {
		t.Fatalf("missing-evidence component should be partial, got %s", a12.Status)
	}
}

func TestArticle50PartialWhenModelMissingIdentity(t *testing.T) {
	scan := Scan{RepoName: "r", CommitSha: "abc123", ToolName: "t", CreatedAt: 1}
	comps := []Component{{Type: "machine-learning-model", Category: "model", Name: "mystery-model", EvidenceCount: 1}}
	a50 := find(Map(scan, comps), "Article 50")
	if a50.Status != StatusPartial {
		t.Fatalf("model without provider/family should be partial, got %s", a50.Status)
	}
}

func TestArticle50ServiceOnly(t *testing.T) {
	scan := Scan{RepoName: "r", CommitSha: "abc123", ToolName: "t", CreatedAt: 1}
	comps := []Component{{Type: "application", Category: "ai-service", Name: "Anthropic API", Provider: "Anthropic", EvidenceCount: 1}}
	a50 := find(Map(scan, comps), "Article 50")
	if a50.Status != StatusPartial {
		t.Fatalf("service-only should be partial, got %s", a50.Status)
	}
}

func TestNotApplicableWhenEmpty(t *testing.T) {
	ms := Map(Scan{RepoName: "r", CommitSha: "abc", ToolName: "t", CreatedAt: 1}, nil)
	for _, m := range ms {
		if m.Status != StatusNotApplicable {
			t.Errorf("%s should be not-applicable on empty inventory, got %s", m.Article, m.Status)
		}
	}
}

func TestDeterministicEvidenceOrder(t *testing.T) {
	scan := Scan{RepoName: "r", CommitSha: "abc123", ToolName: "t", CreatedAt: 1}
	comps := []Component{
		{Type: "model", Category: "model", Name: "zeta", Provider: "P", EvidenceCount: 1},
		{Type: "model", Category: "model", Name: "alpha", Provider: "P", EvidenceCount: 1},
	}
	a50 := find(Map(scan, comps), "Article 50")
	if a50.Evidence[0].Component != "alpha" || a50.Evidence[1].Component != "zeta" {
		t.Errorf("evidence not sorted: %+v", a50.Evidence)
	}
}
