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

func provenanceScan() Scan {
	return Scan{RepoName: "acme/repo", CommitSha: "deadbeefcafe", ToolName: "vulnetix-aibom", ToolVersion: "v3.65.1", CreatedAt: 1784000000000, ComponentCount: 1, PriorScanCount: 1}
}

func TestMapReturnsFullArticleSet(t *testing.T) {
	ms := Map(provenanceScan(), []Component{
		{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", Task: "chat", EvidenceCount: 2, EvidenceMethods: []string{"source"}},
	})
	for _, want := range []string{"Article 10", "Article 11 / Annex IV", "Article 12", "Article 14", "Article 50", "Articles 51-55", "Article 72", "Article 13", "Article 15"} {
		if find(ms, want) == nil {
			t.Errorf("missing %s", want)
		}
	}
}

func TestArticle12Transitions(t *testing.T) {
	comps := []Component{{Type: "model", Category: "model", Name: "m", Provider: "P", EvidenceCount: 1, EvidenceMethods: []string{"iac"}}}
	if s := find(Map(provenanceScan(), comps), "Article 12").Status; s != StatusSatisfied {
		t.Errorf("full evidence+provenance = %s, want satisfied", s)
	}
	// missing provenance → gap
	if s := find(Map(Scan{ComponentCount: 1}, comps), "Article 12").Status; s != StatusGap {
		t.Errorf("no provenance = %s, want gap", s)
	}
	// a component without evidence → partial
	comps2 := append(comps, Component{Type: "model", Category: "model", Name: "n", EvidenceCount: 0})
	if s := find(Map(provenanceScan(), comps2), "Article 12").Status; s != StatusPartial {
		t.Errorf("missing-evidence component = %s, want partial", s)
	}
	// AI-authored commit provenance shows up in evidence
	commitComp := []Component{{Type: "application", Category: "coding-agent", Name: "claude-code", EvidenceCount: 3, EvidenceMethods: []string{"commit", "file"}}}
	a12 := find(Map(provenanceScan(), commitComp), "Article 12")
	sawCommit := false
	for _, e := range a12.Evidence {
		if e.Detail != "" && contains(e.Detail, "AI-authored commit") {
			sawCommit = true
		}
	}
	if !sawCommit {
		t.Error("AI-authored commit evidence not surfaced in Article 12")
	}
}

func TestArticle10DataGovernance(t *testing.T) {
	// not applicable: no data infra
	if s := find(Map(provenanceScan(), []Component{{Category: "model", Name: "m", Provider: "P", EvidenceCount: 1}}), "Article 10").Status; s != StatusNotApplicable {
		t.Errorf("no data infra = %s, want not-applicable", s)
	}
	// training infra without a dataset → partial
	train := []Component{{Category: "training", Name: "pytorch", EvidenceCount: 1}}
	if s := find(Map(provenanceScan(), train), "Article 10").Status; s != StatusPartial {
		t.Errorf("training w/o dataset = %s, want partial", s)
	}
	// dataset resolved → satisfied
	ds := []Component{
		{Category: "training", Name: "pytorch", EvidenceCount: 1},
		{Type: "data", Category: "data", Name: "pvc:training-data", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
	}
	if s := find(Map(provenanceScan(), ds), "Article 10").Status; s != StatusSatisfied {
		t.Errorf("dataset resolved = %s, want satisfied", s)
	}
	// gapped dataset → partial
	gap := []Component{{Type: "data", Category: "data", Name: "vol:x", DataKind: "dataset", ConfidenceGap: true, GapReason: "volume x has no matching volumes[] entry", EvidenceCount: 1}}
	if s := find(Map(provenanceScan(), gap), "Article 10").Status; s != StatusPartial {
		t.Errorf("gapped dataset = %s, want partial", s)
	}
}

func TestArticle11ConfidenceGapIsDisclosedNotHidden(t *testing.T) {
	comps := []Component{
		{Category: "inference", Name: "Triton", ConfidenceGap: true, GapReason: "version unverified: image tag '24.05-py3' is not semver-shaped", EvidenceCount: 1},
	}
	a11 := find(Map(provenanceScan(), comps), "Article 11 / Annex IV")
	if a11.Status != StatusPartial {
		t.Fatalf("gapped component = %s, want partial", a11.Status)
	}
	found := false
	for _, g := range a11.Gaps {
		if contains(g, "not semver-shaped") {
			found = true
		}
	}
	if !found {
		t.Errorf("gap reason not disclosed in Article 11 gaps: %v", a11.Gaps)
	}
}

func TestArticle14AgentAutonomy(t *testing.T) {
	if s := find(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "Article 14").Status; s != StatusNotApplicable {
		t.Errorf("no agents = %s, want not-applicable", s)
	}
	agents := []Component{{Category: "coding-agent", Name: "cursor", EvidenceCount: 1}, {Category: "agent", Name: "langflow", EvidenceCount: 1}}
	if s := find(Map(provenanceScan(), agents), "Article 14").Status; s != StatusInformational {
		t.Errorf("agents = %s, want informational", s)
	}
}

func TestArticle50UsesTaskAndViaSDK(t *testing.T) {
	comps := []Component{{Type: "machine-learning-model", Category: "model", Name: "claude-sonnet-4", Provider: "Anthropic", Family: "Claude", Task: "chat", ViaSDK: "anthropic", EvidenceCount: 1}}
	a50 := find(Map(provenanceScan(), comps), "Article 50")
	if a50.Status != StatusSatisfied {
		t.Fatalf("model w/ identity = %s, want satisfied", a50.Status)
	}
	if !contains(a50.Evidence[0].Detail, "chat") || !contains(a50.Evidence[0].Detail, "anthropic") {
		t.Errorf("task/viaSdk not surfaced: %q", a50.Evidence[0].Detail)
	}
	// inference runtime counts as disclosable service
	svc := []Component{{Category: "inference", Name: "vLLM", EvidenceCount: 1}}
	if s := find(Map(provenanceScan(), svc), "Article 50").Status; s != StatusPartial {
		t.Errorf("runtime-only = %s, want partial", s)
	}
}

func TestArticle51GPAIInformational(t *testing.T) {
	if s := find(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "Articles 51-55").Status; s != StatusNotApplicable {
		t.Errorf("no accel/family = %s, want not-applicable", s)
	}
	accel := []Component{{Category: "accelerator", Name: "GPU / accelerator resources", EvidenceCount: 1}}
	a51 := find(Map(provenanceScan(), accel), "Articles 51-55")
	if a51.Status != StatusInformational {
		t.Errorf("accelerator = %s, want informational", a51.Status)
	}
	if len(a51.Gaps) == 0 {
		t.Error("Article 51 should note FLOP not measured")
	}
}

func TestArticle72Monitoring(t *testing.T) {
	single := provenanceScan()
	single.PriorScanCount = 1
	if s := find(Map(single, nil), "Article 72").Status; s != StatusInformational {
		t.Errorf("single scan = %s, want informational", s)
	}
	repeated := provenanceScan()
	repeated.PriorScanCount = 5
	if s := find(Map(repeated, nil), "Article 72").Status; s != StatusSatisfied {
		t.Errorf("repeated scans = %s, want satisfied", s)
	}
}

func TestArticles13And15NotEvidenceable(t *testing.T) {
	ms := Map(provenanceScan(), []Component{{Category: "model", Name: "m", Provider: "P", EvidenceCount: 1}})
	for _, a := range []string{"Article 13", "Article 15"} {
		mp := find(ms, a)
		if mp.Status != StatusNotApplicable || mp.Rationale == "" {
			t.Errorf("%s should be not-applicable with a reason, got %+v", a, mp)
		}
	}
}

func TestSummarize(t *testing.T) {
	ms := Map(provenanceScan(), []Component{
		{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", EvidenceCount: 2, EvidenceMethods: []string{"source"}},
		{Category: "accelerator", Name: "gpu", EvidenceCount: 1},
	})
	s := SummarizeArticles(ms)
	if s.Articles != len(ms) {
		t.Errorf("summary article count = %d, want %d", s.Articles, len(ms))
	}
	if s.Satisfied+s.Partial+s.Gap+s.Informational+s.NotApplicable != s.Articles {
		t.Errorf("status counts don't sum to articles: %+v", s)
	}
}

func TestDeterministicEvidenceOrder(t *testing.T) {
	comps := []Component{
		{Type: "model", Category: "model", Name: "zeta", Provider: "P", EvidenceCount: 1},
		{Type: "model", Category: "model", Name: "alpha", Provider: "P", EvidenceCount: 1},
	}
	a50 := find(Map(provenanceScan(), comps), "Article 50")
	if a50.Evidence[0].Component != "alpha" || a50.Evidence[1].Component != "zeta" {
		t.Errorf("evidence not sorted: %+v", a50.Evidence)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
