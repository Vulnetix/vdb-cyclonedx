package nistairmf

import (
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func provenanceScan() Scan {
	return Scan{RepoName: "acme/repo", CommitSha: "deadbeefcafe", ToolName: "vulnetix-aibom", ToolVersion: "v3.65.1", CreatedAt: 1784000000000, ComponentCount: 1, PriorScanCount: 1}
}

func findSub(fns []FunctionMapping, id string) *SubcategoryMapping {
	for i := range fns {
		for j := range fns[i].Subcategories {
			if fns[i].Subcategories[j].ID == id {
				return &fns[i].Subcategories[j]
			}
		}
	}
	return nil
}

func TestFourFunctionsPresent(t *testing.T) {
	fns := Map(provenanceScan(), []Component{{Category: "model", Name: "m", Provider: "OpenAI", EvidenceCount: 1}})
	want := map[string]bool{"GOVERN": false, "MAP": false, "MEASURE": false, "MANAGE": false}
	for _, f := range fns {
		want[f.Function] = true
		if len(f.Subcategories) == 0 {
			t.Errorf("%s has no subcategories", f.Function)
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("missing function %s", k)
		}
	}
}

func TestGovern16InventoryIsCore(t *testing.T) {
	// with provenance → satisfied
	g := findSub(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "GOVERN 1.6")
	if g == nil || g.Status != StatusSatisfied {
		t.Fatalf("GOVERN 1.6 w/ provenance = %+v", g)
	}
	// no provenance → partial
	g2 := findSub(Map(Scan{ComponentCount: 1}, []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "GOVERN 1.6")
	if g2.Status != StatusPartial {
		t.Errorf("GOVERN 1.6 no provenance = %s, want partial", g2.Status)
	}
	// empty inventory → not-applicable
	g3 := findSub(Map(provenanceScan(), nil), "GOVERN 1.6")
	if g3.Status != StatusNotApplicable {
		t.Errorf("GOVERN 1.6 empty = %s, want not-applicable", g3.Status)
	}
}

func TestMap22KnowledgeLimitsUsesConfidenceGap(t *testing.T) {
	// clean → satisfied (no limits)
	clean := findSub(Map(provenanceScan(), []Component{{Category: "model", Name: "m", Provider: "P", EvidenceCount: 1}}), "MAP 2.2")
	if clean.Status != StatusSatisfied {
		t.Errorf("MAP 2.2 clean = %s, want satisfied", clean.Status)
	}
	// gapped → satisfied, and the gap reason is surfaced as a documented limit
	gap := findSub(Map(provenanceScan(), []Component{
		{Category: "inference", Name: "Triton", ConfidenceGap: true, GapReason: "version unverified: tag not semver-shaped", EvidenceCount: 1},
	}), "MAP 2.2")
	if gap.Status != StatusSatisfied || len(gap.Evidence) == 0 {
		t.Fatalf("MAP 2.2 gapped = %+v", gap)
	}
	if !contains(gap.Evidence[0].Detail, "not semver-shaped") {
		t.Errorf("gap reason not surfaced: %q", gap.Evidence[0].Detail)
	}
}

func TestMeasure31TracksOverTime(t *testing.T) {
	single := provenanceScan()
	if findSub(Map(single, nil), "MEASURE 3.1").Status != StatusInformational {
		t.Error("single scan MEASURE 3.1 should be informational")
	}
	repeated := provenanceScan()
	repeated.PriorScanCount = 4
	if findSub(Map(repeated, nil), "MEASURE 3.1").Status != StatusSatisfied {
		t.Error("repeated scans MEASURE 3.1 should be satisfied")
	}
}

func TestManage43CommitAndHistory(t *testing.T) {
	scan := provenanceScan()
	scan.PriorScanCount = 3
	comps := []Component{{Category: "coding-agent", Name: "claude-code", EvidenceCount: 2, EvidenceMethods: []string{"commit"}}}
	if s := findSub(Map(scan, comps), "MANAGE 4.3").Status; s != StatusSatisfied {
		t.Errorf("commits + history = %s, want satisfied", s)
	}
	// commit only, single scan → partial
	single := provenanceScan()
	if s := findSub(Map(single, comps), "MANAGE 4.3").Status; s != StatusPartial {
		t.Errorf("commit only = %s, want partial", s)
	}
}

func TestThirdPartyGovernance(t *testing.T) {
	comps := []Component{
		{Category: "ai-service", Name: "OpenAI API", Provider: "OpenAI", EvidenceCount: 1},
		{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
	}
	g61 := findSub(Map(provenanceScan(), comps), "GOVERN 6.1")
	if g61.Status != StatusPartial {
		t.Errorf("GOVERN 6.1 with third-party = %s, want partial", g61.Status)
	}
	m31 := findSub(Map(provenanceScan(), comps), "MANAGE 3.1")
	if m31.Status != StatusPartial {
		t.Errorf("MANAGE 3.1 = %s, want partial", m31.Status)
	}
}

func TestMeasureNotApplicableWithoutEval(t *testing.T) {
	comps := []Component{{Category: "model", Name: "m", Provider: "P", EvidenceCount: 1}}
	if findSub(Map(provenanceScan(), comps), "MEASURE 1.1").Status != StatusNotApplicable {
		t.Error("MEASURE 1.1 without eval should be not-applicable")
	}
	evalComps := []Component{{Category: "evaluation", Name: "lm-eval", EvidenceCount: 1}}
	if findSub(Map(provenanceScan(), evalComps), "MEASURE 1.1").Status != StatusInformational {
		t.Error("MEASURE 1.1 with eval should be informational")
	}
}

func TestMap51NotEvidenceable(t *testing.T) {
	if findSub(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "MAP 5.1").Status != StatusNotApplicable {
		t.Error("MAP 5.1 impact should be not-applicable (not evidenceable)")
	}
}

func TestSummarize(t *testing.T) {
	fns := Map(provenanceScan(), []Component{
		{Category: "model", Name: "gpt-4o", Provider: "OpenAI", Task: "chat", EvidenceCount: 2, EvidenceMethods: []string{"source"}},
		{Category: "evaluation", Name: "lm-eval", EvidenceCount: 1},
	})
	s := SummarizeFunctions(fns)
	total := 0
	for _, f := range fns {
		total += len(f.Subcategories)
	}
	if s.Subcategories != total {
		t.Errorf("summary subcategory count = %d, want %d", s.Subcategories, total)
	}
	if s.Satisfied+s.Partial+s.Gap+s.Informational+s.NotApplicable != s.Subcategories {
		t.Errorf("status counts don't sum: %+v", s)
	}
}

// The nistairmf package must reuse the euaiact Status vocabulary so a GUI
// renders both frameworks with one color map.
func TestStatusTypesAreShared(t *testing.T) {
	var s Status = euaiact.StatusSatisfied
	if s != StatusSatisfied {
		t.Error("Status type not shared with euaiact")
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
