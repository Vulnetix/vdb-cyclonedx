package iso42001

import "testing"

func provenanceScan() Scan {
	return Scan{RepoName: "acme/repo", CommitSha: "deadbeefcafe", ToolName: "vulnetix-aibom", ToolVersion: "v3.65.1", CreatedAt: 1784000000000, ComponentCount: 1, PriorScanCount: 1}
}

func findCtl(cats []CategoryMapping, id string) *ControlMapping {
	for i := range cats {
		for j := range cats[i].Controls {
			if cats[i].Controls[j].ID == id {
				return &cats[i].Controls[j]
			}
		}
	}
	return nil
}

func TestSixCategoriesPresent(t *testing.T) {
	cats := Map(provenanceScan(), []Component{{Category: "model", Name: "m", Provider: "OpenAI", EvidenceCount: 1}})
	want := map[string]bool{"A.4": false, "A.5": false, "A.6": false, "A.7": false, "A.8": false, "A.10": false}
	for _, c := range cats {
		want[c.Category] = true
		if len(c.Controls) == 0 {
			t.Errorf("%s has no controls", c.Category)
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("missing category %s", k)
		}
	}
}

func TestA42ResourcesInventory(t *testing.T) {
	c := findCtl(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "A.4.2")
	if c == nil || c.Status != StatusSatisfied {
		t.Fatalf("A.4.2 w/ provenance = %+v", c)
	}
	c2 := findCtl(Map(Scan{ComponentCount: 1}, []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "A.4.2")
	if c2.Status != StatusPartial {
		t.Errorf("A.4.2 no provenance = %s, want partial", c2.Status)
	}
	c3 := findCtl(Map(provenanceScan(), nil), "A.4.2")
	if c3.Status != StatusNotApplicable {
		t.Errorf("A.4.2 empty = %s, want not-applicable", c3.Status)
	}
}

func TestA628EventLogs(t *testing.T) {
	all := findCtl(Map(provenanceScan(), []Component{
		{Category: "model", Name: "a", EvidenceCount: 1, EvidenceMethods: []string{"source"}},
		{Category: "coding-agent", Name: "b", EvidenceCount: 2, EvidenceMethods: []string{"commit"}},
	}), "A.6.2.8")
	if all.Status != StatusSatisfied {
		t.Errorf("A.6.2.8 full evidence = %s, want satisfied", all.Status)
	}
	partial := findCtl(Map(provenanceScan(), []Component{
		{Category: "model", Name: "a", EvidenceCount: 1},
		{Category: "model", Name: "b", EvidenceCount: 0},
	}), "A.6.2.8")
	if partial.Status != StatusPartial {
		t.Errorf("A.6.2.8 missing-evidence = %s, want partial", partial.Status)
	}
}

func TestA627TechnicalDocGapDisclosed(t *testing.T) {
	c := findCtl(Map(provenanceScan(), []Component{
		{Category: "inference", Name: "Triton", ConfidenceGap: true, GapReason: "version unverified: tag not semver-shaped", EvidenceCount: 1},
	}), "A.6.2.7")
	if c.Status != StatusPartial {
		t.Fatalf("A.6.2.7 gapped = %s, want partial", c.Status)
	}
	found := false
	for _, g := range c.Gaps {
		if contains(g, "not semver-shaped") {
			found = true
		}
	}
	if !found {
		t.Errorf("gap reason not disclosed: %v", c.Gaps)
	}
}

func TestA75DataProvenance(t *testing.T) {
	if findCtl(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "A.7.5").Status != StatusNotApplicable {
		t.Error("A.7.5 without datasets should be not-applicable")
	}
	sourced := findCtl(Map(provenanceScan(), []Component{
		{Type: "data", Category: "data", Name: "pvc:train", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
	}), "A.7.5")
	if sourced.Status != StatusSatisfied {
		t.Errorf("A.7.5 sourced dataset = %s, want satisfied", sourced.Status)
	}
	nosrc := findCtl(Map(provenanceScan(), []Component{
		{Type: "data", Category: "data", Name: "ds", DataKind: "dataset", EvidenceCount: 1},
	}), "A.7.5")
	if nosrc.Status != StatusPartial {
		t.Errorf("A.7.5 no-source dataset = %s, want partial", nosrc.Status)
	}
}

func TestA624VerificationInformational(t *testing.T) {
	if findCtl(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "A.6.2.4").Status != StatusNotApplicable {
		t.Error("A.6.2.4 without eval should be not-applicable")
	}
	e := findCtl(Map(provenanceScan(), []Component{{Category: "evaluation", Name: "lm-eval", EvidenceCount: 1}}), "A.6.2.4")
	if e.Status != StatusInformational {
		t.Errorf("A.6.2.4 with eval = %s, want informational", e.Status)
	}
}

func TestA54NotEvidenceable(t *testing.T) {
	if findCtl(Map(provenanceScan(), []Component{{Category: "model", Name: "m", EvidenceCount: 1}}), "A.5.4").Status != StatusNotApplicable {
		t.Error("A.5.4 societal impact should be not-applicable")
	}
}

func TestThirdPartySuppliers(t *testing.T) {
	comps := []Component{
		{Category: "ai-service", Name: "OpenAI API", Provider: "OpenAI", EvidenceCount: 1},
		{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
	}
	if findCtl(Map(provenanceScan(), comps), "A.10.3").Status != StatusPartial {
		t.Error("A.10.3 with suppliers should be partial")
	}
}

func TestSummarize(t *testing.T) {
	cats := Map(provenanceScan(), []Component{
		{Category: "model", Name: "gpt-4o", Provider: "OpenAI", Task: "chat", EvidenceCount: 2, EvidenceMethods: []string{"source"}},
		{Category: "evaluation", Name: "lm-eval", EvidenceCount: 1},
	})
	s := SummarizeCategories(cats)
	total := 0
	for _, c := range cats {
		total += len(c.Controls)
	}
	if s.Controls != total {
		t.Errorf("summary control count = %d, want %d", s.Controls, total)
	}
	if s.Satisfied+s.Partial+s.Gap+s.Informational+s.NotApplicable != s.Controls {
		t.Errorf("status counts don't sum: %+v", s)
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
