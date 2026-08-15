package euaiact

// F-052, F-053, F-054: three articles whose status did not follow from what the
// data says.
//
//	F-052  Article 10 read `satisfied` because a component categorised
//	       `dataset` exists, while its own rationale said only "inventoried" —
//	       and 10(2)-(5) asks for design choices, provenance, examination for
//	       bias and representativeness
//	F-053  Article 14 satisfied on any suppression at all, and counted
//	       automatic dispositions as human review
//	F-054  Article 15 was hardwired not-applicable on the inventory path and
//	       reachable-satisfied on the report path: one article, two mappers,
//	       opposite verdicts over the same estate

import (
	"strings"
	"testing"
)

func reportArticle(t *testing.T, ctx ReportContext, id string) ArticleMapping {
	t.Helper()
	for _, a := range MapReport(ctx) {
		if a.Article == id {
			return a
		}
	}
	t.Fatalf("%s is absent from the report", id)

	return ArticleMapping{}
}

func TestArticle10DoesNotCallInventoryGovernance(t *testing.T) {
	ctx := ReportContext{Components: []Component{
		{Type: "data", Category: "data", DataKind: "dataset", Name: "training-set", Provider: "acme"},
		{Category: "training", Name: "pytorch", Provider: "meta"},
	}}
	got := reportArticle(t, ctx, "Article 10")

	if got.Status == StatusSatisfied {
		t.Errorf("Article 10 = satisfied because a dataset component exists: %q", got.Rationale)
	}
	if len(got.Gaps) == 0 {
		t.Error("no gap names the governance the article asks for")
	}
	if !strings.Contains(got.Rationale, "Inventory is not governance") {
		t.Errorf("rationale = %q — does not say why an inventory falls short", got.Rationale)
	}

	ctx.ManualEvidenceByControl = map[string]int{"Article 10": 2}
	filed := reportArticle(t, ctx, "Article 10")
	if filed.Status != StatusSatisfied {
		t.Errorf("Article 10 = %q with the data-governance record attached, want satisfied", filed.Status)
	}
}

func TestArticle14NeedsAnAttributableDecision(t *testing.T) {
	// One suppression, nobody's name on it, and dispositions that automation
	// could equally have written.
	anonymous := reportArticle(t, ReportContext{
		SuppressionCount: 1, NotAffectedTotal: 400,
	}, "Article 14")
	if anonymous.Status == StatusSatisfied {
		t.Errorf("Article 14 = satisfied on one unattributed suppression and 400 dispositions any engine could have written: %q", anonymous.Rationale)
	}
	if len(anonymous.Gaps) == 0 {
		t.Error("no gap names the missing attribution")
	}

	named := reportArticle(t, ReportContext{
		SuppressionCount: 3, SuppressionWithOwner: 3, SsvcDecisionByHuman: 4, SarifResultReviewedBy: 12,
	}, "Article 14")
	if named.Status != StatusSatisfied {
		t.Errorf("Article 14 = %q with decisions attributable to named people, want satisfied", named.Status)
	}
	if !strings.Contains(named.Rationale, "named people") {
		t.Errorf("rationale = %q", named.Rationale)
	}
}

// F-054. An article the inventory mapper marks not-applicable *because this
// inventory holds nothing that triggers it* is a statement about the scan, and
// the report may legitimately reach a different verdict over the whole estate.
// What is not legitimate is declaring an obligation unevidenceable in
// principle: `notEvidenceable` said "out of scope for inventory evidence" while
// the report mapper assessed the same article and could reach satisfied.
func TestUnevidenceableArticlesAreNotDeclaredOutOfScope(t *testing.T) {
	ms := Map(Scan{ToolName: "vulnetix"}, []Component{{Category: "model", Name: "m", Provider: "P"}})
	for _, id := range []string{"Article 13", "Article 15"} {
		mp := find(ms, id)
		if mp == nil {
			t.Fatalf("%s missing from the inventory mapping", id)
		}
		if mp.Status == StatusNotApplicable {
			t.Errorf("%s = not-applicable on the inventory path while the report path assesses it — the obligation applies either way", id)
		}
		if strings.Contains(mp.Rationale, "out of scope") {
			t.Errorf("%s rationale claims the obligation is out of scope: %q", id, mp.Rationale)
		}
	}
}
