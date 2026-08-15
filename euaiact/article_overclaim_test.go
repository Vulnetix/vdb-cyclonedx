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

// F-048 and F-050. Articles that bind this customer were absent from the report
// while their evidence sat loaded and unread, and 13 context fields the sibling
// AI frameworks already read were ignored here.
//
// The articles are asserted by name because their absence is not visible in any
// count: a report with 12 articles looks complete until you know which 12.
func TestArticlesThatBindTheCustomerArePresent(t *testing.T) {
	present := map[string]bool{}
	for _, a := range MapReport(maximalCtx()) {
		present[a.Article] = true
	}
	for _, id := range []string{
		"Article 4",  // AI literacy — binds every deployer
		"Article 17", // quality management system
		"Article 18", // documentation keeping
		"Article 19", // automatically generated logs
		"Article 20", // corrective actions
		"Article 26", // deployer obligations
		"Article 53", // GPAI provider obligations
		"Article 55", // systemic-risk obligations
		"Article 73", // serious-incident reporting
	} {
		if !present[id] {
			t.Errorf("%s is absent from the report", id)
		}
	}
}

// The signals each new article rests on have to reach it, or the article is a
// heading with nothing under it.
func TestNewArticlesCiteTheirEvidence(t *testing.T) {
	ctx := maximalCtx()
	for _, tc := range []struct{ id, want string }{
		{"Article 17", "Build gate"},
		{"Article 19", "access record"},
		{"Article 20", "finding"},
		{"Article 26", "attributable decision"},
		{"Article 53", "model"},
		{"Article 55", "assessment run"},
	} {
		got := reportArticle(t, ctx, tc.id)
		if len(got.Evidence) == 0 {
			t.Errorf("%s cites nothing on a maximal estate", tc.id)

			continue
		}
		var found bool
		for _, e := range got.Evidence {
			if strings.Contains(e.Component, tc.want) || strings.Contains(e.Detail, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not cite %q: %+v", tc.id, tc.want, got.Evidence)
		}
	}
}

// F-050's mechanical half, kept as a test so the next field added to the shared
// context cannot be read by the sibling AI frameworks and silently ignored here.
func TestArticle15AndTheQmsReadTheSharedScannerSignals(t *testing.T) {
	ctx := maximalCtx()
	a15 := reportArticle(t, ctx, "Article 15")
	var runs string
	for _, e := range a15.Evidence {
		if strings.Contains(e.Component, "assessment run") {
			runs = e.Detail
		}
	}
	if runs == "" {
		t.Fatal("Article 15 cites no assessment runs")
	}
	for _, want := range []string{"repositor", "distinct tool"} {
		if !strings.Contains(runs, want) {
			t.Errorf("assessment-run evidence = %q, missing %q — the signal is on the context and the sibling frameworks read it", runs, want)
		}
	}

	a17 := reportArticle(t, ctx, "Article 17")
	var seenPolicy, seenVersions bool
	for _, e := range a17.Evidence {
		if e.Component == "Risk methodology" || e.Component == "Licence policy" {
			seenPolicy = true
		}
		if strings.Contains(e.Detail, "recorded tool version") {
			seenVersions = true
		}
	}
	if !seenPolicy {
		t.Error("Article 17 reads neither the risk methodology nor the licence policy")
	}
	if !seenVersions {
		t.Error("Article 17 does not name the tool versions the verification ran")
	}
}
