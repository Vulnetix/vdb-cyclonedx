package euaiact_test

// Invariant: a control reporting `satisfied` must cite at least one evidence
// item. A positive verdict with an empty Evidence slice is a claim an assessor
// cannot sample.
//
// This once failed with eight violations across all three AI-governance
// builders. The shape was always the same: an unconditional status assignment
// paired with evidence emitters that were each separately guarded, so a counter
// that could clear the status guard had no way to carry the claim. Keep this
// test — the pattern is easy to reintroduce whenever a new signal is added to a
// guard without a matching emitter.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
	"github.com/Vulnetix/vdb-cyclonedx/iso42001"
	"github.com/Vulnetix/vdb-cyclonedx/nistairmf"
)

type violation struct {
	framework string
	control   string
	rationale string
}

// scenarios are contexts a real organisation can be in, each chosen to clear a
// status guard while leaving every evidence emitter's own guard unmet.
func scenarios() map[string]euaiact.ReportContext {
	out := map[string]euaiact.ReportContext{
		// Gateway traffic recorded, then inference logging switched off.
		"firewall-logs-disabled": {
			AiFirewallRequestCount: 5,
			AiFirewallLogsEnabled:  false,
		},
		// Two scanner runs, no snapshots, no AI-BOM history.
		"two-scanner-runs-only": {
			ScannerRunCount: 2,
		},
		// Snapshots exist org-wide; this repo scope has no scanner activity.
		"org-snapshots-no-local-runs": {
			IngestionSnapshotCount: 4,
		},
		// A confirmed-affected finding and nothing else: no fix, no VEX, no
		// suppression, no risk strategy.
		"affected-only-no-treatment": {
			AffectedTotal: 3,
		},
		// Scans ran but resolved no AI components at all.
		"scans-but-empty-inventory": {
			AibomScanCount: 12,
		},
	}

	// One scenario per AI-BOM component category, each holding *only* that
	// kind. This is what the scenarios above could not reach: a control whose
	// status guard counts several inventory kinds while its evidence loop
	// covers only some of them stays green for an organisation holding the
	// uncovered kind. F-069 was exactly that — A.4.4 counted tools, SDKs and
	// services, and emitted evidence for SDKs alone, so an estate full of
	// coding agents printed "3 tooling resources documented" with an empty
	// evidence list. Coding-agent detection is a headline feature, so that is
	// an ordinary customer, not a corner case.
	for _, cat := range []string{
		"model", "ai-service", "inference", "managed-ai", "ai-sdk",
		"coding-agent", "ai-convention", "training", "vector-database",
		"accelerator", "evaluation", "data",
	} {
		c := euaiact.Component{Name: "only-" + cat, Category: cat, Provider: "acme"}
		if cat == "data" {
			c.DataKind = "dataset"
		}
		out["inventory-only-"+cat] = euaiact.ReportContext{
			AibomScanCount: 3,
			Components:     []euaiact.Component{c},
		}
	}

	return out
}

func collect(ctx euaiact.ReportContext) []violation {
	var out []violation

	for _, a := range euaiact.MapReport(ctx) {
		if a.Status == euaiact.StatusSatisfied && len(a.Evidence) == 0 {
			out = append(out, violation{"eu_ai_act", a.Article, a.Rationale})
		}
	}
	for _, fn := range nistairmf.MapReport(ctx) {
		for _, s := range fn.Subcategories {
			if s.Status == euaiact.StatusSatisfied && len(s.Evidence) == 0 {
				out = append(out, violation{"nist_ai_rmf", s.ID, s.Rationale})
			}
		}
	}
	for _, cat := range iso42001.MapReport(ctx) {
		for _, c := range cat.Controls {
			if c.Status == euaiact.StatusSatisfied && len(c.Evidence) == 0 {
				out = append(out, violation{"iso_42001", c.ID, c.Rationale})
			}
		}
	}

	return out
}

func TestAuditSatisfiedImpliesEvidence(t *testing.T) {
	total := 0
	for name, ctx := range scenarios() {
		vs := collect(ctx)
		if len(vs) == 0 {
			continue
		}
		total += len(vs)
		t.Logf("scenario %q — %d control(s) satisfied with no evidence:", name, len(vs))
		for _, v := range vs {
			t.Logf("    %-12s %-16s %s", v.framework, v.control, truncate(v.rationale, 92))
		}
	}
	if total > 0 {
		t.Errorf("%d satisfied-with-no-evidence violation(s) across the AI trio", total)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return fmt.Sprintf("%s…", s[:n])
}

// TestInventoryEvidenceCarriesTheScanRef guards F-182: RefID was declared in
// the Go struct, declared in the TypeScript type, and populated by nothing, so
// an assessor sampling a control could not name the record they checked.
func TestInventoryEvidenceCarriesTheScanRef(t *testing.T) {
	ctx := euaiact.ReportContext{
		Components: []euaiact.Component{
			{Category: "model", Name: "gpt-4o", Provider: "OpenAI", Task: "chat", EvidenceCount: 1},
			{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "scan-abc",
		ScannerRunCount: 40, FindingTotal: 100,
	}

	type stamped struct{ total, withRef int }
	count := func(items []euaiact.EvidenceItem) stamped {
		var s stamped
		for _, e := range items {
			if !strings.HasPrefix(e.Link, "/vdb-ai-inventory") {
				continue
			}
			s.total++
			if e.RefID == "scan-abc" {
				s.withRef++
			}
		}

		return s
	}

	var all stamped
	add := func(s stamped) { all.total += s.total; all.withRef += s.withRef }
	for _, a := range euaiact.MapReport(ctx) {
		add(count(a.Evidence))
	}
	for _, fn := range nistairmf.MapReport(ctx) {
		for _, sc := range fn.Subcategories {
			add(count(sc.Evidence))
		}
	}
	for _, cat := range iso42001.MapReport(ctx) {
		for _, c := range cat.Controls {
			add(count(c.Evidence))
		}
	}

	if all.total == 0 {
		t.Fatal("no inventory-linked evidence in any AI report; the fixture is wrong, not the code")
	}
	if all.withRef != all.total {
		t.Errorf("%d of %d inventory-linked evidence items carry the scan id; an assessor cannot name the record behind the rest",
			all.withRef, all.total)
	}
}

func TestStampInventoryRefsLeavesAggregatesAlone(t *testing.T) {
	// Evidence that does not come from the inventory has no scan behind it, and
	// inventing one would be worse than leaving it blank.
	items := []euaiact.EvidenceItem{
		{Component: "ScannerRun", Link: "/vdb-scanner-results"},
		{Component: "Model", Link: "/vdb-ai-inventory/x"},
		{Component: "Pinned", Link: "/vdb-ai-inventory", RefID: "already-set"},
	}
	euaiact.StampInventoryRefs(euaiact.ReportContext{LatestAibomScanUUID: "scan-1"}, items)

	if items[0].RefID != "" {
		t.Errorf("non-inventory evidence got a scan id: %q", items[0].RefID)
	}
	if items[1].RefID != "scan-1" {
		t.Errorf("inventory evidence = %q, want scan-1", items[1].RefID)
	}
	if items[2].RefID != "already-set" {
		t.Errorf("an existing, more specific id was overwritten: %q", items[2].RefID)
	}
}

func TestStampInventoryRefsIsANoopWithoutAScan(t *testing.T) {
	items := []euaiact.EvidenceItem{{Link: "/vdb-ai-inventory"}}
	euaiact.StampInventoryRefs(euaiact.ReportContext{}, items)
	if items[0].RefID != "" {
		t.Errorf("stamped %q with no scan on record", items[0].RefID)
	}
}
