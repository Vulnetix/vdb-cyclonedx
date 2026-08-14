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
	return map[string]euaiact.ReportContext{
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
