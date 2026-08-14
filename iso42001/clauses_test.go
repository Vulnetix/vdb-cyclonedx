package iso42001

// Guards F-068: the clause 4–10 disclaimer was a false statement of limitation.
//
// The report told the customer the management-system clauses "describe
// processes an inventory cannot evidence", while the ISO 27001 builder
// evidenced the equivalent Annex SL clauses — C.6.1.2, C.6.1.3, C.7.3, C.8.1,
// C.9.1, C.10.1 — from the *same* embedded ReportContext. 42001 and 27001 share
// Annex SL, so the mapping was near 1:1. An unimplemented mapping was being
// described to the buyer as a property of the standard.

import (
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func clauseControls(ctx ReportContext) []ControlMapping {
	for _, c := range MapReport(ctx) {
		if c.Category == ClauseCategory {
			return c.Controls
		}
	}

	return nil
}

func TestClausesAreEvidencedNotDisclaimed(t *testing.T) {
	ctx := ReportContext{
		Components:             []euaiact.Component{{Name: "gpt-4o", Category: "model", Task: "chat"}},
		AibomScanCount:         6,
		ScannerRunCount:        40,
		ScannerRunCategories:   []string{"sast", "sca"},
		ScannerRunByCategory:   map[string]int{"sast": 20, "sca": 20},
		ScannerRepoCount:       3,
		HasMethodology:         true,
		RiskStrategyName:       "Exploitation first",
		RiskStrategyRuleCount:  22,
		RiskStrategyIsCustom:   true,
		SsvcDecisionCount:      40,
		FixedTotal:             12,
		NotAffectedTotal:       5,
		OpenVexCount:           3,
		SuppressionCount:       7,
		IngestionSnapshotCount: 9,
		RemediationDaysBySev:   map[string]int{"critical": 7, "high": 14, "medium": 30, "low": 90},
		QualityGateConfigured:  true,
		QualityGateSeverity:    "high",
		CliRunCount:            18,
	}

	ctls := clauseControls(ctx)
	if len(ctls) == 0 {
		t.Fatal("the report emits no management-system clause mappings at all")
	}
	for _, c := range ctls {
		if c.Status == "" {
			t.Errorf("%s carries no status", c.ID)
		}
		if len(c.Evidence) == 0 {
			t.Errorf("%s cites no evidence on an input where every signal it reads is present", c.ID)
		}
		// A management system is not certifiable from telemetry, and every one
		// of these controls must say what it cannot see rather than implying
		// the clause is met.
		if c.Status == euaiact.StatusSatisfied {
			t.Errorf("%s = satisfied; machine telemetry evidences a slice of a management-system clause, never the whole", c.ID)
		}
		if len(c.Gaps) == 0 {
			t.Errorf("%s records no gap, so the unevidenced half of the clause is invisible", c.ID)
		}
	}
}

func TestClausesGapOutOnAnEmptyTenant(t *testing.T) {
	// The other half of the honesty: with nothing recorded, these must read as
	// gaps rather than quietly partial. No findings is not a managed system.
	for _, c := range clauseControls(ReportContext{}) {
		if c.Status != euaiact.StatusGap {
			t.Errorf("%s = %q on an empty tenant, want %q", c.ID, c.Status, euaiact.StatusGap)
		}
	}
}

func TestClausesAreNotCountedAsAnnexA(t *testing.T) {
	// Annex A coverage is stated as "N of 38" in the console. Counting clause
	// controls into that numerator would repeat F-072, where more coverage made
	// the number less honest.
	for _, c := range MapReport(ReportContext{}) {
		if c.Category == ClauseCategory {
			continue
		}
		if !strings.HasPrefix(c.Category, "A.") {
			t.Errorf("category %q is neither Annex A nor the clause category; the console's Annex A fraction cannot classify it", c.Category)
		}
	}
}
