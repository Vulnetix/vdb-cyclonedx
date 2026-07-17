package nistairmf

import (
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func richCtx() ReportContext {
	return euaiact.ReportContext{
		Components: []euaiact.Component{
			{Category: "model", Name: "gpt-4o", Provider: "OpenAI", Task: "chat", EvidenceCount: 1},
			{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "s1",
		FindingTotal: 40000, FindingByCategory: map[string]int{"sca": 5900, "license": 27},
		TriagedTotal: 38000, AffectedTotal: 1300, FixedTotal: 20, NotAffectedTotal: 311,
		OpenVexCount: 850, SuppressionCount: 3,
		ScannerRunCount: 1594, IngestionSnapshotCount: 1594, HasEvaluation: true,
		HasTriagePolicy: true, HasMethodology: true,
	}
}

func findSubR(fns []FunctionMapping, id string) *SubcategoryMapping {
	for i := range fns {
		for j := range fns[i].Subcategories {
			if fns[i].Subcategories[j].ID == id {
				return &fns[i].Subcategories[j]
			}
		}
	}
	return nil
}

func TestReportMeasureSatisfiable(t *testing.T) {
	fns := MapReport(richCtx())
	if findSubR(fns, "MEASURE 1.1").Status != StatusSatisfied {
		t.Error("MEASURE 1.1 with scan runs should be satisfied")
	}
	if findSubR(fns, "MEASURE 2.1").Status != StatusSatisfied {
		t.Error("MEASURE 2.1 with findings should be satisfied")
	}
	if findSubR(fns, "MEASURE 3.1").Status != StatusSatisfied {
		t.Error("MEASURE 3.1 with snapshot history should be satisfied")
	}
}

func TestReportManageFromTriageVex(t *testing.T) {
	fns := MapReport(richCtx())
	if findSubR(fns, "MANAGE 1.3").Status != StatusSatisfied {
		t.Error("MANAGE 1.3 with fixed+vex+suppression should be satisfied")
	}
	if findSubR(fns, "MANAGE 2.1").Status != StatusSatisfied {
		t.Error("MANAGE 2.1 with vex should be satisfied")
	}
}

func TestReportGovernPolicy(t *testing.T) {
	if findSubR(MapReport(richCtx()), "GOVERN 3.1").Status != StatusSatisfied {
		t.Error("GOVERN 3.1 with policy should be satisfied")
	}
	noPolicy := euaiact.ReportContext{Components: richCtx().Components, AibomScanCount: 1}
	if findSubR(MapReport(noPolicy), "GOVERN 3.1").Status != StatusGap {
		t.Error("GOVERN 3.1 without policy should be gap")
	}
}

func TestReportEmptyIsGapNotPanic(t *testing.T) {
	fns := MapReport(euaiact.ReportContext{})
	if len(fns) != 4 {
		t.Fatalf("want 4 functions, got %d", len(fns))
	}
	// every subcategory has a status
	for _, f := range fns {
		for _, sc := range f.Subcategories {
			if sc.Status == "" {
				t.Errorf("%s has empty status", sc.ID)
			}
		}
	}
}
