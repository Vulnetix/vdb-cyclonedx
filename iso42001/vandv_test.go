package iso42001

// Guards F-070: A.6.2.4 "Verification & validation" is the load-bearing
// life-cycle control for an AIMS certification, and it was discharged by
// software assessment counts.
//
// Three defects in one mapper. The status was assigned unconditionally at the
// end, so it read Satisfied with no scanner run at all (HasEvaluation alone
// clears the gap branch). It claimed "recurring automated assessment runs" at
// n=1. And its rationale read "The AI/software is verified and validated" —
// the slash is where the substitution happens: the auditor asks about the AI
// system, the sentence answers about the software delivering it.
//
// ISO/IEC 42001 A.6.2.4 is about verifying and validating *the AI system*:
// performance against defined requirements and acceptance criteria. SAST and
// SCA runs over the repository do not evidence that.

import (
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func vandv(ctx ReportContext) ControlMapping {
	for _, cat := range MapReport(ctx) {
		for _, c := range cat.Controls {
			if c.ID == "A.6.2.4" {
				return c
			}
		}
	}
	panic("A.6.2.4 missing from the report")
}

func TestVandVIsNotSatisfiedBySoftwareScansAlone(t *testing.T) {
	m := vandv(ReportContext{
		ScannerRunCount:      40,
		ScannerRunCategories: []string{"sast", "sca"},
		ScannerRunByCategory: map[string]int{"sast": 20, "sca": 20},
		ScannerRepoCount:     3,
		HasEvaluation:        true, // Finding.isTestSuite — a software test suite.
	})
	if m.Status == euaiact.StatusSatisfied {
		t.Error("A.6.2.4 = satisfied on SAST/SCA runs and a software test suite; neither validates the AI system against its requirements")
	}
	if strings.Contains(m.Rationale, "AI/software") {
		t.Error("the rationale still says \"AI/software\", answering about the software when the control asks about the AI system")
	}
	if len(m.Gaps) == 0 {
		t.Error("no gap recorded for the unevidenced half of the control")
	}
}

func TestVandVNeedsMoreThanOneRunToBeRecurring(t *testing.T) {
	m := vandv(ReportContext{ScannerRunCount: 1, ScannerRunCategories: []string{"sast"}})
	if strings.Contains(m.Rationale, "recurring") {
		t.Errorf("one assessment run is described as recurring: %q", m.Rationale)
	}
}

func TestVandVIsSatisfiedWithAiEvaluationEvidence(t *testing.T) {
	// The satisfied claim must stay reachable for an organisation that does
	// evaluate its AI systems: evaluation tooling in the AI-BOM is the machine
	// record of that, alongside recurring assessment of the software.
	m := vandv(ReportContext{
		ScannerRunCount:      40,
		ScannerRunCategories: []string{"sast", "sca"},
		ScannerRunByCategory: map[string]int{"sast": 20, "sca": 20},
		ScannerRepoCount:     3,
		Components: []euaiact.Component{
			{Name: "ragas", Category: "evaluation", Provider: "explodinggradients"},
			{Name: "gpt-4o", Category: "model", Provider: "OpenAI", Task: "chat"},
		},
	})
	if m.Status != euaiact.StatusSatisfied {
		t.Errorf("A.6.2.4 = %q with AI evaluation tooling and recurring assessment, want %q", m.Status, euaiact.StatusSatisfied)
	}
}
