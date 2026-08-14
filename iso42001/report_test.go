package iso42001

import (
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func richCtx() ReportContext {
	return euaiact.ReportContext{
		Components: []euaiact.Component{
			{Category: "model", Name: "gpt-4o", Provider: "OpenAI", EvidenceCount: 1},
			{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
			{Type: "data", Category: "data", Name: "ds", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "s1",
		FindingTotal: 40000, FindingByCategory: map[string]int{"sca": 5900},
		AffectedTotal: 1300, NotAffectedTotal: 311, FixedTotal: 20,
		OpenVexCount: 850, SuppressionCount: 3,
		ScannerRunCount: 1594, IngestionSnapshotCount: 1594, HasEvaluation: true,
		CycloneDXCount: 378, AccessLogCount: 3084,
	}
}

func findCtlR(cats []CategoryMapping, id string) *ControlMapping {
	for i := range cats {
		for j := range cats[i].Controls {
			if cats[i].Controls[j].ID == id {
				return &cats[i].Controls[j]
			}
		}
	}
	return nil
}

func TestReportEventLogsFromAccessLog(t *testing.T) {
	if findCtlR(MapReport(richCtx()), "A.6.2.8").Status != StatusSatisfied {
		t.Error("A.6.2.8 with access logs should be satisfied")
	}
}

func TestReportVerificationFromScans(t *testing.T) {
	// This asserted Satisfied from scan runs alone, which is the F-070 defect:
	// A.6.2.4 asks whether *the AI system* was verified and validated against
	// its requirements, and SAST/SCA runs over the repository answer about the
	// software delivering it. Scans are half the control, so the expectation is
	// now Partial, and the satisfied case — evaluation tooling recorded in the
	// AI-BOM alongside recurring assessment — is asserted in vandv_test.go.
	m := findCtlR(MapReport(richCtx()), "A.6.2.4")
	if m.Status != StatusPartial {
		t.Errorf("A.6.2.4 with scan runs but no AI evaluation evidence = %q, want %q", m.Status, StatusPartial)
	}
	if len(m.Evidence) == 0 {
		t.Error("the software-verification half is evidenced and must still be cited")
	}
}

func TestReportResponsibleUse(t *testing.T) {
	if findCtlR(MapReport(richCtx()), "A.9.2").Status != StatusSatisfied {
		t.Error("A.9.2 with triage+vex should be satisfied")
	}
	empty := euaiact.ReportContext{Components: richCtx().Components}
	if findCtlR(MapReport(empty), "A.9.2").Status != StatusGap {
		t.Error("A.9.2 without disposition should be gap")
	}
}

func TestReportAiFirewallSignals(t *testing.T) {
	// Guardrails alone rescue A.9.2 to partial (not gap, not satisfied).
	fw := euaiact.ReportContext{AiFirewallConfigured: true, AiFirewallGuardrailCount: 2}
	a92 := findCtlR(MapReport(fw), "A.9.2")
	if a92.Status != StatusPartial {
		t.Errorf("A.9.2 guardrails-only = %s, want partial", a92.Status)
	}
	// Gateway traffic evidences operation monitoring and event logging.
	rt := euaiact.ReportContext{AiFirewallConfigured: true, AiFirewallLogsEnabled: true, AiFirewallRequestCount: 100}
	if s := findCtlR(MapReport(rt), "A.6.2.6").Status; s != StatusSatisfied {
		t.Errorf("A.6.2.6 with gateway history = %s, want satisfied", s)
	}
	if s := findCtlR(MapReport(rt), "A.6.2.8").Status; s != StatusSatisfied {
		t.Errorf("A.6.2.8 with gateway logs = %s, want satisfied", s)
	}
	// Configured but logging off → A.6.2.8 gap carries the logging-disabled line.
	off := euaiact.ReportContext{AiFirewallConfigured: true, AiFirewallGuardrailCount: 1}
	a628 := findCtlR(MapReport(off), "A.6.2.8")
	found := false
	for _, g := range a628.Gaps {
		if g == "AI gateway configured but inference logging is disabled — runtime AI events are not recorded" {
			found = true
		}
	}
	if !found {
		t.Errorf("A.6.2.8 should flag disabled inference logging: %v", a628.Gaps)
	}
}

func TestReportCategoriesAndControls(t *testing.T) {
	cats := MapReport(euaiact.ReportContext{})

	// Was 7 categories / 12 controls. A.3 and A.8 were missing entirely and six
	// controls that already had mappers were never called from this path, so the
	// report covered less of Annex A than a single scan did. Every control still
	// has to carry a status — an unevidenced control is fine, a blank one is not.
	if len(cats) != 9 {
		t.Fatalf("want 9 categories, got %d", len(cats))
	}

	seen := map[string]bool{}
	for _, c := range cats {
		for _, ctl := range c.Controls {
			if ctl.Status == "" {
				t.Errorf("%s empty status", ctl.ID)
			}
			if seen[ctl.ID] {
				t.Errorf("%s emitted twice", ctl.ID)
			}
			seen[ctl.ID] = true
		}
	}

	for _, id := range []string{"A.4.5", "A.5.4", "A.6.2.3", "A.7.5", "A.8.3", "A.10.2"} {
		if !seen[id] {
			t.Errorf("%s has a mapper but is not emitted by the report path", id)
		}
	}
	// A.3 is entirely un-evidenceable, so it is emitted as not-applicable with a
	// stated reason. Silently dropping it made Annex A appear to begin at A.4.
	for _, id := range []string{"A.3.2", "A.3.3"} {
		if !seen[id] {
			t.Errorf("%s is absent; a category the report cannot evidence must still be declared, not omitted", id)
		}
	}
	if len(seen) != 20 {
		t.Errorf("controls = %d, want 20", len(seen))
	}

	// The denominator the summary carries has to be the standard's, not ours.
	s := SummarizeReport(cats)
	if s.AnnexAControls != AnnexATotal {
		t.Errorf("summary AnnexAControls = %d, want %d — without it a partial mapping reads as full coverage", s.AnnexAControls, AnnexATotal)
	}
	if s.Controls >= s.AnnexAControls {
		t.Errorf("mapped %d of %d: the mapped count must stay below the Annex A total or the disclosure is wrong", s.Controls, s.AnnexAControls)
	}
}
