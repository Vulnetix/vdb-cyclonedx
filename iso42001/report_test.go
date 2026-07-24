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
	if findCtlR(MapReport(richCtx()), "A.6.2.4").Status != StatusSatisfied {
		t.Error("A.6.2.4 with scan runs should be satisfied")
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

func TestReportSevenCategories(t *testing.T) {
	cats := MapReport(euaiact.ReportContext{})
	if len(cats) != 7 {
		t.Fatalf("want 7 categories, got %d", len(cats))
	}
	for _, c := range cats {
		for _, ctl := range c.Controls {
			if ctl.Status == "" {
				t.Errorf("%s empty status", ctl.ID)
			}
		}
	}
}
