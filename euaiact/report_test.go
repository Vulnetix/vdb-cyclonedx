package euaiact

import (
	"strings"
	"testing"
)

func richReportCtx() ReportContext {
	return ReportContext{
		OrgName: "acme", PeriodStart: 1, PeriodEnd: 2,
		Components: []Component{
			{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", Task: "chat", EvidenceCount: 1},
			{Category: "accelerator", Name: "gpu", EvidenceCount: 1},
			{Type: "data", Category: "data", Name: "pvc:train", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "scan-uuid", PriorScanCount: 12,
		FindingTotal: 40000, FindingByCategory: map[string]int{"sca": 5900, "sast": 29000},
		TriagedTotal: 38000, AffectedTotal: 1300, NotAffectedTotal: 311, FixedTotal: 20,
		OpenVexCount: 850, SuppressionCount: 3,
		ScannerRunCount: 1594, IngestionSnapshotCount: 1594, HasEvaluation: true,
		CycloneDXCount: 378, AccessLogCount: 3084,
		AiFirewallConfigured: true, AiFirewallLogsEnabled: true,
		AiFirewallGuardrailCount: 3, AiFirewallGuardrailsByType: map[string]int{"blocked_pattern": 1, "pii_redact": 2},
		AiFirewallEnforcingGuardrails: 2, AiFirewallProviderPolicyCount: 1, AiFirewallModelPolicyCount: 2,
		AiFirewallRequestCount: 500, AiFirewallBlockCount: 12, AiFirewallRedactCount: 5, AiFirewallFlagCount: 3,
	}
}

func findRep(ms []ArticleMapping, article string) *ArticleMapping {
	for i := range ms {
		if ms[i].Article == article {
			return &ms[i]
		}
	}
	return nil
}

func TestReportArt15NowSatisfiable(t *testing.T) {
	// Per-scan Art 15 is not-evidenceable; report-level it becomes satisfiable.
	//
	// Scanner runs and findings are no longer enough on their own: the article
	// names accuracy, robustness and cybersecurity, and security telemetry
	// speaks to two of the three (F-044). The fixture therefore carries
	// evaluation tooling from the AI-BOM, which is the machine record of the
	// accuracy half; without it the correct answer is partial, asserted in
	// accuracy_evidence_test.go.
	ctx := richReportCtx()
	ctx.Components = append(ctx.Components, Component{
		Name: "ragas", Category: "evaluation", Provider: "explodinggradients",
	})
	a15 := findRep(MapReport(ctx), "Article 15")
	if a15 == nil || a15.Status != StatusSatisfied {
		t.Fatalf("Art 15 report = %+v", a15)
	}
	// evidence must carry links
	linked := false
	for _, e := range a15.Evidence {
		if e.Link != "" {
			linked = true
		}
	}
	if !linked {
		t.Error("Art 15 evidence has no links")
	}
}

func TestReportArt12FromAccessLogs(t *testing.T) {
	a12 := findRep(MapReport(richReportCtx()), "Article 12")
	if a12.Status != StatusSatisfied {
		t.Errorf("Art 12 report = %s, want satisfied", a12.Status)
	}
}

func TestReportGapVsNotApplicable(t *testing.T) {
	empty := ReportContext{OrgName: "x"}
	ms := MapReport(empty)
	// Art 12 with no logs/scans/inventory → gap (evaluated, none found)
	if findRep(ms, "Article 12").Status != StatusGap {
		t.Errorf("empty Art 12 should be gap")
	}
	// Art 13 → not-applicable (not evaluable), distinct from gap
	a13 := findRep(ms, "Article 13")
	if a13.Status != StatusNotApplicable {
		t.Errorf("Art 13 should be not-applicable, got %s", a13.Status)
	}
	if a13.Rationale == "" {
		t.Error("Art 13 not-applicable needs a rationale")
	}
}

func TestReportArt72Monitoring(t *testing.T) {
	if findRep(MapReport(richReportCtx()), "Article 72").Status != StatusSatisfied {
		t.Error("repeated snapshots should satisfy Art 72")
	}
	single := ReportContext{IngestionSnapshotCount: 1, ScannerRunCount: 1}
	if findRep(MapReport(single), "Article 72").Status != StatusGap {
		t.Error("single record Art 72 should be gap")
	}
}

func TestReportArt15FirewallDowngrade(t *testing.T) {
	// Models inventoried but no runtime gateway → satisfied downgrades to
	// partial with an explicit gap line.
	ctx := richReportCtx()
	ctx.AiFirewallConfigured = false
	ctx.AiFirewallLogsEnabled = false
	ctx.AiFirewallGuardrailCount = 0
	ctx.AiFirewallRequestCount = 0
	a15 := findRep(MapReport(ctx), "Article 15")
	if a15.Status != StatusPartial {
		t.Fatalf("Art 15 without firewall over inventoried models = %s, want partial", a15.Status)
	}
	if len(a15.Gaps) == 0 {
		t.Error("Art 15 downgrade should state the runtime-controls gap")
	}
	// No AI inventory at all → firewall absence must NOT downgrade. It still
	// reads partial, but for the accuracy gap rather than the runtime-controls
	// one: with no inventory there is no evaluation tooling either, and an
	// organisation with no AI systems has evidenced no accuracy (F-044). What
	// this asserts is that the *reason* changed — the missing firewall is not
	// held against an organisation that runs no models.
	ctx.Components = nil
	a15 = findRep(MapReport(ctx), "Article 15")
	for _, g := range a15.Gaps {
		if strings.Contains(g, "runtime input/output controls") {
			t.Errorf("missing firewall is still held against an org with no inventoried models: %q", g)
		}
	}
	if len(a15.Gaps) != 1 || !strings.Contains(a15.Gaps[0], "accuracy") {
		t.Errorf("Art 15 without an inventory should carry exactly the accuracy gap, got %v", a15.Gaps)
	}
}

func TestReportArt12FirewallLoggingDisabled(t *testing.T) {
	ctx := richReportCtx()
	ctx.AiFirewallLogsEnabled = false
	ctx.AiFirewallRequestCount = 0
	a12 := findRep(MapReport(ctx), "Article 12")
	if a12.Status != StatusSatisfied {
		t.Fatalf("Art 12 = %s", a12.Status)
	}
	found := false
	for _, g := range a12.Gaps {
		if g == "AI gateway configured but inference logging is disabled — runtime AI events are not recorded" {
			found = true
		}
	}
	if !found {
		t.Errorf("Art 12 should flag disabled inference logging: %v", a12.Gaps)
	}
	// With logging on, gateway logs must appear as evidence with a link.
	a12 = findRep(MapReport(richReportCtx()), "Article 12")
	linked := false
	for _, e := range a12.Evidence {
		if e.Link == routeAiFirewall {
			linked = true
		}
	}
	if !linked {
		t.Errorf("Art 12 should cite gateway inference logs: %+v", a12.Evidence)
	}
}

func TestReportArt14GuardrailsRescueGap(t *testing.T) {
	// Only guardrails — no agents, no human review → partial, not gap.
	ctx := ReportContext{AiFirewallConfigured: true, AiFirewallGuardrailCount: 2}
	a14 := findRep(MapReport(ctx), "Article 14")
	if a14.Status != StatusPartial {
		t.Fatalf("Art 14 with only guardrails = %s, want partial", a14.Status)
	}
	// Agents without any gateway → gap line about unguarded agents.
	ctx = ReportContext{Components: []Component{{Category: "agent", Name: "bot", EvidenceCount: 1}}}
	a14 = findRep(MapReport(ctx), "Article 14")
	found := false
	for _, g := range a14.Gaps {
		if g == "Detected autonomous agents have no runtime gateway/guardrails" {
			found = true
		}
	}
	if !found {
		t.Errorf("Art 14 should flag unguarded agents: %v", a14.Gaps)
	}
}

func TestReportEvidenceItemLink(t *testing.T) {
	a14 := findRep(MapReport(richReportCtx()), "Article 14")
	hasFindingsLink := false
	for _, e := range a14.Evidence {
		if e.Link == "/vdb-findings" {
			hasFindingsLink = true
		}
	}
	if !hasFindingsLink {
		t.Errorf("Art 14 should link human triage to /vdb-findings: %+v", a14.Evidence)
	}
}
