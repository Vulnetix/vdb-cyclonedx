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

func TestReportAiFirewallSignals(t *testing.T) {
	// Firewall policy alone rescues GOVERN 3.1 from gap.
	fw := euaiact.ReportContext{AiFirewallConfigured: true, AiFirewallGuardrailCount: 2}
	if s := findSubR(MapReport(fw), "GOVERN 3.1").Status; s != StatusSatisfied {
		t.Errorf("GOVERN 3.1 with firewall policy = %s, want satisfied", s)
	}
	// Runtime-only measurement (no findings) → MEASURE 2.1 partial.
	rt := euaiact.ReportContext{AiFirewallConfigured: true, AiFirewallLogsEnabled: true, AiFirewallRequestCount: 100, AiFirewallBlockCount: 4}
	m21 := findSubR(MapReport(rt), "MEASURE 2.1")
	if m21.Status != StatusPartial {
		t.Errorf("MEASURE 2.1 runtime-only = %s, want partial", m21.Status)
	}
	// Gateway interventions count as risk treatment for MANAGE 1.3.
	if s := findSubR(MapReport(rt), "MANAGE 1.3").Status; s != StatusSatisfied {
		t.Errorf("MANAGE 1.3 with gateway blocks = %s, want satisfied", s)
	}
	// Recurring gateway traffic evidences MANAGE 4.1 post-deployment monitoring.
	if s := findSubR(MapReport(rt), "MANAGE 4.1").Status; s != StatusSatisfied {
		t.Errorf("MANAGE 4.1 with gateway history = %s, want satisfied", s)
	}
	// Evidence links must point at the AI Firewall page.
	linked := false
	for _, e := range findSubR(MapReport(rt), "MEASURE 2.1").Evidence {
		if e.Link == routeAiFirewall {
			linked = true
		}
	}
	if !linked {
		t.Error("MEASURE 2.1 gateway evidence should link to /vdb-ai-firewall")
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

func TestReportCoversEverySubcategoryWithAMapper(t *testing.T) {
	fns := MapReport(richCtx())

	seen := map[string]bool{}
	for _, f := range fns {
		for _, sc := range f.Subcategories {
			if seen[sc.ID] {
				t.Errorf("%s emitted twice", sc.ID)
			}
			seen[sc.ID] = true
		}
	}

	// These five had working mappers in nistairmf.go that MapReport never
	// called, so the report covered less of the framework than a single scan
	// did — while running against strictly more evidence.
	for _, id := range []string{"GOVERN 6.2", "MAP 1.1", "MAP 5.1", "MANAGE 3.1", "MANAGE 4.3"} {
		if !seen[id] {
			t.Errorf("%s has a mapper but is not emitted by the report path", id)
		}
	}
	if len(seen) != 17 {
		t.Errorf("subcategories = %d, want 17", len(seen))
	}

	// The report path must never cover less than the per-scan path.
	perScan := map[string]bool{}
	for _, f := range Map(Scan{}, richCtx().Components) {
		for _, sc := range f.Subcategories {
			perScan[sc.ID] = true
		}
	}
	for id := range perScan {
		if !seen[id] {
			t.Errorf("%s is emitted per-scan but dropped by the report, which sees more evidence", id)
		}
	}
}

func TestReportSummaryCarriesTheFrameworkDenominator(t *testing.T) {
	s := SummarizeReport(MapReport(richCtx()))

	if s.FrameworkTotal != FrameworkSubcategories {
		t.Errorf("FrameworkTotal = %d, want %d — without it a partial mapping reads as strong coverage", s.FrameworkTotal, FrameworkSubcategories)
	}
	if s.Subcategories >= s.FrameworkTotal {
		t.Errorf("mapped %d of %d: the mapped count must stay below the framework total or the disclosure is wrong", s.Subcategories, s.FrameworkTotal)
	}
}

func TestReportMap11CapsAtPartial(t *testing.T) {
	// Both context signals present. MAP 1.1 also requires the requirements for
	// the intended purpose, which no artifact states, so satisfied must be
	// unreachable — a green chip here would claim a human wrote something.
	ctx := richCtx()
	ctx.ScannerRepoCount = 9
	sc := findSubR(MapReport(ctx), "MAP 1.1")

	if sc.Status != StatusPartial {
		t.Errorf("MAP 1.1 with task + setting = %s, want partial", sc.Status)
	}
	if len(sc.Evidence) != 2 {
		t.Errorf("MAP 1.1 evidence = %d, want 2 (declared task and deployment setting)", len(sc.Evidence))
	}

	// No AI at all is not-applicable, not a failure.
	if s := findSubR(MapReport(euaiact.ReportContext{}), "MAP 1.1").Status; s != StatusNotApplicable {
		t.Errorf("MAP 1.1 with no AI = %s, want not-applicable", s)
	}
}

func TestReportManage43NeedsRealChangeTracking(t *testing.T) {
	// One inventory, no AI-authored commits: nothing evidences change tracking.
	one := euaiact.ReportContext{Components: richCtx().Components, AibomScanCount: 1}
	if s := findSubR(MapReport(one), "MANAGE 4.3").Status; s != StatusGap {
		t.Errorf("MANAGE 4.3 with a single inventory = %s, want gap", s)
	}

	// Repeated inventories evidence half of the subcategory. The other half is
	// stakeholder communication, which no artifact shows, so it stays partial.
	many := euaiact.ReportContext{Components: richCtx().Components, AibomScanCount: 12}
	sc := findSubR(MapReport(many), "MANAGE 4.3")
	if sc.Status != StatusPartial {
		t.Errorf("MANAGE 4.3 with repeated inventories = %s, want partial", sc.Status)
	}
	if len(sc.Evidence) == 0 {
		t.Error("MANAGE 4.3 promoted above gap while citing nothing")
	}
}

// TestNoSubcategoryIsCappedBelowSatisfied guards F-062. GOVERN 6.1 and MAP 4.1
// terminated at partial unconditionally, so no organization could satisfy them
// whatever it configured -- and the signals that should have lifted them (the
// AI firewall's provider/model allow-deny rows; a configured licence policy)
// were sitting unread on the context, already consulted by sibling frameworks.
//
// A permanently-unreachable status is invisible: it looks exactly like a
// condition that merely happens not to be met.
func TestNoSubcategoryIsCappedBelowSatisfied(t *testing.T) {
	// Everything on at once. Any subcategory that still cannot reach satisfied
	// or not-applicable under this input is capped by construction.
	ctx := richCtx()
	ctx.ScannerRepoCount = 9
	ctx.HasLicensePolicy = true
	ctx.AiFirewallConfigured = true
	ctx.AiFirewallLogsEnabled = true
	ctx.AiFirewallGuardrailCount = 4
	ctx.AiFirewallEnforcingGuardrails = 4
	ctx.AiFirewallProviderPolicyCount = 3
	ctx.AiFirewallModelPolicyCount = 2
	ctx.AiFirewallRequestCount = 5000
	ctx.PriorScanCount = 12
	ctx.AccessLogCount = 3084
	ctx.CycloneDXCount = 378
	ctx.SsvcDecisionCount = 40
	ctx.RiskStrategyName = "default"
	ctx.RiskStrategyRuleCount = 22

	// MAP 1.1 and MANAGE 4.3 cap at partial on purpose: each carries a second
	// obligation (the requirements for the intended purpose; communicating
	// incidents to stakeholders) that no artifact evidences. MAP 5.1 is
	// not-applicable by construction. Those are documented ceilings, not
	// accidents, so they are listed rather than silently tolerated.
	deliberate := map[string]bool{"MAP 1.1": true, "MANAGE 4.3": true, "MAP 5.1": true}

	for _, fn := range MapReport(ctx) {
		for _, sc := range fn.Subcategories {
			if deliberate[sc.ID] {
				continue
			}
			if sc.Status != StatusSatisfied && sc.Status != StatusNotApplicable {
				t.Errorf("%s = %s under maximal input; it cannot be satisfied by any organization", sc.ID, sc.Status)
			}
		}
	}
}

func TestGovern61ReadsTheProviderPolicyItAsksAbout(t *testing.T) {
	ctx := richCtx()
	if s := findSubR(MapReport(ctx), "GOVERN 6.1").Status; s != StatusPartial {
		t.Errorf("GOVERN 6.1 with no provider policy = %s, want partial", s)
	}

	ctx.AiFirewallProviderPolicyCount = 2
	sc := findSubR(MapReport(ctx), "GOVERN 6.1")
	if sc.Status != StatusSatisfied {
		t.Errorf("GOVERN 6.1 with a provider allow/deny policy = %s, want satisfied", sc.Status)
	}
	if len(sc.Evidence) == 0 {
		t.Error("GOVERN 6.1 satisfied while citing nothing")
	}
}

func TestMap41ReadsTheLicencePolicyItAsksAbout(t *testing.T) {
	ctx := richCtx()
	if s := findSubR(MapReport(ctx), "MAP 4.1").Status; s != StatusPartial {
		t.Errorf("MAP 4.1 with no licence policy = %s, want partial", s)
	}

	ctx.HasLicensePolicy = true
	sc := findSubR(MapReport(ctx), "MAP 4.1")
	if sc.Status != StatusSatisfied {
		t.Errorf("MAP 4.1 with a licence policy = %s, want satisfied", sc.Status)
	}
	if len(sc.Evidence) == 0 {
		t.Error("MAP 4.1 satisfied while citing nothing")
	}
}
