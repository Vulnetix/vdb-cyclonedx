package iso42001

// Guards the four R3 findings:
//
//	F-071  A.5.2 could never reach satisfied (no such assignment existed) and
//	       A.10.3 was pinned to partial unconditionally, so an organization
//	       that genuinely manages supplier risk had no way to show it
//	F-073  A.4.4 and A.7.2 decided entirely from the component union, touching
//	       the context only to build a deep link — moving the report from Q1 to
//	       Q4 could not change either verdict by a character
//	F-074  evidence was predominantly invariant prose; A.6.2.7 could emit
//	       "0 components — CycloneDX technical inventory" under satisfied
//	F-183  eight Annex A controls had a mapper on the per-scan path and none
//	       here, so the report covered less of the standard than a single scan

import (
	"strings"
	"testing"
)

func reportControl(ctx ReportContext, id string) *ControlMapping {
	for _, cat := range MapReport(ctx) {
		for i := range cat.Controls {
			if cat.Controls[i].ID == id {
				return &cat.Controls[i]
			}
		}
	}

	return nil
}

func TestEveryAnnexAControlOnTheScanPathIsAlsoOnTheReportPath(t *testing.T) {
	scan := map[string]bool{}
	for _, cat := range Map(Scan{ToolName: "vulnetix"}, []Component{{Category: "model", Name: "m", Provider: "p"}}) {
		for _, c := range cat.Controls {
			scan[c.ID] = true
		}
	}
	for id := range scan {
		if reportControl(ReportContext{}, id) == nil {
			t.Errorf("%s is mapped on the per-scan path and absent from the report, which sees strictly more evidence", id)
		}
	}
}

// F-071. Both controls have to be able to reach the top and the bottom.
func TestPinnedControlsCanReachSatisfied(t *testing.T) {
	impact := ReportContext{FindingTotal: 40}
	impact.RiskStrategyRuleCount = 22
	impact.ManualEvidenceByControl = map[string]int{"A.5.2": 1}
	if c := reportControl(impact, "A.5.2"); c == nil || c.Status != StatusSatisfied {
		t.Errorf("A.5.2 = %v with the impact assessment attached; no organization could reach satisfied before", c)
	}

	suppliers := ReportContext{}
	suppliers.Components = []Component{{Category: "managed-ai", Name: "bedrock", Provider: "aws"}}
	suppliers.FindingByCategory = map[string]int{"sca": 12}
	suppliers.PackageFirewallConfigured = true
	suppliers.PackageFirewallToggles = []string{"malware"}
	suppliers.PackageFirewallRequestCount = 400
	suppliers.PackageFirewallBlockCount = 3
	suppliers.QualityGateConfigured = true
	if c := reportControl(suppliers, "A.10.3"); c == nil || c.Status != StatusSatisfied {
		t.Errorf("A.10.3 = %v with an enforcing install gate and a build gate; it was pinned to partial for every organization", c)
	}

	// And the same control must still be able to say the risk is unmanaged.
	observed := suppliers
	observed.PackageFirewallConfigured = false
	observed.QualityGateConfigured = false
	c := reportControl(observed, "A.10.3")
	if c == nil || c.Status == StatusSatisfied {
		t.Errorf("A.10.3 = %v with nothing acting on supplier risk", c)
	}
	if len(c.Gaps) == 0 {
		t.Error("A.10.3 names no gap when supplier risk is observed but not acted on")
	}
}

// F-073. The period has to be able to change the verdict.
func TestInventoryControlsReadThePeriod(t *testing.T) {
	base := ReportContext{Components: []Component{
		{Category: "ai-sdk", Name: "langchain", Provider: "langchain"},
		{Type: "data", Category: "data", DataKind: "dataset", Name: "training-set"},
	}}
	base.PeriodStart = 1735689600000 // 2025-01-01
	base.PeriodEnd = 1743465600000

	current := base
	current.InventoryTakenAt = 1738368000000 // inside the period
	stale := base
	stale.InventoryTakenAt = 1609459200000 // 2021-01-01

	for _, id := range []string{"A.4.4", "A.7.2"} {
		fresh := reportControl(current, id)
		old := reportControl(stale, id)
		if fresh == nil || old == nil {
			t.Fatalf("%s is absent", id)
		}
		if fresh.Status == old.Status && fresh.Rationale == old.Rationale {
			t.Errorf("%s gives the same verdict for an inventory taken inside the period and one taken four years before it", id)
		}
		if !strings.Contains(old.Rationale, "before this reporting period began") {
			t.Errorf("%s does not say the inventory predates the period: %q", id, old.Rationale)
		}
	}
}

// F-074. A satisfied control must not cite an empty population.
func TestTechnicalDocumentationDoesNotCiteZeroComponents(t *testing.T) {
	ctx := ReportContext{CycloneDXCount: 3}
	c := reportControl(ctx, "A.6.2.7")
	if c == nil {
		t.Fatal("A.6.2.7 is absent")
	}
	for _, e := range c.Evidence {
		if strings.HasPrefix(e.Component, "0 ") {
			t.Errorf("A.6.2.7 cites %q — an evidence row for a population that is empty", e.Component)
		}
	}
	if c.Status == StatusSatisfied {
		t.Errorf("A.6.2.7 = satisfied with no AI component inventoried: %q", c.Rationale)
	}
}

// Every evidence link has to be a route the console serves.
func TestEvidenceLinksAreConsoleRoutes(t *testing.T) {
	ctx := ReportContext{FindingTotal: 10, CycloneDXCount: 2, AccessLogCount: 5, MemberCount: 3}
	ctx.Components = []Component{{Category: "model", Name: "m", Provider: "p"}}
	for _, cat := range MapReport(ctx) {
		for _, c := range cat.Controls {
			for _, e := range c.Evidence {
				if e.Link == "" {
					continue
				}
				if !strings.HasPrefix(e.Link, "/resolve/") {
					t.Errorf("%s cites %q, which is not a console route", c.ID, e.Link)
				}
			}
		}
	}
}

// F-183's real point: the report path emitted the *per-scan* versions of eight
// controls, which return not-applicable unconditionally — "an AI inventory
// observes what runs, not who is accountable for it". True of a scan; false of
// a report that holds the account list, the decision attribution and the alert
// trail. Presence alone is not coverage.
func TestBroughtOverControlsUseTheReportContext(t *testing.T) {
	ctx := ReportContext{}
	ctx.MemberCount = 12
	ctx.MfaMemberCount = 12
	ctx.SsvcDecisionByHuman = 6
	ctx.SuppressionWithOwner = 3
	ctx.AlertCount = 4
	ctx.AlertsAcknowledged = 4
	ctx.AlertsAcknowledgers = 2
	ctx.NotifyIntegrations = []string{"slack"}
	ctx.CliManifestCount = 5
	ctx.CliManifestEcosystems = []string{"npm"}
	ctx.CycloneDXCount = 2
	ctx.OpenVexCount = 7
	ctx.Components = []Component{
		{Category: "model", Name: "gpt-4", Provider: "openai", Family: "gpt"},
		{Category: "managed-ai", Name: "bedrock", Provider: "aws"},
		{Category: "accelerator", Name: "a100"},
		{Type: "data", Category: "data", DataKind: "dataset", Name: "training-set", DataSource: "uri"},
	}

	for _, id := range []string{"A.3.2", "A.3.3", "A.4.5", "A.6.2.3", "A.7.5", "A.8.3", "A.10.2"} {
		c := reportControl(ctx, id)
		if c == nil {
			t.Errorf("%s is absent", id)

			continue
		}
		if c.Status == StatusNotApplicable {
			t.Errorf("%s = not-applicable on an estate carrying accounts, decisions, alerts, manifests and datasets — the per-scan verdict, on the report path", id)
		}
		if len(c.Evidence) == 0 {
			t.Errorf("%s cites nothing", id)
		}
	}
}
