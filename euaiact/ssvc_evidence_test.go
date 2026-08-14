package euaiact

// Guards the T0.3 cross-pollination entry for Article 9.
//
// Article 9 is the risk-management system: identify, estimate, evaluate, treat.
// A recorded SSVC decision is the strongest evidence of *evaluation* this
// product holds — a per-risk decision reproducible from its recorded inputs —
// and ISO 27001 C.6.1.2, NIST GOVERN 3.1, Exposure and CRA all cite it.
// Article 9 cited a scanner count and the ranking strategy, and left the
// decisions themselves unread.

import (
	"strings"
	"testing"
)

func TestArticle9CitesRecordedDecisions(t *testing.T) {
	ctx := ReportContext{
		FindingTotal: 400, ScannerRunCount: 40,
		RiskStrategyName: "Exploitation first", RiskStrategyRuleCount: 22, RiskStrategyIsCustom: true,
		TriagePolicyName: "Standard", RemediationDaysBySev: map[string]int{"critical": 7, "high": 14, "medium": 30, "low": 90},
		SsvcDecisionCount: 250, SsvcMethodologies: []string{"ssvc-vulnetix"},
	}

	m := articleByTitle(MapReport(ctx), "Article 9")
	if m == nil {
		t.Fatal("Article 9 missing")
	}
	joined := m.Rationale
	for _, e := range m.Evidence {
		joined += " " + e.Component + " " + e.Detail
	}
	if !strings.Contains(strings.ToLower(joined), "ssvc") && !strings.Contains(strings.ToLower(joined), "decision record") {
		t.Errorf("Article 9 evidences risk evaluation without citing the 250 recorded decisions that are its strongest proof: %q / %+v", m.Rationale, m.Evidence)
	}
}
