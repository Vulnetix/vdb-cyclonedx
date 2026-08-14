package euaiact

// Guards F-032: the seeded system-default strategy must not certify an
// organization that configured nothing.
//
// loadRiskStrategy falls back to the global isSystemDefault strategy when the
// org has none of its own, and that default ships with 22 enabled rules — so
// HasRiskStrategy() was true for every tenant in the estate. Article 9 requires
// the *provider* to establish, implement, document and maintain the risk
// management system; "our vendor has a default" is not that, and the report
// said "documented end to end".

import "testing"

func articleByTitle(ms []ArticleMapping, article string) *ArticleMapping {
	for i := range ms {
		if ms[i].Article == article {
			return &ms[i]
		}
	}

	return nil
}

func riskCtx(custom bool) ReportContext {
	return ReportContext{
		FindingTotal:          12,
		ScannerRunCount:       6,
		RiskStrategyName:      "Vulnetix default",
		RiskStrategyRuleCount: 22,
		RiskStrategyIsCustom:  custom,
		TriagePolicyName:      "Standard",
		RemediationDaysBySev:  map[string]int{"critical": 7, "high": 14, "medium": 30, "low": 90},
	}
}

func TestArticle9NeedsAnOrgAuthoredRiskStrategy(t *testing.T) {
	m := reportArticle9(riskCtx(false))
	if m.Status == StatusSatisfied {
		t.Errorf("Article 9 = satisfied on the seeded system default; the organization has documented no risk-evaluation method of its own")
	}
	if m.Status != StatusPartial {
		t.Errorf("Article 9 = %q, want %q — the default is in force and does rank risk, so this is not a gap either", m.Status, StatusPartial)
	}
}

func TestArticle9IsSatisfiedWhenTheOrgAuthoredTheStrategy(t *testing.T) {
	// The satisfied claim must stay reachable: the fix must not make Article 9
	// permanently partial in place of permanently satisfied.
	m := reportArticle9(riskCtx(true))
	if m.Status != StatusSatisfied {
		t.Errorf("Article 9 = %q with an organization-authored strategy, committed SLAs and assessment activity, want %q", m.Status, StatusSatisfied)
	}
}
