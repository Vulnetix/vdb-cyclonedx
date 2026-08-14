package iso42001

// Guards F-032 for A.2.2 (AI policy).
//
// The control counts topic-specific policies and reads Satisfied at four. The
// seeded system-default risk strategy is in force for every tenant that
// configured nothing, so it was making up a quarter of that threshold: three
// real organizational policies plus a vendor default certified the customer as
// having "a documented policy set".

import (
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

func policyCtx(custom bool) ReportContext {
	return ReportContext{
		RiskStrategyName:      "Vulnetix default",
		RiskStrategyRuleCount: 22,
		RiskStrategyIsCustom:  custom,
		TriagePolicyName:      "Standard",
		RemediationDaysBySev:  map[string]int{"critical": 7, "high": 14, "medium": 30, "low": 90},
		HasMethodology:        true,
		HasLicensePolicy:      true,
	}
}

func TestAiPolicyDoesNotCountTheVendorDefaultAsAnOrgPolicy(t *testing.T) {
	m := rA22(policyCtx(false))
	if m.Status == euaiact.StatusSatisfied {
		t.Errorf("A.2.2 = satisfied on three organizational policies plus Vulnetix's seeded default ranking")
	}
	// The default is still cited: an assessor should see the ranking that is
	// actually in force, labelled as the product's.
	found := false
	for _, e := range m.Evidence {
		if e.Component == "risk-prioritization strategy" {
			found = true
		}
	}
	if !found {
		t.Error("the in-force default strategy is no longer cited as evidence; it should be shown, just not counted")
	}
}

func TestAiPolicyIsSatisfiedOnFourOrgPolicies(t *testing.T) {
	m := rA22(policyCtx(true))
	if m.Status != euaiact.StatusSatisfied {
		t.Errorf("A.2.2 = %q with four organization-authored policies, want %q", m.Status, euaiact.StatusSatisfied)
	}
}
