package euaiact

// Guards F-044: Article 15's accuracy claim.
//
// "Accuracy" is the first word of Article 15's title, and the only thing in the
// report that spoke to it was a mis-derivation. HasEvaluation is
// `count(*) FROM "Finding" WHERE "isTestSuite" = true` — security findings
// *located in test code* — and Article 15 rendered it as "Model
// evaluation/benchmark workload present". That is not a model evaluation, not a
// benchmark, and not a workload.
//
// Meanwhile the AI-BOM's `evaluation` components, TestFrameworks and
// CliTestConfigCount — real records of test and evaluation tooling, already
// read by ISO 42001 — went unused here.

import (
	"strings"
	"testing"
)

func art15(ctx ReportContext) ArticleMapping {
	for _, a := range MapReport(ctx) {
		if a.Article == "Article 15" {
			return a
		}
	}
	panic("Article 15 missing")
}

func TestArticle15DoesNotCallTestSuiteFindingsAModelEvaluation(t *testing.T) {
	m := art15(ReportContext{ScannerRunCount: 12, FindingTotal: 30, HasEvaluation: true})
	for _, e := range m.Evidence {
		if strings.Contains(e.Detail, "Model evaluation") || strings.Contains(e.Detail, "benchmark") {
			t.Errorf("test-suite findings are described as %q; isTestSuite means a security finding sits in test code, not that a model was evaluated", e.Detail)
		}
	}
}

func TestArticle15IsNotSatisfiedWithoutAccuracyEvidence(t *testing.T) {
	// Everything Vulnetix can see about cybersecurity and robustness, and
	// nothing at all about accuracy.
	m := art15(ReportContext{
		ScannerRunCount: 40, FindingTotal: 100, HasEvaluation: true,
		ReachabilityTotal: 50, SarifResultTotal: 80, SarifResultReviewed: 80,
		QualityGateConfigured: true, CliBreakBuildCount: 10, CliRunCount: 12,
		AiFirewallConfigured: true, AiFirewallGuardrailCount: 4,
	})
	if m.Status == StatusSatisfied {
		t.Error("Article 15 = satisfied with no accuracy evidence of any kind; accuracy is the first obligation the article names")
	}
	joined := strings.ToLower(m.Rationale + " " + strings.Join(m.Gaps, " "))
	if !strings.Contains(joined, "accuracy") {
		t.Errorf("neither the rationale nor the gaps mention accuracy: %q / %v", m.Rationale, m.Gaps)
	}
}

func TestArticle15IsSatisfiedWithRealEvaluationTooling(t *testing.T) {
	// The satisfied claim stays reachable for an organisation that does
	// evaluate: evaluation tooling in the AI-BOM is the machine record of it.
	m := art15(ReportContext{
		ScannerRunCount: 40, FindingTotal: 100,
		ReachabilityTotal: 50, SarifResultTotal: 80, SarifResultReviewed: 80,
		QualityGateConfigured: true, CliBreakBuildCount: 10, CliRunCount: 12,
		AiFirewallConfigured: true, AiFirewallGuardrailCount: 4,
		CliTestConfigCount: 6, TestFrameworks: []string{"pytest"},
		Components: []Component{
			{Name: "ragas", Category: "evaluation", Provider: "explodinggradients"},
			{Name: "gpt-4o", Category: "model", Provider: "OpenAI", Task: "chat"},
		},
	})
	if m.Status != StatusSatisfied {
		t.Errorf("Article 15 = %q with evaluation tooling, a test-framework inventory and full security assurance, want %q", m.Status, StatusSatisfied)
	}
}
