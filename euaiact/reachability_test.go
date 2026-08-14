package euaiact

// Guards F-031, and the class it belongs to.
//
// An unreachable status is invisible by construction: a control capped below
// satisfied renders exactly like one whose condition merely happens not to be
// met, so no amount of reading a report reveals it. NIST AI RMF has had this
// sweep since F-062; EU AI Act and ISO 42001 did not, which is why Article 13
// (hardwired not-applicable) and Articles 51-55 (unconditional informational)
// survived unnoticed.
//
// Deliberate ceilings are listed by name with their reason, so the difference
// between "capped on purpose" and "capped by accident" is written down rather
// than inferred.

import (
	"strings"
	"testing"
)

// maximalCtx turns on every signal the builders read, so anything that still
// cannot reach satisfied is capped by construction rather than unexercised.
func maximalCtx() ReportContext {
	return ReportContext{
		OrgName: "acme", PeriodStart: 1, PeriodEnd: 2,
		Components: []Component{
			{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", Task: "chat", ModelArchitecture: "transformer", EvidenceCount: 1},
			{Category: "ai-service", Name: "bedrock", Provider: "AWS", EvidenceCount: 1},
			{Category: "ai-sdk", Name: "openai", Provider: "OpenAI", EvidenceCount: 1},
			{Category: "coding-agent", Name: "claude-code", Provider: "Anthropic", EvidenceCount: 1},
			{Category: "accelerator", Name: "h100", EvidenceCount: 1},
			{Category: "evaluation", Name: "ragas", EvidenceCount: 1},
			{Category: "training", Name: "trainer", EvidenceCount: 1},
			{Category: "vector-database", Name: "pgvector", EvidenceCount: 1},
			{Type: "data", Category: "data", Name: "pvc:train", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "scan-uuid", PriorScanCount: 12,
		FindingTotal: 4000, FindingByCategory: map[string]int{"sca": 900, "sast": 2900, "license": 200},
		FindingBySeverity: map[string]int{"critical": 10, "high": 90, "medium": 900, "low": 3000},
		TriagedTotal:      3800, AffectedTotal: 130, NotAffectedTotal: 311, FixedTotal: 200, UnderInvestigationTotal: 20,
		OpenVexCount: 850, SuppressionCount: 3, HasEvaluation: true,
		ScannerRunCount: 1594, ScannerRunCategories: []string{"sast", "sca", "secrets", "iac", "container"},
		ScannerRunByCategory: map[string]int{"sast": 800, "sca": 700, "secrets": 40, "iac": 40, "container": 14},
		ScannerRepoCount:     9, ScannerToolNames: []string{"vulnetix", "sonarqube"},
		IngestionSnapshotCount: 1594, CycloneDXCount: 378, SPDXCount: 12, AccessLogCount: 3084,
		HasTriagePolicy: true, HasMethodology: true, HasLicensePolicy: true,
		TriagePolicyName: "Standard", RemediationDaysBySev: map[string]int{"critical": 7, "high": 14, "medium": 30, "low": 90},
		TriageThresholdDays: 3, SsvcDecisionCount: 40,
		RiskStrategyName: "Exploitation first", RiskStrategyRuleCount: 22, RiskStrategyIsCustom: true,
		RiskStrategyMetrics:   []string{"epss", "kev"},
		QualityGateConfigured: true, QualityGateSeverity: "high", QualityGateExploits: "poc",
		QualityGateBlocks: []string{"sast", "sca", "malware"}, QualityGateVersionLag: 3,
		CliRunCount: 400, CliBreakBuildCount: 380, CliFailedGateCount: 42, CliTestConfigCount: 9,
		TestFrameworks: []string{"pytest", "vitest"}, CliVersions: []string{"1.2.3"},
		AiFirewallConfigured: true, AiFirewallLogsEnabled: true,
		AiFirewallGuardrailCount: 6, AiFirewallEnforcingGuardrails: 6,
		AiFirewallGuardrailsByType:    map[string]int{"blocked_pattern": 3, "pii_redact": 3},
		AiFirewallProviderPolicyCount: 3, AiFirewallModelPolicyCount: 2,
		AiFirewallRequestCount: 5000, AiFirewallBlockCount: 12, AiFirewallRedactCount: 5, AiFirewallFlagCount: 3,
		ReachabilityTotal: 500, ReachabilityByVerdict: map[string]int{"REACHABLE": 100, "UNREACHABLE": 400},
		SarifResultTotal: 900, SarifResultReviewed: 900,
		CodeReviewTotal: 90, CodeReviewApproved: 80, CodeReviewIndependent: 78, CodeReviewPullRequests: 90, CodeReviewReviewers: 12, CodeReviewReposCovered: 9,
		SecretAlertTotal: 5, SecretAlertResolved: 5,
		SonarFindingTotal: 40, SonarFindingOpen: 2, SonarRuleTypes: []string{"BUG", "VULNERABILITY"},
		Snapshot: SnapshotRollup{Ingested: 4000, Prioritized: 3800, Outcomes: 200, PatchAvailable: 300},
	}
}

func TestNoArticleIsCappedBelowSatisfied(t *testing.T) {
	// Deliberate ceilings, each with the reason it cannot be lifted from
	// telemetry. Anything else capped under maximal input is an accident.
	deliberate := map[string]string{
		"Articles 51-55": "systemic-risk classification hinges on a training-compute (FLOP) figure Vulnetix does not measure",
	}

	for _, a := range MapReport(maximalCtx()) {
		if _, ok := deliberate[a.Article]; ok {
			continue
		}
		if a.Status != StatusSatisfied && a.Status != StatusNotApplicable {
			t.Errorf("%s (%s) = %s under maximal input; no organization can reach satisfied — rationale: %s",
				a.Article, a.Title, a.Status, a.Rationale)
		}
	}
}

// TestManualEvidencePromotesTheDocumentOnlyArticles guards F-031's other half:
// the articles whose only possible evidence is a document the customer
// attaches. Article 13 was hardwired not-applicable while its own rationale
// asked for an upload, and Articles 51-55 were pinned informational — so the
// instruction was inert and neither could ever move.
func TestManualEvidencePromotesTheDocumentOnlyArticles(t *testing.T) {
	base := maximalCtx()
	for _, id := range []string{"Article 13", "Articles 51-55"} {
		before := findRep(MapReport(base), id)
		if before == nil {
			t.Fatalf("%s missing from the report", id)
		}
		if before.Status == StatusSatisfied {
			t.Errorf("%s = satisfied with nothing attached; Vulnetix holds no evidence for it", id)
		}

		with := base
		with.ManualEvidenceByControl = map[string]int{id: 2}
		after := findRep(MapReport(with), id)
		if after.Status != StatusSatisfied {
			t.Errorf("%s = %q with two attached documents, want %q — attaching evidence is a human act and the rationale asks for it",
				id, after.Status, StatusSatisfied)
		}
		if len(after.Evidence) == 0 {
			t.Errorf("%s cites no evidence after an upload; the attachment is the evidence", id)
		}
		// The claim rests on documents nobody machine-verified, and must say so.
		if !strings.Contains(after.Rationale, "customer-supplied") && !strings.Contains(after.Rationale, "customer evidence") {
			t.Errorf("%s does not disclose that the verdict rests on customer-supplied evidence: %q", id, after.Rationale)
		}
	}
}
