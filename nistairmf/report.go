package nistairmf

// report.go maps a whole compliance report (org + period + scope, aggregated
// across all evidence sources) onto the AI RMF functions, reusing the same
// ReportContext as euaiact. Evidence items carry Links to their source pages.

import "github.com/Vulnetix/vdb-cyclonedx/euaiact"

// ReportContext is the aggregated evidence view (aliased from euaiact so the
// handler builds one context for every framework).
type ReportContext = euaiact.ReportContext

const (
	routeFindings  = "/vdb-findings"
	routeScans     = "/vdb-scanner-results"
	routeInventory = "/vdb-ai-inventory"
)

// MapReport returns the AI RMF function mappings for a whole report.
func MapReport(ctx ReportContext) []FunctionMapping {
	inv := classify(ctx.Components)
	return []FunctionMapping{
		{
			Function: "GOVERN", Title: "Govern",
			Description: "Policies, accountability and inventory mechanisms for AI are in place.",
			Subcategories: []SubcategoryMapping{
				rGovern16(ctx, inv),
				rGovern31(ctx),
				rGovern61(ctx, inv),
			},
		},
		{
			Function: "MAP", Title: "Map",
			Description: "AI systems are categorized; context, capabilities, provenance and risks are mapped.",
			Subcategories: []SubcategoryMapping{
				rMap21(ctx, inv),
				rMap22(inv),
				rMap41(ctx, inv),
			},
		},
		{
			Function: "MEASURE", Title: "Measure",
			Description: "Methods and metrics are applied; AI risks are analyzed, assessed and tracked over time.",
			Subcategories: []SubcategoryMapping{
				rMeasure11(ctx),
				rMeasure21(ctx),
				rMeasure31(ctx),
			},
		},
		{
			Function: "MANAGE", Title: "Manage",
			Description: "AI risks are prioritized, treated and monitored over the lifetime.",
			Subcategories: []SubcategoryMapping{
				rManage11(ctx),
				rManage21(ctx),
				rManage41(ctx),
			},
		},
	}
}

func invLink(ctx ReportContext) string {
	if ctx.LatestAibomScanUUID != "" {
		return routeInventory + "/" + ctx.LatestAibomScanUUID
	}
	return routeInventory
}

// ── GOVERN ───────────────────────────────────────────────────────────────────

func rGovern16(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 1.6", "AI system inventory",
		"Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.")
	if len(inv.all) == 0 && ctx.AibomScanCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory records exist for the scope."
		m.Gaps = append(m.Gaps, "No AI-BOM inventory found")
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "AI component"), Kind: "provenance", Detail: "Automatically inventoried across " + plural(ctx.AibomScanCount, "scan"), Link: invLink(ctx)})
	m.Status = StatusSatisfied
	m.Rationale = "An automatic AI-system inventory exists and is regenerated on each scan."
	return m
}

func rGovern31(ctx ReportContext) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 3.1", "Risk management policy",
		"Processes, procedures and practices for managing AI risks are in place and resourced.")
	if !ctx.HasTriagePolicy && !ctx.HasMethodology && !ctx.HasLicensePolicy {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no triage policy, scoring methodology or license policy is configured for the org."
		m.Gaps = append(m.Gaps, "No risk-management policy configured")
		return m
	}
	if ctx.HasTriagePolicy {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "triage policy", Kind: "policy", Detail: "SLA/remediation risk policy configured"})
	}
	if ctx.HasMethodology {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "scoring methodology", Kind: "policy", Detail: "SSVC/scoring decision methodology configured"})
	}
	if ctx.HasLicensePolicy {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "license policy", Kind: "policy", Detail: "License-analysis policy configured"})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Documented risk-management policy (triage/methodology/license) is configured and applied to scans."
	return m
}

func rGovern61(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 6.1", "Third-party risk policies",
		"Policies address AI risks from third-party software, data and supply chain.")
	third := len(inv.sdks) + len(inv.services) + len(inv.providers) + ctx.FindingByCategory["sca"]
	if third == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no third-party AI software, providers or supply-chain findings recorded."
		m.Gaps = append(m.Gaps, "No third-party AI dependencies found")
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "Third-party AI provider", Link: invLink(ctx)})
	}
	sortEvidence(m.Evidence)
	if n := ctx.FindingByCategory["sca"]; n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(n, "SCA finding"), Kind: "finding", Detail: "Third-party dependency risks identified", Link: routeFindings})
	}
	m.Status = StatusPartial
	m.Rationale = "Third-party AI and dependency risks are inventoried and scanned; policy adherence is a governance activity beyond the inventory."
	return m
}

// ── MAP ──────────────────────────────────────────────────────────────────────

func rMap21(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 2.1", "AI system categorization",
		"The specific tasks and methods used to implement the AI system are defined and categorized.")
	if len(inv.models) == 0 && len(inv.services) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no models or services found to categorize."
		m.Gaps = append(m.Gaps, "No AI methods found")
		return m
	}
	untasked := 0
	sortByName(inv.models)
	for _, mdl := range inv.models {
		d := "Model"
		if mdl.Task != "" {
			d += " — task " + mdl.Task
		} else {
			untasked++
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: d, Link: invLink(ctx)})
	}
	if untasked > 0 {
		m.Status = StatusPartial
		m.Rationale = "AI methods are categorized; " + plural(untasked, "model") + " lack a resolved task."
		m.Gaps = append(m.Gaps, plural(untasked, "model")+" without a categorized task")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Models are categorized by task and serving methods enumerated."
	}
	return m
}

func rMap22(inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 2.2", "Knowledge limits documented",
		"Information about the AI system's knowledge limits is documented.")
	if len(inv.all) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory to document limits for."
		return m
	}
	if len(inv.gapped) == 0 {
		m.Status = StatusSatisfied
		m.Rationale = "Every component was fully resolved — the inventory states no unverified knowledge limits."
		return m
	}
	sortByName(inv.gapped)
	for _, c := range inv.gapped {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: c.Name, Kind: "log", Detail: "Documented knowledge limit: " + c.GapReason})
	}
	m.Status = StatusSatisfied
	m.Rationale = "The inventory explicitly documents its knowledge limits rather than hiding them."
	return m
}

func rMap41(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 4.1", "Third-party & legal risks",
		"Approaches for mapping technology and legal risks — including third-party software/data and IP — are in place.")
	if len(inv.providers) == 0 && ctx.FindingByCategory["license"] == 0 && ctx.FindingByCategory["sca"] == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no third-party providers or license/dependency findings recorded."
		m.Gaps = append(m.Gaps, "No third-party legal-risk surface found")
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "Third-party provider — technology/legal-risk surface", Link: invLink(ctx)})
	}
	sortEvidence(m.Evidence)
	if n := ctx.FindingByCategory["license"]; n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(n, "license finding"), Kind: "finding", Detail: "License/IP legal risks identified", Link: routeFindings})
	}
	m.Status = StatusPartial
	m.Rationale = "Third-party providers and legal/license risks are mapped from the inventory and scans."
	return m
}

// ── MEASURE ──────────────────────────────────────────────────────────────────

func rMeasure11(ctx ReportContext) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 1.1", "Metrics & methods identified",
		"Approaches and metrics for measuring AI risks are selected and applied.")
	if ctx.ScannerRunCount == 0 && !ctx.HasEvaluation {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no assessment runs or evaluation workloads recorded."
		m.Gaps = append(m.Gaps, "No measurement methods in use")
		return m
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Automated risk-measurement methods applied", Link: routeScans})
	}
	if ctx.HasEvaluation {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "evaluation", Kind: "runtime", Detail: "Model evaluation workload present", Link: invLink(ctx)})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Automated measurement methods (security scanning, evaluation) are applied across the period."
	return m
}

func rMeasure21(ctx ReportContext) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 2.1", "Risks analyzed & assessed",
		"AI systems are evaluated and their risks analyzed and assessed.")
	if ctx.FindingTotal == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no findings were recorded to analyze."
		m.Gaps = append(m.Gaps, "No findings found")
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FindingTotal, "finding"), Kind: "finding", Detail: "Identified risks analyzed and scored", Link: routeFindings})
	if ctx.TriagedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.TriagedTotal, "triaged finding"), Kind: "finding", Detail: "Assessed via triage decisions", Link: routeFindings})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Risks are analyzed and assessed via scored, triaged findings across the reporting period."
	return m
}

func rMeasure31(ctx ReportContext) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 3.1", "Risks tracked over time",
		"Mechanisms are in place to track identified AI risks over time.")
	if ctx.IngestionSnapshotCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — only a single assessment record exists; tracking over time needs repeated assessment."
		m.Gaps = append(m.Gaps, "No risk-tracking history yet")
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.IngestionSnapshotCount, "assessment snapshot"), Kind: "scan", Detail: "Risk posture tracked over time", Link: routeScans})
	m.Status = StatusSatisfied
	m.Rationale = "Repeated assessment snapshots track how AI risks change over the period."
	return m
}

// ── MANAGE ───────────────────────────────────────────────────────────────────

func rManage11(ctx ReportContext) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 1.3", "Risk treatment prioritized",
		"Responses to high-priority AI risks are developed, planned and documented.")
	treated := ctx.AffectedTotal + ctx.FixedTotal + ctx.OpenVexCount + ctx.SuppressionCount
	if treated == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no risk-treatment records (triage outcomes, VEX, suppressions) found."
		m.Gaps = append(m.Gaps, "No risk treatment recorded")
		return m
	}
	if ctx.FixedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FixedTotal, "fixed finding"), Kind: "finding", Detail: "Risks remediated", Link: routeFindings})
	}
	if ctx.OpenVexCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.OpenVexCount, "VEX statement"), Kind: "vex", Detail: "Documented risk-treatment decisions"})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.SuppressionCount, "suppression"), Kind: "vex", Detail: "Documented risk-acceptance decisions"})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Risk treatment is documented via remediations, VEX statements and risk-acceptance records."
	return m
}

func rManage21(ctx ReportContext) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 2.1", "Treatment resources & VEX",
		"Resources are allocated to treat and document AI risks, including impact statements.")
	if ctx.OpenVexCount == 0 && ctx.NotAffectedTotal == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no VEX/not-affected justifications recorded."
		m.Gaps = append(m.Gaps, "No documented impact/justification statements")
		return m
	}
	if ctx.OpenVexCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.OpenVexCount, "VEX statement"), Kind: "vex", Detail: "Impact/justification statements recorded"})
	}
	if ctx.NotAffectedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.NotAffectedTotal, "not-affected finding"), Kind: "finding", Detail: "Justified as not affected", Link: routeFindings})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Risk treatment is documented with VEX impact statements and justified dispositions."
	return m
}

func rManage41(ctx ReportContext) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 4.1", "Post-deployment monitoring",
		"Post-deployment monitoring plans are implemented, capturing and evaluating changes.")
	if ctx.IngestionSnapshotCount <= 1 && ctx.ScannerRunCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no recurring assessment history yet."
		m.Gaps = append(m.Gaps, "No monitoring history")
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Recurring post-deployment monitoring", Link: routeScans})
	m.Status = StatusSatisfied
	m.Rationale = "Recurring assessments implement post-deployment monitoring across the period."
	return m
}

// SummarizeReport rolls report-level function mappings into a Summary.
func SummarizeReport(fns []FunctionMapping) Summary { return SummarizeFunctions(fns) }
