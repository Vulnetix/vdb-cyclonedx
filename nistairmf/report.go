package nistairmf

// report.go maps a whole compliance report (org + period + scope, aggregated
// across all evidence sources) onto the AI RMF functions, reusing the same
// ReportContext as euaiact. Evidence items carry Links to their source pages.

import "github.com/Vulnetix/vdb-cyclonedx/euaiact"

// ReportContext is the aggregated evidence view (aliased from euaiact so the
// handler builds one context for every framework).
type ReportContext = euaiact.ReportContext

const (
	routeFindings     = "/vdb-findings"
	routeScans        = "/vdb-scanner-results"
	routeInventory    = "/vdb-ai-inventory"
	routeAiFirewall   = "/vdb-ai-firewall"
	routeRiskStrategy = "/vdb-risk-strategy"
	routePolicies     = "/vdb-suppression-policies"
	routeGate         = "/vdb-quality-gate"
)

func quoted(s string) string { return `"` + s + `"` }

// MapReport returns the AI RMF function mappings for a whole report.
func MapReport(ctx ReportContext) []FunctionMapping {
	fns := mapReportFunctions(ctx)
	for i := range fns {
		for j := range fns[i].Subcategories {
			euaiact.StampInventoryRefs(ctx, fns[i].Subcategories[j].Evidence)
		}
	}

	return fns
}

func mapReportFunctions(ctx ReportContext) []FunctionMapping {
	inv := classify(ctx.Components)
	return []FunctionMapping{
		{
			Function: "GOVERN", Title: "Govern",
			Description: "Policies, accountability and inventory mechanisms for AI are in place.",
			Subcategories: []SubcategoryMapping{
				rGovern16(ctx, inv),
				rGovern31(ctx),
				rGovern61(ctx, inv),
				// Implemented for the per-scan mapper and never called here, so
				// the report — which sees strictly more evidence — covered less
				// of the framework than a single scan did.
				govern62(inv),
			},
		},
		{
			Function: "MAP", Title: "Map",
			Description: "AI systems are categorized; context, capabilities, provenance and risks are mapped.",
			Subcategories: []SubcategoryMapping{
				rMap11(ctx, inv),
				rMap21(ctx, inv),
				rMap22(ctx, inv),
				rMap41(ctx, inv),
				// Not evidenceable, and emitted as such: a subcategory absent
				// from the report cannot be graded and nothing says it is gone.
				map51(),
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
				rManage31(ctx, inv),
				rManage41(ctx),
				rManage43(ctx, inv),
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
	if !ctx.HasTriagePolicy && !ctx.HasMethodology && !ctx.HasLicensePolicy && !ctx.AiFirewallConfigured {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no triage policy, scoring methodology or license policy is configured for the org."
		m.Gaps = append(m.Gaps, "No risk-management policy configured")
		return m
	}
	if ctx.HasTriagePolicy {
		detail := "SLA/remediation risk policy configured"
		if ctx.HasRemediationSLA() {
			detail = "Policy " + quoted(ctx.TriagePolicyName) + ": remediation windows " +
				itoa(ctx.RemediationDaysBySev["critical"]) + "/" + itoa(ctx.RemediationDaysBySev["high"]) + "/" +
				itoa(ctx.RemediationDaysBySev["medium"]) + "/" + itoa(ctx.RemediationDaysBySev["low"]) +
				" days (critical/high/medium/low), " + itoa(ctx.TriageThresholdDays) + "-day triage threshold"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "triage policy", Kind: "policy", Detail: detail, Link: routePolicies})
	}
	// The ordered risk-prioritization strategy is the executable procedure: it
	// decides which AI-related risk is treated first, and it is auditable.
	if ctx.HasRiskStrategy() {
		scope := "system default"
		if ctx.RiskStrategyIsCustom {
			scope = "organization-authored"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "risk-prioritization strategy", Kind: "policy",
			Detail: quoted(ctx.RiskStrategyName) + " (" + scope + "), " + plural(ctx.RiskStrategyRuleCount, "enabled rule") +
				" ranking vulnerability, end-of-life and malware risk in remediation order",
			Link: routeRiskStrategy,
		})
	}
	if ctx.SsvcDecisionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SsvcDecisionCount, "SSVC decision record"), Kind: "policy",
			Detail: "Each prioritization call is reproducible from its recorded inputs", Link: routeFindings,
		})
	}
	if ctx.HasMethodology {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "scoring methodology", Kind: "policy", Detail: "SSVC/scoring decision methodology configured"})
	}
	if ctx.HasLicensePolicy {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "license policy", Kind: "policy", Detail: "License-analysis policy configured"})
	}
	if ctx.AiFirewallConfigured {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "AI Firewall policy", Kind: "policy", Detail: plural(ctx.AiFirewallGuardrailCount, "guardrail") + " plus provider/model allow-deny enforced at the gateway", Link: routeAiFirewall})
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

	// This terminated at partial unconditionally, so no organization could ever
	// satisfy it — while the AI firewall's provider and model allow/deny rows
	// are literally a policy addressing which third-party AI may be used, and
	// both sibling frameworks already read them. The subcategory asks for
	// policies that address third-party AI risk; an enforced allow/deny list is
	// one, so satisfied is now reachable on real configuration.
	policies := ctx.AiFirewallProviderPolicyCount + ctx.AiFirewallModelPolicyCount
	if policies > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(policies, "provider/model policy"), Kind: "policy",
			Detail: "Allow/deny rules governing which third-party AI providers and models may be used",
			Link:   routeAiFirewall,
		})
		m.Status = StatusSatisfied
		m.Rationale = "Third-party AI is inventoried and scanned, and an enforced allow/deny policy governs which providers and models may be used."

		return m
	}

	m.Status = StatusPartial
	m.Rationale = "Third-party AI and dependency risks are inventoried and scanned, but no policy governs which providers or models may be used."
	m.Gaps = append(m.Gaps, "No provider or model allow/deny policy is configured")
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
	// The gate admits services as well as models, but only models were cited —
	// so an inventory of AI services and no models read "Models are categorized
	// by task and serving methods enumerated" while enumerating nothing. The
	// serving method is exactly what a service *is*, so it belongs here.
	sortByName(inv.services)
	for _, svc := range inv.services {
		d := "Serving method — " + svc.Category
		if svc.Provider != "" {
			d += " via " + svc.Provider
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: svc.Name, Kind: "service", Detail: d, Link: invLink(ctx)})
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

func rMap22(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 2.2", "Knowledge limits documented",
		"Information about the AI system's knowledge limits is documented.")
	if len(inv.all) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory to document limits for."
		return m
	}
	if len(inv.gapped) == 0 {
		// This claimed satisfied with an empty evidence list, on the strength of
		// an absence: no component carried a resolution gap. Two problems. The
		// claim was unsamplable — there was nothing for an assessor to check —
		// and a fully-resolved inventory is a statement about *our* resolution
		// confidence, not documentation of the AI system's knowledge limits
		// (training cutoff, context window, domain), which is what MAP 2.2 asks
		// for. The inventory is real evidence toward it, so it is cited and the
		// remaining obligation named, rather than claimed or dropped.
		m.Status = StatusPartial
		m.Rationale = "Every component in the inventory resolved without a confidence gap, so nothing is recorded as unverified. The AI system's own knowledge limits — training cutoff, context window, domain of validity — are not derivable from the inventory and need manual evidence."
		m.Gaps = append(m.Gaps, "No documented knowledge limits for the AI systems themselves")
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(len(inv.all), "inventoried component"), Kind: "inventory",
			Detail: "All resolved with no unverified entries", Link: invLink(ctx),
		})
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

	// Also terminated at partial unconditionally. The subcategory asks whether
	// an *approach* for mapping legal and IP risk is in place — a configured
	// licence policy is exactly that, and it was sitting unread on the context.
	if ctx.HasLicensePolicy {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "Licence policy", Kind: "policy",
			Detail: "A configured licence policy is the documented approach for mapping IP and legal risk in third-party software",
			Link:   routePolicies,
		})
		m.Status = StatusSatisfied
		m.Rationale = "Third-party providers and legal/licence risks are mapped from the inventory and scans, against a configured licence policy."

		return m
	}

	m.Status = StatusPartial
	m.Rationale = "Third-party providers and legal/licence risks are mapped from the inventory and scans, but no licence policy states how they are to be judged."
	m.Gaps = append(m.Gaps, "No licence policy configured, so there is no documented approach for judging IP and legal risk")
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
	// Naming the methods matters more than the run count: a measurement program
	// is only as broad as the analysis categories it actually exercises.
	if ctx.ScannerCategoryCount() > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "measurement breadth", Kind: "scan",
			Detail: plural(ctx.ScannerCategoryCount(), "analysis category") + " exercised (" + joinStrings(ctx.ScannerRunCategories) +
				") across " + plural(ctx.ScannerRepoCount, "repository") + " by " + plural(len(ctx.ScannerToolNames), "distinct tool"),
			Link: routeScans,
		})
	}
	if ctx.ReachabilityTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "reachability analysis", Kind: "analysis",
			Detail: plural(ctx.ReachabilityTotal, "call-path verdict") + ": " + itoa(ctx.ReachableCount()) + " reachable, " +
				itoa(ctx.ReachabilityByVerdict["UNREACHABLE"]) + " ruled unreachable",
			Link: routeFindings,
		})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Automated measurement methods (security scanning, evaluation) are applied across the period."
	return m
}

func joinStrings(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func rMeasure21(ctx ReportContext) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 2.1", "Risks analyzed & assessed",
		"AI systems are evaluated and their risks analyzed and assessed.")
	if ctx.FindingTotal == 0 && ctx.AiFirewallRequestCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no findings were recorded to analyze."
		m.Gaps = append(m.Gaps, "No findings found")
		return m
	}
	if ctx.FindingTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FindingTotal, "finding"), Kind: "finding", Detail: "Identified risks analyzed and scored", Link: routeFindings})
	}
	if ctx.TriagedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.TriagedTotal, "triaged finding"), Kind: "finding", Detail: "Assessed via triage decisions", Link: routeFindings})
	}
	if ctx.AiFirewallLogsEnabled && ctx.AiFirewallRequestCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference"), Kind: "log", Detail: "Screened against guardrails: " + itoa(ctx.AiFirewallBlockCount) + " blocked, " + itoa(ctx.AiFirewallRedactCount) + " redacted, " + itoa(ctx.AiFirewallFlagCount) + " flagged", Link: routeAiFirewall})
	}
	if ctx.FindingTotal == 0 {
		m.Status = StatusPartial
		m.Rationale = "Runtime inferences are measured against guardrails; no static findings were recorded to analyze."
		return m
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
	// The snapshot rollup is the per-run accounting behind the trend: what was
	// ingested, what was closed, and why.
	if ctx.Snapshot.Any() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "disposition accounting", Kind: "log",
			Detail: itoa(ctx.Snapshot.Ingested) + " ingested → " + itoa(ctx.Snapshot.Prioritized) + " prioritized → " +
				itoa(ctx.Snapshot.Outcomes) + " outcome(s); " + itoa(ctx.Snapshot.AutoResolvedTotal()) + " auto-resolved, " +
				itoa(ctx.Snapshot.DedupTotal()) + " deduplicated, " + itoa(ctx.Snapshot.SsvcTotal()) + " SSVC-classified",
			Link: routeScans,
		})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Repeated assessment snapshots track how AI risks change over the period."
	return m
}

// ── MANAGE ───────────────────────────────────────────────────────────────────

func rManage11(ctx ReportContext) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 1.3", "Risk treatment prioritized",
		"Responses to high-priority AI risks are developed, planned and documented.")
	// AffectedTotal is findings triaged as *affected* — confirmed vulnerable
	// and not remediated. Counting them as risk treatment meant 500 confirmed,
	// untreated findings scored "Risk treatment prioritized" as satisfied.
	treated := ctx.FixedTotal + ctx.OpenVexCount + ctx.SuppressionCount + ctx.AiFirewallBlockCount + ctx.AiFirewallRedactCount
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
	if n := ctx.AiFirewallBlockCount + ctx.AiFirewallRedactCount; n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(n, "gateway intervention"), Kind: "policy", Detail: itoa(ctx.AiFirewallBlockCount) + " blocked and " + itoa(ctx.AiFirewallRedactCount) + " redacted inference(s) — automated risk treatment at runtime", Link: routeAiFirewall})
	}
	// Prioritization is what makes treatment "high-priority first" rather than
	// arbitrary; the build gate is what stops an untreated risk from shipping.
	if ctx.HasRiskStrategy() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "risk-prioritization strategy", Kind: "policy",
			Detail: quoted(ctx.RiskStrategyName) + " orders treatment across " + plural(ctx.RiskStrategyRuleCount, "enabled rule"),
			Link:   routeRiskStrategy,
		})
	}
	if ctx.QualityGateConfigured && ctx.CliBreakBuildCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "build-time gate", Kind: "policy",
			Detail: itoa(ctx.CliBreakBuildCount) + " of " + itoa(ctx.CliRunCount) + " pipeline run(s) set to break the build; " +
				itoa(ctx.CliFailedGateCount) + " stopped a change",
			Link: routeGate,
		})
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
	if ctx.IngestionSnapshotCount <= 1 && ctx.ScannerRunCount <= 1 && ctx.AiFirewallRequestCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no recurring assessment history yet."
		m.Gaps = append(m.Gaps, "No monitoring history")
		return m
	}
	// Every counter that can clear the guard above must also be able to emit
	// evidence, or the subcategory reports satisfied citing nothing. Snapshots
	// were the missing one.
	if ctx.IngestionSnapshotCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.IngestionSnapshotCount, "assessment snapshot"), Kind: "scan", Detail: "Risk posture recorded over time", Link: routeScans})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Recurring post-deployment monitoring", Link: routeScans})
	}
	if ctx.AiFirewallRequestCount > 0 {
		detail := "Runtime AI usage monitored at the gateway over the period"
		if !ctx.AiFirewallLogsEnabled {
			detail = "Gateway inference volume observed; per-inference logging is currently disabled"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference"), Kind: "log", Detail: detail, Link: routeAiFirewall})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Recurring assessments implement post-deployment monitoring across the period."
	return m
}

// rManage31 is the report-scoped twin of manage31.
//
// The per-scan version terminates at partial, correctly: one scan evidences the
// monitoring half of the subcategory and nothing about applied risk controls.
// Over a report the AI firewall's enforcing guardrails and provider/model
// allow-deny rows are exactly those controls, so the second half becomes
// evidenceable and the ceiling comes off.
func rManage31(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := manage31(inv)
	if m.Status == StatusNotApplicable {
		return m
	}

	controls := ctx.AiFirewallEnforcingGuardrails + ctx.AiFirewallProviderPolicyCount + ctx.AiFirewallModelPolicyCount
	if controls == 0 {
		m.Gaps = append(m.Gaps, "No enforcing guardrail or provider/model policy is applied to third-party AI")

		return m
	}

	m.Evidence = append(m.Evidence, EvidenceItem{
		Component: plural(controls, "applied control"), Kind: "policy",
		Detail: "Enforcing guardrails and provider/model allow-deny rules applied to third-party AI at the gateway",
		Link:   routeAiFirewall,
	})
	m.Status = StatusSatisfied
	m.Rationale = "Third-party AI resources are inventoried and re-inventoried each scan, and risk controls are applied to them at the gateway."

	return m
}

// rMap11 is the report-scoped twin of map11. The per-scan version reads
// hasProvenance(scan) and scan.RepoName; over a period the equivalent signals
// are the scan count and the repos actually covered, which is strictly more
// context than one scan carries.
func rMap11(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 1.1", "Context & intended purpose",
		"Intended purpose, setting and requirements for the AI system are understood and documented.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected in scope, so there is no intended purpose to document."
		return m
	}

	tasks := 0
	for _, mdl := range inv.models {
		if mdl.Task != "" {
			tasks++
		}
	}
	if ctx.ScannerRepoCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRepoCount, "repository"), Kind: "provenance", Detail: "Deployment setting: the codebases the AI is used in", Link: routeScans})
	}
	if tasks > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(tasks, "model"), Kind: "model", Detail: "Declare a task (chat/embedding/…), indicating intended purpose", Link: invLink(ctx)})
	}

	// Both signals describe the setting, never the requirements — those are
	// written by a human. Satisfied is deliberately unreachable here; the
	// ceiling is partial, and it is stated rather than left to be inferred.
	switch {
	case tasks > 0 && ctx.ScannerRepoCount > 0:
		m.Status = StatusPartial
		m.Rationale = "The inventory documents both the declared purpose of the models and the setting they run in. The requirements for that purpose are a human statement the inventory cannot make."
	case tasks > 0 || ctx.ScannerRepoCount > 0:
		m.Status = StatusPartial
		m.Rationale = "Part of the context is documented by the inventory; declared model tasks and deployment setting together give a fuller picture, and the requirements themselves remain a human statement."
	default:
		m.Status = StatusInformational
		m.Rationale = "AI components are inventoried, but none declares a task and no deployment setting is recorded, so the inventory evidences nothing about intended purpose."
		m.Gaps = append(m.Gaps, "No model declares a task, and no deployment setting is recorded")
	}
	return m
}

// rManage43 is the report-scoped twin of manage43. scan.PriorScanCount becomes
// the period's re-inventory history; the AI-authored-commit signal is the same.
func rManage43(ctx ReportContext, inv inventory) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 4.3", "Incidents & changes tracked",
		"Incidents and errors are communicated to relevant stakeholders; changes to the AI system are tracked.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected in scope, so there are no AI changes to track."
		return m
	}

	revisions := ctx.AibomScanCount
	if ctx.PriorScanCount > revisions {
		revisions = ctx.PriorScanCount
	}
	if inv.aiAuthored > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(inv.aiAuthored, "component"), Kind: "log", Detail: "Change history via AI-authored commits — a tracked record of AI-driven changes", Link: invLink(ctx)})
	}
	if revisions > 1 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(revisions, "inventory revision"), Kind: "provenance", Detail: "AI inventory re-taken over the period, tracking what changed", Link: routeInventory})
	}

	// Communication to stakeholders is never observed, so this caps at partial
	// even with both change-tracking signals present — the subcategory is two
	// obligations and Vulnetix evidences one.
	switch {
	case inv.aiAuthored > 0 && revisions > 1:
		m.Status = StatusPartial
		m.Rationale = "Changes to the AI in use are tracked both by AI-authored commit history and by repeated inventory revisions. Communicating incidents and errors to stakeholders is a human process no artifact evidences."
	case inv.aiAuthored > 0 || revisions > 1:
		m.Status = StatusPartial
		m.Rationale = "Some change tracking is evidenced (commit history or repeated inventories). The other half of this subcategory — communicating incidents to stakeholders — is not evidenced by any artifact."
		m.Gaps = append(m.Gaps, "Only one of the two change-tracking signals is present")
	default:
		m.Status = StatusGap
		m.Rationale = "Evaluated — the AI inventory was taken once and no AI-authored commit history was found, so no change tracking is evidenced for the period."
		m.Gaps = append(m.Gaps, "No repeated AI inventory and no AI-authored commit history")
	}
	return m
}

// SummarizeReport rolls report-level function mappings into a Summary.
func SummarizeReport(fns []FunctionMapping) Summary { return SummarizeFunctions(fns) }
