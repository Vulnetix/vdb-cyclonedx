package iso42001

// report.go maps a whole compliance report (org + period + scope, aggregated
// across all evidence sources) onto ISO/IEC 42001 Annex A controls, reusing the
// same ReportContext as euaiact. Evidence items carry Links to source pages.

import "github.com/Vulnetix/vdb-cyclonedx/euaiact"

// ReportContext is aliased from euaiact so the handler builds one context for
// every framework.
type ReportContext = euaiact.ReportContext

const (
	routeFindings     = "/vdb-findings"
	routeScans        = "/vdb-scanner-results"
	routeInventory    = "/vdb-ai-inventory"
	routeUploads      = "/vdb-uploads"
	routeCrypto       = "/vdb-crypto-inventory"
	routeAiFirewall   = "/vdb-ai-firewall"
	routeRiskStrategy = "/vdb-risk-strategy"
	routePolicies     = "/vdb-suppression-policies"
	routeGate         = "/vdb-quality-gate"
	routeLogs         = "/vdb-logs"
)

// MapReport returns the Annex A control mappings for a whole report.
func MapReport(ctx ReportContext) []CategoryMapping {
	cats := mapReportCategories(ctx)
	for i := range cats {
		for j := range cats[i].Controls {
			euaiact.StampInventoryRefs(ctx, cats[i].Controls[j].Evidence)
		}
	}

	return cats
}

func mapReportCategories(ctx ReportContext) []CategoryMapping {
	inv := classify(ctx.Components)
	return []CategoryMapping{
		{
			Category: "A.2", Title: "Policies related to AI",
			Description: "Documented policy for the development, provision and use of AI systems, with supporting topic-specific policies.",
			Controls: []ControlMapping{
				rA22(ctx),
			},
		},
		{
			// Wholly not-applicable, and said so on the page. Omitting it left
			// Annex A looking like it starts at A.4.
			Category: "A.3", Title: "Internal organization",
			Description: "Roles, responsibilities and reporting arrangements for the AI management system.",
			Controls: []ControlMapping{
				a32(),
				a33(),
			},
		},
		{
			Category: "A.4", Title: "Resources for AI systems",
			Description: "The resources (data, tooling, compute) for AI systems are determined and documented.",
			// a45 maps the same inventory this path already builds. It was
			// implemented for the per-scan mapper and never called here, so the
			// report — which has strictly more evidence — covered less of Annex
			// A than a single scan did.
			Controls: []ControlMapping{
				rA42(ctx, inv),
				rA44(ctx, inv),
				a45(inv),
			},
		},
		{
			Category: "A.5", Title: "Assessing impacts of AI systems",
			Description: "Processes to assess the consequences of AI systems.",
			Controls: []ControlMapping{
				rA52(ctx, inv),
				// Emitted as not-applicable with a stated reason rather than
				// omitted: a control absent from the report cannot be graded,
				// and nothing tells the reader it is missing.
				a54(),
			},
		},
		{
			Category: "A.6", Title: "AI system life cycle",
			Description: "Design, verification, operation, documentation and event logging across the life cycle.",
			Controls: []ControlMapping{
				a623(inv),
				rA624(ctx),
				rA625(ctx),
				rA626(ctx),
				rA627(ctx, inv),
				rA628(ctx),
			},
		},
		{
			Category: "A.7", Title: "Data for AI systems",
			Description: "Data used to develop and operate AI systems, including provenance.",
			Controls: []ControlMapping{
				rA72(ctx, inv),
				a75(inv),
			},
		},
		{
			// A.8 was absent from the report path entirely, though a83 was
			// already written. An omitted category is worse than an unevidenced
			// one: it cannot be graded and nothing says it is missing.
			Category: "A.8", Title: "Information for interested parties",
			Description: "Information about the AI system is available to the parties that need it.",
			Controls: []ControlMapping{
				a83(inv),
			},
		},
		{
			Category: "A.9", Title: "Responsible use of AI systems",
			Description: "Objectives and controls for the responsible use and risk disposition of AI systems.",
			Controls: []ControlMapping{
				rA92(ctx),
			},
		},
		{
			Category: "A.10", Title: "Third-party relationships",
			Description: "AI-related risks from suppliers and third parties are managed.",
			Controls: []ControlMapping{
				a102(inv),
				rA103(ctx, inv),
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

// ── A.2 Policies ──────────────────────────────────────────────────────────────

// rA22 evidences the documented policy set. Vulnetix holds the machine-readable
// half of it: the risk-ranking strategy, the remediation SLA policy, the scoring
// methodology, the license policy, the build gate and the runtime guardrails.
func rA22(ctx ReportContext) ControlMapping {
	m := ctl("A.2", "A.2.2", "AI policy",
		"The organization documents a policy for the development or use of AI systems, supported by topic-specific policies.")
	policies := 0
	if ctx.HasRiskStrategy() {
		// Cited as evidence either way, but only *counted* as a topic-specific
		// policy when the organization authored it. A.2.2 asks what the
		// organization documents; the seeded default is in force for every
		// tenant that configured nothing, and counting it let three real
		// policies plus a vendor default reach the four that read Satisfied.
		if ctx.RiskStrategyIsCustom {
			policies++
		}
		scope := "system default"
		if ctx.RiskStrategyIsCustom {
			scope = "organization-authored"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "risk-prioritization strategy", Kind: "policy",
			Detail: qt(ctx.RiskStrategyName) + " (" + scope + "), " + plural(ctx.RiskStrategyRuleCount, "enabled rule") +
				" ranking vulnerability, end-of-life and malware risk in remediation order",
			Link: routeRiskStrategy,
		})
	}
	if ctx.HasRemediationSLA() {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "remediation policy", Kind: "policy",
			Detail: qt(ctx.TriagePolicyName) + ": " + itoa(ctx.RemediationDaysBySev["critical"]) + "/" +
				itoa(ctx.RemediationDaysBySev["high"]) + "/" + itoa(ctx.RemediationDaysBySev["medium"]) + "/" +
				itoa(ctx.RemediationDaysBySev["low"]) + "-day remediation windows by severity",
			Link: routePolicies,
		})
	} else if ctx.HasTriagePolicy {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "triage policy", Kind: "policy", Detail: "Triage policy configured", Link: routePolicies})
	}
	if ctx.HasMethodology {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "scoring methodology", Kind: "policy", Detail: "Decision methodology documented and field-mapped", Link: routePolicies})
	}
	if ctx.HasLicensePolicy {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "license policy", Kind: "policy", Detail: "Acceptable-license policy configured for third-party components", Link: routeFindings})
	}
	if ctx.QualityGateConfigured {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "build-time policy", Kind: "policy",
			Detail: "Gate blocks " + names(ctx.QualityGateBlocks, "no categories") + " at severity floor " + qt(ctx.QualityGateSeverity) +
				" and exploit maturity " + qt(ctx.QualityGateExploits),
			Link: routeGate,
		})
	}
	if ctx.AiFirewallConfigured {
		policies++
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "runtime AI policy", Kind: "policy",
			Detail: plural(ctx.AiFirewallGuardrailCount, "guardrail") + " plus " +
				plural(ctx.AiFirewallProviderPolicyCount+ctx.AiFirewallModelPolicyCount, "provider/model policy") + " enforced at the gateway",
			Link: routeAiFirewall,
		})
	}
	switch {
	case policies == 0:
		m.Status = StatusGap
		m.Rationale = "Evaluated — no machine-readable policy (risk ranking, remediation SLA, methodology, license, build gate or runtime guardrails) is configured."
		m.Gaps = append(m.Gaps, "No topic-specific AI policies configured")
	case policies >= 4:
		m.Status = StatusSatisfied
		m.Rationale = plural(policies, "topic-specific policy") + " is configured and enforced against real activity, evidencing a documented policy set."
	default:
		m.Status = StatusPartial
		m.Rationale = plural(policies, "topic-specific policy") + " is configured; the overarching AI policy document itself is human-authored — attach it as manual evidence."
		m.Gaps = append(m.Gaps, "Overarching AI policy document not held by Vulnetix")
	}
	return m
}

func qt(s string) string { return `"` + s + `"` }

func names(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	out := list[0]
	for _, s := range list[1:] {
		out += ", " + s
	}
	return out
}

// ── A.4 Resources ─────────────────────────────────────────────────────────────

func rA42(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.2", "AI resources documentation",
		"Information about the resources of the AI system is documented.")
	if len(inv.all) == 0 && ctx.CycloneDXCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory or SBOM resource documentation recorded."
		m.Gaps = append(m.Gaps, "No AI-BOM or SBOM found")
		return m
	}
	if len(inv.all) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "AI resource"), Kind: "provenance", Detail: "Documented in a CycloneDX AI-BOM", Link: invLink(ctx)})
	}
	if ctx.CycloneDXCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.CycloneDXCount, "SBOM"), Kind: "sbom", Detail: "Software resources documented", Link: routeUploads})
	}
	m.Status = StatusSatisfied
	m.Rationale = "AI and software resources are documented in machine-readable inventories."
	return m
}

func rA44(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.4", "Tooling resources",
		"Tooling resources used across the AI life cycle are documented.")
	n := len(inv.tools) + len(inv.sdks) + len(inv.services)
	if n == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI tooling, SDKs or services recorded in the inventory."
		m.Gaps = append(m.Gaps, "No AI tooling found")
		return m
	}
	sortByName(inv.sdks)
	for _, s := range inv.sdks {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "sdk", Detail: "AI SDK/framework tooling", Link: invLink(ctx)})
	}
	m.Status = StatusSatisfied
	m.Rationale = plural(n, "tooling resource") + " documented across the life cycle."
	return m
}

// ── A.5 Impact ────────────────────────────────────────────────────────────────

func rA52(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.5", "A.5.2", "AI system impact assessment process",
		"A process to assess the potential impacts of the AI system is established.")
	if len(inv.models) == 0 && ctx.FindingTotal == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI systems or findings whose impact could be assessed."
		m.Gaps = append(m.Gaps, "No impact-assessment inputs found")
		return m
	}
	if ctx.FindingTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FindingTotal, "finding"), Kind: "finding", Detail: "Risk/impact inputs identified and scored", Link: routeFindings})
	}
	for _, mdl := range inv.models {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: "AI system requiring impact assessment", Link: invLink(ctx)})
	}
	// The ranking strategy is the repeatable estimation method the assessment
	// process needs; without it, impact severity is a per-case judgement call.
	if ctx.HasRiskStrategy() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "impact estimation method", Kind: "policy",
			Detail: qt(ctx.RiskStrategyName) + ": " + plural(ctx.RiskStrategyRuleCount, "enabled rule") +
				" evaluate every identified risk consistently, so impact severity is reproducible rather than ad hoc",
			Link: routeRiskStrategy,
		})
	} else {
		m.Gaps = append(m.Gaps, "No documented ranking method — impact estimation is not reproducible")
	}
	if ctx.SsvcDecisionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SsvcDecisionCount, "SSVC decision record"), Kind: "policy",
			Detail: "Recorded decision inputs and outcomes per assessed risk", Link: routeFindings,
		})
	}
	if ctx.HasRiskStrategy() && ctx.FindingTotal > 0 {
		m.Status = StatusPartial
		m.Rationale = "A reproducible estimation method is applied to identified risks; the organizational impact assessment (affected persons, societal effects) remains a human process — attach it as manual evidence."
		return m
	}
	m.Status = StatusInformational
	m.Rationale = "The inventory and findings provide impact-assessment inputs; a formal impact assessment is a human process — attach it as manual evidence."
	return m
}

// ── A.6 Life cycle ────────────────────────────────────────────────────────────

func rA624(ctx ReportContext) ControlMapping {
	m := ctl("A.6", "A.6.2.4", "Verification & validation",
		"The AI system is verified and validated.")
	if ctx.ScannerRunCount == 0 && !ctx.HasEvaluation {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no verification/validation (scan or evaluation) runs recorded."
		m.Gaps = append(m.Gaps, "No V&V runs found")
		return m
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Automated verification/validation runs", Link: routeScans})
	}
	if ctx.HasEvaluation {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "evaluation", Kind: "runtime", Detail: "Model evaluation workload present", Link: invLink(ctx)})
	}
	// Verification is only as strong as its breadth and whether its results were
	// looked at — cite both rather than the bare run count.
	if ctx.ScannerCategoryCount() > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "verification breadth", Kind: "scan",
			Detail: plural(ctx.ScannerCategoryCount(), "analysis category") + " exercised (" + names(ctx.ScannerRunCategories, "uncategorized") +
				") across " + plural(ctx.ScannerRepoCount, "repository"),
			Link: routeScans,
		})
	}
	if ctx.CliTestConfigCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "test configuration", Kind: "provenance",
			Detail: plural(ctx.CliTestConfigCount, "test configuration") + " detected (" + names(ctx.TestFrameworks, "unclassified frameworks") + ")",
			Link:   routeScans,
		})
	}
	if ctx.SarifResultTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "result review", Kind: "review",
			Detail: itoa(ctx.SarifResultReviewed) + " of " + itoa(ctx.SarifResultTotal) + " analysis result(s) carry a reviewer disposition",
			Link:   routeFindings,
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
	m.Rationale = "The AI/software is verified and validated by recurring automated assessment runs."
	return m
}

// rA625 covers controlled deployment: the build gate is the machine record that
// a release was allowed or refused against declared criteria.
func rA625(ctx ReportContext) ControlMapping {
	m := ctl("A.6", "A.6.2.5", "AI system deployment",
		"The AI system is deployed under a controlled process against defined acceptance criteria.")
	if !ctx.QualityGateConfigured && ctx.CliRunCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no deployment gate is configured and no pipeline-triggered assessment ran, so releases carry no recorded acceptance decision."
		m.Gaps = append(m.Gaps, "No build-time deployment gate")
		return m
	}
	if ctx.QualityGateConfigured {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "acceptance criteria", Kind: "policy",
			Detail: "Blocks " + names(ctx.QualityGateBlocks, "no categories") + "; severity floor " + qt(ctx.QualityGateSeverity) +
				", exploit maturity " + qt(ctx.QualityGateExploits) + ", version lag " + itoa(ctx.QualityGateVersionLag),
			Link: routeGate,
		})
	}
	if ctx.CliRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "deployment decisions", Kind: "scan",
			Detail: plural(ctx.CliRunCount, "pipeline assessment") + "; " + itoa(ctx.CliBreakBuildCount) +
				" set to break the build and " + itoa(ctx.CliFailedGateCount) + " refused a release",
			Link: routeScans,
		})
	}
	if len(ctx.CliVersions) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "toolchain version control", Kind: "provenance",
			Detail: "Assessments ran on " + names(ctx.CliVersions, "an unrecorded version"),
			Link:   routeScans,
		})
	}
	switch {
	case ctx.QualityGateConfigured && ctx.CliBreakBuildCount > 0:
		m.Status = StatusSatisfied
		m.Rationale = "Deployment is gated: acceptance criteria are declared and enforced, and refusals are recorded."
	case ctx.QualityGateConfigured:
		m.Status = StatusPartial
		m.Rationale = "Acceptance criteria are declared, but no assessment in the period was set to block a release — the gate is advisory in practice."
		m.Gaps = append(m.Gaps, "Gate configured but not enforcing")
	default:
		m.Status = StatusPartial
		m.Rationale = "Assessments run in the pipeline, but no acceptance criteria are declared for them to enforce."
		m.Gaps = append(m.Gaps, "No declared acceptance criteria")
	}
	return m
}

func rA626(ctx ReportContext) ControlMapping {
	m := ctl("A.6", "A.6.2.6", "Operation & monitoring",
		"The AI system is operated and monitored, including capturing changes.")
	if ctx.IngestionSnapshotCount <= 1 && ctx.ScannerRunCount <= 1 && ctx.AiFirewallRequestCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no recurring assessment history yet."
		m.Gaps = append(m.Gaps, "No monitoring history")
		return m
	}
	// Every counter that can clear the guard above must also be able to emit
	// evidence, or the control reports satisfied citing nothing.
	if ctx.IngestionSnapshotCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.IngestionSnapshotCount, "assessment snapshot"), Kind: "scan", Detail: "Operational posture recorded over time", Link: routeScans})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Recurring operation monitoring", Link: routeScans})
	}
	if ctx.AiFirewallRequestCount > 0 {
		detail := "Runtime AI operation monitored at the gateway over the period"
		if !ctx.AiFirewallLogsEnabled {
			detail = "Gateway inference volume observed; per-inference logging is currently disabled"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference"), Kind: "log", Detail: detail, Link: routeAiFirewall})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Recurring assessments capture operational changes over the period."
	return m
}

func rA627(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.7", "Technical documentation",
		"Technical documentation of the AI system is created and maintained.")
	if len(inv.all) == 0 && ctx.CycloneDXCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI-BOM or SBOM technical documentation recorded."
		m.Gaps = append(m.Gaps, "No technical documentation found")
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "component"), Kind: "provenance", Detail: "CycloneDX technical inventory", Link: invLink(ctx)})
	if ctx.CycloneDXCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.CycloneDXCount, "SBOM"), Kind: "sbom", Detail: "Software component documentation", Link: routeUploads})
	}
	if len(inv.gapped) > 0 {
		sortByName(inv.gapped)
		for _, c := range inv.gapped {
			m.Gaps = append(m.Gaps, c.Name+": "+c.GapReason)
		}
		m.Status = StatusPartial
		m.Rationale = "Technical documentation exists; " + plural(len(inv.gapped), "component") + " carry a stated limitation."
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Attributable technical documentation exists with no unresolved limitations."
	}
	return m
}

func rA628(ctx ReportContext) ControlMapping {
	m := ctl("A.6", "A.6.2.8", "Recording of event logs",
		"Events over the AI system's life cycle are recorded (logging).")
	if ctx.AccessLogCount == 0 && ctx.ScannerRunCount == 0 && ctx.AiFirewallRequestCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no access-log or assessment-run event records found."
		m.Gaps = append(m.Gaps, "No event logs found")
		if ctx.AiFirewallConfigured && !ctx.AiFirewallLogsEnabled {
			m.Gaps = append(m.Gaps, "AI gateway configured but inference logging is disabled — runtime AI events are not recorded")
		}
		return m
	}
	if ctx.AccessLogCount > 0 {
		detail := "API access events recorded"
		if ctx.AccessLogWithIdentity > 0 {
			detail = itoa(ctx.AccessLogWithIdentity) + " of " + itoa(ctx.AccessLogCount) + " event(s) attributable to a named identity across " +
				plural(ctx.AccessLogMemberCount, "account") + "; " + itoa(ctx.AccessLogWithSource) + " carry a source address"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AccessLogCount, "access-log event"), Kind: "log", Detail: detail, Link: routeLogs})
	}
	if ctx.Snapshot.Any() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "assessment accounting", Kind: "log",
			Detail: itoa(ctx.Snapshot.Ingested) + " ingested, " + itoa(ctx.Snapshot.Prioritized) + " prioritized, " +
				itoa(ctx.Snapshot.Outcomes) + " driven to an outcome; " + itoa(ctx.Snapshot.DedupTotal()) + " deduplicated, " +
				itoa(ctx.Snapshot.AutoResolvedTotal()) + " auto-resolved",
			Link: routeScans,
		})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Assessment events recorded", Link: routeScans})
	}
	if ctx.AiFirewallRequestCount > 0 {
		detail := "Runtime AI events recorded by the AI Firewall gateway (decisions, tokens, latency; no content)"
		if !ctx.AiFirewallLogsEnabled {
			detail = "Gateway inference volume observed; per-inference logging is currently disabled"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference log"), Kind: "log", Detail: detail, Link: routeAiFirewall})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Life-cycle events are recorded via access logs and assessment-run history — the auditable lineage this control requires."
	if ctx.AiFirewallConfigured && !ctx.AiFirewallLogsEnabled {
		m.Gaps = append(m.Gaps, "AI gateway configured but inference logging is disabled — runtime AI events are not recorded")
	}
	return m
}

// ── A.7 Data ──────────────────────────────────────────────────────────────────

func rA72(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.7", "A.7.2", "Data for AI systems",
		"Data used to develop and operate the AI system is identified and managed.")
	n := len(inv.datasets) + len(inv.training) + len(inv.vectordbs)
	if n == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no datasets, training frameworks or retrieval databases recorded."
		m.Gaps = append(m.Gaps, "No data infrastructure found")
		return m
	}
	sortByName(inv.datasets)
	for _, d := range inv.datasets {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: "Dataset used by the AI system", Link: invLink(ctx)})
	}
	for _, v := range inv.vectordbs {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: v.Name, Kind: "runtime", Detail: "Retrieval data store", Link: invLink(ctx)})
	}
	if len(inv.datasets) == 0 {
		m.Status = StatusPartial
		m.Rationale = "Data infrastructure is identified; no concrete dataset artifact resolved."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Data used by the AI system is identified in the inventory."
	}
	return m
}

// ── A.9 Responsible use ───────────────────────────────────────────────────────

func rA92(ctx ReportContext) ControlMapping {
	m := ctl("A.9", "A.9.2", "Responsible use & risk disposition",
		"Processes for the responsible use of AI systems and the disposition of identified risks are in place.")
	disposed := ctx.AffectedTotal + ctx.NotAffectedTotal + ctx.FixedTotal + ctx.OpenVexCount + ctx.SuppressionCount
	if disposed == 0 && ctx.AiFirewallGuardrailCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no risk-disposition records (triage, VEX, suppression) found."
		m.Gaps = append(m.Gaps, "No responsible-use/risk-disposition records")
		return m
	}
	if ctx.AffectedTotal+ctx.NotAffectedTotal+ctx.FixedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AffectedTotal+ctx.NotAffectedTotal+ctx.FixedTotal, "disposed finding"), Kind: "finding", Detail: "Risks dispositioned via triage decisions", Link: routeFindings})
	}
	if ctx.OpenVexCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.OpenVexCount, "VEX statement"), Kind: "vex", Detail: "Documented disposition decisions"})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.SuppressionCount, "suppression"), Kind: "vex", Detail: "Documented risk-acceptance decisions"})
	}
	if ctx.AiFirewallGuardrailCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallGuardrailCount, "guardrail"), Kind: "policy", Detail: "Responsible-use constraints (blocked patterns / PII redaction / message limits) enforced on gateway inferences", Link: routeAiFirewall})
	}
	if disposed == 0 {
		m.Status = StatusPartial
		m.Rationale = "Runtime responsible-use guardrails are configured; no per-finding risk dispositions recorded in scope."
		return m
	}
	m.Status = StatusSatisfied
	m.Rationale = "Responsible use is evidenced by documented triage dispositions, VEX statements and risk-acceptance records."
	return m
}

// ── A.10 Third-party ──────────────────────────────────────────────────────────

func rA103(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.10", "A.10.3", "Suppliers",
		"AI-related risks from suppliers are identified and managed.")
	if len(inv.providers) == 0 && len(inv.sdks) == 0 && ctx.FindingByCategory["sca"] == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no third-party AI suppliers or dependency findings recorded."
		m.Gaps = append(m.Gaps, "No suppliers found")
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "AI supplier in the supply chain", Link: invLink(ctx)})
	}
	sortEvidence(m.Evidence)
	if n := ctx.FindingByCategory["sca"]; n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(n, "SCA finding"), Kind: "finding", Detail: "Supplier/dependency risks scanned", Link: routeFindings})
	}
	m.Status = StatusPartial
	m.Rationale = "AI suppliers are inventoried and their dependency risks scanned each period; supplier-risk management is a downstream activity."
	return m
}

// SummarizeReport rolls report-level category mappings into a Summary.
func SummarizeReport(cats []CategoryMapping) Summary { return SummarizeCategories(cats) }
