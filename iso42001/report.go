package iso42001

// report.go maps a whole compliance report (org + period + scope, aggregated
// across all evidence sources) onto ISO/IEC 42001 Annex A controls, reusing the
// same ReportContext as euaiact. Evidence items carry Links to source pages.

import (
	"sort"
	"time"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

// ReportContext is aliased from euaiact so the handler builds one context for
// every framework.
type ReportContext = euaiact.ReportContext

// Console routes. These were `/vdb-*` paths, which the console has not served
// since it moved to `/resolve/*` — every citation in this report reached the
// 404 page.
const (
	routeFindings     = "/resolve/findings"
	routeScans        = "/resolve/scanner-results"
	routeInventory    = "/resolve/ai-inventory"
	routeUploads      = "/resolve/uploads"
	routeCrypto       = "/resolve/crypto-inventory"
	routeAiFirewall   = "/resolve/ai-firewall"
	routeRiskStrategy = "/resolve/risk-strategy"
	routePolicies     = "/resolve/suppression-policies"
	routeGate         = "/resolve/quality-gate"
	routeLogs         = "/resolve/logs"
	routeMembers      = "/resolve/members"
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
		// The management-system clauses come first because they are what an
		// AIMS certification is *about*; Annex A is the control set beneath
		// them. The report used to omit them entirely and tell the reader they
		// were unevidenceable, which was false — see clauses.go.
		clauseCategory(ctx, inv),
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
				// Were the per-scan versions, which return not-applicable
				// unconditionally: "an AI inventory observes what runs, not who
				// is accountable". True of a scan; false of a report that holds
				// the account list, the decision attribution and the alert trail.
				rA32(ctx),
				rA33(ctx),
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
				rA45(ctx, inv),
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
				rA54(ctx),
			},
		},
		{
			Category: "A.6", Title: "AI system life cycle",
			Description: "Design, verification, operation, documentation and event logging across the life cycle.",
			Controls: []ControlMapping{
				rA623(ctx, inv),
				rA624(ctx, inv),
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
				rA75(ctx, inv),
			},
		},
		{
			// A.8 was absent from the report path entirely, though a83 was
			// already written. An omitted category is worse than an unevidenced
			// one: it cannot be graded and nothing says it is missing.
			Category: "A.8", Title: "Information for interested parties",
			Description: "Information about the AI system is available to the parties that need it.",
			Controls: []ControlMapping{
				rA83(ctx, inv),
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
				rA102(ctx, inv),
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
	// The status counts tools, SDKs and services; the evidence used to cover
	// SDKs alone, so an estate of coding agents and AI services printed
	// "3 tooling resources documented across the life cycle" with nothing an
	// assessor could sample. Coding-agent detection is a headline feature, so
	// that was an ordinary customer rather than a corner case.
	sortByName(inv.sdks)
	for _, s := range inv.sdks {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "sdk", Detail: "AI SDK/framework tooling", Link: invLink(ctx)})
	}
	sortByName(inv.tools)
	for _, s := range inv.tools {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "tool", Detail: "AI development tooling — " + s.Category, Link: invLink(ctx)})
	}
	sortByName(inv.services)
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "service", Detail: "AI service used across the life cycle — " + s.Category, Link: invLink(ctx)})
	}
	// When the inventory was taken decides whether this documents the period or
	// a snapshot from another year. Stated rather than assumed: an inventory
	// older than the period it evidences is stale, whatever it contains.
	m.Evidence = append(m.Evidence, inventoryFreshness(ctx))
	if inventoryStale(ctx) {
		m.Status = StatusPartial
		m.Rationale = plural(n, "tooling resource") + " documented, but the inventory behind them was taken " + inventoryAgeClause(ctx) + " — it may not describe the tooling in use during this period."
		m.Gaps = append(m.Gaps, "The AI inventory predates the reporting period")

		return m
	}
	m.Status = StatusSatisfied
	m.Rationale = plural(n, "tooling resource") + " documented across the life cycle, from an inventory taken " + inventoryAgeClause(ctx) + "."

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
	// The control could not reach satisfied by any path: both branches below
	// ended at partial or informational and no assignment to satisfied existed
	// anywhere in the function. The organizational impact assessment is a human
	// document, so the path to satisfied is the customer attaching it — the same
	// path every other document-completed control in this estate uses.
	if n := ctx.ManualEvidenceCount("A.5.2"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the organization's impact assessment: affected persons, societal effects and the conclusions drawn",
		})
		m.Status = StatusSatisfied
		m.Rationale = "A reproducible estimation method is applied to identified risks, and the organization has attached its impact assessment. Vulnetix does not read the attachment — an assessor samples it."

		return m
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

func rA624(ctx ReportContext, inv inventory) ControlMapping {
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
	// The status used to be assigned unconditionally here, and the rationale
	// read "The AI/software is verified and validated" — the slash is where the
	// substitution happened: A.6.2.4 asks whether *the AI system* was verified
	// and validated against its requirements, and SAST/SCA runs over the
	// repository answer about the software delivering it. Vulnetix can see AI
	// evaluation tooling in the AI-BOM, and that is the machine record of the
	// AI half; without it the control is half-evidenced and says so.
	recurring := ctx.ScannerRunCount > 1
	if len(inv.evaluations) > 0 && recurring {
		sortByName(inv.evaluations)
		for _, e := range inv.evaluations {
			m.Evidence = append(m.Evidence, EvidenceItem{
				Component: e.Name, Kind: "evaluation",
				Detail: "AI evaluation tooling in the inventory", Link: invLink(ctx),
			})
		}
		m.Status = StatusSatisfied
		m.Rationale = "Both halves are evidenced: the software delivering the AI system is verified by recurring automated assessment, and AI evaluation tooling is recorded in the inventory."

		return m
	}

	m.Status = StatusPartial
	switch {
	case recurring:
		m.Rationale = "The software delivering the AI system is verified by recurring automated assessment. The AI system's own validation — performance against defined requirements and acceptance criteria — is not evidenced by these runs."
	case ctx.ScannerRunCount > 0:
		m.Rationale = "A single assessment run was recorded in the period — verification happened once, not as a repeated practice — and it does not validate the AI system against its requirements."
	default:
		m.Rationale = "An evaluation workload is present, but no assessment run was recorded in the period, so neither the software nor the AI system was verified within it."
	}
	m.Gaps = append(m.Gaps, "No AI-system validation evidence — model performance against defined requirements and acceptance criteria needs manual evidence")

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
	// The AI-BOM row used to be emitted even with zero components, so a
	// satisfied control could carry "0 components — CycloneDX technical
	// inventory" as its evidence. Both rows now say what they contain.
	if len(inv.all) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(len(inv.all), "AI component"), Kind: "provenance",
			Detail: "enumerated in the AI-BOM taken " + inventoryAgeClause(ctx) + ", with provider and family where the source discloses them",
			Link:   invLink(ctx),
		})
	}
	if ctx.CycloneDXCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.CycloneDXCount, "SBOM"), Kind: "sbom",
			Detail: "CycloneDX documents of the software the system is built from",
			Link:   routeUploads,
		})
	}
	if len(inv.gapped) > 0 {
		sortByName(inv.gapped)
		for _, c := range inv.gapped {
			m.Gaps = append(m.Gaps, c.Name+": "+c.GapReason)
		}
		m.Status = StatusPartial
		m.Rationale = "Technical documentation exists; " + plural(len(inv.gapped), "component") + " carry a stated limitation."
	} else if len(inv.all) == 0 {
		// SBOMs alone document the software, not the AI system this control is
		// about — satisfied here would be a claim about a different subject.
		m.Status = StatusPartial
		m.Rationale = plural(ctx.CycloneDXCount, "SBOM") + " documents the software, but no AI component is inventoried, so the AI system itself carries no technical documentation."
		m.Gaps = append(m.Gaps, "No AI component inventoried")
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
	// Same period-blindness as A.4.4: this control decided entirely from the
	// component union, so a dataset inventoried years ago read exactly like one
	// inventoried this quarter.
	m.Evidence = append(m.Evidence, inventoryFreshness(ctx))
	switch {
	case len(inv.datasets) == 0:
		m.Status = StatusPartial
		m.Rationale = "Data infrastructure is identified; no concrete dataset artifact resolved."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved")
	case inventoryStale(ctx):
		m.Status = StatusPartial
		m.Rationale = "Data used by the AI system is identified, but the inventory behind it was taken " + inventoryAgeClause(ctx) + " — it may not describe the data in use during this period."
		m.Gaps = append(m.Gaps, "The AI inventory predates the reporting period")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Data used by the AI system is identified in an inventory taken " + inventoryAgeClause(ctx) + "."
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
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.OpenVexCount, "VEX statement"), Kind: "vex", Detail: "Documented disposition decisions", Link: routeUploads})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.SuppressionCount, "suppression"), Kind: "vex", Detail: "Documented risk-acceptance decisions", Link: routePolicies})
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
	// Pinned to partial unconditionally, so an organization that genuinely
	// manages supplier risk had no way to show it. Managing supplier risk is
	// observable here: an install-time gate that refuses a package, and
	// dependency findings carried to a disposition rather than accumulating.
	if ctx.PackageFirewallConfigured {
		detail := "evaluates every install against " + joinNames(ctx.PackageFirewallToggles, "no enabled criteria")
		if ctx.PackageFirewallRequestCount > 0 {
			detail += ", " + itoa(ctx.PackageFirewallBlockCount) + " blocked and " + itoa(ctx.PackageFirewallWarnCount) + " warned across " + plural(ctx.PackageFirewallRequestCount, "decision")
		}
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "Package firewall", Kind: "policy", Detail: detail, Link: routePolicies,
		})
	}
	enforcing := ctx.PackageFirewallConfigured && ctx.PackageFirewallRequestCount > 0
	switch {
	case enforcing && ctx.QualityGateConfigured:
		m.Status = StatusSatisfied
		m.Rationale = "AI suppliers are inventoried, their dependency risks scanned each period, and supplier risk is *managed*: the install-time gate refuses packages that breach the organization's criteria and the build gate refuses the release."
	case enforcing:
		m.Status = StatusPartial
		m.Rationale = "AI suppliers are inventoried and an install-time gate refuses packages that breach the criteria, but no build gate stops a non-conforming dependency shipping."
		m.Gaps = append(m.Gaps, "No build-time gate on supplier risk")
	default:
		m.Status = StatusPartial
		m.Rationale = "AI suppliers are inventoried and their dependency risks scanned each period. Nothing acts on that: no install-time gate refuses a package and no build gate stops one shipping, so supplier risk is observed rather than managed."
		m.Gaps = append(m.Gaps, "Supplier risk is observed but not acted on")
	}

	return m
}

// SummarizeReport rolls report-level category mappings into a Summary.
func SummarizeReport(cats []CategoryMapping) Summary { return SummarizeCategories(cats) }

// inventoryStale reports whether the AI-BOM behind the component union predates
// the reporting period. A component inventoried earlier is still present, so it
// is not excluded — but a control resting entirely on that union is describing
// another period unless the scan falls inside this one.
func inventoryStale(ctx ReportContext) bool {
	return ctx.PeriodStart > 0 && ctx.InventoryTakenAt > 0 && ctx.InventoryTakenAt < ctx.PeriodStart
}

// inventoryAgeClause says when the inventory was taken, in the report's own
// terms, so the reader can judge the evidence rather than assume it is current.
func inventoryAgeClause(ctx ReportContext) string {
	if ctx.InventoryTakenAt <= 0 {
		return "on a date the scan did not record"
	}
	when := time.UnixMilli(ctx.InventoryTakenAt).UTC().Format("2006-01-02")
	if inventoryStale(ctx) {
		return "on " + when + ", before this reporting period began"
	}

	return "on " + when
}

// inventoryFreshness is the evidence row carrying that date.
func inventoryFreshness(ctx ReportContext) EvidenceItem {
	return EvidenceItem{
		Component: "AI-BOM scan", Kind: "provenance",
		Detail: "the inventory these components come from was taken " + inventoryAgeClause(ctx),
		Link:   invLink(ctx),
	}
}

// ── controls the report path did not emit ───────────────────────────────────
//
// Eight Annex A controls had a mapper on the per-scan path and none here, so
// the report — which sees strictly more evidence than a single scan — covered
// less of the standard than the scan did. These are written against the report
// context rather than reusing the inventory-only versions: the point of the
// report path is that it has posture a scan does not.

// rA32 covers roles and responsibilities. Who is accountable is an
// organizational arrangement, but *whether the people are identifiable at all*
// is observable, and so is whether decisions carry their names.
func rA32(ctx ReportContext) ControlMapping {
	m := ctl("A.3", "A.3.2", "AI roles and responsibilities",
		"Roles and responsibilities for the AI management system are defined and allocated.")
	if ctx.MemberCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.MemberCount, "platform account"), Kind: "identity",
			Detail: itoa(ctx.MfaMemberCount) + " protected by a second factor — the people who can act on this estate are individually identifiable",
			Link:   routeMembers,
		})
	}
	attributable := ctx.SsvcDecisionByHuman + ctx.SuppressionWithOwner
	if attributable > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(attributable, "attributable decision"), Kind: "review",
			Detail: "risk decisions carrying the name of whoever made them", Link: routeFindings,
		})
	}
	if n := ctx.ManualEvidenceCount("A.3.2"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the organization's allocation of AI management-system roles",
		})
		m.Status = StatusSatisfied
		m.Rationale = "The people who can act on the estate are identifiable, decisions carry their names, and the organization has attached its role allocation."

		return m
	}
	switch {
	case ctx.MemberCount == 0:
		m.Status = StatusGap
		m.Rationale = "No accounts are recorded against this estate, so no one is identifiable as holding any role in it."
		m.Gaps = append(m.Gaps, "No identifiable role-holder")
	case attributable == 0:
		m.Status = StatusPartial
		m.Rationale = "People with access to the estate are identifiable, but no decision in it carries a name, so responsibility is allocated on paper at best."
		m.Gaps = append(m.Gaps, "No decision is attributable to a named person")
		m.Gaps = append(m.Gaps, "No documented role allocation on record")
	default:
		m.Status = StatusPartial
		m.Rationale = "Named people are making recorded decisions about the AI estate. The formal allocation of AI management-system roles is a document the organization writes, and none is attached."
		m.Gaps = append(m.Gaps, "No documented role allocation on record")
	}

	return m
}

// rA33 covers reporting of concerns. The observable half is whether a channel
// exists that carries something and reaches a person.
func rA33(ctx ReportContext) ControlMapping {
	m := ctl("A.3", "A.3.3", "Reporting of concerns",
		"A process to report concerns about the organization's role with respect to an AI system is defined.")
	if ctx.AlertCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.AlertCount, "alert"), Kind: "log",
			Detail: "raised in the period, " + itoa(ctx.AlertsAcknowledged) + " acknowledged by " + plural(ctx.AlertsAcknowledgers, "responder"),
		})
	}
	if len(ctx.NotifyIntegrations) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "Notification routes", Kind: "policy",
			Detail: "concerns raised by the platform are delivered to " + joinNames(ctx.NotifyIntegrations, "the configured routes"),
		})
	}
	if n := ctx.ManualEvidenceCount("A.3.3"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the organization's concern-reporting process and how it is made known",
		})
		m.Status = StatusSatisfied
		m.Rationale = "A reporting channel carries alerts to named responders, and the organization has attached the process document that defines how concerns are raised."

		return m
	}
	if ctx.AlertCount == 0 && len(ctx.NotifyIntegrations) == 0 {
		m.Status = StatusGap
		m.Rationale = "No alert was raised and no delivery route is configured — nothing evidences a channel by which a concern could reach anyone."
		m.Gaps = append(m.Gaps, "No reporting channel evidenced")

		return m
	}
	m.Status = StatusPartial
	m.Rationale = "A channel exists and carries machine-raised concerns to responders. A process for a *person* to report a concern about the organization's role is a procedure no artifact here evidences."
	m.Gaps = append(m.Gaps, "No documented concern-reporting process")

	return m
}

// rA45 covers system and computing resources.
func rA45(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.5", "System & computing resources",
		"System and computing resources used by the AI system are documented.")
	n := len(inv.services) + len(inv.accelerators)
	if n == 0 {
		m.Status = StatusGap
		m.Rationale = "No serving runtime or compute resource is recorded in the inventory, so the resources the AI system uses are undocumented."
		m.Gaps = append(m.Gaps, "No serving runtime or accelerator inventoried")

		return m
	}
	sortByName(inv.accelerators)
	for _, a := range inv.accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "accelerator", Detail: "compute resource declared in the deployment manifests", Link: invLink(ctx)})
	}
	sortByName(inv.services)
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "runtime", Detail: "serving or inference resource — " + s.Category, Link: invLink(ctx)})
	}
	m.Evidence = append(m.Evidence, inventoryFreshness(ctx))
	if inventoryStale(ctx) {
		m.Status = StatusPartial
		m.Rationale = plural(n, "system and computing resource") + " documented, from an inventory taken " + inventoryAgeClause(ctx) + " — it may not describe what the system ran on during this period."
		m.Gaps = append(m.Gaps, "The AI inventory predates the reporting period")

		return m
	}
	m.Status = StatusSatisfied
	m.Rationale = plural(n, "system and computing resource") + " documented from the deployment manifests, inventoried " + inventoryAgeClause(ctx) + "."

	return m
}

// rA54 covers assessing impacts on individuals and society — a study the
// organization runs. The report can say what would feed it.
func rA54(ctx ReportContext) ControlMapping {
	m := ctl("A.5", "A.5.4", "Assessing impacts on individuals & society",
		"The organization assesses the potential impacts of the AI system on individuals and society.")
	if n := ctx.ManualEvidenceCount("A.5.4"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the organization's assessment of impacts on individuals and society",
		})
		m.Status = StatusSatisfied
		m.Rationale = "The organization has attached its assessment of the AI system's impacts on individuals and society. Vulnetix does not read the attachment — an assessor samples it."

		return m
	}
	if ctx.AiFirewallGuardrailCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.AiFirewallGuardrailCount, "guardrail"), Kind: "policy",
			Detail: itoa(ctx.AiFirewallEnforcingGuardrails) + " of them block or redact at the gateway — constraints the organization placed on how the AI may affect people",
			Link:   routeAiFirewall,
		})
	}
	m.Status = StatusInformational
	m.Rationale = "Not evaluable from Vulnetix data — impacts on individuals and society are assessed by people, from context no scanner holds. Attach the assessment against this control and it will be reported."
	m.Gaps = append(m.Gaps, "No impact assessment for individuals and society on record")

	return m
}

// rA623 covers documentation of design and development.
func rA623(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.3", "Documentation of design & development",
		"The AI system's design and development are documented.")
	if len(inv.all) == 0 && ctx.CycloneDXCount == 0 && ctx.CliManifestCount == 0 {
		m.Status = StatusGap
		m.Rationale = "No AI inventory, SBOM or build manifest is recorded — nothing documents how the system is put together."
		m.Gaps = append(m.Gaps, "No design or build documentation found")

		return m
	}
	if ctx.CliManifestCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.CliManifestCount, "build manifest"), Kind: "provenance",
			Detail: "captured with content hashes across " + joinNames(ctx.CliManifestEcosystems, "the scanned ecosystems") + " — the composition of each build is recorded, not described",
			Link:   routeUploads,
		})
	}
	if len(inv.all) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(len(inv.all), "AI component"), Kind: "provenance",
			Detail: "inventoried with the SDKs, services and models the system is built from", Link: invLink(ctx),
		})
	}
	if n := ctx.ManualEvidenceCount("A.6.2.3"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the design record: choices made, alternatives rejected and why",
		})
		m.Status = StatusSatisfied
		m.Rationale = "The composition of the system is recorded from its manifests and inventory, and the organization has attached the design record behind those choices."

		return m
	}
	m.Status = StatusPartial
	m.Rationale = "What the system is built from is documented by its manifests and inventory. Why it was built that way — the design choices and the alternatives rejected — is a record the organization writes, and none is attached."
	m.Gaps = append(m.Gaps, "No design record on record")

	return m
}

// rA75 covers data provenance.
func rA75(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.7", "A.7.5", "Data provenance",
		"The provenance of data used by the AI system is recorded and maintained.")
	if len(inv.datasets) == 0 && len(inv.vectordbs) == 0 {
		m.Status = StatusGap
		m.Rationale = "No dataset or retrieval store is inventoried, so no data provenance is recorded."
		m.Gaps = append(m.Gaps, "No data artifact inventoried")

		return m
	}
	sourced := 0
	sortByName(inv.datasets)
	for _, d := range inv.datasets {
		detail := "dataset used by the AI system"
		if d.DataSource != "" {
			sourced++
			detail += ", backed by " + d.DataSource
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: detail, Link: invLink(ctx)})
	}
	m.Evidence = append(m.Evidence, inventoryFreshness(ctx))
	switch {
	case sourced == 0:
		m.Status = StatusPartial
		m.Rationale = "Datasets are inventoried, but none records where its data comes from — the inventory names the artifact and not its provenance."
		m.Gaps = append(m.Gaps, "No dataset records its backing source")
	case sourced < len(inv.datasets):
		m.Status = StatusPartial
		m.Rationale = itoa(sourced) + " of " + plural(len(inv.datasets), "dataset") + " record where the data comes from."
		m.Gaps = append(m.Gaps, plural(len(inv.datasets)-sourced, "dataset")+" with no recorded source")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Every inventoried dataset records the source its data is drawn from."
	}

	return m
}

// rA83 covers the information supplied to users of the AI system.
func rA83(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.8", "A.8.3", "Information to users of the AI system",
		"Information about the AI system is provided to its users.")
	if ctx.OpenVexCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.OpenVexCount, "VEX document"), Kind: "vex",
			Detail: "machine-readable statements telling downstream users which vulnerabilities affect them and which do not",
			Link:   routeUploads,
		})
	}
	if sbom := ctx.CycloneDXCount + ctx.SPDXCount; sbom > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(sbom, "SBOM"), Kind: "sbom",
			Detail: "component inventories a consumer can read to see what they are running", Link: routeUploads,
		})
	}
	if len(inv.models) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(len(inv.models), "model"), Kind: "model",
			Detail: "identified with provider and family where the source discloses them", Link: invLink(ctx),
		})
	}
	if n := ctx.ManualEvidenceCount("A.8.3"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the user-facing information about the AI system: its purpose, limitations and how to use it",
		})
		m.Status = StatusSatisfied
		m.Rationale = "Machine-readable information reaches downstream users, and the organization has attached the user-facing documentation of the system's purpose and limitations."

		return m
	}
	if len(m.Evidence) == 0 {
		m.Status = StatusGap
		m.Rationale = "No VEX document, SBOM or model identification is published — nothing reaches a user of this system."
		m.Gaps = append(m.Gaps, "No information published to users")

		return m
	}
	m.Status = StatusPartial
	m.Rationale = "Machine-readable information — SBOMs, VEX statements and model identities — reaches downstream users. Documentation written *for* a user, describing purpose and limitations, is authored outside this platform and none is attached."
	m.Gaps = append(m.Gaps, "No user-facing documentation on record")

	return m
}

// rA102 covers the allocation of responsibilities across the AI life cycle
// between the organization and its suppliers.
func rA102(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("A.10", "A.10.2", "Allocating responsibilities",
		"Responsibilities within the AI life cycle are allocated between the organization, its partners, suppliers and customers.")
	if len(inv.providers) > 0 {
		names := make([]string, 0, len(inv.providers))
		for p := range inv.providers {
			names = append(names, p)
		}
		sort.Strings(names)
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(len(names), "AI supplier"), Kind: "service",
			Detail: "in the supply chain: " + joinNames(names, "none identified"), Link: invLink(ctx),
		})
	}
	if ctx.SuppressionWithOwner > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SuppressionWithOwner, "owned risk acceptance"), Kind: "vex",
			Detail: "decisions about supplier-borne risk, each naming the person who accepted it", Link: routePolicies,
		})
	}
	if n := ctx.ManualEvidenceCount("A.10.2"); n > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "the agreed allocation of responsibilities with partners, suppliers and customers",
		})
		m.Status = StatusSatisfied
		m.Rationale = "Suppliers are identified, decisions about their risk are owned by named people, and the organization has attached the agreed allocation of responsibilities."

		return m
	}
	if len(inv.providers) == 0 {
		m.Status = StatusGap
		m.Rationale = "No AI supplier is identified in the inventory, so no allocation of responsibilities across the life cycle is evidenced."
		m.Gaps = append(m.Gaps, "No supplier identified")

		return m
	}
	m.Status = StatusPartial
	m.Rationale = "The suppliers in the life cycle are identified and risk decisions about them are owned. Who is responsible for what between the organization and each supplier is an agreement no artifact here records."
	m.Gaps = append(m.Gaps, "No recorded allocation of responsibilities with suppliers")

	return m
}
