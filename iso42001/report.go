package iso42001

// report.go maps a whole compliance report (org + period + scope, aggregated
// across all evidence sources) onto ISO/IEC 42001 Annex A controls, reusing the
// same ReportContext as euaiact. Evidence items carry Links to source pages.

import "github.com/Vulnetix/vdb-cyclonedx/euaiact"

// ReportContext is aliased from euaiact so the handler builds one context for
// every framework.
type ReportContext = euaiact.ReportContext

const (
	routeFindings   = "/vdb-findings"
	routeScans      = "/vdb-scanner-results"
	routeInventory  = "/vdb-ai-inventory"
	routeUploads    = "/vdb-uploads"
	routeCrypto     = "/vdb-crypto-inventory"
	routeAiFirewall = "/vdb-ai-firewall"
)

// MapReport returns the Annex A control mappings for a whole report.
func MapReport(ctx ReportContext) []CategoryMapping {
	inv := classify(ctx.Components)
	return []CategoryMapping{
		{
			Category: "A.4", Title: "Resources for AI systems",
			Description: "The resources (data, tooling, compute) for AI systems are determined and documented.",
			Controls: []ControlMapping{
				rA42(ctx, inv),
				rA44(ctx, inv),
			},
		},
		{
			Category: "A.5", Title: "Assessing impacts of AI systems",
			Description: "Processes to assess the consequences of AI systems.",
			Controls: []ControlMapping{
				rA52(ctx, inv),
			},
		},
		{
			Category: "A.6", Title: "AI system life cycle",
			Description: "Design, verification, operation, documentation and event logging across the life cycle.",
			Controls: []ControlMapping{
				rA624(ctx),
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
	m.Status = StatusSatisfied
	m.Rationale = "The AI/software is verified and validated by recurring automated assessment runs."
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
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Recurring operation monitoring", Link: routeScans})
	}
	if ctx.AiFirewallLogsEnabled && ctx.AiFirewallRequestCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference"), Kind: "log", Detail: "Runtime AI operation monitored at the gateway over the period", Link: routeAiFirewall})
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
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AccessLogCount, "access-log event"), Kind: "log", Detail: "API access events recorded"})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Assessment events recorded", Link: routeScans})
	}
	if ctx.AiFirewallLogsEnabled && ctx.AiFirewallRequestCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference log"), Kind: "log", Detail: "Runtime AI events recorded by the AI Firewall gateway (decisions, tokens, latency; no content)", Link: routeAiFirewall})
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
