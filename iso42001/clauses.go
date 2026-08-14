package iso42001

// clauses.go maps the ISO/IEC 42001:2023 management-system clauses (4–10) that
// this telemetry can genuinely speak to.
//
// The report used to tell the customer these clauses "describe processes an
// inventory cannot evidence". That was false, and provably so from inside this
// repository: ISO/IEC 27001 shares Annex SL's clause structure with 42001, and
// the 27001 builder evidences C.6.1.2, C.6.1.3, C.7.3, C.8.1, C.9.1 and C.10.1
// from the *same* embedded ReportContext. An unimplemented mapping was being
// described to the buyer as a property of the standard.
//
// Two things this deliberately does not do. It does not claim satisfied: the
// clauses are about a management system — its scope, its objectives, its
// audits, its management review — and machine telemetry evidences a slice of
// each, never the whole. And it does not silently cover only six of the
// clauses: ClauseTotal states how many the standard has, so the console can
// report the fraction the way the Annex A coverage note does (F-067/F-072),
// rather than letting a partial mapping read as the whole management system.

// ClauseTotal is the number of auditable requirements across ISO/IEC
// 42001:2023 clauses 4–10, counted the same way the 27001 catalog counts its
// C.* entries (each numbered subclause carrying a requirement).
const ClauseTotal = 25

// ClauseCategory is the category code carrying the clause mappings. Kept
// distinct from the "A.*" Annex A codes so consumers counting Annex A coverage
// (the console's "N of Annex A's 38" line, the PDCA wheel) can exclude it —
// adding these to the Annex A denominator would repeat the F-072 defect, where
// more coverage made the number less honest.
const ClauseCategory = "C"

func clauseCategory(ctx ReportContext, inv inventory) CategoryMapping {
	return CategoryMapping{
		Category: ClauseCategory, Title: "Management system clauses (4–10)",
		Description: "AIMS requirements outside Annex A. Machine telemetry evidences part of each; the management system itself — scope, objectives, competence, internal audit, management review — needs manual evidence.",
		Controls: []ControlMapping{
			c41(ctx, inv),
			c612(ctx),
			c613(ctx),
			c81(ctx),
			c91(ctx),
			c101(ctx),
		},
	}
}

// c41 — 4.1/4.3 context and scope. The AI inventory is the machine record of
// what the AIMS would have to cover: you cannot scope a management system
// around AI systems you have not enumerated.
func c41(ctx ReportContext, inv inventory) ControlMapping {
	m := ctl("C", "C.4.1", "Context and scope of the AIMS",
		"The organization determines its context and the scope of the AI management system.")
	if len(inv.all) == 0 && ctx.AibomScanCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory exists, so nothing records which AI systems an AIMS scope would have to cover."
		m.Gaps = append(m.Gaps, "No AI inventory to scope the management system around")

		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{
		Component: plural(len(inv.all), "inventoried AI component"), Kind: "inventory",
		Detail: "Enumerated automatically across " + plural(ctx.AibomScanCount, "scan") +
			": " + plural(len(inv.models), "model") + ", " + plural(len(inv.services), "service") +
			", " + plural(len(inv.sdks), "SDK") + ", " + plural(len(inv.tools), "tool"),
		Link: invLink(ctx),
	})
	m.Status = StatusPartial
	m.Rationale = "The AI systems in use are enumerated automatically, which is the factual basis a scope statement rests on. The scope boundary itself, the interested parties and their expectations are organizational determinations and need manual evidence."
	m.Gaps = append(m.Gaps, "No documented AIMS scope statement, context analysis or interested-party register")

	return m
}

// c612 — 6.1.2 AI risk assessment. Mirrors iso27001's C.6.1.2: the ranking
// strategy plus recorded decisions are the repeatable half.
func c612(ctx ReportContext) ControlMapping {
	m := ctl("C", "C.6.1.2", "AI risk assessment",
		"The organization defines and applies an AI risk assessment process producing consistent, comparable results.")
	if ctx.HasMethodology {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "assessment methodology", Kind: "policy",
			Detail: "A documented decision methodology is configured and mapped to organization fields", Link: routePolicies,
		})
	}
	if ctx.HasRiskStrategy() {
		scope := "system default"
		if ctx.RiskStrategyIsCustom {
			scope = "organization-authored"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "repeatable risk criteria", Kind: "policy",
			Detail: qt(ctx.RiskStrategyName) + " (" + scope + "): " + plural(ctx.RiskStrategyRuleCount, "ordered rule") +
				" produce a reproducible ranking for every identified risk",
			Link: routeRiskStrategy,
		})
	}
	if ctx.SsvcDecisionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SsvcDecisionCount, "recorded assessment"), Kind: "policy",
			Detail: "Each decision is reproducible from its recorded inputs", Link: routeFindings,
		})
	}
	if len(m.Evidence) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no assessment methodology, ranking strategy or recorded decision exists, so risk assessment is not reproducible."
		m.Gaps = append(m.Gaps, "No repeatable AI risk assessment criteria")

		return m
	}
	m.Status = StatusPartial
	m.Rationale = "Technical risk assessment is repeatable and reproducible from recorded criteria. AI-specific risk criteria — harms to individuals and society, fairness, safety — are not derivable from this telemetry and need manual evidence."
	m.Gaps = append(m.Gaps, "No documented AI-specific risk criteria (societal, fairness, safety impacts)")

	return m
}

// c613 — 6.1.3 AI risk treatment. The disposition of an identified risk is
// exactly what triage, VEX and suppression record.
func c613(ctx ReportContext) ControlMapping {
	m := ctl("C", "C.6.1.3", "AI risk treatment",
		"The organization defines and applies a risk treatment process, recording the treatment decision for each identified risk.")
	treated := ctx.NotAffectedTotal + ctx.FixedTotal + ctx.UnderInvestigationTotal
	if treated == 0 && ctx.OpenVexCount == 0 && ctx.SuppressionCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no treatment decision, VEX statement or suppression is recorded for any identified risk."
		m.Gaps = append(m.Gaps, "No recorded risk treatment decisions")

		return m
	}
	if treated > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(treated, "treated risk"), Kind: "finding",
			Detail: itoa(ctx.FixedTotal) + " remediated, " + itoa(ctx.NotAffectedTotal) + " assessed not affected, " +
				itoa(ctx.UnderInvestigationTotal) + " under investigation",
			Link: routeFindings,
		})
	}
	if ctx.OpenVexCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.OpenVexCount, "VEX document"), Kind: "policy",
			Detail: "Machine-readable treatment decisions, published", Link: routeFindings,
		})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SuppressionCount, "suppression rule"), Kind: "policy",
			Detail: "Standing acceptance decisions with their scope recorded", Link: routePolicies,
		})
	}
	m.Status = StatusPartial
	m.Rationale = "Technical risk treatment decisions are recorded per risk with their justification. The risk treatment plan and its approval by risk owners are organizational acts and need manual evidence."
	m.Gaps = append(m.Gaps, "No documented AI risk treatment plan or risk-owner approval")

	return m
}

// c81 — 8.1 operational planning and control. The gate plus pipeline runs are
// the machine record of a controlled process, not just an intention.
func c81(ctx ReportContext) ControlMapping {
	m := ctl("C", "C.8.1", "Operational planning and control",
		"The organization plans, implements and controls the processes needed to meet AIMS requirements, and controls planned changes.")
	if ctx.ScannerRunCount == 0 && !ctx.QualityGateConfigured {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no assessment ran and no acceptance criteria are configured, so no operational control is recorded."
		m.Gaps = append(m.Gaps, "No recorded operational control over AI-related change")

		return m
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan",
			Detail: plural(ctx.ScannerCategoryCount(), "analysis category") + " exercised across " +
				plural(ctx.ScannerRepoCount, "repository"),
			Link: routeScans,
		})
	}
	if ctx.QualityGateConfigured {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "acceptance criteria", Kind: "policy",
			Detail: "Blocks " + names(ctx.QualityGateBlocks, "no categories") + " at severity floor " + qt(ctx.QualityGateSeverity),
			Link:   routeGate,
		})
	}
	if ctx.CliRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "change control", Kind: "scan",
			Detail: plural(ctx.CliRunCount, "pipeline assessment") + "; " + itoa(ctx.CliFailedGateCount) + " refused a release",
			Link:   routeScans,
		})
	}
	m.Status = StatusPartial
	m.Rationale = "The delivery process is controlled and its decisions are recorded per change. Operational planning for the AI systems themselves — their intended use, their operating constraints, the criteria for accepting a model into service — needs manual evidence."
	m.Gaps = append(m.Gaps, "No documented operating constraints or model-acceptance criteria")

	return m
}

// c91 — 9.1 monitoring, measurement, analysis and evaluation.
func c91(ctx ReportContext) ControlMapping {
	m := ctl("C", "C.9.1", "Monitoring, measurement, analysis and evaluation",
		"The organization determines what needs to be monitored and measured, and evaluates AIMS performance.")
	if ctx.IngestionSnapshotCount == 0 && len(ctx.RemediationDaysBySev) == 0 && ctx.ScannerRunCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — nothing is measured: no periodic snapshot, no remediation window and no assessment activity."
		m.Gaps = append(m.Gaps, "No AIMS performance measurement")

		return m
	}
	if ctx.IngestionSnapshotCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.IngestionSnapshotCount, "periodic snapshot"), Kind: "log",
			Detail: "Ingest, prioritization and outcome volumes recorded per iteration", Link: routeScans,
		})
	}
	if ctx.HasRemediationSLA() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "declared performance targets", Kind: "policy",
			Detail: "Remediation windows of " + itoa(ctx.RemediationDaysBySev["critical"]) + "/" +
				itoa(ctx.RemediationDaysBySev["high"]) + "/" + itoa(ctx.RemediationDaysBySev["medium"]) + "/" +
				itoa(ctx.RemediationDaysBySev["low"]) + " days by severity to measure against",
			Link: routePolicies,
		})
	}
	m.Status = StatusPartial
	m.Rationale = "Security performance is measured continuously against declared targets. Evaluation against the organization's own AIMS objectives, and the internal audit and management review that close clause 9, need manual evidence."
	m.Gaps = append(m.Gaps, "No internal audit or management review record")

	return m
}

// c101 — 10.1 continual improvement. Outcomes over time are the machine record
// of the system improving rather than merely running.
func c101(ctx ReportContext) ControlMapping {
	m := ctl("C", "C.10.1", "Continual improvement",
		"The organization continually improves the suitability, adequacy and effectiveness of the AI management system.")
	improved := ctx.FixedTotal + ctx.Snapshot.Outcomes
	if improved == 0 && ctx.IngestionSnapshotCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no risk was driven to an outcome and no iteration record exists, so no improvement is evidenced."
		m.Gaps = append(m.Gaps, "No evidence of improvement over the period")

		return m
	}
	if ctx.FixedTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.FixedTotal, "risk remediated"), Kind: "finding",
			Detail: "Identified risks driven to a closed outcome", Link: routeFindings,
		})
	}
	if ctx.Snapshot.Any() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "iteration record", Kind: "log",
			Detail: itoa(ctx.Snapshot.Ingested) + " ingested, " + itoa(ctx.Snapshot.Prioritized) +
				" prioritized, " + itoa(ctx.Snapshot.Outcomes) + " driven to an outcome",
			Link: routeScans,
		})
	}
	m.Status = StatusPartial
	m.Rationale = "Identified risks are driven to outcomes and the cycle is recorded per iteration. Nonconformity handling, corrective action and the resulting changes to the management system need manual evidence."
	m.Gaps = append(m.Gaps, "No nonconformity or corrective-action records")

	return m
}
