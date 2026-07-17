package euaiact

// report.go adds report-level mapping: instead of one AI-BOM scan, it consumes
// a ReportContext aggregated across an org + period + repo scope, drawing on
// every evidence source (findings/triage, scanner runs + snapshot history,
// VEX/suppression, access logs, SBOM, CBOM, governance policy) — far richer
// than the per-scan inventory. Each evidence item carries a Link to its source
// page. Controls that are evaluated but find nothing return StatusGap (with a
// one-line "no evidence found"); controls that cannot be evaluated from
// available data return StatusNotApplicable with the reason.

// Product route paths for evidence links (stable vdb-* pages).
const (
	routeFindings   = "/vdb-findings"
	routeScans      = "/vdb-scanner-results"
	routeInventory  = "/vdb-ai-inventory"
	routeCrypto     = "/vdb-crypto-inventory"
	routeUploads    = "/vdb-uploads"
	routeLicenses   = "/vdb-licenses"
)

// ReportContext is the aggregated, source-agnostic evidence view for one
// compliance report (org + period + repo scope). Zero values mean "no such
// evidence found" (→ StatusGap for controls that expect it).
type ReportContext struct {
	OrgName     string
	PeriodStart int64
	PeriodEnd   int64
	Repos       []string // in-scope repo names; empty = org-wide

	// AI inventory — union of components across in-scope AI-BOM scans.
	Components          []Component
	AibomScanCount      int
	LatestAibomScanUUID string
	PriorScanCount      int // AI-BOM scans over time (monitoring signal)

	// Findings / risk identification + human triage.
	FindingTotal            int
	FindingByCategory       map[string]int // sast|sca|secrets|iac|oci|license
	FindingBySeverity       map[string]int
	TriagedTotal            int
	AffectedTotal           int
	NotAffectedTotal        int
	UnderInvestigationTotal int
	FixedTotal              int

	// Risk treatment records.
	OpenVexCount     int
	SuppressionCount int

	// Test/eval + continuous monitoring.
	ScannerRunCount        int
	ScannerRunCategories   []string
	IngestionSnapshotCount int // per-run history rows (monitoring over time)
	HasEvaluation          bool

	// Technical documentation.
	CycloneDXCount int
	SPDXCount      int

	// Event logging.
	AccessLogCount int

	// Crypto posture.
	CbomQuantumVulnerable int
	CbomQuantumSafe       int

	// Governance / policy configuration.
	HasTriagePolicy  bool
	HasMethodology   bool
	HasLicensePolicy bool
}

// MapReport returns the EU AI Act article mappings for a whole report.
func MapReport(ctx ReportContext) []ArticleMapping {
	return []ArticleMapping{
		reportArticle10(ctx),
		reportArticle11(ctx),
		reportArticle12(ctx),
		reportArticle14(ctx),
		reportArticle15(ctx),
		reportArticle50(ctx),
		reportArticle51(ctx),
		reportArticle72(ctx),
		notEvidenceable("Article 13", "Instructions for use",
			"Providers must supply deployers with instructions covering the system's characteristics, capabilities and limitations.",
			"Not evaluable from Vulnetix data — instructions-for-use are provider-authored documents; upload them as manual evidence."),
	}
}

func classifyReport(ctx ReportContext) (models, services, datasets, training, accelerators, agents []Component, gapped int) {
	for _, c := range ctx.Components {
		switch {
		case c.isModel():
			models = append(models, c)
		case c.isAIService() || c.isDeployedAIRuntime():
			services = append(services, c)
		}
		switch c.Category {
		case "training":
			training = append(training, c)
		case "accelerator":
			accelerators = append(accelerators, c)
		}
		if c.isDataset() {
			datasets = append(datasets, c)
		}
		if c.Category == "coding-agent" || c.Category == "agent" {
			agents = append(agents, c)
		}
		if c.ConfidenceGap {
			gapped++
		}
	}
	sortByName(models)
	sortByName(services)
	sortByName(datasets)
	return
}

func invLink(ctx ReportContext) string {
	if ctx.LatestAibomScanUUID != "" {
		return routeInventory + "/" + ctx.LatestAibomScanUUID
	}
	return routeInventory
}

func reportArticle10(ctx ReportContext) ArticleMapping {
	m := article("Article 10", "Data and data governance",
		"High-risk AI systems trained on data must use datasets subject to appropriate governance; data provenance and use must be documented.")
	_, _, datasets, training, _, _, _ := classifyReport(ctx)
	if len(datasets) == 0 && len(training) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no datasets or training frameworks are recorded in the in-scope AI inventory."
		m.Gaps = append(m.Gaps, "No datasets or training infrastructure found")
		return m
	}
	for _, d := range datasets {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: "Dataset artifact in the AI inventory", Link: invLink(ctx)})
	}
	for _, t := range training {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: t.Name, Kind: "runtime", Detail: "Training framework — in-house training data governance applies", Link: invLink(ctx)})
	}
	if len(datasets) == 0 {
		m.Status = StatusPartial
		m.Rationale = "Training infrastructure is inventoried, but no concrete dataset artifact was resolved."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Datasets and the infrastructure that consumes them are inventoried."
	}
	return m
}

func reportArticle11(ctx ReportContext) ArticleMapping {
	m := article("Article 11 / Annex IV", "Technical documentation",
		"Providers must draw up technical documentation describing the system's components, architecture, provenance and known limitations.")
	sbom := ctx.CycloneDXCount + ctx.SPDXCount
	if len(ctx.Components) == 0 && sbom == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory or SBOM technical documentation is recorded for the scope."
		m.Gaps = append(m.Gaps, "No AI-BOM or SBOM found")
		return m
	}
	if len(ctx.Components) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(ctx.Components), "AI component"), Kind: "provenance", Detail: "Enumerated in a CycloneDX AI-BOM", Link: invLink(ctx)})
	}
	if sbom > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(sbom, "SBOM"), Kind: "sbom", Detail: "CycloneDX/SPDX technical documentation of software components", Link: routeUploads})
	}
	_, _, _, _, _, _, gapped := classifyReport(ctx)
	if gapped > 0 {
		m.Status = StatusPartial
		m.Rationale = "The system is documented; " + plural(gapped, "component") + " carry an explicit limitation (Annex IV §2(g))."
		m.Gaps = append(m.Gaps, plural(gapped, "component")+" with a stated unverifiable value")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "AI components and software SBOMs together document the system with no unresolved limitations."
	}
	return m
}

func reportArticle12(ctx ReportContext) ArticleMapping {
	m := article("Article 12", "Record-keeping",
		"High-risk AI systems must technically allow automatic recording of events (logs) over their lifetime; maintain an inventory and record changes.")
	if ctx.AccessLogCount == 0 && ctx.ScannerRunCount == 0 && ctx.AibomScanCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no event logs, scan records or inventory history are recorded for the scope."
		m.Gaps = append(m.Gaps, "No access-log, scanner-run or inventory records found")
		return m
	}
	if ctx.AccessLogCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AccessLogCount, "access-log event"), Kind: "log", Detail: "Recorded API access events over the period"})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "scanner run"), Kind: "scan", Detail: "Recorded assessment runs", Link: routeScans})
	}
	if ctx.AibomScanCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AibomScanCount, "AI-BOM scan"), Kind: "provenance", Detail: "Inventory revisions recorded over time", Link: routeInventory})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Events are automatically recorded (access logs, assessment runs and inventory revisions) across the reporting period."
	return m
}

func reportArticle14(ctx ReportContext) ArticleMapping {
	m := article("Article 14", "Human oversight",
		"High-risk AI systems must be designed so that natural persons can effectively oversee them.")
	_, _, _, _, _, agents, _ := classifyReport(ctx)
	humanReview := ctx.AffectedTotal + ctx.NotAffectedTotal + ctx.UnderInvestigationTotal
	if len(agents) == 0 && humanReview == 0 && ctx.SuppressionCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no autonomous agents and no human triage/oversight records found."
		m.Gaps = append(m.Gaps, "No agent autonomy surface and no human review records")
		return m
	}
	for _, a := range agents {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "agent", Detail: "Autonomous agent requiring oversight", Link: invLink(ctx)})
	}
	if humanReview > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(humanReview, "finding"), Kind: "finding", Detail: "Human-reviewed triage decisions (affected/not-affected/under-investigation)", Link: routeFindings})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.SuppressionCount, "suppression"), Kind: "vex", Detail: "Human risk-acceptance decisions"})
	}
	if humanReview > 0 || ctx.SuppressionCount > 0 {
		m.Status = StatusSatisfied
		m.Rationale = "Human oversight is evidenced by reviewed triage decisions and risk-acceptance records over the period."
	} else {
		m.Status = StatusInformational
		m.Rationale = plural(len(agents), "autonomous agent") + " detected; the oversight surface is flagged but no human-review records were found in scope."
	}
	return m
}

func reportArticle15(ctx ReportContext) ArticleMapping {
	m := article("Article 15", "Accuracy, robustness & cybersecurity",
		"High-risk systems must achieve appropriate accuracy, robustness and cybersecurity over their lifecycle.")
	securityTesting := ctx.ScannerRunCount
	if securityTesting == 0 && !ctx.HasEvaluation && ctx.FindingTotal == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no security testing runs, evaluation workloads or findings are recorded for the scope."
		m.Gaps = append(m.Gaps, "No assessment runs or findings found")
		return m
	}
	if securityTesting > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(securityTesting, "assessment run"), Kind: "scan", Detail: "Automated security/robustness testing (SAST/SCA/secrets/IaC/container)", Link: routeScans})
	}
	if ctx.FindingTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FindingTotal, "finding"), Kind: "finding", Detail: "Weaknesses identified and tracked", Link: routeFindings})
	}
	if ctx.HasEvaluation {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "evaluation", Kind: "runtime", Detail: "Model evaluation/benchmark workload present", Link: invLink(ctx)})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Cybersecurity and robustness are continuously assessed via automated testing runs with tracked findings across the period."
	return m
}

func reportArticle50(ctx ReportContext) ArticleMapping {
	m := article("Article 50", "Transparency obligations",
		"Deployers must disclose the AI they use; GPAI model identity, purpose, provider and provenance must be transparent.")
	models, services, _, _, _, _, _ := classifyReport(ctx)
	if len(models) == 0 && len(services) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no models or AI services are recorded in the in-scope inventory."
		m.Gaps = append(m.Gaps, "No models or AI services found")
		return m
	}
	missing := 0
	for _, mdl := range models {
		detail := "Model identity disclosed"
		if mdl.Provider != "" {
			detail += " (provider " + mdl.Provider + ")"
		}
		if mdl.Task != "" {
			detail += " for " + mdl.Task
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail, Link: invLink(ctx)})
		if mdl.Provider == "" && mdl.Family == "" {
			missing++
		}
	}
	for _, s := range services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "service", Detail: "AI service/runtime dependency disclosed", Link: invLink(ctx)})
	}
	switch {
	case len(models) == 0:
		m.Status = StatusPartial
		m.Rationale = "AI service usage is disclosed, but no concrete model identity was resolved."
		m.Gaps = append(m.Gaps, "Service-level disclosure only")
	case missing > 0:
		m.Status = StatusPartial
		m.Rationale = "Model identities are disclosed; some lack a resolved provider or family."
		m.Gaps = append(m.Gaps, plural(missing, "model")+" without a resolved provider/family")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Every detected model discloses provider/family and purpose, and AI services are enumerated."
	}
	return m
}

func reportArticle51(ctx ReportContext) ArticleMapping {
	m := article("Articles 51-55", "General-purpose AI & systemic risk",
		"GPAI models, especially those trained with very large compute, carry additional obligations; systemic-risk classification hinges on training compute.")
	models, _, _, _, accelerators, _, _ := classifyReport(ctx)
	var gpai []Component
	for _, mdl := range models {
		if mdl.Family != "" {
			gpai = append(gpai, mdl)
		}
	}
	if len(accelerators) == 0 && len(gpai) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no accelerator compute and no identified general-purpose model family found."
		m.Gaps = append(m.Gaps, "No GPAI/compute signals found")
		return m
	}
	for _, a := range accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "accelerator", Detail: "Accelerator compute — a systemic-risk classification input", Link: invLink(ctx)})
	}
	for _, g := range gpai {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: g.Name, Kind: "model", Detail: "General-purpose model family " + g.Family, Link: invLink(ctx)})
	}
	m.Status = StatusInformational
	m.Rationale = "GPAI/compute signals are present. The systemic-risk threshold is a training-compute (FLOP) figure Vulnetix does not measure — a human must assess."
	m.Gaps = append(m.Gaps, "Training compute (FLOP) not measured")
	return m
}

func reportArticle72(ctx ReportContext) ArticleMapping {
	m := article("Article 72", "Post-market monitoring",
		"Providers must actively and systematically collect and review information about the system throughout its lifetime.")
	monitoring := ctx.IngestionSnapshotCount + ctx.PriorScanCount
	if monitoring <= 1 && ctx.ScannerRunCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — only a single point-in-time record exists; monitoring requires repeated assessment over time."
		m.Gaps = append(m.Gaps, "No monitoring history yet")
		return m
	}
	if ctx.IngestionSnapshotCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.IngestionSnapshotCount, "assessment snapshot"), Kind: "scan", Detail: "Risk posture recorded over time", Link: routeScans})
	}
	if ctx.PriorScanCount > 1 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.PriorScanCount, "AI-BOM scan"), Kind: "provenance", Detail: "AI inventory regenerated over time", Link: routeInventory})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Repeated assessments and inventory revisions across the period evidence systematic post-market monitoring."
	return m
}

// SummarizeReport rolls report-level mappings into a Summary (same shape as
// SummarizeArticles).
func SummarizeReport(ms []ArticleMapping) Summary { return SummarizeArticles(ms) }
