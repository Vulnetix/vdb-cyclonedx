// Package euaiact maps an AI Bill of Materials to EU AI Act evidence.
//
// It is deliberately provider- and storage-neutral: a caller assembles a
// Scan plus a slice of Components from whatever source it has (the AI-BOM
// detail API, a scheduled report generator, a dashboard widget) and receives
// per-article obligation mappings with the supporting evidence and any gaps.
// Nothing here touches a database, an HTTP request, or the CycloneDX writer,
// so every consumer — current and future — shares one mapping implementation.
//
// This produces auditable evidence INPUTS; it does NOT certify compliance,
// mirroring the framing the AIBOM itself carries. An AI inventory can only
// evidence obligations that are about *what AI is present, where it came
// from, and how it was recorded* — so the mapping is honest about its limits:
// where the inventory merely signals presence without proving a control, the
// status is "informational"; where an obligation cannot be evidenced from an
// inventory at all (accuracy, instructions-for-use), it is "not-applicable"
// with the reason stated rather than silently omitted.
package euaiact

import "sort"

// Framework is the constant framework label carried on every mapping.
const Framework = "EU AI Act"

// Component is the source-agnostic view of one AI-BOM component the mapping
// needs. Field meanings match the AIBOM component model.
//
//	Type:     application | library | machine-learning-model | data
//	Category: coding-agent | ai-service | ai-convention | ai-sdk | model |
//	          data | <infra category: inference|managed-ai|training|
//	          evaluation|vector-database|accelerator|agent>
type Component struct {
	Type              string
	Category          string
	Name              string
	Provider          string
	Family            string
	ModelArchitecture string
	Task              string
	ViaSDK            string
	Homepage          string
	// DataKind is set for data components: dataset | model-artifact.
	DataKind string
	// DataSource is the backing source of a data component
	// (pvc|configMap|secret|hostPath|nfs|csi|uri|file|…).
	DataSource string
	// Confidence is the graded detection confidence (high|medium|low) for the
	// tool/library/model passes; empty for infra/data.
	Confidence string
	// ConfidenceGap + GapReason are the IaC honesty signal: a value that could
	// not be verified from the source (templated Helm value, secret-referenced
	// env, non-semver image tag). This is precisely a record-quality /
	// limitations gap for Articles 11 and 12.
	ConfidenceGap bool
	GapReason     string
	// EvidenceMethods are the distinct evidence methods backing this component
	// (env|file|source|commit|config|home|iac). Presence of "commit" is
	// AI-authored-code provenance; "iac" is deployment-manifest provenance.
	EvidenceMethods []string
	// EvidenceCount is how many evidence records back this component. Zero
	// means it was recorded without an auditable locator.
	EvidenceCount int
}

func (c Component) isModel() bool {
	return c.Type == "machine-learning-model" || c.Category == "model"
}
func (c Component) isAIService() bool   { return c.Category == "ai-service" }
func (c Component) isCodingAgent() bool { return c.Category == "coding-agent" }
func (c Component) isData() bool        { return c.Type == "data" || c.Category == "data" }
func (c Component) isDataset() bool     { return c.isData() && c.DataKind == "dataset" }

// infra category predicates.
func (c Component) isDeployedAIRuntime() bool {
	return c.Category == "inference" || c.Category == "managed-ai"
}
func (c Component) isTrainingInfra() bool { return c.Category == "training" }
func (c Component) isVectorDB() bool      { return c.Category == "vector-database" }
func (c Component) isAccelerator() bool   { return c.Category == "accelerator" }
func (c Component) isAgentInfra() bool    { return c.Category == "agent" }

func (c Component) hasMethod(m string) bool {
	for _, x := range c.EvidenceMethods {
		if x == m {
			return true
		}
	}
	return false
}

// Scan is the provenance envelope around a set of components.
type Scan struct {
	RepoName       string
	CommitSha      string
	ToolName       string
	ToolVersion    string
	CatalogVersion string
	CreatedAt      int64 // unix millis
	ComponentCount int
	// PriorScanCount is how many AI-BOM scans exist for this repo/org
	// (including this one) — the temporal series that evidences post-market
	// monitoring. 0 or 1 means a single point in time.
	PriorScanCount int
}

func (s Scan) hasProvenance() bool {
	return s.RepoName != "" && s.CommitSha != "" && s.ToolName != "" && s.CreatedAt > 0
}

// Status is the coarse evidence posture for one obligation.
type Status string

const (
	// StatusSatisfied — the inventory carries the evidence the obligation needs.
	StatusSatisfied Status = "satisfied"
	// StatusPartial — evidence exists but is incomplete.
	StatusPartial Status = "partial"
	// StatusGap — the obligation applies but the inventory carries no usable
	// evidence for it.
	StatusGap Status = "gap"
	// StatusInformational — the inventory signals that the obligation is in
	// scope (e.g. accelerators present → compute disclosure may apply) but an
	// inventory cannot by itself prove the control. A human must follow up.
	StatusInformational Status = "informational"
	// StatusNotApplicable — nothing in this inventory triggers the obligation,
	// or the obligation is not evidenceable from an inventory at all.
	StatusNotApplicable Status = "not-applicable"
)

// EvidenceItem is one concrete artifact supporting an obligation.
type EvidenceItem struct {
	Component string `json:"component"`
	Kind      string `json:"kind"`   // model | service | sdk | agent | dataset | runtime | accelerator | provenance | log | finding | scan | vex | policy | sbom | crypto
	Detail    string `json:"detail"` // what it evidences
	// Link is an optional route path to the source page for this evidence
	// (e.g. "/vdb-findings", "/vdb-scanner-results/<uuid>", "/vdb-ai-inventory/<uuid>").
	Link string `json:"link,omitempty"`
	// RefID is an optional identifier of the underlying record (uuid, count).
	RefID string `json:"refId,omitempty"`
}

// ArticleMapping is the evidence posture for a single framework article.
type ArticleMapping struct {
	Framework  string         `json:"framework"`
	Article    string         `json:"article"`
	Title      string         `json:"title"`
	Obligation string         `json:"obligation"`
	Status     Status         `json:"status"`
	Rationale  string         `json:"rationale"`
	Evidence   []EvidenceItem `json:"evidence"`
	Gaps       []string       `json:"gaps,omitempty"`
}

// Summary is an at-a-glance posture over all mappings, for a dashboard header.
type Summary struct {
	Framework     string `json:"framework"`
	Satisfied     int    `json:"satisfied"`
	Partial       int    `json:"partial"`
	Gap           int    `json:"gap"`
	Informational int    `json:"informational"`
	NotApplicable int    `json:"notApplicable"`
	// Articles is the total number of articles considered.
	Articles int `json:"articles"`
}

// Map returns the EU AI Act article mappings for one AI-BOM scan. The result
// is deterministic (stable article order, stable evidence order) so callers
// can diff it across runs.
func Map(scan Scan, comps []Component) []ArticleMapping {
	return []ArticleMapping{
		mapArticle10(comps),
		mapArticle11(scan, comps),
		mapArticle12(scan, comps),
		mapArticle14(comps),
		mapArticle50(comps),
		mapArticle51(comps),
		mapArticle72(scan),
		notEvidenceable("Article 13", "Instructions for use",
			"Providers must supply deployers with instructions covering the system's characteristics, capabilities and limitations.",
			"An AI inventory records which AI is present, not the instructions-for-use a provider ships; this obligation is out of scope for inventory evidence."),
		notEvidenceable("Article 15", "Accuracy, robustness and cybersecurity",
			"High-risk systems must achieve appropriate accuracy, robustness and cybersecurity over their lifecycle.",
			"An inventory can show an evaluation workload exists but carries no accuracy or robustness results; this obligation is out of scope for inventory evidence."),
	}
}

// SummarizeArticles rolls mappings into a Summary.
func SummarizeArticles(ms []ArticleMapping) Summary {
	s := Summary{Framework: Framework, Articles: len(ms)}
	for _, m := range ms {
		switch m.Status {
		case StatusSatisfied:
			s.Satisfied++
		case StatusPartial:
			s.Partial++
		case StatusGap:
			s.Gap++
		case StatusInformational:
			s.Informational++
		case StatusNotApplicable:
			s.NotApplicable++
		}
	}
	return s
}

// ── Article 10 — data and data governance ────────────────────────────────────

func mapArticle10(comps []Component) ArticleMapping {
	m := article("Article 10", "Data and data governance",
		"High-risk AI systems trained on data must use datasets subject to appropriate governance; the data's provenance and use must be documented.")

	var datasets, training, vectordbs []Component
	for _, c := range comps {
		switch {
		case c.isDataset():
			datasets = append(datasets, c)
		case c.isTrainingInfra():
			training = append(training, c)
		case c.isVectorDB():
			vectordbs = append(vectordbs, c)
		}
	}
	sortByName(datasets)
	sortByName(training)
	sortByName(vectordbs)

	if len(datasets) == 0 && len(training) == 0 && len(vectordbs) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No datasets, training frameworks or retrieval (vector) databases were detected; this inventory records no data-governed AI."
		return m
	}

	gapped := 0
	for _, d := range datasets {
		detail := "Dataset artifact"
		if d.DataSource != "" {
			detail += " backed by " + d.DataSource
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: detail})
		if d.ConfidenceGap {
			gapped++
			m.Gaps = append(m.Gaps, "Dataset "+d.Name+": "+d.GapReason)
		}
	}
	for _, t := range training {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: t.Name, Kind: "runtime", Detail: "Training framework — models here are trained/fine-tuned in-house, so training-data governance applies"})
	}
	for _, v := range vectordbs {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: v.Name, Kind: "runtime", Detail: "Vector database — retrieval-augmented data source subject to data-provenance governance"})
	}

	switch {
	case len(datasets) == 0:
		m.Status = StatusPartial
		m.Rationale = "Training or retrieval data infrastructure is present, but no concrete dataset artifact was resolved to document its provenance."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved (framework/vector-DB present without a named dataset)")
	case gapped > 0:
		m.Status = StatusPartial
		m.Rationale = "Datasets are inventoried, but some could not be fully resolved from the source manifests."
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Datasets and the data infrastructure that consumes them are inventoried with resolved backing sources."
	}
	return m
}

// ── Article 11 / Annex IV — technical documentation ──────────────────────────

func mapArticle11(scan Scan, comps []Component) ArticleMapping {
	m := article("Article 11 / Annex IV", "Technical documentation",
		"Providers must draw up technical documentation describing the system's components, architecture, provenance and known limitations before it is placed on the market.")

	if len(comps) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected; there is no system to document."
		return m
	}

	modelCards, gapped := 0, 0
	for _, c := range comps {
		if c.isModel() && (c.ModelArchitecture != "" || c.Task != "") {
			modelCards++
		}
		if c.ConfidenceGap {
			gapped++
		}
	}

	m.Evidence = append(m.Evidence, EvidenceItem{
		Component: plural(len(comps), "component"),
		Kind:      "provenance",
		Detail:    "Enumerated in a CycloneDX AI-BOM with per-component evidence — the component inventory Annex IV requires",
	})
	if scan.hasProvenance() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: scan.RepoName,
			Kind:      "provenance",
			Detail:    "Documentation is attributable to " + toolLabel(scan) + " at commit " + shortSha(scan.CommitSha),
		})
	}
	if modelCards > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(modelCards, "model"),
			Kind:      "model",
			Detail:    "Carry a model card (architecture/task) — the model description Annex IV requires",
		})
	}

	switch {
	case !scan.hasProvenance():
		m.Status = StatusPartial
		m.Rationale = "Components are enumerated, but the documentation lacks provenance (repo/commit/tool/timestamp) to be attributable."
		m.Gaps = append(m.Gaps, "No documentation provenance")
	case gapped > 0:
		// Annex IV §2(g) explicitly requires disclosing limitations — so a
		// gap is itself partial evidence, not a failure, as long as it is named.
		m.Status = StatusPartial
		m.Rationale = "The system is documented with provenance; " + plural(gapped, "component") + " carry an explicit limitation (unverifiable value), which Annex IV §2(g) requires to be disclosed."
		for _, c := range comps {
			if c.ConfidenceGap {
				m.Gaps = append(m.Gaps, c.Name+": "+c.GapReason)
			}
		}
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Components are enumerated with attributable provenance and no unresolved limitations."
	}
	return m
}

// ── Article 12 — record-keeping / logging ────────────────────────────────────

func mapArticle12(scan Scan, comps []Component) ArticleMapping {
	m := article("Article 12", "Record-keeping",
		"High-risk AI systems must technically allow for the automatic recording of events (logs) over their lifetime; maintain an inventory and record changes.")

	if len(comps) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected, so there is no AI system to keep records for."
		return m
	}

	withEvidence, withoutEvidence, aiAuthored := 0, 0, 0
	for _, c := range comps {
		if c.EvidenceCount > 0 {
			withEvidence++
		} else {
			withoutEvidence++
		}
		if c.hasMethod("commit") {
			aiAuthored++
		}
	}

	if scan.hasProvenance() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: scan.RepoName,
			Kind:      "provenance",
			Detail:    "Inventory generated by " + toolLabel(scan) + " at commit " + shortSha(scan.CommitSha),
		})
	}
	if withEvidence > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(withEvidence, "component"),
			Kind:      "log",
			Detail:    "Carry an auditable evidence trail (env/file/source/commit/iac locators) recording where the AI usage was found",
		})
	}
	if aiAuthored > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(aiAuthored, "component"),
			Kind:      "log",
			Detail:    "Evidenced by AI-authored commit history — a lifetime record of AI-generated changes",
		})
	}

	switch {
	case !scan.hasProvenance():
		m.Status = StatusGap
		m.Rationale = "The inventory is missing provenance (repository, commit, generating tool, timestamp), so its records are not attributable."
		m.Gaps = append(m.Gaps, "No inventory provenance (repo/commit/tool/timestamp)")
	case withoutEvidence > 0:
		m.Status = StatusPartial
		m.Rationale = "The inventory is attributable and most components carry an evidence trail, but some were recorded without a locator."
		m.Gaps = append(m.Gaps, plural(withoutEvidence, "component")+" recorded without an evidence locator")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "The inventory is attributable (provenance present) and every component carries an auditable evidence trail."
	}
	return m
}

// ── Article 14 — human oversight ─────────────────────────────────────────────

func mapArticle14(comps []Component) ArticleMapping {
	m := article("Article 14", "Human oversight",
		"High-risk AI systems must be designed so that natural persons can effectively oversee them; autonomous agents raise the oversight surface.")

	var agents []Component
	for _, c := range comps {
		if c.isCodingAgent() || c.isAgentInfra() {
			agents = append(agents, c)
		}
	}
	if len(agents) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No autonomous agents or agent platforms were detected; no elevated oversight surface is indicated."
		return m
	}
	sortByName(agents)
	for _, a := range agents {
		kind := "agent"
		detail := "Autonomous AI agent — requires a defined human-oversight measure"
		if a.isAgentInfra() {
			detail = "Deployed agent platform — requires a defined human-oversight measure"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: kind, Detail: detail})
	}
	m.Status = StatusInformational
	m.Rationale = plural(len(agents), "autonomous agent") + " detected. The inventory flags the oversight surface, but cannot verify that a human-oversight control is in place — a reviewer must confirm."
	return m
}

// ── Article 50 — transparency ────────────────────────────────────────────────

func mapArticle50(comps []Component) ArticleMapping {
	m := article("Article 50", "Transparency obligations",
		"Deployers of AI systems must disclose the AI they use; general-purpose AI model identity, purpose, provider and provenance must be transparent.")

	var models, services []Component
	for _, c := range comps {
		switch {
		case c.isModel():
			models = append(models, c)
		case c.isAIService() || c.isDeployedAIRuntime():
			services = append(services, c)
		}
	}
	if len(models) == 0 && len(services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No models, AI services or inference runtimes were detected; there is no third-party AI usage to disclose."
		return m
	}
	sortByName(models)
	sortByName(services)

	missingIdentity := 0
	for _, mdl := range models {
		detail := "Model identity disclosed"
		if mdl.Provider != "" {
			detail += " (provider " + mdl.Provider + ")"
		}
		if mdl.Family != "" {
			detail += " [" + mdl.Family + "]"
		}
		if mdl.Task != "" {
			detail += " for " + mdl.Task
		}
		if mdl.ViaSDK != "" {
			detail += " via " + mdl.ViaSDK
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail})
		if mdl.Provider == "" && mdl.Family == "" {
			missingIdentity++
		}
	}
	for _, svc := range services {
		detail := "AI service / runtime dependency disclosed"
		if svc.Provider != "" {
			detail += " (provider " + svc.Provider + ")"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: svc.Name, Kind: "service", Detail: detail})
	}

	switch {
	case len(models) == 0:
		m.Status = StatusPartial
		m.Rationale = "AI service / runtime usage is disclosed, but no concrete model identity was resolved."
		m.Gaps = append(m.Gaps, "No machine-learning-model identity resolved (service-level disclosure only)")
	case missingIdentity > 0:
		m.Status = StatusPartial
		m.Rationale = "Model identities are disclosed, but some lack a resolved provider or family."
		m.Gaps = append(m.Gaps, plural(missingIdentity, "model")+" without a resolved provider/family")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Every detected model discloses a provider or family (with purpose where known), and AI service dependencies are enumerated."
	}
	return m
}

// ── Articles 51-55 — general-purpose AI models & systemic risk ───────────────

func mapArticle51(comps []Component) ArticleMapping {
	m := article("Articles 51-55", "General-purpose AI & systemic risk",
		"GPAI models, and especially those trained with very large compute, carry additional provider obligations; systemic-risk classification hinges on training compute.")

	var accelerators, gpaiModels []Component
	for _, c := range comps {
		switch {
		case c.isAccelerator():
			accelerators = append(accelerators, c)
		case c.isModel() && c.Family != "":
			gpaiModels = append(gpaiModels, c)
		}
	}
	if len(accelerators) == 0 && len(gpaiModels) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No GPU/accelerator compute and no identified general-purpose model family were detected."
		return m
	}
	sortByName(accelerators)
	sortByName(gpaiModels)
	for _, a := range accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "accelerator", Detail: "Accelerator compute requested — a systemic-risk classification input (compute threshold)"})
	}
	for _, g := range gpaiModels {
		detail := "General-purpose model family " + g.Family
		if g.Provider != "" {
			detail += " from " + g.Provider
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: g.Name, Kind: "model", Detail: detail})
	}
	m.Status = StatusInformational
	m.Rationale = "GPAI/compute signals are present. The EU AI Act's systemic-risk threshold is a training-compute (FLOP) figure that an inventory does not measure — this flags the obligation for a human to assess, it does not classify."
	m.Gaps = append(m.Gaps, "Training compute (FLOP) not measured by an inventory — systemic-risk threshold cannot be auto-classified")
	return m
}

// ── Article 72 — post-market monitoring ──────────────────────────────────────

func mapArticle72(scan Scan) ArticleMapping {
	m := article("Article 72", "Post-market monitoring",
		"Providers must actively and systematically collect and review information about the system throughout its lifetime.")

	switch {
	case scan.PriorScanCount > 1:
		m.Status = StatusSatisfied
		m.Rationale = "The AI inventory has been regenerated over time (" + plural(scan.PriorScanCount, "scan") + " for this repository), evidencing systematic, repeated monitoring of the AI in use."
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: plural(scan.PriorScanCount, "inventory scan") + " recorded over time"})
	default:
		m.Status = StatusInformational
		m.Rationale = "Only a single inventory scan exists. Post-market monitoring is evidenced by repeated inventory over time — schedule recurring scans to satisfy this obligation."
		m.Gaps = append(m.Gaps, "Single point-in-time scan; no monitoring history yet")
	}
	return m
}

// ── helpers ──────────────────────────────────────────────────────────────────

func article(id, title, obligation string) ArticleMapping {
	return ArticleMapping{Framework: Framework, Article: id, Title: title, Obligation: obligation}
}

func notEvidenceable(id, title, obligation, why string) ArticleMapping {
	return ArticleMapping{
		Framework: Framework, Article: id, Title: title, Obligation: obligation,
		Status: StatusNotApplicable, Rationale: why,
	}
}

func sortByName(cs []Component) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
}

func toolLabel(s Scan) string {
	if s.ToolName == "" {
		return "the scanner"
	}
	if s.ToolVersion == "" {
		return s.ToolName
	}
	return s.ToolName + " " + s.ToolVersion
}

func shortSha(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	if sha == "" {
		return "(unknown)"
	}
	return sha
}

func plural(n int, word string) string {
	s := itoa(n) + " " + word
	if n != 1 {
		s += "s"
	}
	return s
}

// itoa avoids pulling strconv for a single small-int conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
