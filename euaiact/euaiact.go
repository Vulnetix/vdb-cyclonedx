// Package euaiact maps an AI Bill of Materials to EU AI Act evidence.
//
// It is deliberately provider- and storage-neutral: a caller assembles a
// Scan plus a slice of Components from whatever source it has (the AI-BOM
// detail API, a scheduled report generator, a dashboard widget) and receives
// per-article obligation mappings with the supporting evidence and any gaps.
// Nothing here touches a database, an HTTP request, or the CycloneDX writer,
// so every consumer — current and future — shares one mapping implementation.
//
// This produces auditable evidence inputs; it does NOT certify compliance,
// mirroring the framing the AIBOM itself carries. The scope is the two
// obligations an AI inventory can directly evidence:
//
//   - Article 12 — record-keeping / logging for high-risk AI systems. The
//     inventory plus its provenance (repository, commit, generating tool,
//     timestamp) and per-component evidence trail are the logging artifacts.
//   - Article 50 — transparency obligations. The model identity, runtime and
//     provider attributes support the disclosure obligations that apply to
//     deployers of general-purpose AI systems.
package euaiact

import "sort"

// Framework is the constant framework label carried on every mapping.
const Framework = "EU AI Act"

// Component is the minimal, source-agnostic view of one AI-BOM component the
// mapping needs. Field meanings match the AIBOM component model:
//
//	Type:     application | library | machine-learning-model
//	Category: coding-agent | ai-service | ai-convention | ai-sdk | model
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
	// EvidenceCount is how many evidence records (env/file/source/commit/…)
	// back this component. Zero means the component was recorded without an
	// auditable locator.
	EvidenceCount int
}

func (c Component) isModel() bool {
	return c.Type == "machine-learning-model" || c.Category == "model"
}

func (c Component) isAIService() bool { return c.Category == "ai-service" }

// Scan is the provenance envelope around a set of components.
type Scan struct {
	RepoName       string
	CommitSha      string
	ToolName       string
	ToolVersion    string
	CatalogVersion string
	CreatedAt      int64 // unix millis
	ComponentCount int
}

func (s Scan) hasProvenance() bool {
	return s.RepoName != "" && s.CommitSha != "" && s.ToolName != "" && s.CreatedAt > 0
}

// Status is the coarse evidence posture for one obligation.
type Status string

const (
	// StatusSatisfied — the inventory carries the evidence the article's
	// disclosure/record-keeping obligation needs.
	StatusSatisfied Status = "satisfied"
	// StatusPartial — evidence exists but is incomplete (e.g. models with no
	// provider, or components with no evidence locator).
	StatusPartial Status = "partial"
	// StatusGap — the obligation applies but the inventory carries no usable
	// evidence for it.
	StatusGap Status = "gap"
	// StatusNotApplicable — nothing in this inventory triggers the obligation.
	StatusNotApplicable Status = "not-applicable"
)

// EvidenceItem is one concrete artifact supporting an obligation.
type EvidenceItem struct {
	Component string `json:"component"`
	Kind      string `json:"kind"`   // model | tool | sdk | service | provenance
	Detail    string `json:"detail"` // what it evidences
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

// Map returns the EU AI Act article mappings for one AI-BOM scan. The result
// is deterministic (stable article order, stable evidence order) so callers
// can diff it across runs.
func Map(scan Scan, comps []Component) []ArticleMapping {
	return []ArticleMapping{
		mapArticle12(scan, comps),
		mapArticle50(comps),
	}
}

// mapArticle12 — logging / record-keeping for high-risk AI systems. The
// evidence is the inventory itself: its provenance envelope and the
// per-component evidence trail (the auditable "log" of what AI is present and
// where it was found).
func mapArticle12(scan Scan, comps []Component) ArticleMapping {
	m := ArticleMapping{
		Framework:  Framework,
		Article:    "Article 12",
		Title:      "Record-keeping",
		Obligation: "High-risk AI systems must technically allow for the automatic recording of events (logs) over their lifetime; maintain an inventory and record changes.",
	}

	if len(comps) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected, so there is no AI system to keep records for."
		return m
	}

	// Provenance is the record envelope: which repo, which commit, which tool
	// produced this inventory and when.
	withEvidence, withoutEvidence := 0, 0
	for _, c := range comps {
		if c.EvidenceCount > 0 {
			withEvidence++
		} else {
			withoutEvidence++
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
			Detail:    "Carry an auditable evidence trail (env/file/source/commit locators) recording where the AI usage was found",
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

// mapArticle50 — transparency obligations. The disclosable facts are the model
// identities (name / provider / family / architecture / task) and the AI
// services / SDKs that constitute general-purpose AI usage.
func mapArticle50(comps []Component) ArticleMapping {
	m := ArticleMapping{
		Framework:  Framework,
		Article:    "Article 50",
		Title:      "Transparency obligations",
		Obligation: "Deployers of AI systems must disclose the AI they use; general-purpose AI model identity, provider and provenance must be transparent.",
	}

	var models, services []Component
	for _, c := range comps {
		switch {
		case c.isModel():
			models = append(models, c)
		case c.isAIService():
			services = append(services, c)
		}
	}

	if len(models) == 0 && len(services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No models or AI services were detected; there is no third-party AI usage to disclose."
		return m
	}

	// Sort models by name for deterministic evidence order.
	sort.Slice(models, func(i, j int) bool { return models[i].Name < models[j].Name })
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })

	modelsMissingIdentity := 0
	for _, mdl := range models {
		detail := "Model identity disclosed"
		if mdl.Provider != "" {
			detail += " (provider " + mdl.Provider + ")"
		}
		if mdl.Family != "" {
			detail += " [" + mdl.Family + "]"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail})
		if mdl.Provider == "" && mdl.Family == "" {
			modelsMissingIdentity++
		}
	}
	for _, svc := range services {
		detail := "AI service dependency disclosed"
		if svc.Provider != "" {
			detail += " (provider " + svc.Provider + ")"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: svc.Name, Kind: "service", Detail: detail})
	}

	switch {
	case len(models) == 0:
		// Only services — usage is disclosed but no concrete model identity.
		m.Status = StatusPartial
		m.Rationale = "AI service usage is disclosed, but no concrete model identity was resolved."
		m.Gaps = append(m.Gaps, "No machine-learning-model identity resolved (service-level disclosure only)")
	case modelsMissingIdentity > 0:
		m.Status = StatusPartial
		m.Rationale = "Model identities are disclosed, but some lack a resolved provider or family."
		m.Gaps = append(m.Gaps, plural(modelsMissingIdentity, "model")+" without a resolved provider/family")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Every detected model discloses a provider or family, and AI service dependencies are enumerated."
	}
	return m
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
