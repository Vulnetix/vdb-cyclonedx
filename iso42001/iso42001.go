// Package iso42001 maps an AI Bill of Materials to ISO/IEC 42001:2023 (AI
// Management System) Annex A control evidence.
//
// Like the euaiact and nistairmf packages it reuses, it is provider- and
// storage-neutral: callers pass the same Component + Scan view and receive
// per-control evidence, so the AI-BOM detail API, a reporting job and a
// dashboard share one mapping. It produces auditable evidence INPUTS, not a
// certification.
//
// ISO/IEC 42001's clauses 4-10 describe the management SYSTEM (leadership,
// planning, process) which an inventory cannot evidence; its Annex A controls
// are the concrete, artifact-backed ones. The AI-BOM directly evidences the
// resource, life-cycle-documentation, event-logging, data-provenance and
// third-party controls — "the auditable lineage the standard's certification
// path requires" — while impact-assessment and policy controls remain human
// activities the inventory can only inform (informational) or not evidence at
// all (not-applicable, with the reason stated).
package iso42001

import (
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

// Framework is the constant framework label.
const Framework = "ISO/IEC 42001"

// Reuse the neutral status vocabulary + shapes from euaiact.
type (
	Status       = euaiact.Status
	EvidenceItem = euaiact.EvidenceItem
	Component    = euaiact.Component
	Scan         = euaiact.Scan
)

const (
	StatusSatisfied     = euaiact.StatusSatisfied
	StatusPartial       = euaiact.StatusPartial
	StatusGap           = euaiact.StatusGap
	StatusInformational = euaiact.StatusInformational
	StatusNotApplicable = euaiact.StatusNotApplicable
)

// ControlMapping is the evidence posture for one Annex A control.
type ControlMapping struct {
	Category  string         `json:"category"` // e.g. "A.6"
	ID        string         `json:"id"`       // e.g. "A.6.2.8"
	Title     string         `json:"title"`
	Objective string         `json:"objective"`
	Status    Status         `json:"status"`
	Rationale string         `json:"rationale"`
	Evidence  []EvidenceItem `json:"evidence"`
	Gaps      []string       `json:"gaps,omitempty"`
}

// CategoryMapping groups the controls of one Annex A control objective.
type CategoryMapping struct {
	Category    string           `json:"category"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Controls    []ControlMapping `json:"controls"`
}

// AnnexATotal is the number of controls in ISO/IEC 42001:2023 Annex A, across
// the nine control objectives A.2 to A.10. It is the honest denominator: a
// reader told "14 of 18 satisfied" with no reference to this number reads a
// partial mapping as full coverage of the standard.
const AnnexATotal = 38

// Summary is an at-a-glance posture over all controls.
type Summary struct {
	Framework     string `json:"framework"`
	Satisfied     int    `json:"satisfied"`
	Partial       int    `json:"partial"`
	Gap           int    `json:"gap"`
	Informational int    `json:"informational"`
	NotApplicable int    `json:"notApplicable"`
	Controls      int    `json:"controls"`
	// AnnexAControls carries AnnexATotal so consumers can state the mapped
	// fraction without hard-coding the standard's size themselves.
	AnnexAControls int `json:"annexAControls"`
	// AnnexAMapped is how many Annex A controls this report actually mapped —
	// the numerator to AnnexAControls. Controls above counts *every* mapped
	// control including the management-system clauses, so using it as the
	// numerator would make added clause coverage look like added Annex A
	// coverage, which is the mistake F-072 fixed in the PDCA denominators.
	AnnexAMapped int `json:"annexAMapped"`
	// ClauseMapped / ClauseControls are the same fraction for clauses 4–10.
	ClauseMapped   int `json:"clauseMapped"`
	ClauseControls int `json:"clauseControls"`
}

// Map returns the Annex A control mappings for one AI-BOM scan.
func Map(scan Scan, comps []Component) []CategoryMapping {
	inv := classify(comps)
	return []CategoryMapping{
		{
			Category: "A.4", Title: "Resources for AI systems",
			Description: "The organization determines and documents the resources (data, tooling, system/computing) needed for its AI systems.",
			Controls: []ControlMapping{
				a42(scan, inv),
				a44(inv),
				a45(inv),
			},
		},
		{
			Category: "A.5", Title: "Assessing impacts of AI systems",
			Description: "Processes to assess the potential consequences of AI systems for individuals, groups and society.",
			Controls: []ControlMapping{
				a52(inv),
				a54(),
			},
		},
		{
			Category: "A.6", Title: "AI system life cycle",
			Description: "Requirements, design, verification, deployment, operation, documentation and event logging across the AI system life cycle.",
			Controls: []ControlMapping{
				a623(inv),
				a624(inv),
				a626(scan),
				a627(scan, inv),
				a628(inv),
			},
		},
		{
			Category: "A.7", Title: "Data for AI systems",
			Description: "Management of data used to develop and operate AI systems, including provenance.",
			Controls: []ControlMapping{
				a72(inv),
				a75(inv),
			},
		},
		{
			Category: "A.8", Title: "Information for interested parties",
			Description: "Documentation and information provided to users and other interested parties about the AI systems.",
			Controls: []ControlMapping{
				a83(inv),
			},
		},
		{
			Category: "A.10", Title: "Third-party relationships",
			Description: "Management of AI-related risks arising from suppliers and other third parties.",
			Controls: []ControlMapping{
				a102(inv),
				a103(inv),
			},
		},
	}
}

// SummarizeCategories rolls all controls into a Summary.
func SummarizeCategories(cats []CategoryMapping) Summary {
	s := Summary{Framework: Framework, AnnexAControls: AnnexATotal, ClauseControls: ClauseTotal}
	for _, c := range cats {
		for _, ctl := range c.Controls {
			s.Controls++
			if c.Category == ClauseCategory {
				s.ClauseMapped++
			} else {
				s.AnnexAMapped++
			}
			switch ctl.Status {
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
	}
	return s
}

// ── classification ───────────────────────────────────────────────────────────

type inventory struct {
	all          []Component
	models       []Component
	services     []Component
	sdks         []Component
	tools        []Component
	datasets     []Component
	training     []Component
	vectordbs    []Component
	accelerators []Component
	evaluations  []Component
	modelCards   int
	providers    map[string]bool
	gapped       []Component
	withEvidence int
	aiAuthored   int
}

func classify(comps []Component) inventory {
	inv := inventory{all: comps, providers: map[string]bool{}}
	for _, c := range comps {
		switch {
		case isModel(c):
			inv.models = append(inv.models, c)
			if c.ModelArchitecture != "" || c.Task != "" {
				inv.modelCards++
			}
		case c.Category == "ai-service" || c.Category == "inference" || c.Category == "managed-ai":
			inv.services = append(inv.services, c)
		case c.Category == "ai-sdk":
			inv.sdks = append(inv.sdks, c)
		case c.Category == "coding-agent" || c.Category == "ai-convention":
			inv.tools = append(inv.tools, c)
		}
		switch c.Category {
		case "training":
			inv.training = append(inv.training, c)
		case "vector-database":
			inv.vectordbs = append(inv.vectordbs, c)
		case "accelerator":
			inv.accelerators = append(inv.accelerators, c)
		case "evaluation":
			inv.evaluations = append(inv.evaluations, c)
		}
		if c.Category == "data" && c.DataKind == "dataset" {
			inv.datasets = append(inv.datasets, c)
		}
		if c.Provider != "" {
			inv.providers[c.Provider] = true
		}
		if c.ConfidenceGap {
			inv.gapped = append(inv.gapped, c)
		}
		if c.EvidenceCount > 0 {
			inv.withEvidence++
		}
		if hasMethod(c, "commit") {
			inv.aiAuthored++
		}
	}
	return inv
}

func isModel(c Component) bool { return c.Type == "machine-learning-model" || c.Category == "model" }
func hasMethod(c Component, m string) bool {
	for _, x := range c.EvidenceMethods {
		if x == m {
			return true
		}
	}
	return false
}

// ── A.3 Internal organization ─────────────────────────────────────────────────
//
// Neither control is artifact-backed: both describe an organizational
// arrangement, not a property of a system Vulnetix can observe. They are
// emitted as not-applicable with a stated reason rather than omitted, because a
// category absent from the report cannot be graded and nothing tells the reader
// it is missing — the whole objective simply vanishes from Annex A.

func a32() ControlMapping {
	m := ctl("A.3", "A.3.2", "AI roles and responsibilities",
		"Roles and responsibilities for the AI management system are defined and allocated.")
	m.Status = StatusNotApplicable
	m.Rationale = "Role allocation is an organizational arrangement recorded outside the system; an AI inventory observes what runs, not who is accountable for it."
	return m
}

func a33() ControlMapping {
	m := ctl("A.3", "A.3.3", "Reporting of concerns",
		"A process to report concerns about the organization's role with respect to an AI system is defined.")
	m.Status = StatusNotApplicable
	m.Rationale = "A concern-reporting process is a human procedure; no scan artifact evidences that one exists or that it is used."
	return m
}

// ── A.4 Resources ─────────────────────────────────────────────────────────────

func a42(scan Scan, inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.2", "AI resources documentation",
		"Information about the resources of the AI system is documented.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI resources were detected to document."
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "AI resource"), Kind: "provenance", Detail: "Documented in a CycloneDX AI-BOM (tools, SDKs, models, infrastructure, data)"})
	if hasProvenance(scan) {
		m.Status = StatusSatisfied
		m.Rationale = "AI resources are documented in an attributable, machine-readable inventory."
	} else {
		m.Status = StatusPartial
		m.Rationale = "AI resources are documented but the inventory lacks provenance to be attributable."
		m.Gaps = append(m.Gaps, "Inventory not attributable (no provenance)")
	}
	return m
}

func a44(inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.4", "Tooling resources",
		"Tooling resources used across the AI system life cycle are documented.")
	n := len(inv.tools) + len(inv.sdks) + len(inv.services)
	if n == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI tooling, SDKs or services were detected."
		return m
	}
	sortByName(inv.sdks)
	for _, s := range inv.sdks {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "sdk", Detail: "AI SDK/framework tooling"})
	}
	sortByName(inv.services)
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "service", Detail: "AI service/runtime tooling"})
	}
	// Counted in n but never cited, so an inventory of coding agents alone
	// reported "N tooling resources are documented" with an empty list.
	sortByName(inv.tools)
	for _, s := range inv.tools {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "tool", Detail: "AI development tooling — " + s.Category})
	}
	m.Status = StatusSatisfied
	m.Rationale = plural(n, "tooling resource") + " are documented across the life cycle."
	return m
}

func a45(inv inventory) ControlMapping {
	m := ctl("A.4", "A.4.5", "System & computing resources",
		"System and computing resources used by the AI system are documented.")
	n := len(inv.services) + len(inv.accelerators)
	if n == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No serving runtimes or compute/accelerator resources were declared in IaC."
		return m
	}
	for _, a := range inv.accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "accelerator", Detail: "Compute/accelerator resource declared"})
	}
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "runtime", Detail: "Serving/inference system resource declared"})
	}
	m.Status = StatusSatisfied
	m.Rationale = "System and computing resources are documented from the deployment manifests."
	return m
}

// ── A.5 Impact assessment ─────────────────────────────────────────────────────

func a52(inv inventory) ControlMapping {
	m := ctl("A.5", "A.5.2", "AI system impact assessment process",
		"A process to assess the potential impacts of the AI system is established.")
	if len(inv.models) == 0 && len(inv.services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No models or AI services were detected whose impact would need assessing."
		return m
	}
	for _, mdl := range inv.models {
		detail := "AI system requiring impact assessment"
		if mdl.Task != "" {
			detail += " (purpose: " + mdl.Task + ")"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail})
	}
	m.Status = StatusInformational
	m.Rationale = "The inventory identifies the AI systems whose impact must be assessed (with purpose where known); the assessment itself is a human process the inventory cannot perform."
	return m
}

func a54() ControlMapping {
	m := ctl("A.5", "A.5.4", "Assessing impacts on individuals & society",
		"Potential impacts of the AI system on individuals, groups and society are assessed.")
	m.Status = StatusNotApplicable
	m.Rationale = "Societal/individual impact is a human risk-assessment judgement; an inventory provides inputs but cannot assess impact."
	return m
}

// ── A.6 Life cycle ────────────────────────────────────────────────────────────

func a623(inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.3", "Documentation of design & development",
		"The design and development of the AI system are documented.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected."
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "component"), Kind: "provenance", Detail: "Design/development components enumerated (SDKs, models, training frameworks)"})
	for _, t := range inv.training {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: t.Name, Kind: "runtime", Detail: "Training/development framework documented"})
	}
	m.Status = StatusPartial
	m.Rationale = "The building blocks of design and development are documented in the inventory; the design rationale/decisions are a downstream document."
	return m
}

func a624(inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.4", "Verification & validation",
		"The AI system is verified and validated.")
	if len(inv.evaluations) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No verification/validation (evaluation) workloads were detected."
		return m
	}
	sortByName(inv.evaluations)
	for _, e := range inv.evaluations {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: e.Name, Kind: "runtime", Detail: "Verification/validation (evaluation) workload present"})
	}
	m.Status = StatusInformational
	m.Rationale = "Verification/validation workloads are present; their results are not carried by an inventory — a reviewer must confirm the outcomes."
	m.Gaps = append(m.Gaps, "Validation results not in the inventory")
	return m
}

func a626(scan Scan) ControlMapping {
	m := ctl("A.6", "A.6.2.6", "Operation & monitoring",
		"The AI system is operated and monitored, including capturing changes.")
	if scan.PriorScanCount > 1 {
		m.Status = StatusSatisfied
		m.Rationale = "Repeated inventory scans (" + plural(scan.PriorScanCount, "scan") + ") capture operational changes to the AI in use over time."
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: plural(scan.PriorScanCount, "monitoring scan") + " over time"})
		return m
	}
	m.Status = StatusInformational
	m.Rationale = "A single scan does not yet evidence ongoing operation monitoring; recurring inventory scans provide it."
	m.Gaps = append(m.Gaps, "No recurring-scan monitoring history yet")
	return m
}

func a627(scan Scan, inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.7", "Technical documentation",
		"Technical documentation of the AI system is created and maintained.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected to document."
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(inv.all), "component"), Kind: "provenance", Detail: "CycloneDX technical inventory of the AI system"})
	if inv.modelCards > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(inv.modelCards, "model"), Kind: "model", Detail: "Carry a model card (architecture/task)"})
	}
	if len(inv.gapped) > 0 {
		sortByName(inv.gapped)
		for _, c := range inv.gapped {
			m.Gaps = append(m.Gaps, c.Name+": "+c.GapReason)
		}
		m.Status = StatusPartial
		m.Rationale = "Technical documentation exists with model cards; " + plural(len(inv.gapped), "component") + " carry an explicit limitation (unverifiable value) that the documentation names."
		return m
	}
	if hasProvenance(scan) {
		m.Status = StatusSatisfied
		m.Rationale = "Attributable technical documentation of the AI system exists with model cards and no unresolved limitations."
	} else {
		m.Status = StatusPartial
		m.Rationale = "Technical documentation exists but lacks provenance to be attributable."
		m.Gaps = append(m.Gaps, "No documentation provenance")
	}
	return m
}

func a628(inv inventory) ControlMapping {
	m := ctl("A.6", "A.6.2.8", "Recording of event logs",
		"Events over the AI system's life cycle are recorded (logging).")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected to log."
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(inv.withEvidence, "component"), Kind: "log", Detail: "Carry an auditable evidence trail (env/file/source/commit/iac locators)"})
	if inv.aiAuthored > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(inv.aiAuthored, "component"), Kind: "log", Detail: "AI-authored commit history — a lifetime event record"})
	}
	if inv.withEvidence == len(inv.all) {
		m.Status = StatusSatisfied
		m.Rationale = "Every component carries an auditable event/evidence trail — the recorded lineage this control requires."
	} else {
		m.Status = StatusPartial
		m.Rationale = "Most components carry an event/evidence trail; " + plural(len(inv.all)-inv.withEvidence, "component") + " were recorded without a locator."
		m.Gaps = append(m.Gaps, plural(len(inv.all)-inv.withEvidence, "component")+" without an evidence locator")
	}
	return m
}

// ── A.7 Data ──────────────────────────────────────────────────────────────────

func a72(inv inventory) ControlMapping {
	m := ctl("A.7", "A.7.2", "Data for AI systems",
		"Data used to develop and operate the AI system is identified and managed.")
	n := len(inv.datasets) + len(inv.training) + len(inv.vectordbs)
	if n == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No datasets, training frameworks or retrieval databases were detected."
		return m
	}
	sortByName(inv.datasets)
	for _, d := range inv.datasets {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: "Dataset used by the AI system"})
	}
	for _, v := range inv.vectordbs {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: v.Name, Kind: "runtime", Detail: "Retrieval (vector) data store"})
	}
	if len(inv.datasets) == 0 {
		m.Status = StatusPartial
		m.Rationale = "Data infrastructure (training/retrieval) is identified, but no concrete dataset artifact was resolved."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "The data used by the AI system is identified in the inventory."
	}
	return m
}

func a75(inv inventory) ControlMapping {
	m := ctl("A.7", "A.7.5", "Data provenance",
		"The provenance of data used by the AI system is documented.")
	if len(inv.datasets) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No dataset artifacts were detected whose provenance could be documented."
		return m
	}
	sortByName(inv.datasets)
	withSource, gapped := 0, 0
	for _, d := range inv.datasets {
		detail := "Dataset provenance"
		if d.DataSource != "" {
			detail += " — backing source " + d.DataSource
			withSource++
		}
		if d.ConfidenceGap {
			gapped++
			m.Gaps = append(m.Gaps, d.Name+": "+d.GapReason)
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: detail})
	}
	switch {
	case withSource == 0:
		m.Status = StatusPartial
		m.Rationale = "Datasets are inventoried but their backing sources were not resolved."
		m.Gaps = append(m.Gaps, "Dataset backing sources unresolved")
	case gapped > 0:
		m.Status = StatusPartial
		m.Rationale = "Dataset provenance is documented; some sources could not be fully resolved from the manifests."
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Each dataset documents its backing-source provenance."
	}
	return m
}

// ── A.8 Information for interested parties ─────────────────────────────────────

func a83(inv inventory) ControlMapping {
	m := ctl("A.8", "A.8.3", "Information to users of the AI system",
		"Information about the AI system (identity, provider, purpose) is available to its users.")
	if len(inv.models) == 0 && len(inv.services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No models or AI services were detected whose information would be disclosed."
		return m
	}
	sortByName(inv.models)
	missing := 0
	for _, mdl := range inv.models {
		detail := "Model identity available"
		if mdl.Provider != "" {
			detail += " (provider " + mdl.Provider + ")"
		} else {
			missing++
		}
		if mdl.Task != "" {
			detail += " for " + mdl.Task
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail})
	}
	if missing > 0 || len(inv.models) == 0 {
		m.Status = StatusPartial
		m.Rationale = "System information is available, but some models lack a resolved provider."
		if missing > 0 {
			m.Gaps = append(m.Gaps, plural(missing, "model")+" without a resolved provider")
		}
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Model identity, provider and purpose are available for the AI systems in use."
	}
	return m
}

// ── A.10 Third-party relationships ─────────────────────────────────────────────

func a102(inv inventory) ControlMapping {
	m := ctl("A.10", "A.10.2", "Allocating responsibilities",
		"Responsibilities within the AI life cycle are allocated between the organization and third parties.")
	if len(inv.providers) == 0 && len(inv.services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No third-party AI providers or services were detected to allocate responsibility for."
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "Third-party provider — a responsibility boundary"})
	}
	sortEvidence(m.Evidence)
	m.Status = StatusInformational
	m.Rationale = "Third-party providers are identified, delineating where responsibility crosses an organizational boundary; the responsibility allocation itself is a contractual/governance activity."
	return m
}

func a103(inv inventory) ControlMapping {
	m := ctl("A.10", "A.10.3", "Suppliers",
		"AI-related risks from suppliers are identified and managed.")
	n := len(inv.providers) + len(inv.sdks) + len(inv.services)
	if n == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No third-party AI suppliers were detected."
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "AI supplier in the supply chain"})
	}
	sortEvidence(m.Evidence)
	sortByName(inv.sdks)
	for _, s := range inv.sdks {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "sdk", Detail: "Third-party AI SDK supplier"})
	}
	m.Status = StatusPartial
	m.Rationale = "AI suppliers (providers, SDKs, services) are inventoried and re-inventoried each scan; managing the supplier risk is a downstream activity."
	return m
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ctl(category, id, title, objective string) ControlMapping {
	return ControlMapping{Category: category, ID: id, Title: title, Objective: objective}
}

func hasProvenance(s Scan) bool {
	return s.RepoName != "" && s.CommitSha != "" && s.ToolName != "" && s.CreatedAt > 0
}

func sortByName(cs []Component) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
}

func sortEvidence(es []EvidenceItem) {
	sort.Slice(es, func(i, j int) bool { return es[i].Component < es[j].Component })
}

func plural(n int, word string) string {
	s := itoa(n) + " " + word
	if n != 1 {
		s += "s"
	}
	return s
}

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

// joinNames renders a list for evidence prose, with a fallback when empty.
func joinNames(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}

	return strings.Join(list, ", ")
}
