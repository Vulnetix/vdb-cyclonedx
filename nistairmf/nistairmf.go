// Package nistairmf maps an AI Bill of Materials to NIST AI Risk Management
// Framework (AI RMF 1.0) evidence across the four functions GOVERN, MAP,
// MEASURE and MANAGE.
//
// Like the euaiact package it reuses, it is provider- and storage-neutral:
// callers pass the same Component + Scan view (from euaiact) and receive
// per-subcategory evidence, so the AI-BOM detail API, a reporting job and a
// dashboard share one mapping. It produces auditable evidence INPUTS, not a
// certification: where an inventory only signals that a subcategory outcome
// is in scope without proving it (evaluation exists but no results; agent
// autonomy present but no oversight control), the status is "informational";
// where a subcategory cannot be evidenced from an inventory at all (societal
// impact characterization), it is "not-applicable" with the reason stated.
//
// The AI-BOM's core contribution is the AI-system inventory itself, which is
// exactly what GOVERN 1.6 requires — and, tracked over repeated scans, what
// MEASURE 3 and MANAGE 4 require for change tracking and monitoring.
package nistairmf

import (
	"sort"

	"github.com/Vulnetix/vdb-cyclonedx/euaiact"
)

// Framework is the constant framework label.
const Framework = "NIST AI RMF"

// Reuse the neutral status vocabulary + evidence shape from euaiact so a
// consumer renders both frameworks with one set of status colors.
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

// SubcategoryMapping is the evidence posture for one AI RMF subcategory.
type SubcategoryMapping struct {
	Function  string         `json:"function"` // GOVERN | MAP | MEASURE | MANAGE
	ID        string         `json:"id"`       // e.g. "GOVERN 1.6"
	Title     string         `json:"title"`
	Outcome   string         `json:"outcome"` // the subcategory's outcome statement
	Status    Status         `json:"status"`
	Rationale string         `json:"rationale"`
	Evidence  []EvidenceItem `json:"evidence"`
	Gaps      []string       `json:"gaps,omitempty"`
}

// FunctionMapping groups the subcategories of one AI RMF function.
type FunctionMapping struct {
	Function      string               `json:"function"`
	Title         string               `json:"title"`
	Description   string               `json:"description"`
	Subcategories []SubcategoryMapping `json:"subcategories"`
}

// Summary is an at-a-glance posture over all subcategories.
// FrameworkSubcategories is the number of subcategories in the NIST AI RMF 1.0
// core, across GOVERN, MAP, MEASURE and MANAGE. It is the honest denominator: a
// reader told "12 of 17 satisfied" with no reference to this number reads a
// partial mapping as strong coverage of the framework.
const FrameworkSubcategories = 72

type Summary struct {
	Framework     string `json:"framework"`
	Satisfied     int    `json:"satisfied"`
	Partial       int    `json:"partial"`
	Gap           int    `json:"gap"`
	Informational int    `json:"informational"`
	NotApplicable int    `json:"notApplicable"`
	Subcategories int    `json:"subcategories"`
	// FrameworkTotal carries FrameworkSubcategories so consumers can state the
	// mapped fraction without hard-coding the framework's size themselves.
	FrameworkTotal int `json:"frameworkTotal"`
}

// Map returns the AI RMF function mappings for one AI-BOM scan. Deterministic
// order and evidence for diffable output.
func Map(scan Scan, comps []Component) []FunctionMapping {
	inv := classify(comps)
	return []FunctionMapping{
		{
			Function: "GOVERN", Title: "Govern",
			Description: "A culture of risk management is cultivated and present; policies, accountability and inventory mechanisms for AI are in place.",
			Subcategories: []SubcategoryMapping{
				govern16(scan, inv),
				govern61(inv),
				govern62(inv),
			},
		},
		{
			Function: "MAP", Title: "Map",
			Description: "Context is recognized and risks related to context are identified; AI systems are categorized and their capabilities, provenance and third-party dependencies are mapped.",
			Subcategories: []SubcategoryMapping{
				map11(scan, inv),
				map21(inv),
				map22(inv),
				map41(inv),
				map51(),
			},
		},
		{
			Function: "MEASURE", Title: "Measure",
			Description: "Appropriate methods and metrics are identified and applied; AI risks are analyzed, assessed and tracked over time.",
			Subcategories: []SubcategoryMapping{
				measure11(inv),
				measure21(inv),
				measure31(scan),
			},
		},
		{
			Function: "MANAGE", Title: "Manage",
			Description: "AI risks are prioritized, treated and monitored; third-party risks and post-deployment changes are managed over the system's lifetime.",
			Subcategories: []SubcategoryMapping{
				manage31(inv),
				manage41(scan),
				manage43(scan, inv),
			},
		},
	}
}

// SummarizeFunctions rolls all subcategories into a Summary.
func SummarizeFunctions(fns []FunctionMapping) Summary {
	s := Summary{Framework: Framework, FrameworkTotal: FrameworkSubcategories}
	for _, f := range fns {
		for _, sc := range f.Subcategories {
			s.Subcategories++
			switch sc.Status {
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

// ── inventory classification (free funcs over the neutral Component) ──────────

type inventory struct {
	all         []Component
	models      []Component
	services    []Component // ai-service + inference/managed-ai runtimes
	sdks        []Component
	agents      []Component // coding-agent + agent infra
	datasets    []Component
	training    []Component
	vectordbs   []Component
	accelerators []Component
	evaluations []Component
	providers   map[string]bool // distinct third-party providers
	gapped      []Component
	aiAuthored  int
}

func classify(comps []Component) inventory {
	inv := inventory{all: comps, providers: map[string]bool{}}
	for _, c := range comps {
		switch {
		case isModel(c):
			inv.models = append(inv.models, c)
		case c.Category == "ai-service" || c.Category == "inference" || c.Category == "managed-ai":
			inv.services = append(inv.services, c)
		case c.Category == "ai-sdk":
			inv.sdks = append(inv.sdks, c)
		}
		if c.Category == "coding-agent" || c.Category == "agent" {
			inv.agents = append(inv.agents, c)
		}
		if c.Category == "data" && c.DataKind == "dataset" {
			inv.datasets = append(inv.datasets, c)
		}
		if c.Category == "training" {
			inv.training = append(inv.training, c)
		}
		if c.Category == "vector-database" {
			inv.vectordbs = append(inv.vectordbs, c)
		}
		if c.Category == "accelerator" {
			inv.accelerators = append(inv.accelerators, c)
		}
		if c.Category == "evaluation" {
			inv.evaluations = append(inv.evaluations, c)
		}
		if c.Provider != "" {
			inv.providers[c.Provider] = true
		}
		if c.ConfidenceGap {
			inv.gapped = append(inv.gapped, c)
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

// ── GOVERN ───────────────────────────────────────────────────────────────────

func govern16(scan Scan, inv inventory) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 1.6", "AI system inventory",
		"Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected; there is no AI system to inventory."
		return m
	}
	m.Evidence = append(m.Evidence, EvidenceItem{
		Component: plural(len(inv.all), "AI component"),
		Kind:      "provenance",
		Detail:    "Automatically inventoried in a CycloneDX AI-BOM (tools, SDKs, models, infrastructure and data)",
	})
	if hasProvenance(scan) {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: "Inventory attributable to " + toolLabel(scan) + " at commit " + shortSha(scan.CommitSha)})
		m.Status = StatusSatisfied
		m.Rationale = "An automatic, attributable AI-system inventory exists — the core mechanism GOVERN 1.6 requires."
	} else {
		m.Status = StatusPartial
		m.Rationale = "An AI-system inventory exists but lacks provenance (repo/commit/tool/timestamp) to be attributable."
		m.Gaps = append(m.Gaps, "Inventory not attributable (no provenance)")
	}
	return m
}

func govern61(inv inventory) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 6.1", "Third-party risk policies",
		"Policies and procedures are in place to address AI risks arising from third-party software, data and other supply-chain issues.")
	third := len(inv.sdks) + len(inv.services) + len(inv.providers)
	if third == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No third-party AI software, services or providers were detected."
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "Third-party AI provider in the supply chain"})
	}
	sortEvidence(m.Evidence)
	m.Status = StatusPartial
	m.Rationale = "Third-party AI (SDKs, services, providers) is inventoried, giving supply-chain policies a concrete scope; whether the policies themselves exist is out of scope for an inventory."
	m.Gaps = append(m.Gaps, "Policy existence/adherence not evidenceable from an inventory")
	return m
}

func govern62(inv inventory) SubcategoryMapping {
	m := sub("GOVERN", "GOVERN 6.2", "Third-party failure contingencies",
		"Contingency processes are in place to handle failures or incidents in third-party data or AI systems.")
	if len(inv.services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No external AI services or runtimes were detected whose failure would need a contingency."
		return m
	}
	sortByName(inv.services)
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "service", Detail: "External AI dependency whose availability is a contingency concern"})
	}
	m.Status = StatusInformational
	m.Rationale = plural(len(inv.services), "external AI dependency") + " detected. The inventory identifies what a contingency plan must cover; it cannot confirm the plan exists."
	return m
}

// ── MAP ──────────────────────────────────────────────────────────────────────

func map11(scan Scan, inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 1.1", "Context & intended purpose",
		"Intended purpose, setting and requirements for the AI system are understood and documented.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected."
		return m
	}
	tasks := 0
	for _, mdl := range inv.models {
		if mdl.Task != "" {
			tasks++
		}
	}
	if hasProvenance(scan) {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: "Deployment context: repository and commit the AI is used in"})
	}
	if tasks > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(tasks, "model"), Kind: "model", Detail: "Declare a task (chat/embedding/…), indicating intended purpose"})
	}
	m.Status = StatusPartial
	m.Rationale = "Deployment context and per-model purpose are captured; the broader organizational mission/requirements context is out of scope for an inventory."
	return m
}

func map21(inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 2.1", "AI system categorization",
		"The specific tasks and methods used to implement the AI system are defined and categorized.")
	if len(inv.models) == 0 && len(inv.services) == 0 && len(inv.training) == 0 &&
		len(inv.agents) == 0 && len(inv.accelerators) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No models, services, agents, training or compute methods were detected to categorize."
		return m
	}
	untasked := 0
	sortByName(inv.models)
	for _, mdl := range inv.models {
		detail := "Model"
		if mdl.Task != "" {
			detail += " — task " + mdl.Task
		} else {
			untasked++
		}
		if mdl.ViaSDK != "" {
			detail += " (via " + mdl.ViaSDK + ")"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail})
	}
	for _, s := range inv.services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "runtime", Detail: "Serving/inference method categorized"})
	}
	sortByName(inv.agents)
	for _, a := range inv.agents {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "agent", Detail: "Autonomous agent method categorized"})
	}
	for _, t := range inv.training {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: t.Name, Kind: "runtime", Detail: "Training/fine-tuning method categorized"})
	}
	for _, ac := range inv.accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: ac.Name, Kind: "accelerator", Detail: "Compute method (accelerator) categorized"})
	}
	if untasked > 0 {
		m.Status = StatusPartial
		m.Rationale = "AI methods (models, runtimes, agents, training, compute) are categorized; " + plural(untasked, "model") + " lack a resolved task."
		m.Gaps = append(m.Gaps, plural(untasked, "model")+" without a categorized task")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Models are categorized by task and broker (SDK), and serving/agent/training/compute methods are enumerated."
	}
	return m
}

func map22(inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 2.2", "Knowledge limits documented",
		"Information about the AI system's knowledge limits and how outputs may be used/overseen is documented.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected."
		return m
	}
	// The IaC confidence-gap signal is a machine-readable statement of the
	// inventory's own knowledge limits — a direct MAP 2.2 artifact.
	if len(inv.gapped) == 0 {
		m.Status = StatusSatisfied
		m.Rationale = "Every component was fully resolved from source — no unverifiable values — so the inventory states no knowledge limits."
		return m
	}
	sortByName(inv.gapped)
	for _, c := range inv.gapped {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: c.Name, Kind: "log", Detail: "Documented knowledge limit: " + c.GapReason})
	}
	m.Status = StatusSatisfied
	m.Rationale = "The inventory explicitly documents its knowledge limits (" + plural(len(inv.gapped), "component") + " with a stated unverifiable value) rather than hiding them."
	return m
}

func map41(inv inventory) SubcategoryMapping {
	m := sub("MAP", "MAP 4.1", "Third-party & legal risks",
		"Approaches for mapping AI technology and legal risks of its components — including third-party software/data and intellectual property — are in place.")
	if len(inv.providers) == 0 && len(inv.sdks) == 0 && len(inv.datasets) == 0 && len(inv.vectordbs) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No third-party AI components, providers or external data sources were detected."
		return m
	}
	for p := range inv.providers {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: p, Kind: "service", Detail: "Third-party provider — a technology/legal-risk surface (terms, data handling)"})
	}
	sortEvidence(m.Evidence)
	sortByName(inv.sdks)
	for _, s := range inv.sdks {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "sdk", Detail: "Third-party AI SDK — supply-chain and licensing risk surface"})
	}
	sortByName(inv.datasets)
	for _, d := range inv.datasets {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: "Dataset — data-provenance and IP/legal-risk surface"})
	}
	sortByName(inv.vectordbs)
	for _, v := range inv.vectordbs {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: v.Name, Kind: "runtime", Detail: "Retrieval (vector) database — external-data provenance risk surface"})
	}
	m.Status = StatusPartial
	m.Rationale = "Third-party AI components, providers and external data sources are mapped, giving legal/technology-risk analysis a concrete surface; the risk analysis itself is a downstream activity."
	return m
}

func map51() SubcategoryMapping {
	m := sub("MAP", "MAP 5.1", "Impact characterization",
		"Likelihood and magnitude of each identified risk's impact (including to individuals, groups and society) are characterized.")
	m.Status = StatusNotApplicable
	m.Rationale = "Impact likelihood/magnitude is a human risk-assessment judgement; an AI inventory provides inputs but cannot characterize societal impact."
	return m
}

// ── MEASURE ──────────────────────────────────────────────────────────────────

func measure11(inv inventory) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 1.1", "Metrics & methods identified",
		"Approaches and metrics for measuring AI risks are selected and the reasons documented.")
	if len(inv.evaluations) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No evaluation/benchmark workloads were detected in the inventory."
		return m
	}
	sortByName(inv.evaluations)
	for _, e := range inv.evaluations {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: e.Name, Kind: "runtime", Detail: "Evaluation/benchmark framework present — a measurement method is in use"})
	}
	m.Status = StatusInformational
	m.Rationale = plural(len(inv.evaluations), "evaluation framework") + " detected, indicating measurement is in place; the specific metrics and their results are not carried by an inventory."
	return m
}

func measure21(inv inventory) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 2.1", "Trustworthiness evaluated",
		"AI systems are evaluated for trustworthy characteristics (validity, reliability, safety, bias, etc.).")
	if len(inv.evaluations) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No evaluation workloads were detected; no trustworthiness measurement is evidenced."
		return m
	}
	for _, e := range inv.evaluations {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: e.Name, Kind: "runtime", Detail: "Trustworthiness evaluation workload present"})
	}
	m.Status = StatusInformational
	m.Rationale = "Evaluation workloads are present, but their results (validity, bias, safety scores) are not carried by an inventory — a reviewer must confirm the outcomes."
	m.Gaps = append(m.Gaps, "Evaluation results not present in the inventory")
	return m
}

func measure31(scan Scan) SubcategoryMapping {
	m := sub("MEASURE", "MEASURE 3.1", "Risks tracked over time",
		"Approaches and mechanisms are in place to track identified AI risks over time.")
	if scan.PriorScanCount > 1 {
		m.Status = StatusSatisfied
		m.Rationale = "The AI inventory has been regenerated over time (" + plural(scan.PriorScanCount, "scan") + "), providing a mechanism to track how the AI in use — and its risks — change."
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: plural(scan.PriorScanCount, "inventory scan") + " recorded over time"})
		return m
	}
	m.Status = StatusInformational
	m.Rationale = "Only a single inventory scan exists; risk tracking over time requires repeated inventory — schedule recurring scans."
	m.Gaps = append(m.Gaps, "Single point-in-time scan; no change history yet")
	return m
}

// ── MANAGE ───────────────────────────────────────────────────────────────────

func manage31(inv inventory) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 3.1", "Third-party risk management",
		"AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.")
	if len(inv.providers) == 0 && len(inv.sdks) == 0 && len(inv.services) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No third-party AI resources were detected to manage."
		return m
	}
	third := len(inv.providers) + len(inv.sdks) + len(inv.services)
	m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(third, "third-party resource"), Kind: "sdk", Detail: "Third-party AI resources are enumerated for ongoing risk management"})
	m.Status = StatusPartial
	m.Rationale = "Third-party AI resources are inventoried and re-inventoried on each scan; applying and documenting the risk controls is a downstream management activity."
	return m
}

func manage41(scan Scan) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 4.1", "Post-deployment monitoring",
		"Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating changes.")
	if scan.PriorScanCount > 1 {
		m.Status = StatusSatisfied
		m.Rationale = "Repeated inventory scans (" + plural(scan.PriorScanCount, "scan") + ") implement a mechanism for capturing post-deployment changes to the AI in use."
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: plural(scan.PriorScanCount, "monitoring scan") + " over time"})
		return m
	}
	m.Status = StatusInformational
	m.Rationale = "A single scan does not yet evidence a monitoring plan; recurring inventory scans implement post-deployment monitoring."
	m.Gaps = append(m.Gaps, "No recurring-scan monitoring history yet")
	return m
}

func manage43(scan Scan, inv inventory) SubcategoryMapping {
	m := sub("MANAGE", "MANAGE 4.3", "Incidents & changes tracked",
		"Incidents and errors are communicated to relevant stakeholders; changes to the AI system are tracked.")
	if len(inv.all) == 0 {
		m.Status = StatusNotApplicable
		m.Rationale = "No AI components were detected."
		return m
	}
	if inv.aiAuthored > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(inv.aiAuthored, "component"), Kind: "log", Detail: "Change history via AI-authored commits — a tracked record of AI-driven changes"})
	}
	if scan.PriorScanCount > 1 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: scan.RepoName, Kind: "provenance", Detail: plural(scan.PriorScanCount, "inventory revision") + " tracking changes over time"})
	}
	switch {
	case inv.aiAuthored > 0 && scan.PriorScanCount > 1:
		m.Status = StatusSatisfied
		m.Rationale = "Changes to the AI in use are tracked both by AI-authored commit history and by repeated inventory revisions."
	case inv.aiAuthored > 0 || scan.PriorScanCount > 1:
		m.Status = StatusPartial
		m.Rationale = "Some change tracking is evidenced (commit history or repeated scans); a full change-communication process is a downstream activity."
	default:
		m.Status = StatusInformational
		m.Rationale = "A single scan with no AI-authored commit history yet; recurring scans and tracked commits evidence change management."
		m.Gaps = append(m.Gaps, "No change history yet (single scan, no AI-authored commits)")
	}
	return m
}

// ── helpers ──────────────────────────────────────────────────────────────────

func sub(function, id, title, outcome string) SubcategoryMapping {
	return SubcategoryMapping{Function: function, ID: id, Title: title, Outcome: outcome}
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
