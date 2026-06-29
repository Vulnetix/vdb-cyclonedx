package cyclonedx

// AIBOM — AI Bill of Materials.
//
// This file owns the Vulnetix AIBOM format end to end: the detection data model
// (the contract between a producer's detection layer and the BOM), the property
// vocabulary (vulnetix:ai/*, vulnetix:git/*, vulnetix:env/*), creation
// (BuildAIBOM: detections -> validated CycloneDX), and parsing (ParseAIBOM:
// CycloneDX -> a flat, persistable inventory). Validation reuses the shared
// CycloneDX schema validator in this package.
//
// Component mapping:
//
//	AI coding tool / agent  -> component type "application"           (category coding-agent|ai-service|ai-convention)
//	AI SDK / framework       -> component type "library"              (category ai-sdk)
//	model name (literal)     -> component type "machine-learning-model" + modelCard (category model)
//
// Custom evidence rides on each component's properties (namespace vulnetix:ai/evidence).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── Property keys ────────────────────────────────────────────────────────────

const (
	PropAIProfile          = "vulnetix:aibom/profile"
	PropAIGenerator        = "vulnetix:aibom/generator"
	PropAICatalogVersion   = "vulnetix:aibom/catalog-version"
	PropAIToolsDetected    = "vulnetix:aibom/tools-detected"
	PropAILibsDetected     = "vulnetix:aibom/libraries-detected"
	PropAIModelsDetected   = "vulnetix:aibom/models-detected"
	PropAICategory         = "vulnetix:ai/category"
	PropAIToolID           = "vulnetix:ai/tool-id"
	PropAIToolType         = "vulnetix:ai/tool-type"
	PropAILibraryID        = "vulnetix:ai/library-id"
	PropAIProvider         = "vulnetix:ai/provider"
	PropAILanguages        = "vulnetix:ai/languages"
	PropAIConfidence       = "vulnetix:ai/confidence"
	PropAIModelKnown       = "vulnetix:ai/model/known"
	PropAIModelFamily      = "vulnetix:ai/model/family"
	PropAIModelViaSDK      = "vulnetix:ai/model/via-sdk"
	PropAIModelOccurrences = "vulnetix:ai/model/occurrences"
	PropAIDiscoveredPrefix = "vulnetix:ai/discovered/"
	PropAIEvidenceCount    = "vulnetix:ai/evidence-count"
	PropAIEvidence         = "vulnetix:ai/evidence"

	PropGitBranch    = "vulnetix:git/branch"
	PropGitCommit    = "vulnetix:git/commit"
	PropGitCommitTS  = "vulnetix:git/commit-timestamp"
	PropGitCommitMsg = "vulnetix:git/commit-message"
	PropGitCommitBy  = "vulnetix:git/commit-author"
	PropGitTags      = "vulnetix:git/tags"
	PropGitDirty     = "vulnetix:git/dirty"
	PropGitWorktree  = "vulnetix:git/is-worktree"
	PropGitRepoRoot  = "vulnetix:git/repo-root"

	PropEnvHostname = "vulnetix:env/hostname"
	PropEnvShell    = "vulnetix:env/shell"
	PropEnvOS       = "vulnetix:env/os"
	PropEnvArch     = "vulnetix:env/arch"
	PropEnvUser     = "vulnetix:env/user"
)

// maxEvidencePerComponent caps how many evidence properties a single component
// carries, so a repo with thousands of call sites can't bloat the BOM.
const maxEvidencePerComponent = 50

// ── Detection model (the producer contract) ──────────────────────────────────

// AIEvidence is one observation supporting a detection. Method is one of
// env|file|source|commit. For file evidence Category is the catalog path
// category (config, instructions, agents, ...). For source evidence Category is
// import|model. Locator is an env var name, a file path, or "file:line".
type AIEvidence struct {
	Method   string `json:"method"`
	Category string `json:"category,omitempty"`
	Locator  string `json:"locator,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
}

// AITool is a detected AI coding agent / assistant / service / convention.
type AITool struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Vendor         string         `json:"vendor,omitempty"`
	Type           string         `json:"type,omitempty"` // ""|service|convention
	Homepage       string         `json:"homepage,omitempty"`
	ArtifactCounts map[string]int `json:"artifactCounts,omitempty"`
	Confidence     string         `json:"confidence,omitempty"`
	Evidence       []AIEvidence   `json:"evidence,omitempty"`
}

// AILibrary is a detected AI SDK / framework used by the source code.
type AILibrary struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Provider   string       `json:"provider,omitempty"`
	Languages  []string     `json:"languages,omitempty"`
	Purl       string       `json:"purl,omitempty"`
	Confidence string       `json:"confidence,omitempty"`
	Evidence   []AIEvidence `json:"evidence,omitempty"`
}

// AIModel is a model name literal extracted from source or config.
type AIModel struct {
	Name        string       `json:"name"`
	Provider    string       `json:"provider,omitempty"`
	Family      string       `json:"family,omitempty"`
	ViaSDK      string       `json:"viaSdk,omitempty"`
	Task        string       `json:"task,omitempty"`
	Known       bool         `json:"known"`
	Occurrences int          `json:"occurrences,omitempty"`
	Confidence  string       `json:"confidence,omitempty"`
	Evidence    []AIEvidence `json:"evidence,omitempty"`
}

// AIDetections is the full result of an AIBOM scan.
type AIDetections struct {
	Tools          []AITool    `json:"tools,omitempty"`
	Libraries      []AILibrary `json:"libraries,omitempty"`
	Models         []AIModel   `json:"models,omitempty"`
	CatalogVersion string      `json:"catalogVersion,omitempty"`
}

// AIBOMContact is a git committer recorded as a component author.
type AIBOMContact struct {
	Name  string
	Email string
}

// AIBOMSystem is the host/process environment recorded on metadata.
type AIBOMSystem struct {
	Hostname string
	Shell    string
	OS       string
	Arch     string
	Username string
}

// AIBOMProject describes the scanned repository, used to build metadata.component
// and the vulnetix:git/* / vulnetix:env/* properties. All fields are optional;
// a nil project yields a minimal "project" component.
type AIBOMProject struct {
	Name             string
	Version          string
	Description      string
	Branch           string
	Commit           string
	CommitTimestamp  string
	CommitMessage    string
	CommitAuthor     string
	CommitEmail      string
	Tags             []string
	IsDirty          bool
	IsWorktree       bool
	RepoRoot         string
	RemoteURLs       []string
	RecentCommitters []AIBOMContact
	System           *AIBOMSystem
}

// AIBOMOptions configures BuildAIBOM.
type AIBOMOptions struct {
	SpecVersion string        // default "1.7"
	ToolName    string        // default "vulnetix-aibom"
	ToolVersion string        // default "cli"
	GeneratedAt string        // RFC3339; default time.Now().UTC()
	Project     *AIBOMProject // nil → minimal project component
}

// ── Writer model (AIBOM-specific, minimal subset of CycloneDX) ───────────────

type aibomDoc struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     *aibomMetadata `json:"metadata,omitempty"`
	Components   []aibomComp    `json:"components,omitempty"`
	Dependencies []aibomDep     `json:"dependencies,omitempty"`
}

type aibomMetadata struct {
	Timestamp  string           `json:"timestamp,omitempty"`
	Lifecycles []aibomLifecycle `json:"lifecycles,omitempty"`
	Tools      *aibomTools      `json:"tools,omitempty"`
	Component  *aibomComp       `json:"component,omitempty"`
	Properties []aibomProp      `json:"properties,omitempty"`
}

type aibomLifecycle struct {
	Phase string `json:"phase"`
}

type aibomTools struct {
	Components []aibomComp `json:"components,omitempty"`
}

type aibomComp struct {
	Type               string          `json:"type"`
	BOMRef             string          `json:"bom-ref,omitempty"`
	Name               string          `json:"name"`
	Version            string          `json:"version,omitempty"`
	Group              string          `json:"group,omitempty"`
	Publisher          string          `json:"publisher,omitempty"`
	Description        string          `json:"description,omitempty"`
	Purl               string          `json:"purl,omitempty"`
	Authors            []aibomContact  `json:"authors,omitempty"`
	ExternalReferences []aibomExtRef   `json:"externalReferences,omitempty"`
	Properties         []aibomProp     `json:"properties,omitempty"`
	ModelCard          *aibomModelCard `json:"modelCard,omitempty"`
	// CryptoProperties is set only by the CBOM builder (cbom.go) on
	// "cryptographic-asset" components; the AIBOM builder never sets it
	// (omitempty keeps it absent from AIBOM output).
	CryptoProperties *cdxCryptoProperties `json:"cryptoProperties,omitempty"`
}

type aibomContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type aibomExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type aibomProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type aibomModelCard struct {
	ModelParameters *aibomModelParams `json:"modelParameters,omitempty"`
}

type aibomModelParams struct {
	Task              string `json:"task,omitempty"`
	ModelArchitecture string `json:"modelArchitecture,omitempty"`
}

type aibomDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func mkProp(name, value string) aibomProp { return aibomProp{Name: name, Value: value} }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ── BuildAIBOM (creating) ────────────────────────────────────────────────────

// BuildAIBOM maps detection results to a CycloneDX AIBOM and returns the
// indented JSON. The result is validated against the CycloneDX schema for the
// declared spec version; a schema violation returns an error.
func BuildAIBOM(det AIDetections, opts AIBOMOptions) ([]byte, error) {
	doc := BuildAIBOMDocument(det, opts)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, violations, verr := ValidateCycloneDX(data); verr != nil {
		return nil, fmt.Errorf("aibom: validation error: %w", verr)
	} else if len(violations) > 0 {
		return nil, fmt.Errorf("aibom: schema violation at %s: %s", violations[0].Path, violations[0].Message)
	}
	return data, nil
}

// BuildAIBOMDocument assembles the AIBOM as a marshalable document without
// validating — useful for callers that want to inspect or re-serialize it.
func BuildAIBOMDocument(det AIDetections, opts AIBOMOptions) any {
	spec := opts.SpecVersion
	if spec == "" {
		spec = "1.7"
	}
	toolName := opts.ToolName
	if toolName == "" {
		toolName = "vulnetix-aibom"
	}
	toolVersion := opts.ToolVersion
	if toolVersion == "" {
		toolVersion = "cli"
	}
	ts := opts.GeneratedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	projComp, envProps := buildProjectComponent(opts.Project)

	doc := &aibomDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  spec,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &aibomMetadata{
			Timestamp:  ts,
			Lifecycles: []aibomLifecycle{{Phase: "build"}},
			Tools:      &aibomTools{Components: []aibomComp{{Type: "application", Name: toolName, Version: toolVersion}}},
			Component:  projComp,
		},
	}

	projRef := projComp.BOMRef
	doc.Metadata.Properties = append(doc.Metadata.Properties,
		mkProp(PropAIProfile, "ai-usage"),
		mkProp(PropAIGenerator, toolName),
	)
	if det.CatalogVersion != "" {
		doc.Metadata.Properties = append(doc.Metadata.Properties, mkProp(PropAICatalogVersion, det.CatalogVersion))
	}
	doc.Metadata.Properties = append(doc.Metadata.Properties,
		mkProp(PropAIToolsDetected, strconv.Itoa(len(det.Tools))),
		mkProp(PropAILibsDetected, strconv.Itoa(len(det.Libraries))),
		mkProp(PropAIModelsDetected, strconv.Itoa(len(det.Models))),
	)
	doc.Metadata.Properties = append(doc.Metadata.Properties, envProps...)

	validRefs := map[string]bool{projRef: true}
	deps := map[string][]string{}

	// AI coding tools / agents → application components.
	for _, t := range det.Tools {
		ref := "urn:ai-tool:" + t.ID
		comp := aibomComp{Type: "application", BOMRef: ref, Name: t.Name, Publisher: t.Vendor, Group: t.Vendor}
		if t.Homepage != "" {
			comp.ExternalReferences = append(comp.ExternalReferences, aibomExtRef{Type: "website", URL: t.Homepage})
		}
		category := "coding-agent"
		switch t.Type {
		case "service":
			category = "ai-service"
		case "convention":
			category = "ai-convention"
		}
		comp.Properties = append(comp.Properties, mkProp(PropAICategory, category), mkProp(PropAIToolID, t.ID))
		if t.Type != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIToolType, t.Type))
		}
		if t.Confidence != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIConfidence, t.Confidence))
		}
		for _, k := range sortedCountKeys(t.ArtifactCounts) {
			comp.Properties = append(comp.Properties, mkProp(PropAIDiscoveredPrefix+k, strconv.Itoa(t.ArtifactCounts[k])))
		}
		appendEvidenceProps(&comp, t.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true
		deps[projRef] = append(deps[projRef], ref)
	}

	// AI SDKs / frameworks → library components.
	libRefByID := map[string]string{}
	for _, l := range det.Libraries {
		ref := "urn:ai-lib:" + l.ID
		comp := aibomComp{Type: "library", BOMRef: ref, Name: l.Name, Publisher: l.Provider, Purl: l.Purl}
		comp.Properties = append(comp.Properties, mkProp(PropAICategory, "ai-sdk"), mkProp(PropAILibraryID, l.ID))
		if l.Provider != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIProvider, l.Provider))
		}
		if len(l.Languages) > 0 {
			comp.Properties = append(comp.Properties, mkProp(PropAILanguages, strings.Join(l.Languages, ",")))
		}
		if l.Confidence != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIConfidence, l.Confidence))
		}
		appendEvidenceProps(&comp, l.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true
		libRefByID[l.ID] = ref
		deps[projRef] = append(deps[projRef], ref)
	}

	// model name literals → machine-learning-model components.
	for i, m := range det.Models {
		ref := fmt.Sprintf("urn:ai-model:%d", i)
		comp := aibomComp{
			Type: "machine-learning-model", BOMRef: ref, Name: m.Name, Publisher: m.Provider, Group: m.Provider,
			ModelCard: &aibomModelCard{ModelParameters: &aibomModelParams{Task: m.Task, ModelArchitecture: m.Name}},
		}
		comp.Properties = append(comp.Properties, mkProp(PropAICategory, "model"), mkProp(PropAIModelKnown, boolStr(m.Known)))
		if m.Provider != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIProvider, m.Provider))
		}
		if m.Family != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIModelFamily, m.Family))
		}
		if m.ViaSDK != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIModelViaSDK, m.ViaSDK))
		}
		if m.Occurrences > 0 {
			comp.Properties = append(comp.Properties, mkProp(PropAIModelOccurrences, strconv.Itoa(m.Occurrences)))
		}
		if m.Confidence != "" {
			comp.Properties = append(comp.Properties, mkProp(PropAIConfidence, m.Confidence))
		}
		appendEvidenceProps(&comp, m.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true

		parent := projRef
		if r, ok := libRefByID[m.ViaSDK]; ok {
			parent = r
		}
		deps[parent] = append(deps[parent], ref)
	}

	doc.Dependencies = buildDeps(deps, validRefs)
	return doc
}

// buildProjectComponent builds metadata.component plus the env properties from a
// project description. A nil project yields the minimal default component.
func buildProjectComponent(p *AIBOMProject) (*aibomComp, []aibomProp) {
	if p == nil {
		return &aibomComp{Type: "application", BOMRef: "urn:project", Name: "project"}, nil
	}

	comp := &aibomComp{
		Type:        "application",
		BOMRef:      "urn:project",
		Name:        nonEmpty(p.Name, "project"),
		Version:     p.Version,
		Description: nonEmpty(p.Description, "Source code repository"),
	}
	for _, u := range p.RemoteURLs {
		comp.ExternalReferences = append(comp.ExternalReferences, aibomExtRef{Type: "vcs", URL: normalizeVCSURL(u)})
	}
	if p.Branch != "" {
		comp.Properties = append(comp.Properties, mkProp(PropGitBranch, p.Branch))
	}
	if p.Commit != "" {
		comp.Properties = append(comp.Properties, mkProp(PropGitCommit, p.Commit))
	}
	if p.CommitTimestamp != "" {
		comp.Properties = append(comp.Properties, mkProp(PropGitCommitTS, p.CommitTimestamp))
	}
	if p.CommitMessage != "" {
		comp.Properties = append(comp.Properties, mkProp(PropGitCommitMsg, p.CommitMessage))
	}
	if p.CommitAuthor != "" {
		v := p.CommitAuthor
		if p.CommitEmail != "" {
			v += " <" + p.CommitEmail + ">"
		}
		comp.Properties = append(comp.Properties, mkProp(PropGitCommitBy, v))
	}
	if len(p.Tags) > 0 {
		comp.Properties = append(comp.Properties, mkProp(PropGitTags, strings.Join(p.Tags, ", ")))
	}
	comp.Properties = append(comp.Properties, mkProp(PropGitDirty, boolStr(p.IsDirty)), mkProp(PropGitWorktree, boolStr(p.IsWorktree)))
	if p.RepoRoot != "" {
		comp.Properties = append(comp.Properties, mkProp(PropGitRepoRoot, p.RepoRoot))
	}
	for _, c := range p.RecentCommitters {
		comp.Authors = append(comp.Authors, aibomContact{Name: c.Name, Email: c.Email})
	}

	var envProps []aibomProp
	if s := p.System; s != nil {
		if s.Hostname != "" {
			envProps = append(envProps, mkProp(PropEnvHostname, s.Hostname))
		}
		if s.Shell != "" {
			envProps = append(envProps, mkProp(PropEnvShell, s.Shell))
		}
		if s.OS != "" {
			envProps = append(envProps, mkProp(PropEnvOS, s.OS))
		}
		if s.Arch != "" {
			envProps = append(envProps, mkProp(PropEnvArch, s.Arch))
		}
		if s.Username != "" {
			envProps = append(envProps, mkProp(PropEnvUser, s.Username))
		}
	}
	return comp, envProps
}

func appendEvidenceProps(comp *aibomComp, ev []AIEvidence) {
	if len(ev) == 0 {
		return
	}
	comp.Properties = append(comp.Properties, mkProp(PropAIEvidenceCount, strconv.Itoa(len(ev))))
	limit := len(ev)
	if limit > maxEvidencePerComponent {
		limit = maxEvidencePerComponent
	}
	for _, e := range ev[:limit] {
		comp.Properties = append(comp.Properties, mkProp(PropAIEvidence, FormatEvidence(e)))
	}
}

// FormatEvidence renders one evidence record as a compact, single-line value:
//
//	"<method> <category> <locator> :: <snippet>"
func FormatEvidence(e AIEvidence) string {
	var b strings.Builder
	b.WriteString(e.Method)
	if e.Category != "" {
		b.WriteString(" ")
		b.WriteString(e.Category)
	}
	if e.Locator != "" {
		b.WriteString(" ")
		b.WriteString(e.Locator)
	}
	if e.Snippet != "" {
		b.WriteString(" :: ")
		b.WriteString(e.Snippet)
	}
	return b.String()
}

func buildDeps(deps map[string][]string, validRefs map[string]bool) []aibomDep {
	out := make([]aibomDep, 0, len(deps))
	for ref := range deps {
		if !validRefs[ref] {
			continue
		}
		seen := map[string]bool{}
		var on []string
		for _, t := range deps[ref] {
			if t == ref || seen[t] || !validRefs[t] {
				continue
			}
			seen[t] = true
			on = append(on, t)
		}
		sort.Strings(on)
		out = append(out, aibomDep{Ref: ref, DependsOn: on})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func sortedCountKeys(m map[string]int) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// normalizeVCSURL converts an SSH git remote URL to its HTTPS equivalent so the
// result is a valid IRI-reference as required by CycloneDX schemas.
//
//	git@github.com:owner/repo.git  →  https://github.com/owner/repo
func normalizeVCSURL(u string) string {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "git@") {
		rest := strings.TrimPrefix(u, "git@")
		if i := strings.Index(rest, ":"); i >= 0 {
			host := rest[:i]
			path := strings.TrimSuffix(rest[i+1:], ".git")
			return "https://" + host + "/" + path
		}
	}
	if strings.HasPrefix(u, "ssh://") {
		rest := strings.TrimPrefix(u, "ssh://")
		rest = strings.TrimPrefix(rest, "git@")
		rest = strings.TrimSuffix(rest, ".git")
		return "https://" + rest
	}
	return strings.TrimSuffix(u, ".git")
}

// ── ParseAIBOM (parsing) ─────────────────────────────────────────────────────

type cdxParseProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxParseExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxParseModelCard struct {
	ModelParameters *struct {
		Task              string `json:"task"`
		ModelArchitecture string `json:"modelArchitecture"`
	} `json:"modelParameters"`
}

type cdxParseComp struct {
	Type               string             `json:"type"`
	Name               string             `json:"name"`
	Group              string             `json:"group"`
	Publisher          string             `json:"publisher"`
	Version            string             `json:"version"`
	Purl               string             `json:"purl"`
	Properties         []cdxParseProp     `json:"properties"`
	ExternalReferences []cdxParseExtRef   `json:"externalReferences"`
	ModelCard          *cdxParseModelCard `json:"modelCard"`
}

type cdxParseBOM struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Metadata     *struct {
		Component  *cdxParseComp  `json:"component"`
		Properties []cdxParseProp `json:"properties"`
		Tools      *struct {
			Components []cdxParseComp `json:"components"`
		} `json:"tools"`
	} `json:"metadata"`
	Components   []cdxParseComp  `json:"components"`
	Dependencies json.RawMessage `json:"dependencies"`
}

// AIBOMComponentRow is one decomposed component, flattened for persistence.
type AIBOMComponentRow struct {
	ComponentType     string
	Category          string
	Name              string
	Group             string
	Publisher         string
	Version           string
	Purl              string
	ToolID            string
	LibraryID         string
	Provider          string
	Family            string
	ViaSDK            string
	Task              string
	ModelArchitecture string
	Known             *bool
	Occurrences       int
	Confidence        string
	ToolType          string
	Homepage          string
	Languages         string
	PropertiesJSON    string
	ExternalRefsJSON  string
	ModelCardJSON     string
	Evidence          []AIEvidence
}

// AIBOMInventory is the flattened, persistable decomposition of a CycloneDX AIBOM.
type AIBOMInventory struct {
	SpecVersion      string
	SerialNumber     string
	CatalogVersion   string
	ToolName         string
	ToolVersion      string
	ToolVendor       string
	RepoName         string
	BranchName       string
	CommitSha        string
	ComponentCount   int
	ToolCount        int
	LibraryCount     int
	ModelCount       int
	MetadataJSON     string
	DependenciesJSON string
	Components       []AIBOMComponentRow
}

func firstProp(props []cdxParseProp, name string) string {
	for _, p := range props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// categoryForParsedComponent resolves the AIBOM category. Vulnetix-generated BOMs
// carry vulnetix:ai/category; for generic CycloneDX AIBOMs we fall back by type
// (models and libraries map cleanly; an unannotated application is ambiguous).
func categoryForParsedComponent(c cdxParseComp) string {
	if cat := firstProp(c.Properties, PropAICategory); cat != "" {
		return cat
	}
	switch c.Type {
	case "machine-learning-model":
		return "model"
	case "library":
		return "ai-sdk"
	}
	return ""
}

// ParseEvidenceValue splits a "method [category] locator :: snippet" property
// value (as written by FormatEvidence) back into fields. Snippet is whatever
// follows " :: "; the head's first token is the method, the remainder is the
// locator (the category boundary isn't reliably recoverable, so it folds in).
func ParseEvidenceValue(v string) AIEvidence {
	head := v
	snippet := ""
	if i := strings.Index(v, " :: "); i >= 0 {
		head = v[:i]
		snippet = v[i+4:]
	}
	head = strings.TrimSpace(head)
	method, locator := head, ""
	if sp := strings.IndexByte(head, ' '); sp >= 0 {
		method = head[:sp]
		locator = strings.TrimSpace(head[sp+1:])
	}
	return AIEvidence{Method: method, Locator: locator, Snippet: snippet}
}

// ParseAIBOM decomposes a CycloneDX AIBOM into a flat inventory ready for
// persistence. It accepts both Vulnetix-generated AIBOMs (rich vulnetix:ai/*
// annotations) and generic CycloneDX AIBOMs (machine-learning-model / library
// components). Returns an error if the bytes are not a CycloneDX document or
// contain no AI components.
func ParseAIBOM(data []byte) (*AIBOMInventory, error) {
	var bom cdxParseBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("aibom: invalid JSON — expected a CycloneDX document: %w", err)
	}
	if !strings.EqualFold(bom.BOMFormat, "CycloneDX") {
		return nil, fmt.Errorf("aibom: not a CycloneDX document (bomFormat missing)")
	}

	inv := &AIBOMInventory{SpecVersion: bom.SpecVersion, SerialNumber: bom.SerialNumber}
	if m := bom.Metadata; m != nil {
		inv.CatalogVersion = firstProp(m.Properties, PropAICatalogVersion)
		if m.Component != nil {
			inv.RepoName = m.Component.Name
			inv.BranchName = firstProp(m.Component.Properties, PropGitBranch)
			inv.CommitSha = firstProp(m.Component.Properties, PropGitCommit)
		}
		if m.Tools != nil && len(m.Tools.Components) > 0 {
			inv.ToolName = m.Tools.Components[0].Name
			inv.ToolVersion = m.Tools.Components[0].Version
			inv.ToolVendor = m.Tools.Components[0].Publisher
		}
		inv.MetadataJSON = marshalString(m)
	}
	if len(bom.Dependencies) > 0 {
		inv.DependenciesJSON = string(bom.Dependencies)
	}

	for _, c := range bom.Components {
		cat := categoryForParsedComponent(c)
		if cat == "" {
			continue
		}
		row := AIBOMComponentRow{
			ComponentType:    c.Type,
			Category:         cat,
			Name:             c.Name,
			Group:            c.Group,
			Publisher:        c.Publisher,
			Version:          c.Version,
			Purl:             c.Purl,
			ToolID:           firstProp(c.Properties, PropAIToolID),
			LibraryID:        firstProp(c.Properties, PropAILibraryID),
			Provider:         firstProp(c.Properties, PropAIProvider),
			Family:           firstProp(c.Properties, PropAIModelFamily),
			ViaSDK:           firstProp(c.Properties, PropAIModelViaSDK),
			Confidence:       firstProp(c.Properties, PropAIConfidence),
			ToolType:         firstProp(c.Properties, PropAIToolType),
			Languages:        firstProp(c.Properties, PropAILanguages),
			PropertiesJSON:   marshalString(c.Properties),
			ExternalRefsJSON: marshalString(c.ExternalReferences),
		}
		if c.ModelCard != nil {
			row.ModelCardJSON = marshalString(c.ModelCard)
			if c.ModelCard.ModelParameters != nil {
				row.Task = c.ModelCard.ModelParameters.Task
				row.ModelArchitecture = c.ModelCard.ModelParameters.ModelArchitecture
			}
		}
		for _, ref := range c.ExternalReferences {
			if ref.Type == "website" {
				row.Homepage = ref.URL
				break
			}
		}
		if v := firstProp(c.Properties, PropAIModelKnown); v != "" {
			b := v == "true"
			row.Known = &b
		}
		if v := firstProp(c.Properties, PropAIModelOccurrences); v != "" {
			row.Occurrences, _ = strconv.Atoi(v)
		}
		for _, p := range c.Properties {
			if p.Name == PropAIEvidence && p.Value != "" {
				row.Evidence = append(row.Evidence, ParseEvidenceValue(p.Value))
			}
		}

		inv.Components = append(inv.Components, row)
		switch cat {
		case "coding-agent", "ai-service", "ai-convention":
			inv.ToolCount++
		case "ai-sdk":
			inv.LibraryCount++
		case "model":
			inv.ModelCount++
		}
	}
	inv.ComponentCount = len(inv.Components)
	if len(inv.Components) == 0 {
		return nil, fmt.Errorf("aibom: no AI components found — expected machine-learning-model components, AI SDK libraries, or vulnetix:ai annotated components")
	}
	return inv, nil
}

func marshalString(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return ""
	}
	return string(b)
}
