package cyclonedx

// The single CycloneDX VEX writer.
//
// Before this existed there were three: one in the CLI, one in vdb-api and one
// in vdb-site. They had already drifted apart, and the drift shipped invalid
// documents to consumers. vdb-site wrapped `analysis.response` in an array, as
// the schema requires; vdb-api emitted it as a bare string and put a sentence of
// reachability evidence in it; the CLI omitted the field entirely and emitted an
// `analysis.state` that is not in the CycloneDX enum at all.
//
// A VEX statement is a claim about whether a vulnerability affects something.
// Every field this file constrains is one a consumer reads to decide whether to
// act, so an invalid value is not a cosmetic fault: `response` tells a consumer
// what the publisher intends to do, and free text there means the machine
// reading it learns nothing.
//
// The document this produces is also meant to be *usable*, not merely valid. A
// VEX with no `affects` says a vulnerability exists somewhere and stops, which
// is why every vulnerability here is linked by bom-ref to the components it
// applies to.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The CycloneDX impact-analysis enums, from bom-1.7.schema.json. They are
// closed sets: a value outside them fails schema validation, so anything a
// caller supplies is checked against these and rerouted rather than emitted.
var (
	// cdxVEXStates is `impactAnalysisState`.
	//
	// Note what is missing: "under_investigation". Both previous writers used
	// it for an untriaged finding, and it has never been a CycloneDX state. The
	// spelling the specification defines is "in_triage".
	cdxVEXStates = map[string]bool{
		"resolved":               true,
		"resolved_with_pedigree": true,
		"exploitable":            true,
		"in_triage":              true,
		"false_positive":         true,
		"not_affected":           true,
	}

	// cdxVEXJustifications is `impactAnalysisJustification`.
	cdxVEXJustifications = map[string]bool{
		"code_not_present":                true,
		"code_not_reachable":              true,
		"requires_configuration":          true,
		"requires_dependency":             true,
		"requires_environment":            true,
		"protected_by_compiler":           true,
		"protected_at_runtime":            true,
		"protected_at_perimeter":          true,
		"protected_by_mitigating_control": true,
	}

	// cdxVEXResponses is the member type of `analysis.response`, which is an
	// array. This is the enum the invalid documents violated.
	cdxVEXResponses = map[string]bool{
		"can_not_fix":          true,
		"will_not_fix":         true,
		"update":               true,
		"rollback":             true,
		"workaround_available": true,
	}

	// cdxVEXSeverities is `severity`, used for ratings.
	cdxVEXSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true, "none": true, "unknown": true,
	}
)

// VEXFinding is one triage decision about one vulnerability in one package.
type VEXFinding struct {
	// CVEID is the vulnerability identifier. Findings sharing one are merged
	// into a single vulnerability entry whose `affects` lists every component.
	CVEID string

	Package      string
	Ecosystem    string
	InstalledVer string
	FixedVer     string

	// Status is the publisher's own vocabulary, mapped onto the CycloneDX
	// state enum by VEXState. A value already in the CycloneDX enum passes
	// through unchanged.
	Status string

	Justification string
	Detail        string
	Severity      string

	// Responses are what the publisher intends to do. Members outside the
	// CycloneDX enum are moved into the detail narrative instead of being
	// emitted, because an invalid member fails the whole document and a
	// consumer can still read the narrative.
	Responses []string

	// Properties carry anything the schema has no field for, such as the
	// threat-model axes. Emitted as namespaced `properties` entries.
	Properties map[string]string
}

// VEXOptions configures BuildCDXVEX.
type VEXOptions struct {
	SpecVersion string // default "1.7"
	ToolName    string // default "vulnetix-cdx"
	ToolVersion string // default "cli"
	GeneratedAt string // RFC3339; default now
	// AuthorName identifies who is making these claims. A VEX statement is an
	// assertion by somebody, and a document that does not say who is asserting
	// is worth less than one that does.
	AuthorName string
	// Project describes the subject the claims are about, and becomes
	// metadata.component.
	Project *AIBOMProject
}

// vexDoc is the write-side document. The read-side CDXBom in cyclonedx.go has
// no omitempty and no vulnerabilities, so it cannot be used to author one.
type vexDoc struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     *aibomMetadata `json:"metadata,omitempty"`
	Components   []aibomComp    `json:"components,omitempty"`

	Vulnerabilities []vexVulnerability `json:"vulnerabilities,omitempty"`
}

type vexVulnerability struct {
	BOMRef      string       `json:"bom-ref,omitempty"`
	ID          string       `json:"id"`
	Source      *vexSource   `json:"source,omitempty"`
	Ratings     []vexRating  `json:"ratings,omitempty"`
	Recommend   string       `json:"recommendation,omitempty"`
	Analysis    *vexAnalysis `json:"analysis,omitempty"`
	Affects     []vexAffect  `json:"affects,omitempty"`
	Properties  []aibomProp  `json:"properties,omitempty"`
	Description string       `json:"description,omitempty"`
}

type vexSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type vexRating struct {
	Source   *vexSource `json:"source,omitempty"`
	Severity string     `json:"severity,omitempty"`
}

type vexAnalysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type vexAffect struct {
	Ref string `json:"ref"`
}

// BuildCDXVEX assembles a CycloneDX VEX document and validates it before
// returning.
//
// Validation is not optional here. The defect this file replaces reached
// production and was served to consumers for months because nothing checked the
// bytes against the schema version they declared.
func BuildCDXVEX(findings []VEXFinding, opts VEXOptions) ([]byte, error) {
	doc := BuildCDXVEXDocument(findings, opts)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, violations, verr := ValidateCycloneDX(data); verr != nil {
		return nil, fmt.Errorf("vex: validation error: %w", verr)
	} else if len(violations) > 0 {
		return nil, fmt.Errorf("vex: schema violation at %s: %s",
			violations[0].Path, violations[0].Message)
	}
	return data, nil
}

// BuildCDXVEXDocument assembles the document without validating it, for callers
// that need to sign or post-process before the final bytes exist.
func BuildCDXVEXDocument(findings []VEXFinding, opts VEXOptions) any {
	spec := nonEmpty(opts.SpecVersion, "1.7")
	ts := opts.GeneratedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	doc := &vexDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  spec,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &aibomMetadata{
			Timestamp: ts,
			Tools: &aibomTools{Components: []aibomComp{{
				Type:    "application",
				Name:    nonEmpty(opts.ToolName, "vulnetix-cdx"),
				Version: nonEmpty(opts.ToolVersion, "cli"),
			}}},
		},
	}
	if opts.AuthorName != "" {
		doc.Metadata.Authors = []aibomContact{{Name: opts.AuthorName}}
	}
	if opts.Project != nil {
		projComp, _ := buildProjectComponent(opts.Project)
		doc.Metadata.Component = projComp
	}

	components, refByKey := vexComponents(findings)
	doc.Components = components
	doc.Vulnerabilities = vexVulnerabilities(findings, refByKey)
	return doc
}

// vexComponents collapses the findings into one component per package.
//
// The previous writer emitted one component per *finding*, so two CVEs against
// the same library produced two byte-identical component objects and the
// document failed the schema's uniqueItems constraint. Keying by purl is what
// fixes it, and it is also simply what the document means: a component appears
// once, and the vulnerabilities point at it.
func vexComponents(findings []VEXFinding) ([]aibomComp, map[string]string) {
	refByKey := map[string]string{}
	var comps []aibomComp

	for _, f := range findings {
		if f.Package == "" {
			continue
		}
		purl := vexPurl(f)
		if _, seen := refByKey[purl]; seen {
			continue
		}
		ref := purl
		refByKey[purl] = ref
		comps = append(comps, aibomComp{
			Type:    "library",
			BOMRef:  ref,
			Name:    f.Package,
			Version: f.InstalledVer,
			Purl:    purl,
		})
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	return comps, refByKey
}

// vexVulnerabilities collapses the findings into one entry per vulnerability
// identifier, with every affected component listed under `affects`.
//
// This is the half that makes the document usable. A vulnerability with no
// `affects` tells a consumer that something, somewhere, is vulnerable.
func vexVulnerabilities(findings []VEXFinding, refByKey map[string]string) []vexVulnerability {
	byID := map[string]*vexVulnerability{}
	affected := map[string]map[string]bool{}
	var order []string

	for _, f := range findings {
		if f.CVEID == "" {
			continue
		}
		v := byID[f.CVEID]
		if v == nil {
			v = &vexVulnerability{
				BOMRef:   "vuln:" + f.CVEID,
				ID:       f.CVEID,
				Source:   &vexSource{Name: "vulnetix"},
				Analysis: vexAnalysisFor(f),
			}
			if sev := strings.ToLower(strings.TrimSpace(f.Severity)); cdxVEXSeverities[sev] && sev != "unknown" {
				v.Ratings = []vexRating{{Source: &vexSource{Name: "vulnetix"}, Severity: sev}}
			}
			if f.FixedVer != "" {
				v.Recommend = "Upgrade to " + f.FixedVer
			}
			v.Properties = vexProperties(f.Properties)
			byID[f.CVEID] = v
			affected[f.CVEID] = map[string]bool{}
			order = append(order, f.CVEID)
		}
		if ref, ok := refByKey[vexPurl(f)]; ok && !affected[f.CVEID][ref] {
			affected[f.CVEID][ref] = true
			v.Affects = append(v.Affects, vexAffect{Ref: ref})
		}
	}

	sort.Strings(order)
	out := make([]vexVulnerability, 0, len(order))
	for _, id := range order {
		v := byID[id]
		sort.Slice(v.Affects, func(i, j int) bool { return v.Affects[i].Ref < v.Affects[j].Ref })
		out = append(out, *v)
	}
	return out
}

// vexAnalysisFor maps one finding onto a CycloneDX analysis object, keeping
// every value inside the enum the schema defines.
func vexAnalysisFor(f VEXFinding) *vexAnalysis {
	a := &vexAnalysis{State: VEXState(f.Status)}

	if cdxVEXJustifications[f.Justification] {
		a.Justification = f.Justification
	}

	// Anything outside the response enum is narrative, and narrative belongs in
	// detail. The invalid documents put a sentence of reachability evidence
	// here: "matched routine X in Y". That sentence is worth keeping, so it is
	// moved rather than dropped.
	var stray []string
	for _, r := range f.Responses {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		switch {
		case cdxVEXResponses[r]:
			if !containsString(a.Response, r) {
				a.Response = append(a.Response, r)
			}
		default:
			stray = append(stray, r)
		}
	}

	detail := strings.TrimSpace(f.Detail)
	if len(stray) > 0 {
		joined := strings.Join(stray, "; ")
		if detail == "" {
			detail = joined
		} else {
			detail = detail + " " + joined
		}
	}
	if detail == "" {
		detail = vexDefaultDetail(a.State)
	}
	a.Detail = detail
	return a
}

// VEXState maps a publisher's status vocabulary onto the CycloneDX
// impactAnalysisState enum.
//
// A value already in the enum passes through, so a caller that speaks
// CycloneDX natively is not translated twice.
func VEXState(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	if cdxVEXStates[s] {
		return s
	}
	switch s {
	case "not_affected", "notaffected":
		return "not_affected"
	case "fixed", "resolved":
		return "resolved"
	case "affected", "exploitable":
		return "exploitable"
	case "false_positive", "falsepositive":
		return "false_positive"
	default:
		// Everything untriaged, including the "under_investigation" the
		// previous writers emitted, which was never a CycloneDX state.
		return "in_triage"
	}
}

func vexDefaultDetail(state string) string {
	switch state {
	case "exploitable":
		return "vulnerability has been triaged and confirmed"
	case "in_triage":
		return "vulnerability is being investigated"
	default:
		return ""
	}
}

// vexPurl builds the package URL a component is keyed and identified by.
func vexPurl(f VEXFinding) string {
	eco := strings.TrimSpace(f.Ecosystem)
	if eco == "" {
		eco = "generic"
	}
	if f.InstalledVer == "" {
		return fmt.Sprintf("pkg:%s/%s", eco, f.Package)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", eco, f.Package, f.InstalledVer)
}

func vexProperties(props map[string]string) []aibomProp {
	if len(props) == 0 {
		return nil
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]aibomProp, 0, len(names))
	for _, n := range names {
		if props[n] != "" {
			out = append(out, mkProp(n, props[n]))
		}
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ValidVEXResponse reports whether a value is a CycloneDX analysis.response
// member. Exported so a caller can route its own vocabulary before building.
func ValidVEXResponse(v string) bool { return cdxVEXResponses[strings.TrimSpace(v)] }

// ValidVEXJustification reports whether a value is a CycloneDX
// analysis.justification member.
func ValidVEXJustification(v string) bool { return cdxVEXJustifications[strings.TrimSpace(v)] }
