package cyclonedx

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── BOM authoring identity ───────────────────────────────────────────────────
//
// CycloneDX has no field called "authoring". It splits the idea across five
// members of `metadata`, and the strict definition of what makes a tool an
// authoring tool falls out of their own descriptions:
//
//	manufacturer  "The organization that created the BOM. Manufacturer is common
//	              in BOMs created through automated processes."
//	authors       "The person(s) who created the BOM. Authors are common in BOMs
//	              created through manual processes."
//	tools         "The tool(s) used in the creation, enrichment, and validation
//	              of the BOM."
//	supplier      "The organization that supplied the component that the BOM
//	              describes."  — subject-level, not document-level.
//	lifecycles    "Communicate the stage(s) in which data in the BOM was
//	              captured."
//
// Three consequences, and this file exists to make all three hard to get wrong:
//
//   - A tool authors a BOM when it *emits a document*. It then owns
//     serialNumber, version, timestamp, manufacturer, lifecycles, and the first
//     entry in metadata.tools.
//   - Participation in metadata.tools is broader than authorship. The spec text
//     admits creation, enrichment *and validation*, so an enricher or validator
//     belongs in the tool table of a document it did not create — without
//     claiming manufacturer or authors, and without dropping prior entries.
//   - Reading is not authoring. Parsing, diffing, querying or verifying a
//     document stamps nothing at all.

// LifecyclePhase is the metadata.lifecycles[].phase enum (CycloneDX 1.5+).
//
// It is a statement about the observation, not about the product: "the stage(s)
// in which data in the BOM was captured". A manifest read and a container-image
// read produce different phases from the same repository, and a consumer uses
// the difference to decide how much the component list can be trusted.
type LifecyclePhase string

const (
	PhaseDesign       LifecyclePhase = "design"
	PhasePreBuild     LifecyclePhase = "pre-build"
	PhaseBuild        LifecyclePhase = "build"
	PhasePostBuild    LifecyclePhase = "post-build"
	PhaseOperations   LifecyclePhase = "operations"
	PhaseDiscovery    LifecyclePhase = "discovery"
	PhaseDecommission LifecyclePhase = "decommission"
)

// lifecyclePhaseOrder is the schema's own enum order. Emission follows it so
// that the same set of phases always serialises identically.
var lifecyclePhaseOrder = []LifecyclePhase{
	PhaseDesign, PhasePreBuild, PhaseBuild, PhasePostBuild,
	PhaseOperations, PhaseDiscovery, PhaseDecommission,
}

// Valid reports whether p is one of the pre-defined phases.
func (p LifecyclePhase) Valid() bool {
	for _, known := range lifecyclePhaseOrder {
		if p == known {
			return true
		}
	}
	return false
}

// LifecyclePhases returns the pre-defined phases in schema enum order.
func LifecyclePhases() []LifecyclePhase {
	out := make([]LifecyclePhase, len(lifecyclePhaseOrder))
	copy(out, lifecyclePhaseOrder)
	return out
}

// ParseLifecyclePhases parses a comma-separated phase list, as a --lifecycle
// flag would supply. An unknown phase is an error rather than a custom-phase
// fallback: a typo silently becoming a custom lifecycle name is worse than a
// rejected flag, because nothing downstream can tell the two apart.
func ParseLifecyclePhases(csv string) ([]LifecyclePhase, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	var out []LifecyclePhase
	for _, field := range strings.Split(csv, ",") {
		phase := LifecyclePhase(strings.ToLower(strings.TrimSpace(field)))
		if phase == "" {
			continue
		}
		if !phase.Valid() {
			return nil, fmt.Errorf("unknown lifecycle phase %q (valid: %s)", field, joinPhases(lifecyclePhaseOrder))
		}
		out = append(out, phase)
	}
	return out, nil
}

func joinPhases(phases []LifecyclePhase) string {
	parts := make([]string, len(phases))
	for i, p := range phases {
		parts[i] = string(p)
	}
	return strings.Join(parts, ", ")
}

// lifecyclesFor renders phases as metadata.lifecycles entries, deduplicated and
// in schema enum order.
func lifecyclesFor(phases []LifecyclePhase) []Lifecycle {
	if len(phases) == 0 {
		return nil
	}
	seen := make(map[LifecyclePhase]bool, len(phases))
	for _, p := range phases {
		seen[p] = true
	}
	out := make([]Lifecycle, 0, len(seen))
	for _, p := range lifecyclePhaseOrder {
		if seen[p] {
			out = append(out, Lifecycle{Phase: string(p)})
			delete(seen, p)
		}
	}
	// Anything left is a custom phase the caller supplied; keep it, ordered, so
	// it is neither dropped nor a source of run-to-run churn.
	rest := make([]string, 0, len(seen))
	for p := range seen {
		rest = append(rest, string(p))
	}
	sort.Strings(rest)
	for _, p := range rest {
		out = append(out, Lifecycle{Phase: p})
	}
	return out
}

// Authorship is who made this document and when the data in it was captured.
type Authorship struct {
	// Manufacturer is the organization that created the BOM. For an automated
	// run that is the organization running the automation, not the vendor of
	// the tool — the tool is named in metadata.tools. Leave it nil rather than
	// guess: an absent manufacturer is honest, a wrong one is not.
	Manufacturer *OrganizationalEntity

	// Authors is for documents created by manual means. A tool must not
	// populate it on its own behalf; it is set when a person made the claims,
	// as with a hand-curated VEX statement.
	Authors []OrganizationalContact

	// Supplier is subject-level: who supplied the component the BOM describes.
	Supplier *OrganizationalEntity

	// Tool becomes metadata.tools.components[0] — the entry identifying the
	// program that authored the document, as distinct from every program that
	// later enriched or validated it.
	Tool Component

	Phases       []LifecyclePhase
	SerialNumber string // "" mints a fresh urn:uuid
	BOMVersion   int    // 0 means 1
	Timestamp    string // RFC3339; "" means now, UTC
}

// Validate reports whether the authorship can identify its own tool. Everything
// else is optional by design — a document with no resolvable manufacturer is
// valid and honest — but a document that cannot say what produced it is not.
func (a Authorship) Validate() error {
	if strings.TrimSpace(a.Tool.Name) == "" {
		return errors.New("authorship: Tool.Name is required")
	}
	for _, p := range a.Phases {
		if !p.Valid() {
			return fmt.Errorf("authorship: unknown lifecycle phase %q", p)
		}
	}
	return nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// NewSerialNumber mints a CycloneDX serialNumber.
func NewSerialNumber() string { return "urn:uuid:" + uuid.New().String() }

// NormalizeSerialNumber coerces an identifier into the urn:uuid form the schema
// constrains serialNumber to from 1.6.
//
// SPDX documents identify themselves with a DocumentNamespace, which is a URI
// but rarely a UUID urn. Copying it straight across produces a document that
// fails its own schema; minting a fresh random one instead would make the same
// SPDX file convert to a different identity on every run. A UUIDv5 derived from
// the namespace is stable and valid, which is what a converted document needs.
func NormalizeSerialNumber(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return NewSerialNumber()
	}
	if strings.HasPrefix(strings.ToLower(id), "urn:uuid:") {
		if _, err := uuid.Parse(strings.TrimPrefix(strings.ToLower(id), "urn:uuid:")); err == nil {
			return "urn:uuid:" + strings.ToLower(strings.TrimPrefix(strings.ToLower(id), "urn:uuid:"))
		}
	}
	if parsed, err := uuid.Parse(id); err == nil {
		return "urn:uuid:" + parsed.String()
	}
	return "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(id)).String()
}

// ApplyAuthorship stamps a document this program is creating.
//
// It is the author tier: it owns serialNumber, version, timestamp,
// manufacturer, authors, lifecycles and the first entry in metadata.tools.
//
// Applying it twice is idempotent. A prior self-identification is superseded
// rather than left alongside the new one — which matters both because
// metadata.tools.components carries uniqueItems:true from 1.5, and because a
// document naming this product at two versions cannot be read as a statement
// about which one produced it.
//
// downgrades lists members the declared specVersion could not carry; the
// document is still valid, it simply says less than was asked of it.
func ApplyAuthorship(doc *Document, a Authorship) ([]Downgrade, error) {
	if doc == nil {
		return nil, errors.New("authorship: nil document")
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if doc.BOMFormat == "" {
		doc.BOMFormat = "CycloneDX"
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}

	doc.SerialNumber = NormalizeSerialNumber(firstNonEmpty(a.SerialNumber, doc.SerialNumber))
	doc.Version = a.BOMVersion
	if doc.Version <= 0 {
		doc.Version = 1
	}

	meta := doc.Metadata
	meta.Timestamp = firstNonEmpty(a.Timestamp, nowRFC3339())
	if a.Manufacturer != nil {
		meta.Manufacturer = a.Manufacturer
	}
	if len(a.Authors) > 0 {
		meta.Authors = a.Authors
	}
	if a.Supplier != nil {
		meta.Supplier = a.Supplier
	}
	if phases := lifecyclesFor(a.Phases); len(phases) > 0 {
		meta.Lifecycles = phases
	}

	if meta.Tools == nil {
		meta.Tools = &Tools{}
	}
	meta.Tools.Components = prependAuthoringTool(meta.Tools.Components, a.Tool)

	_, downgrades := doc.projectToSpecVersion()
	return downgrades, nil
}

// AppendToolParticipation stamps a document this program is transforming —
// enriching, merging, converting or validating one it did not author.
//
// metadata.tools is "the tool(s) used in the creation, enrichment, and
// validation of the BOM", so a transformer belongs in it. Everything else is
// the author's: manufacturer, authors, lifecycles, serialNumber, version and
// timestamp are left exactly as found, and prior entries keep their order.
func AppendToolParticipation(doc *Document, tool Component) error {
	if doc == nil {
		return errors.New("authorship: nil document")
	}
	if strings.TrimSpace(tool.Name) == "" {
		return errors.New("authorship: tool name is required")
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}
	if doc.Metadata.Tools == nil {
		doc.Metadata.Tools = &Tools{}
	}
	doc.Metadata.Tools.Components = appendToolOnce(doc.Metadata.Tools.Components, tool)
	return nil
}

// NextRevision re-identifies a document a transformer is emitting as a new
// artefact rather than editing in place: fresh serialNumber, version reset, and
// a fresh timestamp, with the document it derived from recorded so the chain
// stays followable.
func NextRevision(doc *Document, derivedFrom string) error {
	if doc == nil {
		return errors.New("authorship: nil document")
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}
	if derivedFrom == "" {
		derivedFrom = doc.SerialNumber
	}
	doc.SerialNumber = NewSerialNumber()
	doc.Version = 1
	doc.Metadata.Timestamp = nowRFC3339()
	if derivedFrom != "" {
		doc.Metadata.SetProperty(PropDerivedFrom, derivedFrom)
	}
	return nil
}

// ReviseInPlace stamps a document being rewritten at the path it was read from.
//
// An authoring subcommand pointed at an existing BOM file is not creating a new
// artefact, so minting a fresh serialNumber would break the identity of a
// document that consumers already track. It keeps the serial and increments the
// version — which is what CycloneDX's `version` member is for, and what makes
// two revisions of one document orderable.
//
// Who gets to claim authorship depends on who authored what is already there:
//
//   - If this product authored the original, this run re-authors it. The
//     manufacturer, authors and lifecycles in a are applied, and the earlier
//     self-identification in metadata.tools is superseded by this version.
//   - If somebody else authored it — a syft SBOM being enriched in place — the
//     original's manufacturer and authors are left untouched, because they are
//     still true: that organization did create this document. This run appends
//     itself to metadata.tools, which is exactly what the tools member is for,
//     and unions its capture phases into the existing lifecycles, because data
//     captured by this pass really was captured at those stages.
func ReviseInPlace(doc *Document, a Authorship) ([]Downgrade, error) {
	if doc == nil {
		return nil, errors.New("authorship: nil document")
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if doc.BOMFormat == "" {
		doc.BOMFormat = "CycloneDX"
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}

	authoredByUs := true
	if existing := AuthoringTool(doc); existing != nil {
		authoredByUs = IsVulnetixTool(*existing)
	}

	revised := a
	revised.SerialNumber = firstNonEmpty(doc.SerialNumber, a.SerialNumber)
	revised.BOMVersion = doc.Version + 1
	if revised.BOMVersion < 2 {
		revised.BOMVersion = 2
	}

	if authoredByUs {
		return ApplyAuthorship(doc, revised)
	}

	// A third party authored this. Their identity stands; ours is a
	// participation, not a claim of creation.
	doc.SerialNumber = NormalizeSerialNumber(revised.SerialNumber)
	doc.Version = revised.BOMVersion
	doc.Metadata.Lifecycles = unionLifecycles(doc.Metadata.Lifecycles, a.Phases)
	if err := AppendToolParticipation(doc, a.Tool); err != nil {
		return nil, err
	}
	_, downgrades := doc.projectToSpecVersion()
	return downgrades, nil
}

func unionLifecycles(existing []Lifecycle, phases []LifecyclePhase) []Lifecycle {
	if len(phases) == 0 {
		return existing
	}
	all := make([]LifecyclePhase, 0, len(existing)+len(phases))
	custom := make([]Lifecycle, 0, len(existing))
	for _, l := range existing {
		if l.Phase != "" {
			all = append(all, LifecyclePhase(l.Phase))
			continue
		}
		custom = append(custom, l)
	}
	all = append(all, phases...)
	return append(lifecyclesFor(all), custom...)
}

// AuthoringTool returns the entry that created the document — by construction
// the first in metadata.tools — or nil when the document names no producer.
//
// Four separate readers used to reach into Tools.Components[0] by hand, each
// with its own idea of what to do when it was absent.
func AuthoringTool(doc *Document) *Component {
	if doc == nil || doc.Metadata == nil || doc.Metadata.Tools == nil {
		return nil
	}
	if len(doc.Metadata.Tools.Components) == 0 {
		return nil
	}
	return &doc.Metadata.Tools.Components[0]
}

// ToolParticipants returns metadata.tools.components in order: the author
// first, then each transformer in the order it touched the document.
func ToolParticipants(doc *Document) []Component {
	if doc == nil || doc.Metadata == nil || doc.Metadata.Tools == nil {
		return nil
	}
	return doc.Metadata.Tools.Components
}

// Find returns the named tool entry, or nil.
func (t *Tools) Find(name string) *Component {
	if t == nil {
		return nil
	}
	for i := range t.Components {
		if strings.EqualFold(t.Components[i].Name, name) {
			return &t.Components[i]
		}
	}
	return nil
}

// prependAuthoringTool puts tool at the head of the tool table, superseding any
// prior entry for the same tool and preserving every other entry in order.
//
// Superseding is keyed on the tool's name, not on name+version: a seed written
// by an older release names this same command at an older version, and a
// document naming one command at two versions cannot be read as a statement
// about which of them produced it. Other Vulnetix entries are left alone — a
// document authored by the SCA pass and later enriched by the licence pass
// legitimately names both, because they are different tools.
func prependAuthoringTool(existing []Component, tool Component) []Component {
	out := make([]Component, 0, len(existing)+1)
	out = append(out, tool)
	for _, c := range existing {
		if sameToolName(c, tool) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// appendToolOnce adds tool to the end of the table, replacing an existing entry
// for the same tool rather than sitting beside it. metadata.tools.components
// carries uniqueItems:true from 1.5, so enriching one document twice would
// otherwise produce a document that fails its own schema.
func appendToolOnce(existing []Component, tool Component) []Component {
	for i, c := range existing {
		if sameToolName(c, tool) {
			existing[i] = tool
			return existing
		}
	}
	return append(existing, tool)
}

func sameToolName(a, b Component) bool {
	return strings.EqualFold(a.Name, b.Name) && strings.EqualFold(a.Group, b.Group)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// authorshipFrom reconciles an explicit Authorship with the older
// ToolName/ToolVersion/GeneratedAt option fields.
//
// Both are honoured so that adding authorship did not break every existing
// caller in one step. The explicit struct wins where it says something; the
// legacy fields fill the gaps, which is what lets a caller adopt the new field
// for the manufacturer while still passing its tool name the old way.
//
// The result always names a tool, so ApplyAuthorship cannot fail validation on
// a document assembled by one of this module's own builders.
func authorshipFrom(explicit *Authorship, toolName, toolVersion, generatedAt string, defaultPhases ...LifecyclePhase) Authorship {
	var a Authorship
	if explicit != nil {
		a = *explicit
	}
	if a.Tool.Name == "" {
		a.Tool = toolComponentFor(toolName, toolVersion)
	}
	if a.Tool.Type == "" {
		a.Tool.Type = "application"
	}
	if a.Timestamp == "" {
		a.Timestamp = generatedAt
	}
	if len(a.Phases) == 0 {
		a.Phases = defaultPhases
	}
	return a
}

// toolComponentFor builds a tool entry from a bare name and version. Vulnetix's
// own commands get the full identity — group, purl, references — while a name
// this product does not own is recorded as given, because attributing a third
// party's tool to Vulnetix would misstate who produced the document.
func toolComponentFor(name, version string) Component {
	if IsVulnetixToolName(name) {
		return VulnetixTool(name, version)
	}
	if strings.TrimSpace(version) == "" {
		version = UnknownToolVersion
	}
	return Component{Type: "application", Name: name, Version: version}
}
