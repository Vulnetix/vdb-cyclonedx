package cyclonedx

import "strings"

// ── This product's identity in metadata.tools ────────────────────────────────
//
// One tool entry, built one way, for every document any Vulnetix command emits.
// Three implementations of this used to exist across two repositories, and the
// output disagreed on more than cosmetics: some entries carried no version at
// all, and four builders defaulted the version to the literal string "cli",
// which is not a version — every consumer reading metadata.tools[].version got
// a category error rather than a value it could compare.

const (
	// Tool names, one per emitting command. They are deliberately distinct:
	// what produced a document is a real question a consumer asks, and the
	// answer "an SBOM built from manifests" differs from "an inventory read out
	// of a container image" in ways the component list alone does not show.
	ToolSCA         = "vulnetix-sca"
	ToolContainers  = "vulnetix-containers"
	ToolCDX         = "vulnetix-cdx"
	ToolAIBOM       = "vulnetix-aibom"
	ToolCBOM        = "vulnetix-cbom"
	ToolVEX         = "vulnetix-vex"
	ToolLicense     = "vulnetix-license-analyzer"
	ToolBOMEnrich   = "vulnetix-bom-enrich"
	ToolBOMImport   = "vulnetix-bom-import"
	ToolBOMMerge    = "vulnetix-bom-merge"
	ToolBOMValidate = "vulnetix-bom-validate"

	VulnetixToolGroup = "Vulnetix"
	VulnetixSiteURL   = "https://www.vulnetix.com"
	VulnetixRepoURL   = "https://github.com/vulnetix/cli"

	// UnknownToolVersion is what an unversioned build reports. It is a valid
	// version string that sorts below every release, so a consumer comparing
	// versions gets a usable answer instead of a parse failure.
	UnknownToolVersion = "0.0.0-unknown"
)

// vulnetixToolNames is the closed set of names this product emits. Membership
// is checked against it rather than by prefix alone so that a third-party tool
// which happens to be called "vulnetix-something" is not mistaken for ours —
// though the prefix check is kept as a fallback for names emitted by releases
// older than this list.
var vulnetixToolNames = map[string]bool{
	ToolSCA: true, ToolContainers: true, ToolCDX: true, ToolAIBOM: true,
	ToolCBOM: true, ToolVEX: true, ToolLicense: true, ToolBOMEnrich: true,
	ToolBOMImport: true, ToolBOMMerge: true, ToolBOMValidate: true,
}

// VulnetixTool builds the metadata.tools entry for one Vulnetix command.
//
// The entry carries more than a name because a tool table entry is a component,
// and a consumer that wants to know what produced a document should not have to
// take the name on trust: the group attributes it, the purl identifies the
// program in a registry, and the external references say where to go next.
func VulnetixTool(name, version string) Component {
	if strings.TrimSpace(version) == "" {
		version = UnknownToolVersion
	}
	return Component{
		Type:    "application",
		BOMRef:  "urn:tool:" + name,
		Group:   VulnetixToolGroup,
		Name:    name,
		Version: version,
		Purl:    "pkg:golang/github.com/vulnetix/cli@v" + strings.TrimPrefix(version, "v"),
		ExternalReferences: []ExternalReference{
			{Type: "website", URL: VulnetixSiteURL},
			{Type: "vcs", URL: VulnetixRepoURL},
		},
	}
}

// IsVulnetixToolName reports whether a tool name is one of this product's.
//
// It is string-keyed rather than component-keyed because the same question gets
// asked of SARIF driver names ("Vulnetix Malscan", "Vulnetix SCA") when
// deciding whether a report being relayed is one we generated ourselves — a
// document this product produced must not be re-submitted as though a third
// party had found it.
func IsVulnetixToolName(name string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return false
	}
	if vulnetixToolNames[trimmed] {
		return true
	}
	return trimmed == "vulnetix" ||
		strings.HasPrefix(trimmed, "vulnetix-") ||
		strings.HasPrefix(trimmed, "vulnetix ")
}

// IsVulnetixTool reports whether a tool component identifies this product.
func IsVulnetixTool(c Component) bool { return IsVulnetixToolName(c.Name) }

// FindVulnetixTool returns this product's entry in a document's tool table, or
// nil when the document was not produced by us. When several are present — the
// SCA pass authored it and the licence pass enriched it — the first is
// returned, which is the author.
func FindVulnetixTool(doc *Document) *Component {
	for i, c := range ToolParticipants(doc) {
		if IsVulnetixTool(c) {
			return &doc.Metadata.Tools.Components[i]
		}
	}
	return nil
}

// ToolMetaFromDocument is ExtractToolMeta's write-side twin: it reports what
// produced a document, using the same vendor precedence.
func ToolMetaFromDocument(doc *Document) ToolMeta {
	meta := ToolMeta{}
	if doc == nil {
		return meta
	}
	meta.SpecVersion = doc.SpecVersion
	tool := AuthoringTool(doc)
	if tool == nil {
		return meta
	}
	meta.ToolName = tool.Name
	meta.ToolVersion = tool.Version
	switch {
	case tool.Publisher != "":
		meta.ToolVendor = tool.Publisher
	case tool.Supplier != nil && tool.Supplier.Name != "":
		meta.ToolVendor = tool.Supplier.Name
	case tool.Group != "":
		meta.ToolVendor = tool.Group
	}
	for _, h := range tool.Hashes {
		if h.Content != "" {
			meta.ToolHash = h.Content
			break
		}
	}
	return meta
}
