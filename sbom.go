package cyclonedx

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	PropSBOMProfile          = "vulnetix:sbom/profile"
	PropSBOMGenerator        = "vulnetix:sbom/generator"
	PropSBOMPackagesDetected = "vulnetix:sbom/packages-detected"
	PropSBOMSourceFile       = "vulnetix:source-file"
	PropSBOMSourceType       = "vulnetix:source-type"
	PropSBOMEcosystem        = "vulnetix:ecosystem"
	PropSBOMScope            = "vulnetix:scope"
	PropSBOMEnvironment      = "vulnetix:environment"
	PropSBOMDirect           = "vulnetix:direct"
	PropSBOMInstalledPath    = "vulnetix:installed-path"
	PropSBOMVersionSpec      = "vulnetix:version-spec"
	PropSBOMRegistryType     = "vulnetix:oci:registryType"
	PropSBOMPrivateRegistry  = "vulnetix:oci:private"
	PropSBOMIntegrity        = "vulnetix:integrity"
	PropSBOMGoSumH1          = "vulnetix:gosum-h1"
	PropSBOMEvidenceCount    = "vulnetix:sbom/evidence-count"
	PropSBOMEvidence         = "vulnetix:sbom/evidence"
	PropSBOMSignaturePrefix  = "vulnetix:signature/"
	PropSBOMTLogPrefix       = "vulnetix:tlog/"
)

// SBOMHash is a component hash. Alg should use the CycloneDX spelling when
// possible, for example SHA-256, SHA-512 or SHA-1. Non-CycloneDX hashes are
// preserved as properties by BuildSBOM.
type SBOMHash struct {
	Alg     string
	Content string
}

// SBOMEvidence is one observation supporting package discovery.
type SBOMEvidence struct {
	Method     string
	Locator    string
	Detail     string
	Confidence string
}

// SBOMTransparencyLogEntry records offline transparency-log provenance, such
// as Rekor inclusion metadata found inside a Sigstore bundle or attestation.
type SBOMTransparencyLogEntry struct {
	LogID          string
	UUID           string
	Index          int64
	IntegratedTime string
	InclusionProof string
	Checkpoint     string
	SignerIdentity string
	Issuer         string
}

// SBOMSignature records local signature material or signature-file provenance.
// Signature values are stored as CycloneDX properties so callers can include
// Sigstore, minisign, GPG and checksum sidecar evidence without depending on one
// signature envelope shape.
type SBOMSignature struct {
	Algorithm       string
	Value           string
	PublicKey       string
	Certificate     string
	SourceFile      string
	TransparencyLog *SBOMTransparencyLogEntry
}

// SBOMPackage is a discovered package/component.
type SBOMPackage struct {
	Type              string
	BOMRef            string
	Name              string
	Version           string
	VersionSpec       string
	Ecosystem         string
	Scope             string
	Purl              string
	SourceFile        string
	SourceType        string
	InstalledPath     string
	IsDirect          bool
	RegistryType      string
	IsPrivateRegistry bool
	Hashes            []SBOMHash
	Licenses          []string
	Evidence          []SBOMEvidence
	Signatures        []SBOMSignature
	Properties        map[string]string
}

// SBOMDependency is one edge set in the CycloneDX dependency graph: the
// component identified by Ref depends on every bom-ref in DependsOn. Refs that
// do not resolve to a component in the finished document are dropped, so a
// caller may pass a graph derived from lockfile edges without pre-filtering it.
type SBOMDependency struct {
	Ref       string
	DependsOn []string
}

// SBOMInventory is the complete input to BuildSBOM.
type SBOMInventory struct {
	Packages         []SBOMPackage
	AIDetections     *AIDetections
	CryptoDetections *CryptoDetections
	// Dependencies carries a resolved dependency graph (typically from lockfile
	// or installed-tree edges). It is merged with the project→direct-dependency
	// edges BuildSBOM derives from SBOMPackage.IsDirect. Use "urn:project" to
	// attach edges to the metadata component.
	Dependencies []SBOMDependency
}

// SBOMOptions configures BuildSBOM.
type SBOMOptions struct {
	SpecVersion string // default DefaultSpecVersion
	// Authorship states who created this document and at which lifecycle stage
	// its data was captured. When set it takes precedence over the three fields
	// below, which remain honoured so existing callers keep working.
	Authorship  *Authorship
	ToolName    string        // default ToolCDX
	ToolVersion string        // default UnknownToolVersion
	GeneratedAt string        // RFC3339; default time.Now().UTC()
	Project     *AIBOMProject // nil -> minimal project component
	// CanonicalSPDXID optionally resolves a license string to its canonical
	// SPDX identifier, returning "" when the value is not a recognised id. When
	// set, recognised values are emitted as `license.id` (the enum-constrained
	// field) instead of the free-text `license.name`. Callers that have no SPDX
	// table leave it nil, which keeps every license value free text.
	CanonicalSPDXID func(string) string
}

// BuildSBOM maps a package inventory plus optional AIBOM/CBOM detections into a
// single validated CycloneDX document.
func BuildSBOM(inv SBOMInventory, opts SBOMOptions) ([]byte, error) {
	doc := BuildSBOMDocument(inv, opts)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, violations, verr := ValidateCycloneDX(data); verr != nil {
		return nil, fmt.Errorf("sbom: validation error: %w", verr)
	} else if len(violations) > 0 {
		return nil, fmt.Errorf("sbom: schema violation at %s: %s", violations[0].Path, violations[0].Message)
	}
	return data, nil
}

// BuildSBOMDocument assembles a combined package SBOM/AIBOM/CBOM document
// without validating it.
func BuildSBOMDocument(inv SBOMInventory, opts SBOMOptions) any {
	spec := nonEmpty(opts.SpecVersion, DefaultSpecVersion)
	authorship := authorshipFrom(opts.Authorship, nonEmpty(opts.ToolName, ToolCDX), opts.ToolVersion, opts.GeneratedAt, PhaseBuild)
	projComp, envProps := buildProjectComponent(opts.Project)
	projRef := projComp.BOMRef

	doc := &Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: spec,
		Metadata: &Metadata{
			Component: projComp,
			Properties: []Property{
				mkProp(PropSBOMProfile, "software"),
				mkProp(PropSBOMGenerator, authorship.Tool.Name),
				mkProp(PropSBOMPackagesDetected, strconv.Itoa(len(inv.Packages))),
			},
		},
	}
	// authorshipFrom always names a tool, so the only failure mode Validate has
	// cannot occur here; the returned downgrades are surfaced by BuildSBOM's
	// schema validation if the projection was not enough.
	_, _ = ApplyAuthorship(doc, authorship)
	doc.Metadata.Properties = append(doc.Metadata.Properties, envProps...)

	validRefs := map[string]bool{projRef: true}
	deps := map[string][]string{}
	componentIndex := map[string]int{}
	for _, pkg := range inv.Packages {
		comp := sbomPackageComponent(pkg, opts.CanonicalSPDXID)
		if comp.Name == "" {
			continue
		}
		key := componentDedupeKey(comp)
		if idx, ok := componentIndex[key]; ok {
			mergeComponent(&doc.Components[idx], comp)
			validRefs[doc.Components[idx].BOMRef] = true
			if pkg.IsDirect {
				deps[projRef] = append(deps[projRef], doc.Components[idx].BOMRef)
			}
			continue
		}
		componentIndex[key] = len(doc.Components)
		doc.Components = append(doc.Components, comp)
		validRefs[comp.BOMRef] = true
		if pkg.IsDirect {
			deps[projRef] = append(deps[projRef], comp.BOMRef)
		}
	}

	if inv.AIDetections != nil {
		aiDoc, ok := BuildAIBOMDocument(*inv.AIDetections, AIBOMOptions{
			SpecVersion: spec, ToolName: ToolAIBOM, ToolVersion: authorship.Tool.Version, GeneratedAt: doc.Metadata.Timestamp, Project: opts.Project,
		}).(*Document)
		if ok {
			mergeSubBOM(doc, aiDoc, componentIndex, validRefs, deps)
		}
	}
	if inv.CryptoDetections != nil {
		cbomDoc, ok := BuildCBOMDocument(*inv.CryptoDetections, CBOMOptions{
			SpecVersion: spec, ToolName: ToolCBOM, ToolVersion: authorship.Tool.Version, GeneratedAt: doc.Metadata.Timestamp, Project: opts.Project,
		}).(*Document)
		if ok {
			mergeSubBOM(doc, cbomDoc, componentIndex, validRefs, deps)
		}
	}

	// Caller-supplied graph edges last: buildDeps drops refs that never became a
	// component, so an edge naming a package this document does not carry (a
	// lockfile entry filtered out upstream) is discarded rather than dangling.
	for _, dep := range inv.Dependencies {
		deps[dep.Ref] = append(deps[dep.Ref], dep.DependsOn...)
	}

	doc.Dependencies = buildDeps(deps, validRefs)
	return doc
}

func sbomPackageComponent(pkg SBOMPackage, canonicalSPDXID func(string) string) Component {
	purl := pkg.Purl
	if purl == "" {
		purl = SBOMPurl(pkg.Name, pkg.Version, pkg.Ecosystem)
	}
	bomRef := pkg.BOMRef
	if bomRef == "" {
		bomRef = purl
	}
	if bomRef == "" {
		bomRef = "urn:package:" + sanitizeRef(pkg.Ecosystem) + ":" + sanitizeRef(pkg.Name) + ":" + sanitizeRef(pkg.Version)
	}
	compType := pkg.Type
	if compType == "" {
		compType = "library"
		if strings.EqualFold(pkg.Ecosystem, "oci") {
			compType = "container"
		}
	}
	comp := Component{
		Type:    compType,
		BOMRef:  bomRef,
		Name:    pkg.Name,
		Version: pkg.Version,
		Scope:   mapSBOMScope(pkg.Scope),
		Purl:    purl,
	}
	comp.Properties = append(comp.Properties,
		mkProp(PropSBOMEcosystem, pkg.Ecosystem),
		mkProp(PropSBOMScope, pkg.Scope),
		mkProp(PropSBOMEnvironment, sbomEnvironment(pkg.Scope)),
		mkProp(PropSBOMDirect, boolStr(pkg.IsDirect)),
	)
	addProp := func(name, value string) {
		if value != "" {
			comp.Properties = append(comp.Properties, mkProp(name, value))
		}
	}
	addProp(PropSBOMSourceFile, pkg.SourceFile)
	addProp(PropSBOMSourceType, pkg.SourceType)
	addProp(PropSBOMInstalledPath, pkg.InstalledPath)
	addProp(PropSBOMVersionSpec, pkg.VersionSpec)
	addProp(PropSBOMRegistryType, pkg.RegistryType)
	if pkg.RegistryType != "" {
		comp.Properties = append(comp.Properties, mkProp(PropSBOMPrivateRegistry, boolStr(pkg.IsPrivateRegistry)))
	}
	for _, k := range sortedKeys(pkg.Properties) {
		addProp(k, pkg.Properties[k])
	}
	for _, h := range pkg.Hashes {
		alg := normalizeSBOMHashAlg(h.Alg)
		content := strings.TrimSpace(h.Content)
		if content == "" {
			continue
		}
		switch alg {
		case "MD5", "SHA-1", "SHA-256":
			if isHexDigest(content, map[string]int{"MD5": 32, "SHA-1": 40, "SHA-256": 64}[alg]) {
				comp.Hashes = append(comp.Hashes, Hash{Alg: alg, Content: strings.ToLower(content)})
			} else {
				addProp("vulnetix:checksum/"+strings.ToLower(alg), content)
			}
		case "SHA-512":
			if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
				content = hex.EncodeToString(decoded)
			}
			if isHexDigest(content, 128) {
				comp.Hashes = append(comp.Hashes, Hash{Alg: "SHA-512", Content: strings.ToLower(content)})
			} else {
				addProp("vulnetix:checksum/sha-512", content)
			}
		case "H1":
			addProp(PropSBOMGoSumH1, content)
		default:
			addProp("vulnetix:checksum/"+strings.ToLower(strings.ReplaceAll(alg, " ", "-")), content)
		}
	}
	for _, lic := range pkg.Licenses {
		if lc := licenseChoiceWith(lic, canonicalSPDXID); lc.License != nil || lc.Expression != "" {
			comp.Licenses = append(comp.Licenses, lc)
		}
	}
	appendSBOMEvidenceProps(&comp, pkg.Evidence)
	appendSignatureProps(&comp, pkg.Signatures)
	return comp
}

// SBOMPurl builds a best-effort package URL for common Vulnetix ecosystems.
func SBOMPurl(name, version, ecosystem string) string {
	purlType := sbomPurlType(ecosystem)
	if purlType == "" || name == "" {
		return ""
	}
	if purlType == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:npm/%s/%s@%s", url.PathEscape(parts[0]), parts[1], url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:npm/%s/%s", url.PathEscape(parts[0]), parts[1])
		}
	}
	if purlType == "maven" && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:maven/%s/%s@%s", url.PathEscape(parts[0]), url.PathEscape(parts[1]), url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:maven/%s/%s", url.PathEscape(parts[0]), url.PathEscape(parts[1]))
		}
	}
	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, url.PathEscape(name), url.PathEscape(version))
	}
	return fmt.Sprintf("pkg:%s/%s", purlType, url.PathEscape(name))
}

func sbomPurlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "golang", "go":
		return "golang"
	case "cargo", "rust":
		return "cargo"
	case "gem", "rubygems":
		return "gem"
	case "maven", "java", "clojars", "clojure":
		return "maven"
	case "composer", "php":
		return "composer"
	case "nuget":
		return "nuget"
	case "pub", "dart":
		return "pub"
	case "hex", "elixir":
		return "hex"
	case "swift":
		return "swift"
	case "helm":
		return "helm"
	case "conda":
		return "conda"
	case "oci", "docker":
		return "oci"
	case "deb", "apk", "rpm", "arch", "brew", "chocolatey", "scoop", "winget":
		return strings.ToLower(ecosystem)
	default:
		return strings.ToLower(ecosystem)
	}
}

func mapSBOMScope(scope string) string {
	switch scope {
	case "development", "dev", "test", "peer", "optional", "provided", "system":
		return "optional"
	default:
		return "required"
	}
}

func sbomEnvironment(scope string) string {
	switch scope {
	case "development", "dev":
		return "development"
	case "test":
		return "test"
	default:
		return "production"
	}
}

func appendSBOMEvidenceProps(comp *Component, ev []SBOMEvidence) {
	if len(ev) == 0 {
		return
	}
	comp.Properties = append(comp.Properties, mkProp(PropSBOMEvidenceCount, strconv.Itoa(len(ev))))
	limit := len(ev)
	if limit > maxEvidencePerComponent {
		limit = maxEvidencePerComponent
	}
	for _, e := range ev[:limit] {
		var parts []string
		if e.Method != "" {
			parts = append(parts, e.Method)
		}
		if e.Confidence != "" {
			parts = append(parts, e.Confidence)
		}
		if e.Locator != "" {
			parts = append(parts, e.Locator)
		}
		value := strings.Join(parts, " ")
		if e.Detail != "" {
			value += " :: " + e.Detail
		}
		comp.Properties = append(comp.Properties, mkProp(PropSBOMEvidence, strings.TrimSpace(value)))
	}
}

func appendSignatureProps(comp *Component, sigs []SBOMSignature) {
	for i, s := range sigs {
		prefix := PropSBOMSignaturePrefix + strconv.Itoa(i) + "/"
		addSigProp := func(name, value string) {
			if value != "" {
				comp.Properties = append(comp.Properties, mkProp(prefix+name, value))
			}
		}
		addSigProp("algorithm", s.Algorithm)
		addSigProp("value", s.Value)
		addSigProp("public-key", s.PublicKey)
		addSigProp("certificate", s.Certificate)
		addSigProp("source-file", s.SourceFile)
		if tlog := s.TransparencyLog; tlog != nil {
			tp := PropSBOMTLogPrefix + strconv.Itoa(i) + "/"
			addTLogProp := func(name, value string) {
				if value != "" {
					comp.Properties = append(comp.Properties, mkProp(tp+name, value))
				}
			}
			addTLogProp("log-id", tlog.LogID)
			addTLogProp("uuid", tlog.UUID)
			if tlog.Index > 0 {
				addTLogProp("index", strconv.FormatInt(tlog.Index, 10))
			}
			addTLogProp("integrated-time", tlog.IntegratedTime)
			addTLogProp("inclusion-proof", tlog.InclusionProof)
			addTLogProp("checkpoint", tlog.Checkpoint)
			addTLogProp("signer-identity", tlog.SignerIdentity)
			addTLogProp("issuer", tlog.Issuer)
		}
	}
}

func normalizeSBOMHashAlg(alg string) string {
	key := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.TrimSpace(alg)))
	switch key {
	case "md5":
		return "MD5"
	case "sha1":
		return "SHA-1"
	case "sha256":
		return "SHA-256"
	case "sha512":
		return "SHA-512"
	case "h1":
		return "H1"
	default:
		return strings.ToUpper(strings.TrimSpace(alg))
	}
}

func isHexDigest(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func mergeSubBOM(dst, src *Document, componentIndex map[string]int, validRefs map[string]bool, deps map[string][]string) {
	if src == nil {
		return
	}
	if src.Metadata != nil {
		if src.Metadata.Tools != nil && dst.Metadata != nil {
			for _, tool := range src.Metadata.Tools.Components {
				mergeToolComponent(dst.Metadata.Tools, tool)
			}
		}
		if dst.Metadata != nil {
			dst.Metadata.Properties = mergeProps(dst.Metadata.Properties, src.Metadata.Properties)
		}
	}
	for _, comp := range src.Components {
		key := componentDedupeKey(comp)
		if idx, ok := componentIndex[key]; ok {
			mergeComponent(&dst.Components[idx], comp)
			validRefs[dst.Components[idx].BOMRef] = true
			continue
		}
		componentIndex[key] = len(dst.Components)
		dst.Components = append(dst.Components, comp)
		validRefs[comp.BOMRef] = true
	}
	for _, dep := range src.Dependencies {
		deps[dep.Ref] = append(deps[dep.Ref], dep.DependsOn...)
	}
}

func mergeToolComponent(tools *Tools, tool Component) {
	if tools == nil {
		return
	}
	key := componentDedupeKey(tool)
	for _, existing := range tools.Components {
		if componentDedupeKey(existing) == key {
			return
		}
	}
	tools.Components = append(tools.Components, tool)
}

func componentDedupeKey(c Component) string {
	if c.Purl != "" {
		return "purl:" + c.Purl
	}
	if c.BOMRef != "" {
		return "ref:" + c.BOMRef
	}
	return strings.ToLower(c.Type + ":" + c.Name + "@" + c.Version)
}

func mergeComponent(dst *Component, src Component) {
	if dst.BOMRef == "" {
		dst.BOMRef = src.BOMRef
	}
	if dst.Version == "" {
		dst.Version = src.Version
	}
	if dst.Group == "" {
		dst.Group = src.Group
	}
	if dst.Publisher == "" {
		dst.Publisher = src.Publisher
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.Scope == "" {
		dst.Scope = src.Scope
	}
	if dst.Purl == "" {
		dst.Purl = src.Purl
	}
	if dst.ModelCard == nil {
		dst.ModelCard = src.ModelCard
	}
	if dst.CryptoProperties == nil {
		dst.CryptoProperties = src.CryptoProperties
	}
	dst.Hashes = mergeHashes(dst.Hashes, src.Hashes)
	dst.Licenses = mergeLicenses(dst.Licenses, src.Licenses)
	dst.Authors = mergeContacts(dst.Authors, src.Authors)
	dst.ExternalReferences = mergeExtRefs(dst.ExternalReferences, src.ExternalReferences)
	dst.Properties = mergeProps(dst.Properties, src.Properties)
}

func mergeHashes(dst, src []Hash) []Hash {
	seen := map[string]bool{}
	for _, h := range dst {
		seen[h.Alg+"="+h.Content] = true
	}
	for _, h := range src {
		key := h.Alg + "=" + h.Content
		if !seen[key] {
			seen[key] = true
			dst = append(dst, h)
		}
	}
	return dst
}

func mergeLicenses(dst, src []LicenseChoice) []LicenseChoice {
	seen := map[string]bool{}
	keyOf := func(l LicenseChoice) string {
		if l.Expression != "" {
			return "expr:" + l.Expression
		}
		if l.License != nil {
			return "lic:" + l.License.ID + ":" + l.License.Name
		}
		return ""
	}
	for _, l := range dst {
		seen[keyOf(l)] = true
	}
	for _, l := range src {
		key := keyOf(l)
		if key != "" && !seen[key] {
			seen[key] = true
			dst = append(dst, l)
		}
	}
	return dst
}

func mergeContacts(dst, src []OrganizationalContact) []OrganizationalContact {
	seen := map[string]bool{}
	for _, c := range dst {
		seen[c.Name+"<"+c.Email+">"] = true
	}
	for _, c := range src {
		key := c.Name + "<" + c.Email + ">"
		if !seen[key] {
			seen[key] = true
			dst = append(dst, c)
		}
	}
	return dst
}

func mergeExtRefs(dst, src []ExternalReference) []ExternalReference {
	seen := map[string]bool{}
	for _, r := range dst {
		seen[r.Type+"="+r.URL] = true
	}
	for _, r := range src {
		key := r.Type + "=" + r.URL
		if !seen[key] {
			seen[key] = true
			dst = append(dst, r)
		}
	}
	return dst
}

func mergeProps(dst, src []Property) []Property {
	seen := map[string]bool{}
	for _, p := range dst {
		seen[p.Name+"="+p.Value] = true
	}
	for _, p := range src {
		key := p.Name + "=" + p.Value
		if !seen[key] {
			seen[key] = true
			dst = append(dst, p)
		}
	}
	sort.Slice(dst, func(i, j int) bool {
		if dst[i].Name == dst[j].Name {
			return dst[i].Value < dst[j].Value
		}
		return dst[i].Name < dst[j].Name
	})
	return dst
}

// licenseChoiceWith maps a license string to a schema-valid CycloneDX license
// choice. Only license.id is enum-constrained, so a value is emitted there only
// when canonicalSPDXID recognises it; everything else becomes an expression (for
// compound SPDX) or a free-text name.
func licenseChoiceWith(value string, canonicalSPDXID func(string) string) LicenseChoice {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "UNKNOWN") {
		return LicenseChoice{}
	}
	if canonicalSPDXID != nil {
		if canon := canonicalSPDXID(value); canon != "" {
			return LicenseChoice{License: &LicenseData{ID: canon}}
		}
	}
	upper := strings.ToUpper(value)
	if strings.Contains(upper, " OR ") || strings.Contains(upper, " AND ") || strings.Contains(upper, " WITH ") {
		return LicenseChoice{Expression: value}
	}
	return LicenseChoice{License: &LicenseData{Name: value}}
}
