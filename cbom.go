package cyclonedx

// CBOM — Cryptography Bill of Materials.
//
// This file owns the Vulnetix CBOM format end to end: the detection data model
// (the contract between a producer's crypto-detection layer and the BOM), the
// property vocabulary (vulnetix:cbom/*, vulnetix:crypto/*), creation
// (BuildCBOM: detections -> validated CycloneDX) and parsing (ParseCBOM:
// CycloneDX -> a flat, persistable inventory). Validation reuses the shared
// CycloneDX schema validator in this package (the bundled 1.6/1.7 schemas define
// the "cryptographic-asset" component type and cryptoProperties).
//
// Component mapping:
//
//	cryptographic algorithm  -> component type "cryptographic-asset" (assetType algorithm)
//	X.509 certificate        -> component type "cryptographic-asset" (assetType certificate)
//	a certificate's key       -> component type "cryptographic-asset" (assetType related-crypto-material)
//	crypto library / SDK      -> component type "library"
//
// Post-quantum posture (quantum-safe | quantum-vulnerable | deprecated | hybrid)
// is surfaced BOTH as the schema's nistQuantumSecurityLevel and as an explicit
// vulnetix:crypto/pqc-status property. Per-country approval status rides on
// vulnetix:crypto/standards/<body> properties.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ── Property keys ────────────────────────────────────────────────────────────

const (
	PropCBOMProfile           = "vulnetix:cbom/profile"
	PropCBOMGenerator         = "vulnetix:cbom/generator"
	PropCBOMCatalogVersion    = "vulnetix:cbom/catalog-version"
	PropCBOMAssetsDetected    = "vulnetix:cbom/algorithms-detected"
	PropCBOMCertsDetected     = "vulnetix:cbom/certificates-detected"
	PropCBOMLibsDetected      = "vulnetix:cbom/libraries-detected"
	PropCBOMQuantumVulnerable = "vulnetix:cbom/quantum-vulnerable"
	PropCBOMQuantumSafe       = "vulnetix:cbom/quantum-safe"
	PropCBOMDeprecated        = "vulnetix:cbom/deprecated"
	PropCBOMHybrid            = "vulnetix:cbom/hybrid"

	PropCryptoCategory       = "vulnetix:crypto/category" // algorithm|certificate|key|library
	PropCryptoSpdxID         = "vulnetix:crypto/spdx-id"
	PropCryptoPQCStatus      = "vulnetix:crypto/pqc-status"
	PropCryptoClassicalLevel = "vulnetix:crypto/classical-security-level"
	PropCryptoQuantumLevel   = "vulnetix:crypto/nist-quantum-security-level"
	PropCryptoProvider       = "vulnetix:crypto/provider"
	PropCryptoLanguages      = "vulnetix:crypto/languages"
	PropCryptoConfidence     = "vulnetix:crypto/confidence"
	PropCryptoOccurrences    = "vulnetix:crypto/occurrences"
	PropCryptoLibraryID      = "vulnetix:crypto/library-id"
	PropCryptoStandardPrefix = "vulnetix:crypto/standards/" // + body, e.g. "NIST"
	PropCryptoEvidenceCount  = "vulnetix:crypto/evidence-count"
	PropCryptoEvidence       = "vulnetix:crypto/evidence"
)

// PQC status values surfaced on vulnetix:crypto/pqc-status.
const (
	PQCQuantumSafe       = "quantum-safe"
	PQCQuantumVulnerable = "quantum-vulnerable"
	PQCDeprecated        = "deprecated"
	PQCHybrid            = "hybrid"
)

// ── Detection model (the producer contract) ──────────────────────────────────

// CryptoEvidence is one observation supporting a crypto detection. Method is one
// of source|config|certificate|dependency. Locator is "file:line". It is
// structurally identical to AIEvidence, so the shared FormatEvidence/
// ParseEvidenceValue helpers apply.
type CryptoEvidence = AIEvidence

// CryptoAsset is a detected cryptographic algorithm, identified by its canonical
// SPDX id/name. All algorithmProperties are optional and emitted only when known.
type CryptoAsset struct {
	SPDXID                   string            `json:"spdxId"`
	Name                     string            `json:"name"`
	OID                      string            `json:"oid,omitempty"`
	Primitive                string            `json:"primitive,omitempty"` // CycloneDX primitive enum
	ParameterSetIdentifier   string            `json:"parameterSetIdentifier,omitempty"`
	Curve                    string            `json:"curve,omitempty"`
	Mode                     string            `json:"mode,omitempty"`    // CycloneDX mode enum
	Padding                  string            `json:"padding,omitempty"` // CycloneDX padding enum
	CryptoFunctions          []string          `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int               `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int               `json:"nistQuantumSecurityLevel"` // 0..6 (0 = not quantum-safe)
	PQCStatus                string            `json:"pqcStatus,omitempty"`
	Standards                map[string]string `json:"standards,omitempty"` // body -> approval status
	Confidence               string            `json:"confidence,omitempty"`
	Occurrences              int               `json:"occurrences,omitempty"`
	Evidence                 []CryptoEvidence  `json:"evidence,omitempty"`
}

// CryptoLib is a detected cryptographic library / SDK.
type CryptoLib struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Provider   string           `json:"provider,omitempty"`
	Languages  []string         `json:"languages,omitempty"`
	Purl       string           `json:"purl,omitempty"`
	Confidence string           `json:"confidence,omitempty"`
	Evidence   []CryptoEvidence `json:"evidence,omitempty"`
}

// CryptoCert is a certificate parsed from disk. SignatureAlgorithm and
// PublicKeyAlgorithm are canonical SPDX names so they line up with CryptoAsset.
type CryptoCert struct {
	Name               string           `json:"name"`
	Subject            string           `json:"subject,omitempty"`
	Issuer             string           `json:"issuer,omitempty"`
	NotBefore          string           `json:"notBefore,omitempty"` // RFC3339
	NotAfter           string           `json:"notAfter,omitempty"`  // RFC3339
	Format             string           `json:"format,omitempty"`    // e.g. X.509
	FileExtension      string           `json:"fileExtension,omitempty"`
	SignatureAlgorithm string           `json:"signatureAlgorithm,omitempty"`
	PublicKeyAlgorithm string           `json:"publicKeyAlgorithm,omitempty"`
	PublicKeyType      string           `json:"publicKeyType,omitempty"` // related-crypto-material type, e.g. public-key
	KeySize            int              `json:"keySize,omitempty"`
	PQCStatus          string           `json:"pqcStatus,omitempty"`
	Evidence           []CryptoEvidence `json:"evidence,omitempty"`
}

// CryptoSummary is the post-quantum posture rollup used for the CLI summary and
// the --fail-on gate.
type CryptoSummary struct {
	QuantumVulnerable int `json:"quantumVulnerable"`
	QuantumSafe       int `json:"quantumSafe"`
	Deprecated        int `json:"deprecated"`
	Hybrid            int `json:"hybrid"`
	Unknown           int `json:"unknown"`
}

// CryptoDetections is the full result of a CBOM scan.
type CryptoDetections struct {
	Assets         []CryptoAsset `json:"assets,omitempty"`
	Libraries      []CryptoLib   `json:"libraries,omitempty"`
	Certificates   []CryptoCert  `json:"certificates,omitempty"`
	CatalogVersion string        `json:"catalogVersion,omitempty"`
	Summary        CryptoSummary `json:"summary,omitempty"`
}

// ComputeCryptoSummary tallies PQC posture across algorithms and certificates so
// producers and consumers agree on the rollup. A certificate is counted by its
// own pqcStatus (driven by its signature algorithm).
func ComputeCryptoSummary(det CryptoDetections) CryptoSummary {
	var s CryptoSummary
	tally := func(status string) {
		switch status {
		case PQCQuantumVulnerable:
			s.QuantumVulnerable++
		case PQCQuantumSafe:
			s.QuantumSafe++
		case PQCDeprecated:
			s.Deprecated++
		case PQCHybrid:
			s.Hybrid++
		default:
			s.Unknown++
		}
	}
	for _, a := range det.Assets {
		tally(a.PQCStatus)
	}
	for _, c := range det.Certificates {
		tally(c.PQCStatus)
	}
	return s
}

// ── Reused project metadata (alias the AIBOM project model) ──────────────────

// CBOMProject/CBOMSystem/CBOMContact reuse the AIBOM project metadata model so
// metadata.component and the vulnetix:git/* + vulnetix:env/* properties are built
// by the same buildProjectComponent path.
type (
	CBOMProject = AIBOMProject
	CBOMSystem  = AIBOMSystem
	CBOMContact = AIBOMContact
)

// CBOMOptions configures BuildCBOM.
type CBOMOptions struct {
	SpecVersion string // default DefaultSpecVersion
	// Authorship states who created this document and at which lifecycle stage
	// its data was captured. When set it takes precedence over the three fields
	// below, which remain honoured so existing callers keep working.
	Authorship  *Authorship
	ToolName    string       // default ToolCBOM
	ToolVersion string       // default UnknownToolVersion
	GeneratedAt string       // RFC3339; default time.Now().UTC()
	Project     *CBOMProject // nil → minimal project component
}

// ── BuildCBOM (creating) ─────────────────────────────────────────────────────

// BuildCBOM maps crypto detections to a CycloneDX CBOM and returns indented JSON.
// The result is validated against the CycloneDX schema for the declared spec
// version; a schema violation returns an error.
func BuildCBOM(det CryptoDetections, opts CBOMOptions) ([]byte, error) {
	doc := BuildCBOMDocument(det, opts)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, violations, verr := ValidateCycloneDX(data); verr != nil {
		return nil, fmt.Errorf("cbom: validation error: %w", verr)
	} else if len(violations) > 0 {
		return nil, fmt.Errorf("cbom: schema violation at %s: %s", violations[0].Path, violations[0].Message)
	}
	return data, nil
}

// BuildCBOMDocument assembles the CBOM as a marshalable document without
// validating — useful for callers that want to inspect or re-serialize it.
func BuildCBOMDocument(det CryptoDetections, opts CBOMOptions) any {
	spec := opts.SpecVersion
	if spec == "" {
		spec = DefaultSpecVersion
	}
	// A crypto inventory is found by observing source, config and certificates
	// on disk, which is what the discovery phase describes.
	authorship := authorshipFrom(opts.Authorship, nonEmpty(opts.ToolName, ToolCBOM), opts.ToolVersion, opts.GeneratedAt, PhaseDiscovery)
	toolName := authorship.Tool.Name

	projComp, envProps := buildProjectComponent(opts.Project)

	doc := &Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: spec,
		Metadata:    &Metadata{Component: projComp},
	}
	_, _ = ApplyAuthorship(doc, authorship)

	summary := ComputeCryptoSummary(det)
	projRef := projComp.BOMRef
	doc.Metadata.Properties = append(doc.Metadata.Properties,
		mkProp(PropCBOMProfile, "cryptography"),
		mkProp(PropCBOMGenerator, toolName),
	)
	if det.CatalogVersion != "" {
		doc.Metadata.Properties = append(doc.Metadata.Properties, mkProp(PropCBOMCatalogVersion, det.CatalogVersion))
	}
	doc.Metadata.Properties = append(doc.Metadata.Properties,
		mkProp(PropCBOMAssetsDetected, strconv.Itoa(len(det.Assets))),
		mkProp(PropCBOMCertsDetected, strconv.Itoa(len(det.Certificates))),
		mkProp(PropCBOMLibsDetected, strconv.Itoa(len(det.Libraries))),
		mkProp(PropCBOMQuantumVulnerable, strconv.Itoa(summary.QuantumVulnerable)),
		mkProp(PropCBOMQuantumSafe, strconv.Itoa(summary.QuantumSafe)),
		mkProp(PropCBOMDeprecated, strconv.Itoa(summary.Deprecated)),
		mkProp(PropCBOMHybrid, strconv.Itoa(summary.Hybrid)),
	)
	doc.Metadata.Properties = append(doc.Metadata.Properties, envProps...)

	validRefs := map[string]bool{projRef: true}
	deps := map[string][]string{}
	// algoRefByName maps a canonical algorithm name to its component bom-ref so
	// certificates can wire signatureAlgorithmRef without dangling references.
	algoRefByName := map[string]string{}

	// algorithms → cryptographic-asset (algorithm) components.
	for _, a := range det.Assets {
		ref := "urn:crypto:algorithm:" + a.SPDXID
		if a.ParameterSetIdentifier != "" {
			ref += ":" + sanitizeRef(a.ParameterSetIdentifier)
		}
		comp := Component{
			Type:   "cryptographic-asset",
			BOMRef: ref,
			Name:   a.Name,
			CryptoProperties: &CryptoProperties{
				AssetType:           "algorithm",
				AlgorithmProperties: algorithmProps(a),
				OID:                 a.OID,
			},
		}
		comp.Properties = append(comp.Properties,
			mkProp(PropCryptoCategory, "algorithm"),
			mkProp(PropCryptoSpdxID, a.SPDXID),
		)
		if a.PQCStatus != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoPQCStatus, a.PQCStatus))
		}
		if a.ClassicalSecurityLevel > 0 {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoClassicalLevel, strconv.Itoa(a.ClassicalSecurityLevel)))
		}
		comp.Properties = append(comp.Properties, mkProp(PropCryptoQuantumLevel, strconv.Itoa(a.NISTQuantumSecurityLevel)))
		for _, body := range sortedKeys(a.Standards) {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoStandardPrefix+body, a.Standards[body]))
		}
		if a.Confidence != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoConfidence, a.Confidence))
		}
		if a.Occurrences > 0 {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoOccurrences, strconv.Itoa(a.Occurrences)))
		}
		appendCryptoEvidenceProps(&comp, a.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true
		algoRefByName[strings.ToLower(a.Name)] = ref
		algoRefByName[strings.ToLower(a.SPDXID)] = ref
		deps[projRef] = append(deps[projRef], ref)
	}

	// crypto libraries → library components.
	for _, l := range det.Libraries {
		ref := "urn:crypto:library:" + l.ID
		comp := Component{Type: "library", BOMRef: ref, Name: l.Name, Publisher: l.Provider, Purl: l.Purl}
		comp.Properties = append(comp.Properties, mkProp(PropCryptoCategory, "library"), mkProp(PropCryptoLibraryID, l.ID))
		if l.Provider != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoProvider, l.Provider))
		}
		if len(l.Languages) > 0 {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoLanguages, strings.Join(l.Languages, ",")))
		}
		if l.Confidence != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoConfidence, l.Confidence))
		}
		appendCryptoEvidenceProps(&comp, l.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true
		deps[projRef] = append(deps[projRef], ref)
	}

	// certificates → cryptographic-asset (certificate) components, plus a
	// related-crypto-material (public-key) component each.
	for i, ct := range det.Certificates {
		ref := fmt.Sprintf("urn:crypto:certificate:%d", i)
		certProps := &CertificateProperties{
			SubjectName:          ct.Subject,
			IssuerName:           ct.Issuer,
			NotValidBefore:       ct.NotBefore,
			NotValidAfter:        ct.NotAfter,
			CertificateFormat:    nonEmpty(ct.Format, "X.509"),
			CertificateExtension: strings.TrimPrefix(ct.FileExtension, "."),
		}
		if r, ok := algoRefByName[strings.ToLower(ct.SignatureAlgorithm)]; ok {
			certProps.SignatureAlgorithmRef = r
		}

		// public key as related-crypto-material.
		keyRef := ref + ":key"
		keyType := nonEmpty(ct.PublicKeyType, "public-key")
		keyComp := Component{
			Type:   "cryptographic-asset",
			BOMRef: keyRef,
			Name:   nonEmpty(ct.PublicKeyAlgorithm, "public-key") + " (" + ct.Name + ")",
			CryptoProperties: &CryptoProperties{
				AssetType:                  "related-crypto-material",
				RelatedCryptoMaterialProps: relatedKeyProps(keyType, ct, algoRefByName),
			},
		}
		keyComp.Properties = append(keyComp.Properties, mkProp(PropCryptoCategory, "key"))
		if ct.PublicKeyAlgorithm != "" {
			keyComp.Properties = append(keyComp.Properties, mkProp(PropCryptoSpdxID, ct.PublicKeyAlgorithm))
		}
		doc.Components = append(doc.Components, keyComp)
		validRefs[keyRef] = true
		certProps.SubjectPublicKeyRef = keyRef

		comp := Component{
			Type:   "cryptographic-asset",
			BOMRef: ref,
			Name:   ct.Name,
			CryptoProperties: &CryptoProperties{
				AssetType:             "certificate",
				CertificateProperties: certProps,
			},
		}
		comp.Properties = append(comp.Properties, mkProp(PropCryptoCategory, "certificate"))
		if ct.PQCStatus != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoPQCStatus, ct.PQCStatus))
		}
		if ct.SignatureAlgorithm != "" {
			comp.Properties = append(comp.Properties, mkProp(PropCryptoSpdxID, ct.SignatureAlgorithm))
		}
		appendCryptoEvidenceProps(&comp, ct.Evidence)
		doc.Components = append(doc.Components, comp)
		validRefs[ref] = true
		deps[projRef] = append(deps[projRef], ref, keyRef)
		deps[ref] = append(deps[ref], keyRef)
		if certProps.SignatureAlgorithmRef != "" {
			deps[ref] = append(deps[ref], certProps.SignatureAlgorithmRef)
		}
	}

	doc.Dependencies = buildDeps(deps, validRefs)
	return doc
}

// algorithmProps builds the CycloneDX algorithmProperties for an asset, emitting
// only schema-valid, non-empty fields. nistQuantumSecurityLevel is always set
// (0 is meaningful: "not quantum-safe").
func algorithmProps(a CryptoAsset) *AlgorithmProperties {
	p := &AlgorithmProperties{
		Primitive:              a.Primitive,
		ParameterSetIdentifier: a.ParameterSetIdentifier,
		Curve:                  a.Curve,
		Mode:                   a.Mode,
		Padding:                a.Padding,
		CryptoFunctions:        a.CryptoFunctions,
	}
	nq := a.NISTQuantumSecurityLevel
	p.NISTQuantumSecurityLevel = &nq
	if a.ClassicalSecurityLevel > 0 {
		cl := a.ClassicalSecurityLevel
		p.ClassicalSecurityLevel = &cl
	}
	return p
}

func relatedKeyProps(keyType string, ct CryptoCert, algoRefByName map[string]string) *RelatedCryptoMaterialProperties {
	p := &RelatedCryptoMaterialProperties{Type: keyType}
	if ct.KeySize > 0 {
		sz := ct.KeySize
		p.Size = &sz
	}
	if r, ok := algoRefByName[strings.ToLower(ct.PublicKeyAlgorithm)]; ok {
		p.AlgorithmRef = r
	}
	return p
}

func appendCryptoEvidenceProps(comp *Component, ev []CryptoEvidence) {
	if len(ev) == 0 {
		return
	}
	comp.Properties = append(comp.Properties, mkProp(PropCryptoEvidenceCount, strconv.Itoa(len(ev))))
	limit := len(ev)
	if limit > maxEvidencePerComponent {
		limit = maxEvidencePerComponent
	}
	for _, e := range ev[:limit] {
		comp.Properties = append(comp.Properties, mkProp(PropCryptoEvidence, FormatEvidence(e)))
	}
}

// sanitizeRef makes a parameter-set identifier safe for a bom-ref suffix.
func sanitizeRef(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func sortedKeys(m map[string]string) []string {
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

// ── ParseCBOM (parsing) ──────────────────────────────────────────────────────

type cdxParseCryptoProps struct {
	AssetType           string `json:"assetType"`
	AlgorithmProperties *struct {
		Primitive                string `json:"primitive"`
		ParameterSetIdentifier   string `json:"parameterSetIdentifier"`
		ClassicalSecurityLevel   *int   `json:"classicalSecurityLevel"`
		NISTQuantumSecurityLevel *int   `json:"nistQuantumSecurityLevel"`
	} `json:"algorithmProperties"`
	OID string `json:"oid"`
}

type cdxParseCryptoComp struct {
	Type             string               `json:"type"`
	Name             string               `json:"name"`
	BOMRef           string               `json:"bom-ref"`
	Purl             string               `json:"purl"`
	Properties       []cdxParseProp       `json:"properties"`
	CryptoProperties *cdxParseCryptoProps `json:"cryptoProperties"`
}

type cdxParseCBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    *struct {
		Component  *cdxParseComp  `json:"component"`
		Properties []cdxParseProp `json:"properties"`
	} `json:"metadata"`
	Components []cdxParseCryptoComp `json:"components"`
}

// CBOMComponentRow is one decomposed crypto component, flattened for persistence.
type CBOMComponentRow struct {
	ComponentType            string
	Category                 string
	AssetType                string
	Name                     string
	SPDXID                   string
	OID                      string
	Primitive                string
	ParameterSetIdentifier   string
	ClassicalSecurityLevel   int
	NISTQuantumSecurityLevel int
	PQCStatus                string
	Provider                 string
	Languages                string
	Purl                     string
	Confidence               string
	Standards                map[string]string
	PropertiesJSON           string
	Evidence                 []CryptoEvidence
}

// CBOMInventory is the flattened, persistable decomposition of a CycloneDX CBOM.
type CBOMInventory struct {
	SpecVersion       string
	CatalogVersion    string
	RepoName          string
	BranchName        string
	CommitSha         string
	ComponentCount    int
	AlgorithmCount    int
	CertificateCount  int
	LibraryCount      int
	QuantumVulnerable int
	QuantumSafe       int
	Deprecated        int
	Hybrid            int
	Components        []CBOMComponentRow
}

// ParseCBOM decomposes a CycloneDX CBOM into a flat inventory ready for
// persistence. It accepts both Vulnetix-generated CBOMs (rich vulnetix:crypto/*
// annotations) and generic CycloneDX CBOMs (cryptographic-asset components).
func ParseCBOM(data []byte) (*CBOMInventory, error) {
	var bom cdxParseCBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("cbom: invalid JSON — expected a CycloneDX document: %w", err)
	}
	if !strings.EqualFold(bom.BOMFormat, "CycloneDX") {
		return nil, fmt.Errorf("cbom: not a CycloneDX document (bomFormat missing)")
	}

	inv := &CBOMInventory{SpecVersion: bom.SpecVersion}
	if m := bom.Metadata; m != nil {
		inv.CatalogVersion = firstProp(m.Properties, PropCBOMCatalogVersion)
		if m.Component != nil {
			inv.RepoName = m.Component.Name
			inv.BranchName = firstProp(m.Component.Properties, PropGitBranch)
			inv.CommitSha = firstProp(m.Component.Properties, PropGitCommit)
		}
	}

	for _, c := range bom.Components {
		cat := firstProp(c.Properties, PropCryptoCategory)
		if cat == "" {
			switch c.Type {
			case "cryptographic-asset":
				cat = "algorithm"
			case "library":
				if firstProp(c.Properties, PropCryptoLibraryID) == "" {
					continue // an ordinary (non-crypto) library
				}
				cat = "library"
			default:
				continue
			}
		}
		row := CBOMComponentRow{
			ComponentType:  c.Type,
			Category:       cat,
			Name:           c.Name,
			SPDXID:         firstProp(c.Properties, PropCryptoSpdxID),
			PQCStatus:      firstProp(c.Properties, PropCryptoPQCStatus),
			Provider:       firstProp(c.Properties, PropCryptoProvider),
			Languages:      firstProp(c.Properties, PropCryptoLanguages),
			Purl:           c.Purl,
			Confidence:     firstProp(c.Properties, PropCryptoConfidence),
			Standards:      standardsFromProps(c.Properties),
			PropertiesJSON: marshalString(c.Properties),
		}
		if cp := c.CryptoProperties; cp != nil {
			row.AssetType = cp.AssetType
			row.OID = cp.OID
			if ap := cp.AlgorithmProperties; ap != nil {
				row.Primitive = ap.Primitive
				row.ParameterSetIdentifier = ap.ParameterSetIdentifier
				if ap.ClassicalSecurityLevel != nil {
					row.ClassicalSecurityLevel = *ap.ClassicalSecurityLevel
				}
				if ap.NISTQuantumSecurityLevel != nil {
					row.NISTQuantumSecurityLevel = *ap.NISTQuantumSecurityLevel
				}
			}
		}
		for _, p := range c.Properties {
			if p.Name == PropCryptoEvidence && p.Value != "" {
				row.Evidence = append(row.Evidence, ParseEvidenceValue(p.Value))
			}
		}
		inv.Components = append(inv.Components, row)
		switch cat {
		case "algorithm":
			inv.AlgorithmCount++
		case "certificate":
			inv.CertificateCount++
		case "library":
			inv.LibraryCount++
		}
		switch row.PQCStatus {
		case PQCQuantumVulnerable:
			inv.QuantumVulnerable++
		case PQCQuantumSafe:
			inv.QuantumSafe++
		case PQCDeprecated:
			inv.Deprecated++
		case PQCHybrid:
			inv.Hybrid++
		}
	}
	inv.ComponentCount = len(inv.Components)
	if len(inv.Components) == 0 {
		return nil, fmt.Errorf("cbom: no cryptographic components found — expected cryptographic-asset components or vulnetix:crypto annotated components")
	}
	return inv, nil
}

func standardsFromProps(props []cdxParseProp) map[string]string {
	var out map[string]string
	for _, p := range props {
		if strings.HasPrefix(p.Name, PropCryptoStandardPrefix) {
			if out == nil {
				out = map[string]string{}
			}
			out[strings.TrimPrefix(p.Name, PropCryptoStandardPrefix)] = p.Value
		}
	}
	return out
}
