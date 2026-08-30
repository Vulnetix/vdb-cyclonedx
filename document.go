package cyclonedx

import "encoding/json"

// ── CycloneDX write-side document model ──────────────────────────────────────
//
// This is the model every builder in this module writes through, and the model
// consumers author with. It was unexported for a long time, which is precisely
// why the CLI grew a second, parallel declaration of the same shapes: nothing
// outside this package could name `aibomDoc`, so anything that needed to build
// a document had no choice but to redeclare it. A second declaration is a
// second set of omissions, and the omissions did not match.
//
// The read-side model in cyclonedx.go (CDXBom and friends) stays separate on
// purpose. It is version-tolerant and lossy by design — it accepts the 1.2–1.4
// shapes and coalesces them — whereas this one has to produce bytes that
// validate against a declared spec version.

// Document is a CycloneDX Bill of Materials.
//
// Members this model does not interpret survive round-tripping through Extra,
// so a tool that only labels a document does not silently narrow it.
type Document struct {
	// BOMFormat and SpecFormat are the same statement under two names: CycloneDX
	// 2.0 renamed `bomFormat` to `specFormat`, and both the 1.x and 2.0 schemas
	// close the document root, so emitting the wrong one — or both — fails
	// validation outright. Callers set BOMFormat; marshalling emits whichever
	// name the declared specVersion requires, and unmarshalling accepts either.
	BOMFormat    string    `json:"bomFormat,omitempty"`
	SpecFormat   string    `json:"specFormat,omitempty"`
	SpecVersion  string    `json:"specVersion"`
	SerialNumber string    `json:"serialNumber,omitempty"`
	Version      int       `json:"version,omitempty"`
	Metadata     *Metadata `json:"metadata,omitempty"`

	Components   []Component  `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
	Properties   []Property   `json:"properties,omitempty"`

	// Vulnerabilities carries the VEX and SCA finding profile. It shares this
	// type with the inventory profile because a document is frequently both —
	// vex.go used to declare a near-identical vexDoc purely to add this field.
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

// Metadata describes how, when and by whom the document was produced.
//
// The three fields the CycloneDX schema keeps deliberately distinct:
//
//   - Manufacturer is "the organization that created the BOM", and is the
//     correct field for a document produced by an automated process.
//   - Authors are "the person(s) who created the BOM", and belong to documents
//     produced by manual means.
//   - Supplier is subject-level: the organization that supplied the component
//     the BOM *describes*. It says nothing about who wrote the document.
//
// Manufacturer exists only in CycloneDX 1.6+, Lifecycles only in 1.5+, and
// `metadata` carries "additionalProperties": false from 1.4 — so emitting
// either into an older document is a validation failure, not a harmless extra.
// Document.MarshalJSON projects them away for versions that cannot carry them;
// see specversion.go.
type Metadata struct {
	Timestamp    string                `json:"timestamp,omitempty"`
	Lifecycles   []Lifecycle           `json:"lifecycles,omitempty"`
	Tools        *Tools                `json:"tools,omitempty"`
	Manufacturer *OrganizationalEntity `json:"manufacturer,omitempty"`
	// Authors names who is making the claims in this document. It matters most
	// for VEX, where every statement is an assertion by somebody and a document
	// that does not say who asserted it is worth less than one that does.
	Authors   []OrganizationalContact `json:"authors,omitempty"`
	Component *Component              `json:"component,omitempty"`
	Supplier  *OrganizationalEntity   `json:"supplier,omitempty"`
	Licenses  []LicenseChoice         `json:"licenses,omitempty"`
	// Manufacture is the deprecated 1.2–1.7 spelling, superseded by
	// metadata.component.manufacturer and removed in 2.0. It is read from
	// inbound documents and normalised; nothing in this module writes it.
	Manufacture *OrganizationalEntity `json:"manufacture,omitempty"`
	Properties  []Property            `json:"properties,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

// Lifecycle is one entry in metadata.lifecycles (CycloneDX 1.5+). Phase carries
// a value from the pre-defined enum; Name and Description describe a custom
// phase instead. The two forms are mutually exclusive in the schema.
type Lifecycle struct {
	Phase       string `json:"phase,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Tools is metadata.tools in its 1.5+ object form: "the tool(s) used in the
// creation, enrichment, and validation of the BOM".
//
// The bare-array form of earlier versions is accepted on read (see
// CDXTools.UnmarshalJSON) and produced on write only when the declared spec
// version predates 1.5. Components carries uniqueItems:true from 1.5, so
// dedupe on append is a validity requirement rather than tidiness.
type Tools struct {
	Components []Component       `json:"components,omitempty"`
	Services   []json.RawMessage `json:"services,omitempty"`
}

// OrganizationalEntity is CycloneDX `organizationalEntity`: the full shape, not
// the {name} stub CDXOrg models on the read side.
type OrganizationalEntity struct {
	BOMRef  string                  `json:"bom-ref,omitempty"`
	Name    string                  `json:"name,omitempty"`
	Address *PostalAddress          `json:"address,omitempty"`
	URL     []string                `json:"url,omitempty"`
	Contact []OrganizationalContact `json:"contact,omitempty"`
}

// PostalAddress is CycloneDX `postalAddress` (1.6+).
type PostalAddress struct {
	BOMRef        string `json:"bom-ref,omitempty"`
	Country       string `json:"country,omitempty"`
	Region        string `json:"region,omitempty"`
	Locality      string `json:"locality,omitempty"`
	PostOfficeBox string `json:"postOfficeBox,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
}

// OrganizationalContact is CycloneDX `organizationalContact`.
type OrganizationalContact struct {
	BOMRef string `json:"bom-ref,omitempty"`
	Name   string `json:"name,omitempty"`
	Email  string `json:"email,omitempty"`
	Phone  string `json:"phone,omitempty"`
}

// Component is a software, hardware or cryptographic component.
type Component struct {
	Type   string `json:"type"`
	BOMRef string `json:"bom-ref,omitempty"`
	// Publisher / Group identify the producer of the component. Used by the
	// AIBOM builder to attribute an AI tool to its vendor and a model to its
	// provider (e.g. "Anthropic", "OpenAI").
	Publisher   string `json:"publisher,omitempty"`
	Group       string `json:"group,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Purl        string `json:"purl,omitempty"`
	Cpe         string `json:"cpe,omitempty"`

	Supplier     *OrganizationalEntity `json:"supplier,omitempty"`
	Manufacturer *OrganizationalEntity `json:"manufacturer,omitempty"`

	Hashes   []Hash          `json:"hashes,omitempty"`
	Licenses []LicenseChoice `json:"licenses,omitempty"`
	// Authors is supported in CycloneDX 1.6+.
	Authors            []OrganizationalContact `json:"authors,omitempty"`
	ExternalReferences []ExternalReference     `json:"externalReferences,omitempty"`
	Properties         []Property              `json:"properties,omitempty"`
	// ModelCard (CycloneDX 1.5+) describes a machine learning model. The schema
	// requires it to appear ONLY on components of type "machine-learning-model".
	ModelCard *ModelCard `json:"modelCard,omitempty"`
	// CryptoProperties is set only by the CBOM builder (cbom.go) on
	// "cryptographic-asset" components; the AIBOM builder never sets it
	// (omitempty keeps it absent from AIBOM output).
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

// Hash is a cryptographic hash of a component.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// LicenseChoice is either a specific license or an SPDX expression.
type LicenseChoice struct {
	License    *LicenseData `json:"license,omitempty"`
	Expression string       `json:"expression,omitempty"`
}

// LicenseData describes a specific license.
type LicenseData struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// ExternalReference is an external URL resource associated with a component or
// the document. Type is one of the CycloneDX defined types: vcs, website,
// issue-tracker, distribution, license, build-meta, build-system, and so on.
type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property is a name-value pair. CycloneDX convention is that a given property
// name appears once; use SetProperty rather than append to preserve that.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency is one node of the dependency graph.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ── Vulnerability / VEX profile ──────────────────────────────────────────────

// Vulnerability is a CycloneDX vulnerability entry.
type Vulnerability struct {
	BOMRef         string      `json:"bom-ref,omitempty"`
	ID             string      `json:"id"`
	Source         *VulnSource `json:"source,omitempty"`
	Ratings        []Rating    `json:"ratings,omitempty"`
	Description    string      `json:"description,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`
	Advisories     []Advisory  `json:"advisories,omitempty"`
	Analysis       *Analysis   `json:"analysis,omitempty"`
	Affects        []Affect    `json:"affects,omitempty"`
	Properties     []Property  `json:"properties,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

// VulnSource identifies where vulnerability data comes from. Named VulnSource
// rather than Source because sign.go already owns Signature/Source naming in
// this package.
type VulnSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Rating is a vulnerability scoring entry.
//
// Score is a pointer because an unscored rating is common — a severity with no
// numeric score — and a value type would emit "score": 0 beside
// "severity": "high", which asserts a score of zero rather than the absence of
// one.
type Rating struct {
	Score    *float64    `json:"score,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Method   string      `json:"method,omitempty"`
	Source   *VulnSource `json:"source,omitempty"`
}

// Affect identifies a component affected by a vulnerability.
type Affect struct {
	Ref string `json:"ref"`
}

// Analysis contains vulnerability analysis state (CycloneDX VEX profile).
//
// Note the two distinct enums: Justification (impactAnalysisJustification) is
// only meaningful when State == "not_affected", whereas Response
// (impactAnalysisResponse: can_not_fix, will_not_fix, update, rollback,
// workaround_available) describes the remediation taken and is the correct
// home for values like "update" on a "resolved" finding.
type Analysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// Advisory is an external advisory reference.
type Advisory struct {
	URL string `json:"url,omitempty"`
}

// ── Model card (AIBOM) ───────────────────────────────────────────────────────

// ModelCard describes a machine learning model.
type ModelCard struct {
	BOMRef          string           `json:"bom-ref,omitempty"`
	ModelParameters *ModelParameters `json:"modelParameters,omitempty"`
}

// ModelParameters captures the architecture / task of the model. modelParameters
// is closed (additionalProperties:false) so only these keys are valid.
type ModelParameters struct {
	Approach           *Approach `json:"approach,omitempty"`
	Task               string    `json:"task,omitempty"`
	ArchitectureFamily string    `json:"architectureFamily,omitempty"`
	ModelArchitecture  string    `json:"modelArchitecture,omitempty"`
}

// Approach is the learning approach. Type must be one of the schema enum:
// supervised, unsupervised, reinforcement-learning, semi-supervised,
// self-supervised. Omitted for hosted models whose training regime is unknown.
type Approach struct {
	Type string `json:"type,omitempty"`
}

// ── Cryptographic properties (CBOM) ──────────────────────────────────────────

// CryptoProperties is the cryptoProperties block on a cryptographic-asset
// component (CycloneDX 1.6+).
type CryptoProperties struct {
	AssetType                  string                           `json:"assetType"`
	AlgorithmProperties        *AlgorithmProperties             `json:"algorithmProperties,omitempty"`
	CertificateProperties      *CertificateProperties           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProps *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                        string                           `json:"oid,omitempty"`
}

// AlgorithmProperties describes a cryptographic algorithm asset.
type AlgorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	Padding                  string   `json:"padding,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

// CertificateProperties describes an X.509 certificate asset. Metadata only —
// key material is never carried here.
type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
	CertificateExtension  string `json:"certificateExtension,omitempty"`
}

// RelatedCryptoMaterialProperties describes key material, tokens and similar
// related crypto assets.
type RelatedCryptoMaterialProperties struct {
	Type         string `json:"type,omitempty"`
	ID           string `json:"id,omitempty"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
	Size         *int   `json:"size,omitempty"`
	Format       string `json:"format,omitempty"`
}
