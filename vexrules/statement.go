// Package vexrules decides what a VEX statement means for a finding, and
// carries the suppression-rule matcher every Vulnetix service shares.
//
// A VEX statement and a suppression rule make the same kind of claim: this
// finding should not be acted on, for this reason. Before this package the two
// lived apart. A suppression rule hid findings; an uploaded VEX document was
// stored and never consulted. This package is the bridge: it reads OpenVEX,
// CycloneDX VEX and CSAF VEX into one statement model that keeps the raw
// fields each format uses, classifies each statement (Classify), and matches
// rules against findings (Set.Match) the same way in the CLI and on the server.
//
// Only two dispositions become rules: a false positive (the scanner was wrong)
// and a won't fix (the owner has decided not to act). Every other statement is
// evidence for triage, never a rule. The formats express those two decisions in
// different fields, and some only in prose, so Classify reads all of them.
//
// The package is pure: no I/O beyond parsing bytes, no database, no clock
// except where a caller passes one. The database engine that applies rules
// lives in the private vdb-sca-match/suppression package.
package vexrules

import (
	"strings"
	"time"
)

// Format identifies a VEX serialisation.
type Format string

const (
	FormatOpenVEX   Format = "openvex"
	FormatCycloneDX Format = "cyclonedx"
	FormatCSAF      Format = "csaf"
	FormatUnknown   Format = "unknown"
)

// Status is the OpenVEX status a statement normalises to. The classifier does
// not decide on Status alone; it reads Raw, because the normalisation loses
// the distinctions that matter (CycloneDX false_positive and not_affected both
// become not_affected).
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Product identifies what a statement is about.
type Product struct {
	// Purl is the product's package URL, when it has one.
	Purl string `json:"purl,omitempty"`
	// ID is the raw product identifier as written in the document.
	ID string `json:"id,omitempty"`
	// Versions are explicit versions the statement is scoped to. Empty means
	// every version of the product.
	Versions []string `json:"versions,omitempty"`
	// Subcomponents are purls the statement narrows to within the product.
	Subcomponents []string `json:"subcomponents,omitempty"`
}

// Remediation is one CSAF remediation.
type Remediation struct {
	Category string `json:"category"`
	Details  string `json:"details,omitempty"`
}

// RawDisposition keeps every source field the classifier reads. It is stored
// with the statement (OpenVexStatement.rawDispositionJSON) so a decision can be
// explained later from what the document actually said.
type RawDisposition struct {
	Format Format `json:"format"`

	CDXState         string            `json:"cdxState,omitempty"`
	CDXJustification string            `json:"cdxJustification,omitempty"`
	CDXResponses     []string          `json:"cdxResponses,omitempty"`
	CDXDetail        string            `json:"cdxDetail,omitempty"`
	CDXProperties    map[string]string `json:"cdxProperties,omitempty"`

	OpenVEXStatus          string `json:"openvexStatus,omitempty"`
	OpenVEXJustification   string `json:"openvexJustification,omitempty"`
	OpenVEXStatusNotes     string `json:"openvexStatusNotes,omitempty"`
	OpenVEXActionStatement string `json:"openvexActionStatement,omitempty"`
	OpenVEXImpactStatement string `json:"openvexImpactStatement,omitempty"`

	CSAFProductStatus string        `json:"csafProductStatus,omitempty"`
	CSAFFlags         []string      `json:"csafFlags,omitempty"`
	CSAFRemediations  []Remediation `json:"csafRemediations,omitempty"`
	CSAFNotes         []string      `json:"csafNotes,omitempty"`
}

// Statement is one normalised VEX assertion.
type Statement struct {
	VulnID          string    `json:"vulnId"`
	Aliases         []string  `json:"aliases,omitempty"`
	Status          Status    `json:"status"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impactStatement,omitempty"`
	ActionStatement string    `json:"actionStatement,omitempty"`
	Products        []Product `json:"products,omitempty"`
	// Timestamp is when the assertion was made. A newer statement for the same
	// vulnerability and product supersedes an older one, whatever order they
	// arrive in.
	Timestamp time.Time `json:"timestamp,omitempty"`
	// Ref names the statement inside its document: the OpenVEX statement @id,
	// or the format and position ("cyclonedx#3").
	Ref string `json:"ref,omitempty"`
	// Index is the statement's position in the document.
	Index int `json:"index"`
	// Raw is what the classifier reads.
	Raw RawDisposition `json:"raw"`
}

// Document is a parsed VEX document.
type Document struct {
	Format     Format      `json:"format"`
	ID         string      `json:"id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Timestamp  time.Time   `json:"timestamp,omitempty"`
	Statements []Statement `json:"statements"`
}

// NormalizeVulnID reduces a vulnerability identifier to its bare form. Real
// documents carry it as a URL as often as a bare id
// (https://github.com/advisories/GHSA-xxxx), and a URL never matches a scan's
// bare id.
func NormalizeVulnID(raw string) string {
	id := strings.TrimSpace(raw)
	if id == "" {
		return ""
	}
	if i := strings.IndexAny(id, "?#"); i >= 0 {
		id = id[:i]
	}
	if idx := strings.LastIndex(id, "/"); idx >= 0 && idx < len(id)-1 {
		id = id[idx+1:]
	}
	return strings.TrimSpace(id)
}

// PurlBase strips the version, qualifiers and subpath from a purl, and
// lowercases the type. "pkg:npm/%40scope/a@1.2.3?x=y" becomes
// "pkg:npm/%40scope/a". The supersede key and the rule prefilter match on it.
func PurlBase(purl string) string {
	p := strings.TrimSpace(purl)
	if !strings.HasPrefix(strings.ToLower(p), "pkg:") {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	// The version separator is the last "@" after the final "/", so a scoped
	// npm name (%40scope or a literal @scope) is not cut.
	slash := strings.LastIndex(p, "/")
	if at := strings.LastIndex(p, "@"); at > slash && slash >= 0 {
		p = p[:at]
	}
	rest := p[4:]
	if t, name, ok := strings.Cut(rest, "/"); ok {
		return "pkg:" + strings.ToLower(t) + "/" + name
	}
	return "pkg:" + strings.ToLower(rest)
}
