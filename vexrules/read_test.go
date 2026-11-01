package vexrules

import (
	"testing"
)

func TestParseCycloneDXKeepsRawFields(t *testing.T) {
	doc, err := Parse([]byte(`{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1",
  "metadata": {"timestamp": "2026-10-01T00:00:00Z", "authors": [{"name": "Acme PSIRT"}]},
  "components": [{"bom-ref": "c1", "purl": "pkg:npm/lodash@4.17.20",
    "components": [{"bom-ref": "c2", "purl": "pkg:npm/minimist@1.2.0"}]}],
  "vulnerabilities": [
    {"id": "CVE-2021-23337", "references": [{"id": "GHSA-35jh-r3h4-6jhm"}],
     "analysis": {"state": "false_positive", "detail": "scanner misread the lockfile", "lastUpdated": "2026-10-02T00:00:00Z"},
     "affects": [{"ref": "c1"}],
     "properties": [{"name": "vulnetix:suppression/uuid", "value": "u1"}]},
    {"id": "CVE-2021-44906", "analysis": {"state": "exploitable", "response": ["will_not_fix"]}, "affects": [{"ref": "c2"}]},
    {"id": "CVE-2000-0001"}
  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatCycloneDX || doc.Author != "Acme PSIRT" || len(doc.Statements) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	s := doc.Statements[0]
	if s.Raw.CDXState != "false_positive" || s.Status != StatusNotAffected {
		t.Errorf("raw state lost: %+v", s.Raw)
	}
	if s.Products[0].Purl != "pkg:npm/lodash@4.17.20" || s.Aliases[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("product/alias = %+v %+v", s.Products, s.Aliases)
	}
	if s.Timestamp.Format("2006-01-02") != "2026-10-02" {
		t.Errorf("timestamp = %v, want analysis.lastUpdated", s.Timestamp)
	}
	if s.Raw.CDXProperties["vulnetix:suppression/uuid"] != "u1" {
		t.Errorf("properties lost")
	}
	if p := doc.Statements[1].Products[0].Purl; p != "pkg:npm/minimist@1.2.0" {
		t.Errorf("nested component purl = %q", p)
	}
	if got := Classify(doc.Statements[1]); got.Kind != KindWontFix {
		t.Errorf("second statement = %+v", got)
	}
}

func TestParseOpenVEXKeepsStatusNotes(t *testing.T) {
	doc, err := Parse([]byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.com/vex/1", "author": "Acme",
  "timestamp": "2026-10-01T00:00:00Z",
  "statements": [{"@id": "s1", "vulnerability": {"name": "https://nvd.nist.gov/vuln/detail/CVE-2023-1"},
    "products": [{"@id": "pkg:golang/example.com/a@v1.0.0"}],
    "status": "affected", "action_statement": "Will not fix: EOL", "status_notes": "n"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Statements[0]
	if s.VulnID != "CVE-2023-1" || s.Ref != "s1" || s.Raw.OpenVEXStatusNotes != "n" {
		t.Fatalf("statement = %+v", s)
	}
	if d := Classify(s); d.Kind != KindWontFix || d.Active {
		t.Errorf("text basis rule must start inactive: %+v", d)
	}
}

func TestParseCSAFKeepsRemediationsAndFlags(t *testing.T) {
	doc, err := Parse([]byte(`{
  "document": {"category": "csaf_vex", "tracking": {"id": "ACME-1", "current_release_date": "2026-10-01T00:00:00Z"}, "publisher": {"name": "Acme"}},
  "product_tree": {"branches": [{"branches": [{"product": {"product_id": "P1", "product_identification_helper": {"purl": "pkg:pypi/requests@2.0.0"}}}]}]},
  "vulnerabilities": [{"cve": "CVE-2024-2",
    "product_status": {"known_affected": ["P1"], "known_not_affected": ["P2"]},
    "remediations": [{"category": "no_fix_planned", "details": "EOL", "product_ids": ["P1"]}],
    "flags": [{"label": "component_not_present", "product_ids": ["P2"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d", len(doc.Statements))
	}
	for _, s := range doc.Statements {
		d := Classify(s)
		switch s.Raw.CSAFProductStatus {
		case "known_affected":
			if d.Kind != KindWontFix || s.Products[0].Purl != "pkg:pypi/requests@2.0.0" {
				t.Errorf("affected = %+v %+v", d, s.Products)
			}
		case "known_not_affected":
			if d.Kind != KindFalsePositive {
				t.Errorf("not affected = %+v", d)
			}
		}
	}
}

func TestDetectUnknown(t *testing.T) {
	if Detect([]byte(`{"version":"2.1.0","runs":[]}`)) != FormatUnknown {
		t.Fatal("SARIF detected as VEX")
	}
	if _, err := Parse([]byte(`{}`)); err == nil {
		t.Fatal("empty object parsed")
	}
}

func TestPurlBase(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":              "pkg:npm/lodash",
		"pkg:npm/%40scope/a@1.2.3?x=y":        "pkg:npm/%40scope/a",
		"pkg:NPM/@scope/a@1.0.0":              "pkg:npm/@scope/a",
		"pkg:golang/example.com/a@v1.0.0#sub": "pkg:golang/example.com/a",
		"pkg:maven/org.apache/log4j-core":     "pkg:maven/org.apache/log4j-core",
		"not a purl":                          "",
	} {
		if got := PurlBase(in); got != want {
			t.Errorf("PurlBase(%q) = %q, want %q", in, got, want)
		}
	}
}
