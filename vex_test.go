package cyclonedx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures below reproduce the exact defects the OWASP TEA conformance
// suite found in documents this module now authors. They are written by hand
// rather than copied from the run that found them: those captures are a
// tenant's own scan data, including absolute paths from a build agent, and this
// module is public.
//
// TestRealCapturedDocuments picks the captures up from disk when they are
// available, so the real bytes can still be checked without being published.

func buildOrFail(t *testing.T, findings []VEXFinding, opts VEXOptions) map[string]any {
	t.Helper()
	data, err := BuildCDXVEX(findings, opts)
	if err != nil {
		t.Fatalf("BuildCDXVEX rejected its own output: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

// The first defect: a sentence of reachability evidence in analysis.response,
// which the schema defines as an array of five enum members.
func TestFreeTextResponseMovesToDetail(t *testing.T) {
	evidence := "matched routine github.com/charmbracelet/bubbletea in internal/license/detect.go"

	doc := buildOrFail(t, []VEXFinding{{
		CVEID: "CVE-2025-0001", Package: "github.com/charmbracelet/bubbletea",
		Ecosystem: "golang", InstalledVer: "1.3.10",
		Status: "affected", Responses: []string{evidence},
	}}, VEXOptions{})

	analysis := firstAnalysis(t, doc)
	if _, present := analysis["response"]; present {
		t.Errorf("free text was emitted as a response member: %v", analysis["response"])
	}
	detail, _ := analysis["detail"].(string)
	if !strings.Contains(detail, "matched routine") {
		t.Errorf("the evidence was dropped instead of moved to detail; detail is %q", detail)
	}
}

func TestValidResponsesSurviveAsAnArray(t *testing.T) {
	doc := buildOrFail(t, []VEXFinding{{
		CVEID: "CVE-2025-0002", Package: "lodash", Ecosystem: "npm", InstalledVer: "4.17.20",
		Status: "affected", FixedVer: "4.17.21",
		Responses: []string{"update", "workaround_available"},
	}}, VEXOptions{})

	analysis := firstAnalysis(t, doc)
	resp, ok := analysis["response"].([]any)
	if !ok {
		t.Fatalf("response is %T, expected an array", analysis["response"])
	}
	if len(resp) != 2 {
		t.Fatalf("response has %d members, expected 2: %v", len(resp), resp)
	}
}

func TestMixedResponsesKeepTheValidAndRelocateTheRest(t *testing.T) {
	doc := buildOrFail(t, []VEXFinding{{
		CVEID: "CVE-2025-0003", Package: "urllib3", Ecosystem: "pypi", InstalledVer: "1.26.0",
		Status: "affected", Detail: "confirmed by triage",
		Responses: []string{"will_not_fix", "the maintainer declined the backport"},
	}}, VEXOptions{})

	analysis := firstAnalysis(t, doc)
	resp, _ := analysis["response"].([]any)
	if len(resp) != 1 || resp[0] != "will_not_fix" {
		t.Errorf("the valid member did not survive alone: %v", resp)
	}
	detail, _ := analysis["detail"].(string)
	for _, want := range []string{"confirmed by triage", "declined the backport"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail lost %q; it is %q", want, detail)
		}
	}
}

// The second defect: one component per finding, so two vulnerabilities in one
// library produced two identical component objects and broke uniqueItems.
func TestComponentsAndVulnerabilitiesAreUnique(t *testing.T) {
	findings := []VEXFinding{
		{CVEID: "CVE-2025-1111", Package: "bubbletea", Ecosystem: "golang", InstalledVer: "1.3.10", Status: "affected"},
		{CVEID: "CVE-2025-2222", Package: "bubbletea", Ecosystem: "golang", InstalledVer: "1.3.10", Status: "affected"},
		{CVEID: "CVE-2025-1111", Package: "pflag", Ecosystem: "golang", InstalledVer: "1.0.5", Status: "affected"},
	}
	doc := buildOrFail(t, findings, VEXOptions{})

	comps, _ := doc["components"].([]any)
	if len(comps) != 2 {
		t.Errorf("emitted %d components for 2 distinct packages", len(comps))
	}
	assertUniqueJSON(t, "components", comps)

	vulns, _ := doc["vulnerabilities"].([]any)
	if len(vulns) != 2 {
		t.Errorf("emitted %d vulnerabilities for 2 distinct identifiers", len(vulns))
	}
	assertUniqueJSON(t, "vulnerabilities", vulns)
}

// The third defect, which the sampled documents happened not to contain: both
// previous writers emitted an analysis.state of "under_investigation", which has
// never been a member of the CycloneDX enum.
func TestUntriagedStateIsInTriage(t *testing.T) {
	for _, status := range []string{"", "under_investigation", "unknown", "pending"} {
		if got := VEXState(status); got != "in_triage" {
			t.Errorf("VEXState(%q) is %q, expected in_triage", status, got)
		}
	}
	for status, want := range map[string]string{
		"not_affected": "not_affected", "fixed": "resolved", "affected": "exploitable",
		"false_positive": "false_positive",
		// A caller already speaking CycloneDX is not translated twice.
		"resolved_with_pedigree": "resolved_with_pedigree", "in_triage": "in_triage",
	} {
		if got := VEXState(status); got != want {
			t.Errorf("VEXState(%q) is %q, expected %q", status, got, want)
		}
	}
}

// A VEX that does not say what is affected tells a consumer that something,
// somewhere, is vulnerable.
func TestVulnerabilitiesAffectTheirComponents(t *testing.T) {
	doc := buildOrFail(t, []VEXFinding{
		{CVEID: "CVE-2025-3333", Package: "bubbletea", Ecosystem: "golang", InstalledVer: "1.3.10", Status: "affected"},
		{CVEID: "CVE-2025-3333", Package: "pflag", Ecosystem: "golang", InstalledVer: "1.0.5", Status: "affected"},
	}, VEXOptions{})

	vulns, _ := doc["vulnerabilities"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("expected the shared identifier to merge into one entry, got %d", len(vulns))
	}
	v, _ := vulns[0].(map[string]any)
	affects, _ := v["affects"].([]any)
	if len(affects) != 2 {
		t.Fatalf("the merged vulnerability affects %d components, expected 2", len(affects))
	}

	// Every affects ref must resolve to a component actually in the document,
	// or a consumer follows it to nothing.
	refs := map[string]bool{}
	for _, c := range doc["components"].([]any) {
		refs[c.(map[string]any)["bom-ref"].(string)] = true
	}
	for _, a := range affects {
		ref := a.(map[string]any)["ref"].(string)
		if !refs[ref] {
			t.Errorf("affects ref %q resolves to no component", ref)
		}
	}
}

func TestDocumentCarriesItsOwnProvenance(t *testing.T) {
	doc := buildOrFail(t, []VEXFinding{{
		CVEID: "CVE-2025-4444", Package: "lodash", Ecosystem: "npm", InstalledVer: "4.17.20",
		Status: "not_affected", Justification: "code_not_reachable",
	}}, VEXOptions{ToolName: "vulnetix", ToolVersion: "v3.84.19", AuthorName: "Vulnetix"})

	serial, _ := doc["serialNumber"].(string)
	if !strings.HasPrefix(serial, "urn:uuid:") {
		t.Errorf("serialNumber is %q; a consumer cannot deduplicate without one", serial)
	}
	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		t.Fatal("the document has no metadata, so it does not say when or by what it was made")
	}
	if ts, _ := meta["timestamp"].(string); ts == "" {
		t.Error("metadata carries no timestamp")
	}
	if meta["tools"] == nil {
		t.Error("metadata names no authoring tool")
	}
	if meta["authors"] == nil {
		t.Error("metadata names no author, so nobody is asserting these claims")
	}

	// A not_affected decision without a justification is the one case the
	// specification calls out as needing one.
	if got := firstAnalysis(t, doc)["justification"]; got != "code_not_reachable" {
		t.Errorf("justification is %v, expected code_not_reachable", got)
	}
}

func TestInvalidJustificationIsDropped(t *testing.T) {
	doc := buildOrFail(t, []VEXFinding{{
		CVEID: "CVE-2025-5555", Package: "lodash", Ecosystem: "npm", InstalledVer: "4.17.20",
		Status: "not_affected", Justification: "we looked and it was fine",
	}}, VEXOptions{})
	if got, present := firstAnalysis(t, doc)["justification"]; present {
		t.Errorf("an invalid justification was emitted: %v", got)
	}
}

// BuildCDXVEX validates before returning, so a caller cannot persist a document
// that does not match the version it declares. This is the guard that was
// missing when the invalid documents shipped.
func TestBuildRefusesToReturnAnInvalidDocument(t *testing.T) {
	for _, spec := range []string{"1.5", "1.6", "1.7"} {
		if _, err := BuildCDXVEX([]VEXFinding{{
			CVEID: "CVE-2025-6666", Package: "lodash", Ecosystem: "npm",
			InstalledVer: "4.17.20", Status: "affected",
			Responses: []string{"update"},
		}}, VEXOptions{SpecVersion: spec}); err != nil {
			t.Errorf("a conformant document was rejected for CycloneDX %s: %v", spec, err)
		}
	}
}

func TestEmptyFindingsProduceAValidDocument(t *testing.T) {
	// A clean scan still has to produce something a consumer can read.
	if _, err := BuildCDXVEX(nil, VEXOptions{}); err != nil {
		t.Errorf("an empty finding set produced an invalid document: %v", err)
	}
}

// TestRealCapturedDocuments re-validates the documents the conformance suite
// actually captured, when a run directory is available on this machine. They are
// tenant scan data and are deliberately not committed here.
//
//	VEX_CAPTURE_DIR=~/GitHub/owasp-tea-conformance/reports/vulnetix/responses/cyclonedx go test ./...
func TestRealCapturedDocuments(t *testing.T) {
	dir := os.Getenv("VEX_CAPTURE_DIR")
	if dir == "" {
		t.Skip("set VEX_CAPTURE_DIR to a conformance run's cyclonedx recordings to check real captures")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(matches) == 0 {
		t.Skipf("no recordings under %s", dir)
	}

	var checked, invalid int
	for _, path := range matches {
		if strings.HasSuffix(path, ".meta.json") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		version, violations, verr := ValidateCycloneDX(raw)
		if verr != nil || version == "" {
			continue // not a CycloneDX document
		}
		checked++
		if len(violations) > 0 {
			invalid++
			t.Logf("%s declares CycloneDX %s and violates it: %s: %s",
				filepath.Base(path), version, violations[0].Path, violations[0].Message)
		}
	}
	t.Logf("checked %d captured CycloneDX documents, %d invalid", checked, invalid)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func firstAnalysis(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	vulns, _ := doc["vulnerabilities"].([]any)
	if len(vulns) == 0 {
		t.Fatal("the document declares no vulnerabilities")
	}
	v, _ := vulns[0].(map[string]any)
	a, _ := v["analysis"].(map[string]any)
	if a == nil {
		t.Fatal("the vulnerability carries no analysis")
	}
	return a
}

// assertUniqueJSON is the uniqueItems constraint the schema applies, checked
// the same way: by comparing the serialised members.
func assertUniqueJSON(t *testing.T, field string, items []any) {
	t.Helper()
	seen := map[string]int{}
	for i, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("encode %s[%d]: %v", field, i, err)
		}
		if first, dup := seen[string(encoded)]; dup {
			t.Errorf("%s[%d] is identical to %s[%d], which violates uniqueItems", field, i, field, first)
			continue
		}
		seen[string(encoded)] = i
	}
}
