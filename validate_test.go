package cyclonedx

import (
	"fmt"
	"strings"
	"testing"
)

const resolvedResponseBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "vulnerabilities": [
    {"id": "CVE-2024-0001", "analysis": {"state": "resolved", "response": ["update"], "detail": "fixed by upgrade"}}
  ]
}`

const justificationUpdateBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "vulnerabilities": [
    {"id": "CVE-2024-0001", "analysis": {"state": "resolved", "justification": "update", "detail": "fixed by upgrade"}}
  ]
}`

// TestValidateCycloneDX_ResolvedResponseIsValid is the positive side of the
// generator fix: state=resolved with response=["update"] must validate clean.
func TestValidateCycloneDX_ResolvedResponseIsValid(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(resolvedResponseBOM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got %+v", violations)
	}
}

// TestValidateCycloneDX_JustificationUpdateRejected reproduces the original bug:
// "update" in analysis.justification must be rejected (it is a response value).
func TestValidateCycloneDX_JustificationUpdateRejected(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(justificationUpdateBOM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) == 0 {
		t.Fatal("expected violations for invalid justification, got none")
	}
	joined := ""
	for _, v := range violations {
		joined += v.Path + " " + v.Message + "\n"
	}
	if !strings.Contains(joined, "justification") {
		t.Errorf("expected a justification violation, got:\n%s", joined)
	}
}

func TestValidateCycloneDX_NonCycloneDXIsPassthrough(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "" || len(violations) != 0 {
		t.Errorf("non-CycloneDX should return empty version and no violations, got version=%q violations=%+v", version, violations)
	}
}

func TestValidateCycloneDX_UnsupportedVersion(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"9.9","version":1}`
	version, violations, err := ValidateCycloneDX([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "9.9" {
		t.Errorf("version = %q, want 9.9", version)
	}
	if len(violations) != 1 || violations[0].Path != "/specVersion" {
		t.Fatalf("expected one /specVersion violation, got %+v", violations)
	}
}

func TestSupportedVersionsOrdering(t *testing.T) {
	desc := SupportedVersions()
	if desc[0] != "2.0" || desc[len(desc)-1] != "1.2" {
		t.Errorf("SupportedVersions should be highest-first, got %v", desc)
	}
	asc := SupportedVersionsAscending()
	if asc[0] != "1.2" || asc[len(asc)-1] != "2.0" {
		t.Errorf("SupportedVersionsAscending should be lowest-first, got %v", asc)
	}
}

// TestValidateCycloneDX_MalformedJSONIsFatal pins the contract that malformed
// JSON is a fatal error (doc comment at validate.go:52), not a version="" pass.
func TestValidateCycloneDX_MalformedJSONIsFatal(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte("{not json"))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error message %q should contain \"invalid JSON\"", err.Error())
	}
	if version != "" {
		t.Errorf("version = %q, want empty on fatal error", version)
	}
	if violations != nil {
		t.Errorf("violations = %+v, want nil on fatal error", violations)
	}
}

// TestValidateCycloneDX_ViolationListTruncatesAt25 pins the contract that the
// violation list is bounded at 25 leaves with a truncation marker appended
// (validate.go:96-120). The 1.7 schema requires "type" on every component, so
// 30 components that each omit it yield 30 leaf violations and overshoot the
// bound; distinct names keep the array-items-unique check quiet.
func TestValidateCycloneDX_ViolationListTruncatesAt25(t *testing.T) {
	var components strings.Builder
	for i := 0; i < 30; i++ {
		if i > 0 {
			components.WriteByte(',')
		}
		fmt.Fprintf(&components, `{"name":"component%d"}`, i)
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[` + components.String() + `]}`
	version, violations, err := ValidateCycloneDX([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) != 26 {
		t.Fatalf("len(violations) = %d, want 26 (25 leaves + truncation marker)", len(violations))
	}
	if !strings.Contains(violations[25].Message, "additional violations truncated") {
		t.Errorf("violations[25].Message = %q, want truncation marker", violations[25].Message)
	}
}
