package cyclonedx

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

// errWriter fails every write, so an encoder error propagates to the caller.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// minimalEmitDoc is the smallest document that validates: root format and
// spec version, plus a metadata component to carry a purl.
func minimalEmitDoc() *Document {
	return &Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000017",
		Version:      1,
		Metadata: &Metadata{
			Component: &Component{
				Type:    "application",
				Name:    "app",
				Version: "1.0.0",
				Purl:    "pkg:generic/app@1.0.0",
			},
		},
	}
}

func TestWriteJSON_MatchesMarshalIndent(t *testing.T) {
	doc := minimalEmitDoc()
	var buf bytes.Buffer
	if err := doc.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	want, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	want = append(want, '\n') // Encode appends a trailing newline
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("WriteJSON output diverges from MarshalIndent:\n%s", buf.Bytes())
	}
}

// SetEscapeHTML(false) is what keeps the encoder's compaction from rewriting
// bytes inside members spliced in from Extra: json.Marshal inside MarshalJSON
// escapes <, > and & in declared fields, but Extra values travel as raw JSON and
// must reach the output verbatim. A default encoder would turn them into \u0026
// escapes, changing the bytes a digest of the document keys on.
func TestWriteJSON_DoesNotHTMLEscape(t *testing.T) {
	doc := minimalEmitDoc()
	doc.Extra = map[string]json.RawMessage{
		"vulnetix:test/url": json.RawMessage(`{"purl":"pkg:npm/lodash@4.17.21?a=1&b=2","note":"<raw>"}`),
	}
	var buf bytes.Buffer
	if err := doc.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()
	for _, s := range []string{"pkg:npm/lodash@4.17.21?a=1&b=2", "<raw>"} {
		if !strings.Contains(out, s) {
			t.Errorf("expected verbatim %q in output:\n%s", s, out)
		}
	}
}

func TestMarshalValidatedJSON_ValidDocument(t *testing.T) {
	doc := minimalEmitDoc()
	validated, err := doc.MarshalValidatedJSON()
	if err != nil {
		t.Fatalf("MarshalValidatedJSON on a valid document: %v", err)
	}
	var buf bytes.Buffer
	if err := doc.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !bytes.Equal(validated, buf.Bytes()) {
		t.Fatalf("MarshalValidatedJSON differs from WriteJSON:\n%q\n%q", validated, buf.Bytes())
	}
	version, violations, err := ValidateCycloneDX(validated)
	if err != nil {
		t.Fatalf("revalidation: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) != 0 {
		t.Fatalf("validated output has %d violations: %+v", len(violations), violations)
	}
}

// The write-time schema guard must reject a document whose analysis state is
// outside the schema enum, and must produce no output when it does.
func TestMarshalValidatedJSON_RejectsInvalidEnum(t *testing.T) {
	doc := minimalEmitDoc()
	doc.Vulnerabilities = []Vulnerability{{
		ID: "CVE-2024-0001",
		Analysis: &Analysis{
			State: "resolved_tomorrow", // not in impactAnalysisState enum
		},
	}}
	out, err := doc.MarshalValidatedJSON()
	if err == nil {
		t.Fatal("expected schema validation error for invalid analysis state, got nil")
	}
	if out != nil {
		t.Fatalf("expected no output on validation failure, got %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "schema validation") {
		t.Fatalf("expected schema validation failure, got %v", err)
	}
}

// A document whose Extra carries malformed raw JSON must fail validation rather
// than be returned as a BOM a downstream consumer would reject.
func TestMarshalValidatedJSON_RejectsMalformedOutput(t *testing.T) {
	doc := minimalEmitDoc()
	doc.Extra = map[string]json.RawMessage{"broken": json.RawMessage(`{"x":`)}
	out, err := doc.MarshalValidatedJSON()
	if err == nil {
		t.Fatal("expected error for malformed marshalled output, got nil")
	}
	if out != nil {
		t.Fatalf("expected no output, got %d bytes", len(out))
	}
}

// An unencodable value inside a declared field makes the encoder fail before
// any byte is written, so MarshalValidatedJSON must surface that error too.
func TestMarshalValidatedJSON_PropagatesEncodeError(t *testing.T) {
	doc := minimalEmitDoc()
	doc.Metadata.Component = &Component{
		Type: "application",
		Name: "app",
	}
	severity := math.NaN() // encoding/json rejects NaN
	doc.Vulnerabilities = []Vulnerability{{
		ID:      "CVE-2024-0001",
		Ratings: []Rating{{Score: &severity, Severity: "high"}},
	}}
	out, err := doc.MarshalValidatedJSON()
	if err == nil {
		t.Fatal("expected encode error for NaN score, got nil")
	}
	if out != nil {
		t.Fatalf("expected no output on encode failure, got %d bytes", len(out))
	}
}

func TestWriteJSON_PropagatesWriterError(t *testing.T) {
	doc := minimalEmitDoc()
	err := doc.WriteJSON(errWriter{})
	if err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("WriteJSON: got %v, want the writer's error", err)
	}
}
