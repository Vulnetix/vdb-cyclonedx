package cyclonedx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The document model covers the part of CycloneDX these tools reason about,
// which is not all of it. This test is the guarantee that the difference is
// invisible: a document read in and written back out keeps every member it
// arrived with, including the ones nothing here understands.
//
// It is the precondition for the CLI aliasing its own model onto this one. If
// it fails, the shared model is narrowing documents, and the parallel map-based
// implementations it replaced were right to exist.

// kitchenSink carries at least one unmodelled member at each level the model
// declares an Extra map for, plus several the schemas define but this module
// deliberately does not interpret.
const kitchenSink = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 3,
  "metadata": {
    "timestamp": "2026-01-02T03:04:05Z",
    "lifecycles": [{"phase": "post-build"}],
    "manufacturer": {"name": "Acme Corp", "url": ["https://acme.example"]},
    "tools": {"components": [{"type": "application", "name": "syft", "version": "1.2.3"}]},
    "component": {"type": "application", "name": "subject", "version": "0.1.0"},
    "unmodelledMetadataMember": {"kept": true}
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/left-pad@1.0.0",
      "name": "left-pad",
      "version": "1.0.0",
      "evidence": {"identity": [{"field": "purl", "confidence": 0.9}]},
      "pedigree": {"notes": "vendored"},
      "swid": {"tagId": "swid-1", "name": "left-pad"}
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2026-0001",
      "cwes": [79],
      "published": "2026-01-01T00:00:00Z",
      "ratings": [{"severity": "high", "method": "CVSSv31", "score": 8.1}]
    }
  ],
  "dependencies": [{"ref": "pkg:npm/left-pad@1.0.0"}],
  "compositions": [{"aggregate": "complete"}],
  "annotations": [{"bom-ref": "ann-1", "text": "reviewed"}],
  "formulation": [{"bom-ref": "form-1"}],
  "declarations": {"assessors": [{"bom-ref": "assessor-1"}]},
  "signature": {"algorithm": "ES256", "value": "AAAA"}
}`

func semanticJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("re-decode: %v\n%s", err, b)
	}
	return out
}

func TestDocumentRoundTripPreservesUnmodelledMembers(t *testing.T) {
	var doc Document
	if err := json.Unmarshal([]byte(kitchenSink), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := semanticJSON(t, []byte(kitchenSink))
	got := semanticJSON(t, out)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip lost or altered members\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDocumentRoundTripIsByteStable(t *testing.T) {
	// Callers digest these bytes — vulnetix:bom/source-digest and the BOM corpus
	// index both key on content — so map iteration order must not reach output.
	var doc Document
	if err := json.Unmarshal([]byte(kitchenSink), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	first, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 25; i++ {
		next, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal %d: %v", i, err)
		}
		if string(next) != string(first) {
			t.Fatalf("marshal is not deterministic\nfirst: %s\nthen:  %s", first, next)
		}
	}
}

func TestDocumentRoundTripRealFixtures(t *testing.T) {
	// The CLI's fixtures are documents this module did not write — the shape
	// that matters, because a document we authored round-trips trivially.
	paths, _ := filepath.Glob("../cli/internal/bom/testdata/*.cdx.json")
	if len(paths) == 0 {
		t.Skip("sibling cli checkout not present")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var doc Document
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			out, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			want, got := semanticJSON(t, raw), semanticJSON(t, out)
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("round trip altered %s", path)
			}
		})
	}
}

func TestLegacyToolsArrayIsReadAndUpgraded(t *testing.T) {
	// A 1.4 document names its producer in an array. Reading only the 1.5+
	// object shape reports "unknown" for a tool the document states plainly.
	const legacy = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.4",
	  "metadata": {"tools": [{"vendor": "Anchore", "name": "syft", "version": "0.9.0"}]}
	}`
	var doc Document
	if err := json.Unmarshal([]byte(legacy), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Metadata == nil || doc.Metadata.Tools == nil || len(doc.Metadata.Tools.Components) != 1 {
		t.Fatalf("legacy tools array not read: %#v", doc.Metadata)
	}
	got := doc.Metadata.Tools.Components[0]
	if got.Name != "syft" || got.Version != "0.9.0" || got.Group != "Anchore" {
		t.Fatalf("legacy tool mapped wrong: %#v", got)
	}
}

func TestMarshalProjectsAwayMembersTheSpecVersionCannotCarry(t *testing.T) {
	base := Document{
		BOMFormat: "CycloneDX",
		Metadata: &Metadata{
			Manufacturer: &OrganizationalEntity{Name: "Acme Corp"},
			Lifecycles:   []Lifecycle{{Phase: string(PhasePostBuild)}},
			Tools:        &Tools{Components: []Component{{Type: "application", Name: "vulnetix-cdx", Version: "3.98.0", Group: "Vulnetix"}}},
		},
	}

	cases := []struct {
		specVersion       string
		wantManufacturer  bool
		wantLifecycles    bool
		wantToolsAsObject bool
	}{
		{"1.4", false, false, false},
		{"1.5", false, true, true},
		{"1.6", true, true, true},
		{"1.7", true, true, true},
		{"2.0", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.specVersion, func(t *testing.T) {
			doc := base
			meta := *base.Metadata
			doc.Metadata = &meta
			doc.SpecVersion = tc.specVersion

			out, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded struct {
				Metadata map[string]json.RawMessage `json:"metadata"`
			}
			if err := json.Unmarshal(out, &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, has := decoded.Metadata["manufacturer"]; has != tc.wantManufacturer {
				t.Errorf("manufacturer present=%v, want %v", has, tc.wantManufacturer)
			}
			if _, has := decoded.Metadata["lifecycles"]; has != tc.wantLifecycles {
				t.Errorf("lifecycles present=%v, want %v", has, tc.wantLifecycles)
			}
			tools := decoded.Metadata["tools"]
			if len(tools) == 0 {
				t.Fatalf("tools dropped entirely at %s", tc.specVersion)
			}
			isObject := tools[0] == '{'
			if isObject != tc.wantToolsAsObject {
				t.Errorf("tools object=%v, want %v: %s", isObject, tc.wantToolsAsObject, tools)
			}
			// Whichever shape it took, the producer must still be named.
			if !hasSubstring(string(tools), "vulnetix-cdx") {
				t.Errorf("tool name lost in projection: %s", tools)
			}
		})
	}
}

func hasSubstring(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// The projection must also survive an unrelated round trip: emitting at 1.4
// then reading it back must still name the producer.
func TestLegacyProjectionRoundTrips(t *testing.T) {
	doc := Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Metadata: &Metadata{
			Tools: &Tools{Components: []Component{{Type: "application", Name: "vulnetix-sca", Version: "3.98.0", Group: "Vulnetix"}}},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Document
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Metadata == nil || back.Metadata.Tools == nil || len(back.Metadata.Tools.Components) != 1 {
		t.Fatalf("producer lost across 1.4 projection: %s", out)
	}
	if got := back.Metadata.Tools.Components[0]; got.Name != "vulnetix-sca" || got.Group != "Vulnetix" {
		t.Fatalf("producer altered across 1.4 projection: %#v", got)
	}
}
