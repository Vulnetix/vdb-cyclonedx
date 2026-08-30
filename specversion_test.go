package cyclonedx

import (
	"encoding/json"
	"fmt"
	"testing"
)

// AuthorshipSupportFor is a table, and a table can drift from what it describes.
// This asserts it back against the bundled schemas themselves, so refreshing the
// schema bundle either agrees with the table or fails here — rather than
// producing documents that fail validation at whatever consumer reads them.
func TestAuthorshipSupportMatchesTheBundledSchemas(t *testing.T) {
	for _, spec := range SupportedVersionsAscending() {
		t.Run(spec, func(t *testing.T) {
			props := metadataPropertiesFromSchema(t, spec)
			got := AuthorshipSupportFor(spec)

			if _, declared := props["manufacturer"]; declared != got.Manufacturer {
				t.Errorf("Manufacturer: schema declares=%v, table says=%v", declared, got.Manufacturer)
			}
			if _, declared := props["manufacture"]; declared != got.Manufacture {
				t.Errorf("Manufacture: schema declares=%v, table says=%v", declared, got.Manufacture)
			}
			if _, declared := props["lifecycles"]; declared != got.Lifecycles {
				t.Errorf("Lifecycles: schema declares=%v, table says=%v", declared, got.Lifecycles)
			}
			if _, declared := props["properties"]; declared != got.MetadataProps {
				t.Errorf("MetadataProps: schema declares=%v, table says=%v", declared, got.MetadataProps)
			}
			if declared := schemaToolsAcceptsObject(t, props["tools"]); declared != got.ToolsObject {
				t.Errorf("ToolsObject: schema accepts=%v, table says=%v", declared, got.ToolsObject)
			}
			if declared := schemaMetadataIsClosed(t, spec); declared != got.StrictMetadata {
				t.Errorf("StrictMetadata: schema closes metadata=%v, table says=%v", declared, got.StrictMetadata)
			}
		})
	}
}

// metadataPropertiesFromSchema reads the metadata property set out of a bundled
// schema. 1.x keeps definitions under `definitions`; 2.0 splits them across
// per-area `$defs` bundles, so the lookup has to handle both layouts.
func metadataPropertiesFromSchema(t *testing.T, specVersion string) map[string]json.RawMessage {
	t.Helper()
	node := metadataSchemaNode(t, specVersion)
	var shape struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(node, &shape); err != nil {
		t.Fatalf("%s: decode metadata properties: %v", specVersion, err)
	}
	return shape.Properties
}

func schemaMetadataIsClosed(t *testing.T, specVersion string) bool {
	t.Helper()
	var shape struct {
		AdditionalProperties *bool `json:"additionalProperties"`
	}
	if err := json.Unmarshal(metadataSchemaNode(t, specVersion), &shape); err != nil {
		t.Fatalf("%s: decode additionalProperties: %v", specVersion, err)
	}
	return shape.AdditionalProperties != nil && !*shape.AdditionalProperties
}

func metadataSchemaNode(t *testing.T, specVersion string) json.RawMessage {
	t.Helper()
	path, ok := supportedSpecVersions[specVersion]
	if !ok {
		t.Fatalf("no bundled schema for %s", specVersion)
	}
	raw, err := schemaFS.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var root struct {
		Definitions map[string]json.RawMessage `json:"definitions"`
		Defs        map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if node, ok := root.Definitions["metadata"]; ok {
		return node
	}
	// 2.0 layout: $defs/cyclonedx-metadata-<version>/$defs/metadata
	for _, bundle := range root.Defs {
		var inner struct {
			Defs map[string]json.RawMessage `json:"$defs"`
		}
		if err := json.Unmarshal(bundle, &inner); err != nil {
			continue
		}
		if node, ok := inner.Defs["metadata"]; ok {
			return node
		}
	}
	t.Fatalf("%s: no metadata definition found in %s", specVersion, path)
	return nil
}

// schemaToolsAcceptsObject reports whether the schema's metadata.tools accepts
// the {components, services} object form, as opposed to only the legacy array.
func schemaToolsAcceptsObject(t *testing.T, toolsSchema json.RawMessage) bool {
	t.Helper()
	if len(toolsSchema) == 0 {
		t.Fatal("schema declares no metadata.tools")
	}
	var shape struct {
		Type  string            `json:"type"`
		OneOf []json.RawMessage `json:"oneOf"`
	}
	if err := json.Unmarshal(toolsSchema, &shape); err != nil {
		t.Fatalf("decode tools schema: %v", err)
	}
	if shape.Type == "object" {
		return true
	}
	for _, branch := range shape.OneOf {
		var b struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(branch, &b); err == nil && b.Type == "object" {
			return true
		}
	}
	return false
}

func TestCompareSpecVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.5", "1.6", -1},
		{"1.6", "1.5", 1},
		{"1.6", "1.6", 0},
		{"1.7", "2.0", -1},
		{"2.0", "1.7", 1},
		{"1.10", "1.9", 1}, // numeric, not lexical
		{"", "1.2", -1},    // unparseable sorts lowest, so unknown is treated conservatively
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_vs_%s", tc.a, tc.b), func(t *testing.T) {
			if got := CompareSpecVersions(tc.a, tc.b); got != tc.want {
				t.Errorf("CompareSpecVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// CycloneDX 2.0 renamed bomFormat to specFormat and closes the document root,
// so a builder that always wrote bomFormat could not produce a valid 2.0
// document at all — even though the 2.0 schema was bundled and selectable.
func TestDocumentRootFormatMemberFollowsSpecVersion(t *testing.T) {
	for _, tc := range []struct{ spec, want, absent string }{
		{"1.7", "bomFormat", "specFormat"},
		{"2.0", "specFormat", "bomFormat"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			data, err := json.Marshal(Document{BOMFormat: "CycloneDX", SpecVersion: tc.spec})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var root map[string]json.RawMessage
			if err := json.Unmarshal(data, &root); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, ok := root[tc.want]; !ok {
				t.Errorf("%s missing at %s: %s", tc.want, tc.spec, data)
			}
			if _, ok := root[tc.absent]; ok {
				t.Errorf("%s present at %s: %s", tc.absent, tc.spec, data)
			}
		})
	}
}
