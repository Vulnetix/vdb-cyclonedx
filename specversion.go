package cyclonedx

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ── Spec-version projection ──────────────────────────────────────────────────
//
// BOM authoring metadata is not one fixed shape. `metadata.manufacturer`
// arrived in 1.6, `metadata.lifecycles` in 1.5, and the object form of
// `metadata.tools` in 1.5 — and from 1.4 onward `metadata` carries
// "additionalProperties": false, so a member the declared version does not know
// about is a hard validation failure rather than a harmless extra.
//
// That is why authorship belongs here rather than in each caller. The CLI emits
// VEX at 1.5 and SCA documents at 1.6/1.7 from the same authorship decision; if
// every caller had to know which members its version could carry, one of them
// would eventually get it wrong and emit a document that fails its own schema.

// CompareSpecVersions orders two CycloneDX spec versions numerically, returning
// -1, 0 or 1. An unparseable version sorts lowest, so an unknown value is
// treated conservatively rather than being assumed modern.
func CompareSpecVersions(a, b string) int {
	as, bs := parseSpecVersion(a), parseSpecVersion(b)
	for i := 0; i < 2; i++ {
		switch {
		case as[i] < bs[i]:
			return -1
		case as[i] > bs[i]:
			return 1
		}
	}
	return 0
}

func parseSpecVersion(v string) [2]int {
	major, minor, _ := strings.Cut(strings.TrimSpace(v), ".")
	out := [2]int{-1, -1}
	if n, err := strconv.Atoi(major); err == nil {
		out[0] = n
		out[1] = 0
	}
	if n, err := strconv.Atoi(minor); err == nil {
		out[1] = n
	}
	return out
}

func specAtLeast(v, floor string) bool { return CompareSpecVersions(v, floor) >= 0 }

// AuthorshipSupport reports which BOM-authoring members a spec version accepts.
//
// The values come from the bundled schemas, and specversion_test.go asserts
// them back against those files rather than against a second hand-written
// table — so refreshing the schema bundle cannot silently desync this.
type AuthorshipSupport struct {
	Lifecycles     bool // 1.5+
	ToolsObject    bool // 1.5+; below this metadata.tools is an array of `tool`
	Manufacturer   bool // 1.6+
	Manufacture    bool // 1.2–1.7, removed in 2.0
	MetadataProps  bool // 1.3+
	StrictMetadata bool // 1.4+ ("additionalProperties": false)
}

// AuthorshipSupportFor answers what the named spec version can carry. An
// unrecognised version is treated as the oldest supported one.
func AuthorshipSupportFor(specVersion string) AuthorshipSupport {
	return AuthorshipSupport{
		Lifecycles:     specAtLeast(specVersion, "1.5"),
		ToolsObject:    specAtLeast(specVersion, "1.5"),
		Manufacturer:   specAtLeast(specVersion, "1.6"),
		Manufacture:    !specAtLeast(specVersion, "2.0"),
		MetadataProps:  specAtLeast(specVersion, "1.3"),
		StrictMetadata: specAtLeast(specVersion, "1.4"),
	}
}

// Downgrade records one member the target spec version could not carry. Path is
// a JSON Pointer into the document that was asked for, not the one emitted.
type Downgrade struct {
	Path   string
	Reason string
}

// legacyTool is metadata.tools[] as CycloneDX 1.2–1.4 defines it. The object
// form did not exist yet, and those versions close `metadata`, so a document
// declaring 1.4 with an object-shaped tools block does not validate.
type legacyTool struct {
	Vendor             string              `json:"vendor,omitempty"`
	Name               string              `json:"name,omitempty"`
	Version            string              `json:"version,omitempty"`
	Hashes             []Hash              `json:"hashes,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
}

// projectToSpecVersion returns a copy of d carrying only the authoring members
// its declared specVersion accepts, plus the list of what was dropped or
// reshaped. It is applied on every marshal as a last line of defence: a caller
// that sets a manufacturer and then emits at 1.5 gets a valid 1.5 document,
// not a validation error at the far end of a pipeline.
func (d Document) projectToSpecVersion() (Document, []Downgrade) {
	// The document root is closed in every version from 1.4, so the format
	// member has to carry exactly the one name its version declares.
	if specAtLeast(d.SpecVersion, "2.0") {
		d.SpecFormat = firstNonEmpty(d.SpecFormat, d.BOMFormat, "CycloneDX")
		d.BOMFormat = ""
	} else {
		d.BOMFormat = firstNonEmpty(d.BOMFormat, d.SpecFormat, "CycloneDX")
		d.SpecFormat = ""
	}

	if d.Metadata == nil {
		return d, nil
	}
	support := AuthorshipSupportFor(d.SpecVersion)
	if support.Lifecycles && support.ToolsObject && support.Manufacturer && support.Manufacture {
		return d, nil
	}

	var downgrades []Downgrade
	meta := *d.Metadata // shallow copy; every field we touch is replaced, not mutated

	if !support.Manufacturer && meta.Manufacturer != nil {
		downgrades = append(downgrades, Downgrade{
			Path:   "/metadata/manufacturer",
			Reason: "metadata.manufacturer requires CycloneDX 1.6 or later",
		})
		meta.Manufacturer = nil
	}
	if !support.Manufacture && meta.Manufacture != nil {
		downgrades = append(downgrades, Downgrade{
			Path:   "/metadata/manufacture",
			Reason: "metadata.manufacture was removed in CycloneDX 2.0",
		})
		meta.Manufacture = nil
	}
	if !support.Lifecycles && len(meta.Lifecycles) > 0 {
		downgrades = append(downgrades, Downgrade{
			Path:   "/metadata/lifecycles",
			Reason: "metadata.lifecycles requires CycloneDX 1.5 or later",
		})
		meta.Lifecycles = nil
	}
	if !support.MetadataProps && len(meta.Properties) > 0 {
		downgrades = append(downgrades, Downgrade{
			Path:   "/metadata/properties",
			Reason: "metadata.properties requires CycloneDX 1.3 or later",
		})
		meta.Properties = nil
	}
	if !support.ToolsObject && meta.Tools != nil {
		raw, err := json.Marshal(legacyToolsFrom(meta.Tools))
		if err == nil {
			// The legacy shape is an array where the model declares an object,
			// so it travels as an extra member: Tools is cleared (omitempty
			// keeps it out) and "tools" is spliced back in on marshal.
			extra := make(map[string]json.RawMessage, len(meta.Extra)+1)
			for k, v := range meta.Extra {
				extra[k] = v
			}
			extra["tools"] = raw
			meta.Extra = extra
			meta.Tools = nil
			downgrades = append(downgrades, Downgrade{
				Path:   "/metadata/tools",
				Reason: "CycloneDX below 1.5 requires the legacy metadata.tools array",
			})
		}
	}

	d.Metadata = &meta
	return d, downgrades
}

// legacyToolsFrom flattens tool components into the pre-1.5 array shape. Vendor
// has no direct equivalent on a component, so it comes from group, falling back
// to publisher — the two fields that actually carry "who makes this tool".
func legacyToolsFrom(t *Tools) []legacyTool {
	out := make([]legacyTool, 0, len(t.Components))
	for _, c := range t.Components {
		vendor := c.Group
		if vendor == "" {
			vendor = c.Publisher
		}
		out = append(out, legacyTool{
			Vendor:             vendor,
			Name:               c.Name,
			Version:            c.Version,
			Hashes:             c.Hashes,
			ExternalReferences: c.ExternalReferences,
		})
	}
	return out
}

// UnmarshalJSON accepts both shapes metadata.tools has had: the 1.2–1.4 array
// of `tool` objects and the 1.5+ {components, services} object. A reader that
// only understands one of them sees an empty tool table for half the documents
// in the wild, and reports "unknown" for a producer the document names plainly.
func (t *Tools) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if trimmed[0] == '[' {
		var legacy []legacyTool
		if err := json.Unmarshal(b, &legacy); err != nil {
			return err
		}
		t.Components = make([]Component, 0, len(legacy))
		for _, l := range legacy {
			t.Components = append(t.Components, Component{
				Type:               "application",
				Name:               l.Name,
				Version:            l.Version,
				Group:              l.Vendor,
				Hashes:             l.Hashes,
				ExternalReferences: l.ExternalReferences,
			})
		}
		return nil
	}
	type toolsShadow Tools
	return json.Unmarshal(b, (*toolsShadow)(t))
}

// DefaultSpecVersion is the CycloneDX version this module emits unless a caller
// asks for another. It tracks the newest version the builders are known to
// produce valid output for, not simply the newest bundled schema.
const DefaultSpecVersion = "1.7"
