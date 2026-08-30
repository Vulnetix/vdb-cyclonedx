package cyclonedx

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// ── Lossless round-tripping ──────────────────────────────────────────────────
//
// CycloneDX is large and this module models the part of it these tools reason
// about. That is a reasonable scope for a reader; it is not a licence to
// *narrow* a document on the way through. A tool that reads someone else's BOM
// to add a property, apply a VEX statement or stamp a deployment label has no
// business dropping the `signature`, `compositions`, `formulation`,
// `declarations` or `annotations` blocks it does not understand.
//
// Before this file the only way to avoid that was to not use the model at all:
// the CLI carried a second, map-based implementation of deployment labelling
// for exactly this reason, with a comment saying that decoding into the typed
// model "would silently drop every field the internal model does not declare".
// Two implementations of one operation is the cost of a lossy model, and it is
// the more expensive of the two costs.
//
// So Document, Metadata, Component and Vulnerability each carry an Extra map
// holding every member they did not declare, and re-emit it on marshal.
//
// Emission order is deterministic — declared fields in struct order, then extra
// members sorted by name — because callers digest these bytes:
// `vulnetix:bom/source-digest` and the BOM corpus index both key on content,
// and a map-ordered tail would make the same document hash differently on
// consecutive runs.

var jsonFieldCache sync.Map // reflect.Type -> map[string]bool

// declaredJSONNames returns the set of JSON member names a struct type claims,
// so unmarshalWithExtra can tell an unmodelled member from a modelled one.
func declaredJSONNames(t reflect.Type) map[string]bool {
	if cached, ok := jsonFieldCache.Load(t); ok {
		return cached.(map[string]bool)
	}
	names := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		names[name] = true
	}
	jsonFieldCache.Store(t, names)
	return names
}

// unmarshalWithExtra decodes b into shadow — which must be a pointer to a type
// with the same JSON tags as the outer type but no custom UnmarshalJSON, or the
// decode recurses forever — and collects every member shadow does not declare
// into extra.
func unmarshalWithExtra(b []byte, shadow any, extra *map[string]json.RawMessage) error {
	if err := json.Unmarshal(b, shadow); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	declared := declaredJSONNames(reflect.TypeOf(shadow).Elem())
	var rest map[string]json.RawMessage
	for name, value := range raw {
		if declared[name] {
			continue
		}
		if rest == nil {
			rest = make(map[string]json.RawMessage, len(raw)-len(declared))
		}
		rest[name] = value
	}
	*extra = rest
	return nil
}

// marshalWithExtra marshals shadow and splices extra's members onto the end of
// the object, sorted by name so the bytes are stable across runs.
func marshalWithExtra(shadow any, extra map[string]json.RawMessage) ([]byte, error) {
	base, err := json.Marshal(shadow)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return base, nil
	}
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)

	trimmed := bytes.TrimSpace(base)
	// A shadow that marshalled to something other than an object has nowhere to
	// splice into; emit it unchanged rather than producing invalid JSON.
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return base, nil
	}
	var buf bytes.Buffer
	buf.Grow(len(trimmed) + 64*len(names))
	buf.Write(trimmed[:len(trimmed)-1])
	if len(trimmed) > 2 { // not "{}"
		buf.WriteByte(',')
	}
	for i, name := range names {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(name)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(extra[name])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// ── Document ─────────────────────────────────────────────────────────────────

type documentShadow Document

// UnmarshalJSON decodes a document, retaining unmodelled members in Extra.
func (d *Document) UnmarshalJSON(b []byte) error {
	if err := unmarshalWithExtra(b, (*documentShadow)(d), &d.Extra); err != nil {
		return err
	}
	// 2.0 spells it specFormat; everything before spells it bomFormat. Both
	// populate BOMFormat so a reader never has to ask which vintage it has.
	if d.BOMFormat == "" {
		d.BOMFormat = d.SpecFormat
	}
	return nil
}

// MarshalJSON emits the document, re-emitting unmodelled members from Extra and
// projecting away members the declared specVersion cannot carry.
func (d Document) MarshalJSON() ([]byte, error) {
	projected, _ := d.projectToSpecVersion()
	return marshalWithExtra(documentShadow(projected), projected.Extra)
}

// ── Metadata ─────────────────────────────────────────────────────────────────

type metadataShadow Metadata

func (m *Metadata) UnmarshalJSON(b []byte) error {
	if err := unmarshalWithExtra(b, (*metadataShadow)(m), &m.Extra); err != nil {
		return err
	}
	// `manufacture` is the deprecated spelling, superseded by
	// metadata.component.manufacturer. Reading it into the modern location keeps
	// a consumer from having to know which vintage produced the document; the
	// original stays put so a round-trip does not move it.
	if m.Manufacture != nil && m.Component != nil && m.Component.Manufacturer == nil {
		m.Component.Manufacturer = m.Manufacture
	}
	return nil
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(metadataShadow(m), m.Extra)
}

// ── Component ────────────────────────────────────────────────────────────────

type componentShadow Component

func (c *Component) UnmarshalJSON(b []byte) error {
	return unmarshalWithExtra(b, (*componentShadow)(c), &c.Extra)
}

func (c Component) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(componentShadow(c), c.Extra)
}

// ── Vulnerability ────────────────────────────────────────────────────────────

type vulnerabilityShadow Vulnerability

func (v *Vulnerability) UnmarshalJSON(b []byte) error {
	return unmarshalWithExtra(b, (*vulnerabilityShadow)(v), &v.Extra)
}

func (v Vulnerability) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(vulnerabilityShadow(v), v.Extra)
}
