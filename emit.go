package cyclonedx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ── Emitting a document ──────────────────────────────────────────────────────
//
// These two methods live here rather than with their callers because Go forbids
// defining a method on an alias to a type from another package, and the alias is
// what lets a consumer adopt this model without rewriting every call site it
// already has.

// MarshalValidatedJSON serialises the document to indented JSON and validates
// the result against the CycloneDX schema for its declared specVersion.
//
// It returns an error *without producing output* when the document does not
// validate, so a caller never persists a BOM that downstream consumers would
// reject. This is the write-time guard that turns a generator regression — an
// invalid analysis enum, a member the declared version cannot carry — into an
// immediate local failure rather than a support ticket from whoever read it.
func (d *Document) MarshalValidatedJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := d.WriteJSON(&buf); err != nil {
		return nil, err
	}
	version, violations, err := ValidateCycloneDX(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("validating generated CycloneDX BOM: %w", err)
	}
	if len(violations) > 0 {
		return nil, fmt.Errorf("generated CycloneDX %s BOM failed schema validation (%d issue(s)); first: %s — %s",
			version, len(violations), violations[0].Path, violations[0].Message)
	}
	return buf.Bytes(), nil
}

// WriteJSON writes the document as indented JSON. HTML escaping is off because
// purls and URLs routinely contain characters the encoder would otherwise
// escape, producing bytes that differ from every other CycloneDX producer's for
// no gain.
func (d *Document) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(d)
}
