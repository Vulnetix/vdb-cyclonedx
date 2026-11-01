package vexrules

import (
	"strings"
)

// Markers let a VEX document Vulnetix minted say which suppression rule it came
// from. When the document comes back (a CLI passes it to --vex-file, a
// customer re-uploads it), the marker links the statement to that rule instead
// of creating a second one. Without it, every mint would breed a duplicate rule
// on the next ingest.
//
// CycloneDX carries markers as vulnerability properties. OpenVEX has no
// extension field, so they ride in status_notes, which the spec defines as free
// text; CSAF carries them in a vulnerability note titled "vulnetix:suppression".
// The textual form is "key=value" pairs separated by "; ".
const (
	markerPrefix    = "vulnetix:suppression/"
	markerNoteTitle = "vulnetix:suppression"

	MarkerType   = markerPrefix + "type"
	MarkerUUID   = markerPrefix + "uuid"
	MarkerSource = markerPrefix + "source"
)

// Marker is the decoded marker of one statement.
type Marker struct {
	// Type is the Suppression.suppressionType the rule had.
	Type string `json:"type"`
	// UUID is the Suppression.uuid. The engine links only when the uuid
	// belongs to the ingesting org.
	UUID string `json:"uuid"`
	// Source is the rule's sourceKind (console, cli, nosec, vex, bulk).
	Source string `json:"source,omitempty"`
}

// Valid reports whether the marker names a rule.
func (m Marker) Valid() bool { return m.UUID != "" && m.Type != "" }

// EncodeText renders the marker for OpenVEX status_notes and CSAF notes.
func (m Marker) EncodeText() string {
	parts := []string{MarkerType + "=" + m.Type, MarkerUUID + "=" + m.UUID}
	if m.Source != "" {
		parts = append(parts, MarkerSource+"="+m.Source)
	}
	return strings.Join(parts, "; ")
}

// Properties renders the marker as CycloneDX vulnerability properties.
func (m Marker) Properties() map[string]string {
	out := map[string]string{MarkerType: m.Type, MarkerUUID: m.UUID}
	if m.Source != "" {
		out[MarkerSource] = m.Source
	}
	return out
}

// DecodeMarker reads a marker from whichever field the statement's format uses.
func DecodeMarker(raw RawDisposition) Marker {
	switch raw.Format {
	case FormatCycloneDX:
		return Marker{
			Type:   strings.TrimSpace(raw.CDXProperties[MarkerType]),
			UUID:   strings.TrimSpace(raw.CDXProperties[MarkerUUID]),
			Source: strings.TrimSpace(raw.CDXProperties[MarkerSource]),
		}
	case FormatOpenVEX:
		return decodeMarkerText(raw.OpenVEXStatusNotes)
	case FormatCSAF:
		for _, n := range raw.CSAFNotes {
			if m := decodeMarkerText(n); m.Valid() {
				return m
			}
		}
	}
	return Marker{}
}

func decodeMarkerText(s string) Marker {
	var m Marker
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case MarkerType:
			m.Type = strings.TrimSpace(v)
		case MarkerUUID:
			m.UUID = strings.TrimSpace(v)
		case MarkerSource:
			m.Source = strings.TrimSpace(v)
		}
	}
	return m
}

// KindForSuppressionType maps a Suppression.suppressionType onto the
// disposition a VEX statement about it expresses. false_positive, nosec and
// rego_rule say the finding is not real; mitigated says it is real but
// protected; wont_fix, risk_accepted and deferred say it is real and the owner
// has chosen not to act.
func KindForSuppressionType(t string) Kind {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "false_positive", "nosec", "rego_rule":
		return KindFalsePositive
	case "mitigated":
		return KindMitigated
	default:
		return KindWontFix
	}
}

// VEXEncoding is how one suppression is written in each format.
type VEXEncoding struct {
	CDXState             string
	CDXJustification     string
	CDXResponses         []string
	OpenVEXStatus        string
	OpenVEXJustification string
	OpenVEXAction        string
	CSAFProductStatus    string
	CSAFRemediation      string
	CSAFFlag             string
	Marker               Marker
}

// EncodeSuppression returns the VEX fields for a statement minted because the
// rule applied. Classify on the result returns the same kind, which the golden
// round-trip cases check.
func EncodeSuppression(m Marker, reason string) VEXEncoding {
	enc := VEXEncoding{Marker: m}
	switch KindForSuppressionType(m.Type) {
	case KindFalsePositive:
		enc.CDXState = "false_positive"
		enc.OpenVEXStatus = "not_affected"
		enc.OpenVEXJustification = "vulnerable_code_not_present"
		enc.CSAFProductStatus = "known_not_affected"
		enc.CSAFFlag = "vulnerable_code_not_present"
	case KindMitigated:
		enc.CDXState = "not_affected"
		enc.CDXJustification = "protected_by_mitigating_control"
		enc.OpenVEXStatus = "not_affected"
		enc.OpenVEXJustification = "inline_mitigations_already_exist"
		enc.CSAFProductStatus = "known_not_affected"
		enc.CSAFFlag = "inline_mitigations_already_exist"
	default:
		enc.CDXState = "exploitable"
		enc.CDXResponses = []string{"will_not_fix"}
		enc.OpenVEXStatus = "affected"
		action := "Will not fix"
		if r := strings.TrimSpace(reason); r != "" {
			action += ": " + r
		}
		enc.OpenVEXAction = action
		enc.CSAFProductStatus = "known_affected"
		enc.CSAFRemediation = "no_fix_planned"
	}
	return enc
}
