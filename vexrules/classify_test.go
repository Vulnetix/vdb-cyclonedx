package vexrules

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenPath is the contract for Classify. The website copies it byte for byte
// to src/shared/vex-disposition-cases.json and runs the same cases against its
// TypeScript port. Regenerate with VEXRULES_UPDATE=1 go test ./vexrules/ and
// copy the file across in the same change.
const goldenPath = "testdata/classify-golden.json"

type goldenWant struct {
	Kind            Kind   `json:"kind"`
	Basis           Basis  `json:"basis"`
	Rule            bool   `json:"rule"`
	Active          bool   `json:"active"`
	SuppressionType string `json:"suppressionType"`
}

type goldenCase struct {
	Name string         `json:"name"`
	Raw  RawDisposition `json:"raw"`
	Want goldenWant     `json:"want"`
}

type goldenFile struct {
	Comment string       `json:"comment"`
	Cases   []goldenCase `json:"cases"`
}

const markerUUID = "5b0c2a8e-1f6e-4d3a-9c1b-7e2f4a6d8c10"

func cdx(state, just string, resp []string, props map[string]string) RawDisposition {
	return RawDisposition{Format: FormatCycloneDX, CDXState: state, CDXJustification: just, CDXResponses: resp, CDXProperties: props}
}

func ov(status, just, action, notes string) RawDisposition {
	return RawDisposition{Format: FormatOpenVEX, OpenVEXStatus: status, OpenVEXJustification: just, OpenVEXActionStatement: action, OpenVEXStatusNotes: notes}
}

func csaf(ps string, flags, rems, notes []string) RawDisposition {
	r := RawDisposition{Format: FormatCSAF, CSAFProductStatus: ps, CSAFFlags: flags, CSAFNotes: notes}
	for _, c := range rems {
		r.CSAFRemediations = append(r.CSAFRemediations, Remediation{Category: c})
	}
	return r
}

func marker(t, extra string) string {
	s := MarkerType + "=" + t + "; " + MarkerUUID + "=" + markerUUID
	if extra != "" {
		s += "; " + MarkerSource + "=" + extra
	}
	return s
}

func props(t, src string) map[string]string {
	m := map[string]string{MarkerType: t, MarkerUUID: markerUUID}
	if src != "" {
		m[MarkerSource] = src
	}
	return m
}

var (
	fp   = goldenWant{KindFalsePositive, BasisStructured, true, true, "false_positive"}
	wf   = goldenWant{KindWontFix, BasisStructured, true, true, "wont_fix"}
	wft  = goldenWant{KindWontFix, BasisText, true, false, "wont_fix"}
	tri  = goldenWant{Kind: KindTriageOnly, Basis: BasisStructured}
	conf = goldenWant{Kind: KindConflict, Basis: BasisStructured}
	und  = goldenWant{Kind: KindUndecided}
)

func mk(kind Kind, t string) goldenWant {
	return goldenWant{kind, BasisMarker, true, true, t}
}

var goldenCases = []goldenCase{
	// CycloneDX
	{"cdx false_positive", cdx("false_positive", "", nil, nil), fp},
	{"cdx false_positive ignores its justification", cdx("false_positive", "code_not_reachable", nil, nil), fp},
	{"cdx false_positive mixed case", cdx("False_Positive", "", nil, nil), fp},
	{"cdx exploitable will_not_fix", cdx("exploitable", "", []string{"will_not_fix"}, nil), wf},
	{"cdx exploitable will_not_fix with workaround", cdx("exploitable", "", []string{"will_not_fix", "workaround_available"}, nil), wf},
	{"cdx exploitable can_not_fix alone", cdx("exploitable", "", []string{"can_not_fix"}, nil), wf},
	{"cdx exploitable can_not_fix with workaround is triage", cdx("exploitable", "", []string{"can_not_fix", "workaround_available"}, nil), tri},
	{"cdx no state will_not_fix", cdx("", "", []string{"will_not_fix"}, nil), wf},
	{"cdx will_not_fix and update conflict", cdx("exploitable", "", []string{"will_not_fix", "update"}, nil), conf},
	{"cdx will_not_fix and rollback conflict", cdx("exploitable", "", []string{"will_not_fix", "rollback"}, nil), conf},
	{"cdx can_not_fix and update conflict", cdx("exploitable", "", []string{"can_not_fix", "update"}, nil), conf},
	{"cdx exploitable update is triage", cdx("exploitable", "", []string{"update"}, nil), tri},
	{"cdx bare exploitable is triage", cdx("exploitable", "", nil, nil), tri},
	{"cdx in_triage is undecided", cdx("in_triage", "", nil, nil), und},
	{"cdx in_triage with will_not_fix is undecided", cdx("in_triage", "", []string{"will_not_fix"}, nil), und},
	{"cdx not_affected is triage", cdx("not_affected", "code_not_reachable", nil, nil), tri},
	{"cdx not_affected code_not_present is triage", cdx("not_affected", "code_not_present", nil, nil), tri},
	{"cdx resolved is triage", cdx("resolved", "", nil, nil), tri},
	{"cdx resolved_with_pedigree is triage", cdx("resolved_with_pedigree", "", nil, nil), tri},
	{"cdx unknown state is undecided", cdx("ignored", "", nil, nil), und},
	{"cdx no state no response is undecided", cdx("", "", nil, nil), und},
	{"cdx marker false_positive", cdx("false_positive", "", nil, props("false_positive", "console")), mk(KindFalsePositive, "false_positive")},
	{"cdx marker wont_fix", cdx("exploitable", "", []string{"will_not_fix"}, props("wont_fix", "")), mk(KindWontFix, "wont_fix")},
	{"cdx marker risk_accepted keeps its type", cdx("exploitable", "", []string{"will_not_fix"}, props("risk_accepted", "")), mk(KindWontFix, "risk_accepted")},
	{"cdx marker mitigated", cdx("not_affected", "protected_by_mitigating_control", nil, props("mitigated", "")), mk(KindMitigated, "mitigated")},
	{"cdx marker nosec reads as false positive", cdx("false_positive", "", nil, props("nosec", "")), mk(KindFalsePositive, "nosec")},
	{"cdx marker without uuid is ignored", cdx("not_affected", "", nil, map[string]string{MarkerType: "false_positive"}), tri},
	// OpenVEX
	{"openvex not_affected component_not_present", ov("not_affected", "component_not_present", "", ""), fp},
	{"openvex not_affected vulnerable_code_not_present is triage", ov("not_affected", "vulnerable_code_not_present", "", ""), tri},
	{"openvex not_affected not_in_execute_path is triage", ov("not_affected", "vulnerable_code_not_in_execute_path", "", ""), tri},
	{"openvex not_affected inline_mitigations is triage", ov("not_affected", "inline_mitigations_already_exist", "", ""), tri},
	{"openvex not_affected no justification is triage", ov("not_affected", "", "", ""), tri},
	{"openvex affected will not fix", ov("affected", "", "Will not fix: vendor EOL", ""), wft},
	{"openvex affected won't fix curly apostrophe", ov("affected", "", "We won’t fix this in 1.x", ""), wft},
	{"openvex affected wont fix", ov("affected", "", "wont fix", ""), wft},
	{"openvex affected will not be fixed", ov("affected", "", "This will not be fixed in the 1.x line", ""), wft},
	{"openvex affected no fix planned", ov("affected", "", "No fix is planned for this release line.", ""), wft},
	{"openvex affected risk accepted", ov("affected", "", "Risk accepted by the product owner", ""), wft},
	{"openvex affected accepted the risk", ov("affected", "", "Security has accepted the risk until Q3", ""), wft},
	{"openvex affected upgrade is triage", ov("affected", "", "Upgrade to 2.4.1", ""), tri},
	{"openvex affected fix soon is triage", ov("affected", "", "A fix will ship next week", ""), tri},
	{"openvex affected empty action is triage", ov("affected", "", "", ""), tri},
	{"openvex fixed is triage", ov("fixed", "", "", ""), tri},
	{"openvex under_investigation is undecided", ov("under_investigation", "", "", ""), und},
	{"openvex uppercase status", ov("NOT_AFFECTED", "component_not_present", "", ""), fp},
	{"openvex marker false_positive", ov("not_affected", "vulnerable_code_not_present", "", marker("false_positive", "vex")), mk(KindFalsePositive, "false_positive")},
	{"openvex marker wont_fix", ov("affected", "", "Will not fix: legacy", marker("wont_fix", "")), mk(KindWontFix, "wont_fix")},
	{"openvex unrelated status notes", ov("not_affected", "vulnerable_code_not_present", "", "Reviewed by the platform team"), tri},
	// CSAF
	{"csaf known_not_affected component_not_present", csaf("known_not_affected", []string{"component_not_present"}, nil, nil), fp},
	{"csaf known_not_affected other flag is triage", csaf("known_not_affected", []string{"vulnerable_code_not_in_execute_path"}, nil, nil), tri},
	{"csaf known_not_affected no flag is triage", csaf("known_not_affected", nil, nil, nil), tri},
	{"csaf known_affected no_fix_planned", csaf("known_affected", nil, []string{"no_fix_planned"}, nil), wf},
	{"csaf no_fix_planned with workaround", csaf("known_affected", nil, []string{"no_fix_planned", "workaround"}, nil), wf},
	{"csaf no_fix_planned with vendor_fix conflict", csaf("known_affected", nil, []string{"no_fix_planned", "vendor_fix"}, nil), conf},
	{"csaf none_available alone", csaf("known_affected", nil, []string{"none_available"}, nil), wf},
	{"csaf none_available with mitigation is triage", csaf("known_affected", nil, []string{"none_available", "mitigation"}, nil), tri},
	{"csaf none_available with vendor_fix is triage", csaf("known_affected", nil, []string{"none_available", "vendor_fix"}, nil), tri},
	{"csaf known_affected vendor_fix is triage", csaf("known_affected", nil, []string{"vendor_fix"}, nil), tri},
	{"csaf fixed is triage", csaf("fixed", nil, nil, nil), tri},
	{"csaf first_fixed is triage", csaf("first_fixed", nil, nil, nil), tri},
	{"csaf under_investigation is undecided", csaf("under_investigation", nil, nil, nil), und},
	{"csaf marker", csaf("known_affected", nil, []string{"no_fix_planned"}, []string{marker("wont_fix", "")}), mk(KindWontFix, "wont_fix")},
}

func TestClassifyGolden(t *testing.T) {
	for _, c := range goldenCases {
		d := Classify(Statement{Raw: c.Raw})
		got := goldenWant{d.Kind, d.Basis, d.Rule, d.Active, d.SuppressionType}
		if got != c.Want {
			t.Errorf("%s: got %+v, want %+v (%s)", c.Name, got, c.Want, d.Reason)
		}
		if d.Reason == "" {
			t.Errorf("%s: no reason", c.Name)
		}
	}
}

func TestGoldenFileMatchesTable(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(goldenFile{
		Comment: "Contract for vexrules.Classify (vdb-cyclonedx). Pinned byte for byte by website src/shared/vex-disposition-cases.json. Change both together.",
		Cases:   goldenCases,
	}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("VEXRULES_UPDATE") == "1" {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(filepath.Clean(goldenPath))
	if err != nil {
		t.Fatalf("%v: run VEXRULES_UPDATE=1 go test ./vexrules/", err)
	}
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("%s is stale: run VEXRULES_UPDATE=1 go test ./vexrules/ and copy it to website src/shared/vex-disposition-cases.json", goldenPath)
	}
}

func TestEncodeSuppressionRoundTrips(t *testing.T) {
	for _, typ := range []string{"false_positive", "wont_fix", "risk_accepted", "deferred", "mitigated", "nosec", "rego_rule"} {
		m := Marker{Type: typ, UUID: markerUUID, Source: "console"}
		enc := EncodeSuppression(m, "vendor EOL")
		want := KindForSuppressionType(typ)
		raws := []RawDisposition{
			{Format: FormatCycloneDX, CDXState: enc.CDXState, CDXJustification: enc.CDXJustification, CDXResponses: enc.CDXResponses, CDXProperties: m.Properties()},
			{Format: FormatOpenVEX, OpenVEXStatus: enc.OpenVEXStatus, OpenVEXJustification: enc.OpenVEXJustification, OpenVEXActionStatement: enc.OpenVEXAction, OpenVEXStatusNotes: m.EncodeText()},
		}
		for _, raw := range raws {
			d := Classify(Statement{Raw: raw})
			if d.Kind != want || d.Basis != BasisMarker || d.Marker == nil || d.Marker.UUID != markerUUID || d.SuppressionType != typ {
				t.Errorf("%s/%s: round trip gave %+v", typ, raw.Format, d)
			}
			// Without the marker the encoded fields still classify as the
			// same kind for false positives and won't fix, so a consumer that
			// strips properties still reads the decision.
			raw.CDXProperties, raw.OpenVEXStatusNotes = nil, ""
			bare := Classify(Statement{Raw: raw})
			if want == KindWontFix && raw.Format == FormatCycloneDX && bare.Kind != KindWontFix {
				t.Errorf("%s/%s: bare encoding gave %s", typ, raw.Format, bare.Kind)
			}
			if want == KindFalsePositive && raw.Format == FormatCycloneDX && bare.Kind != KindFalsePositive {
				t.Errorf("%s/%s: bare encoding gave %s", typ, raw.Format, bare.Kind)
			}
		}
	}
}
