package vexrules

import (
	"regexp"
	"strings"
)

// Kind is what a statement means for suppression.
type Kind string

const (
	// KindFalsePositive: the scanner was wrong. Becomes a rule.
	KindFalsePositive Kind = "false_positive"
	// KindWontFix: the finding is real and the owner has decided not to act.
	// Becomes a rule.
	KindWontFix Kind = "wont_fix"
	// KindMitigated is only produced from a Vulnetix marker for a mitigated
	// rule. A third-party "protected by a control" statement is triage only.
	KindMitigated Kind = "mitigated"
	// KindTriageOnly: a real decision that is not a suppression (not affected,
	// fixed, affected). Written to Triage as evidence.
	KindTriageOnly Kind = "triage_only"
	// KindConflict: the statement says two incompatible things (will not fix
	// and update). No rule; flagged on the triage evidence.
	KindConflict Kind = "conflict"
	// KindUndecided: in triage or under investigation. No rule.
	KindUndecided Kind = "undecided"
)

// Basis is how the classifier reached its verdict.
type Basis string

const (
	// BasisStructured: an enumerated field in the format says it.
	BasisStructured Basis = "structured"
	// BasisText: only prose says it (OpenVEX action_statement). A rule on this
	// basis starts inactive and waits for review.
	BasisText Basis = "text"
	// BasisMarker: a Vulnetix marker names the rule.
	BasisMarker Basis = "marker"
)

// Disposition is the classifier's verdict on one statement.
type Disposition struct {
	Kind  Kind  `json:"kind"`
	Basis Basis `json:"basis,omitempty"`
	// Rule reports whether the statement becomes a suppression rule.
	Rule bool `json:"rule"`
	// Active reports whether that rule is live as soon as it is written. A
	// text-basis rule is not: it waits in the review queue.
	Active bool `json:"active"`
	// SuppressionType is the Suppression.suppressionType for the rule.
	SuppressionType string `json:"suppressionType,omitempty"`
	// Reason says, in a sentence, what in the document led here.
	Reason string `json:"reason"`
	// Marker is set when the statement carries a Vulnetix marker.
	Marker *Marker `json:"marker,omitempty"`
}

// wontFixPhrase matches the ways an OpenVEX action_statement says "won't fix".
// Curly apostrophes are folded to straight ones before matching.
var wontFixPhrase = regexp.MustCompile(`(?i)\b(will\s+not|won't|wont)\s+(be\s+)?fix(ed)?\b|\bno\s+fix\s+(is\s+)?planned\b|\bfix\s+(is\s+)?not\s+planned\b|\brisk\s+accepted\b|\baccept(ed|ing)?\s+(the\s+)?risk\b`)

// WontFixPhrase reports whether text says the owner will not fix.
func WontFixPhrase(text string) bool {
	t := strings.NewReplacer("’", "'", "‘", "'").Replace(text)
	return wontFixPhrase.MatchString(t)
}

// Classify decides what a statement means for suppression. It is a pure
// function of the statement's raw fields; the golden cases in
// testdata/classify-golden.json are the contract (pinned byte for byte by the
// website's src/shared/vex-disposition-cases.json).
func Classify(s Statement) Disposition {
	if m := DecodeMarker(s.Raw); m.Valid() {
		kind := KindForSuppressionType(m.Type)
		mm := m
		return Disposition{
			Kind:            kind,
			Basis:           BasisMarker,
			Rule:            true,
			Active:          true,
			SuppressionType: m.Type,
			Reason:          "Minted by Vulnetix for suppression rule " + m.UUID,
			Marker:          &mm,
		}
	}
	switch s.Raw.Format {
	case FormatCycloneDX:
		return classifyCDX(s.Raw)
	case FormatOpenVEX:
		return classifyOpenVEX(s.Raw)
	case FormatCSAF:
		return classifyCSAF(s.Raw)
	}
	return Disposition{Kind: KindUndecided, Reason: "Unknown VEX format"}
}

func lowerSet(vals []string) map[string]bool {
	out := make(map[string]bool, len(vals))
	for _, v := range vals {
		out[strings.ToLower(strings.TrimSpace(v))] = true
	}
	return out
}

func falsePositive(basis Basis, reason string) Disposition {
	return Disposition{Kind: KindFalsePositive, Basis: basis, Rule: true, Active: basis != BasisText, SuppressionType: "false_positive", Reason: reason}
}

func wontFix(basis Basis, reason string) Disposition {
	return Disposition{Kind: KindWontFix, Basis: basis, Rule: true, Active: basis != BasisText, SuppressionType: "wont_fix", Reason: reason}
}

func triageOnly(reason string) Disposition {
	return Disposition{Kind: KindTriageOnly, Basis: BasisStructured, Reason: reason}
}

func classifyCDX(r RawDisposition) Disposition {
	state := strings.ToLower(strings.TrimSpace(r.CDXState))
	resp := lowerSet(r.CDXResponses)
	willNot := resp["will_not_fix"]
	canNot := resp["can_not_fix"]
	fixing := resp["update"] || resp["rollback"]

	switch state {
	case "false_positive":
		return falsePositive(BasisStructured, "CycloneDX analysis state is false_positive")
	case "in_triage":
		return Disposition{Kind: KindUndecided, Reason: "CycloneDX analysis state is in_triage, so no decision has been made"}
	case "not_affected":
		return triageOnly("CycloneDX analysis state is not_affected")
	case "resolved", "resolved_with_pedigree":
		return triageOnly("CycloneDX analysis state is " + state)
	case "exploitable", "":
	default:
		return Disposition{Kind: KindUndecided, Reason: "CycloneDX analysis state " + state + " is not in the specification"}
	}

	// exploitable (or a response with no state): the responses decide.
	if (willNot || canNot) && fixing {
		return Disposition{Kind: KindConflict, Basis: BasisStructured, Reason: "CycloneDX responses say both that it will not be fixed and that it will be updated or rolled back"}
	}
	if willNot {
		return wontFix(BasisStructured, "CycloneDX response is will_not_fix")
	}
	if canNot && !resp["workaround_available"] {
		return wontFix(BasisStructured, "CycloneDX response is can_not_fix, with no workaround offered")
	}
	if state == "" {
		return Disposition{Kind: KindUndecided, Reason: "CycloneDX analysis has no state"}
	}
	return triageOnly("CycloneDX analysis state is exploitable")
}

func classifyOpenVEX(r RawDisposition) Disposition {
	status := strings.ToLower(strings.TrimSpace(r.OpenVEXStatus))
	just := strings.ToLower(strings.TrimSpace(r.OpenVEXJustification))
	switch status {
	case "not_affected":
		if just == "component_not_present" {
			return falsePositive(BasisStructured, "OpenVEX not_affected with justification component_not_present: the reported component is not in the product")
		}
		return triageOnly("OpenVEX not_affected" + suffix(just))
	case "affected":
		if WontFixPhrase(r.OpenVEXActionStatement) {
			return wontFix(BasisText, "OpenVEX affected, and the action statement says it will not be fixed")
		}
		return triageOnly("OpenVEX affected")
	case "fixed":
		return triageOnly("OpenVEX fixed")
	case "under_investigation":
		return Disposition{Kind: KindUndecided, Reason: "OpenVEX under_investigation"}
	}
	return Disposition{Kind: KindUndecided, Reason: "OpenVEX status " + status + " is not in the specification"}
}

func suffix(j string) string {
	if j == "" {
		return ""
	}
	return " (" + j + ")"
}

func classifyCSAF(r RawDisposition) Disposition {
	flags := lowerSet(r.CSAFFlags)
	cats := map[string]bool{}
	for _, rem := range r.CSAFRemediations {
		cats[strings.ToLower(strings.TrimSpace(rem.Category))] = true
	}
	switch strings.ToLower(r.CSAFProductStatus) {
	case "known_not_affected":
		if flags["component_not_present"] {
			return falsePositive(BasisStructured, "CSAF known_not_affected with flag component_not_present")
		}
		return triageOnly("CSAF known_not_affected")
	case "known_affected":
		if cats["no_fix_planned"] && cats["vendor_fix"] {
			return Disposition{Kind: KindConflict, Basis: BasisStructured, Reason: "CSAF remediations offer a vendor fix and also say no fix is planned"}
		}
		if cats["no_fix_planned"] {
			return wontFix(BasisStructured, "CSAF remediation category is no_fix_planned")
		}
		if cats["none_available"] && !cats["vendor_fix"] && !cats["workaround"] && !cats["mitigation"] {
			return wontFix(BasisStructured, "CSAF remediation category is none_available, with no fix, workaround or mitigation")
		}
		return triageOnly("CSAF known_affected")
	case "fixed", "first_fixed":
		return triageOnly("CSAF " + r.CSAFProductStatus)
	case "under_investigation":
		return Disposition{Kind: KindUndecided, Reason: "CSAF under_investigation"}
	}
	return Disposition{Kind: KindUndecided, Reason: "CSAF product status " + r.CSAFProductStatus + " is not in the specification"}
}
