package euaiact

// The context-coverage matrix found AiFirewallEnforcingGuardrails and
// AiFirewallGuardrailsByType loaded and read by nothing, while the Article 9
// evidence said "N guardrails constrain model use at the gateway" from the
// enabled count alone. A guardrail set to flag observes; only block and redact
// constrain, so an observing gateway read like an enforcing one.

import (
	"strings"
	"testing"
)

func riskManagementEvidence(t *testing.T, ctx ReportContext) string {
	t.Helper()
	var b strings.Builder
	for _, m := range MapReport(ctx) {
		for _, e := range m.Evidence {
			b.WriteString(e.Component)
			b.WriteString(" | ")
			b.WriteString(e.Detail)
			b.WriteString("\n")
		}
	}

	return b.String()
}

func TestGuardrailEvidenceSeparatesEnforcingFromEnabled(t *testing.T) {
	ctx := ReportContext{}
	ctx.AiFirewallConfigured = true
	ctx.AiFirewallGuardrailCount = 9
	ctx.AiFirewallEnforcingGuardrails = 4
	ctx.AiFirewallGuardrailsByType = map[string]int{"blocked_pattern": 4, "max_messages": 5}
	ctx.ScannerRunCount = 12
	ctx.HasTriagePolicy = true
	ctx.FindingTotal = 40

	got := riskManagementEvidence(t, ctx)
	if !strings.Contains(got, "4 guardrails block or redact") {
		t.Errorf("the evidence does not separate enforcing guardrails from enabled ones:\n%s", got)
	}
	if !strings.Contains(got, "blocked_pattern x4") {
		t.Errorf("the evidence does not say what kind of constraint is in force:\n%s", got)
	}
}

func TestGuardrailEvidenceSaysObservingWhenNoneEnforce(t *testing.T) {
	ctx := ReportContext{}
	ctx.AiFirewallConfigured = true
	ctx.AiFirewallGuardrailCount = 9
	ctx.ScannerRunCount = 12
	ctx.HasTriagePolicy = true
	ctx.FindingTotal = 40

	got := riskManagementEvidence(t, ctx)
	// Both places that describe the gateway must say it, or neutering one
	// leaves the other passing this test for it — the F-193 lesson.
	if !strings.Contains(got, "are enabled but none blocks or redacts") {
		t.Errorf("the runtime-measures evidence still reads as constraining model use:\n%s", got)
	}
	if !strings.Contains(got, "none of which blocks or redacts") {
		t.Errorf("the human-oversight evidence still reads as constraining model use:\n%s", got)
	}
}
