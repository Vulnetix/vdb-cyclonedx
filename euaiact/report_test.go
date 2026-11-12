package euaiact

import (
	"strings"
	"testing"
)

func richReportCtx() ReportContext {
	return ReportContext{
		OrgName: "acme", PeriodStart: 1, PeriodEnd: 2,
		Components: []Component{
			{Type: "machine-learning-model", Category: "model", Name: "gpt-4o", Provider: "OpenAI", Family: "GPT", Task: "chat", EvidenceCount: 1},
			{Category: "accelerator", Name: "gpu", EvidenceCount: 1},
			{Type: "data", Category: "data", Name: "pvc:train", DataKind: "dataset", DataSource: "pvc", EvidenceCount: 1},
		},
		AibomScanCount: 12, LatestAibomScanUUID: "scan-uuid", PriorScanCount: 12,
		FindingTotal: 40000, FindingByCategory: map[string]int{"sca": 5900, "sast": 29000},
		TriagedTotal: 38000, AffectedTotal: 1300, NotAffectedTotal: 311, FixedTotal: 20,
		OpenVexCount: 850, SuppressionCount: 3,
		ScannerRunCount: 1594, IngestionSnapshotCount: 1594, HasEvaluation: true,
		CycloneDXCount: 378, AccessLogCount: 3084,
		AiFirewallConfigured: true, AiFirewallLogsEnabled: true,
		AiFirewallGuardrailCount: 3, AiFirewallGuardrailsByType: map[string]int{"blocked_pattern": 1, "pii_redact": 2},
		AiFirewallEnforcingGuardrails: 2, AiFirewallProviderPolicyCount: 1, AiFirewallModelPolicyCount: 2,
		AiFirewallRequestCount: 500, AiFirewallBlockCount: 12, AiFirewallRedactCount: 5, AiFirewallFlagCount: 3,
	}
}

func findRep(ms []ArticleMapping, article string) *ArticleMapping {
	for i := range ms {
		if ms[i].Article == article {
			return &ms[i]
		}
	}
	return nil
}

func TestReportArt15NowSatisfiable(t *testing.T) {
	// Per-scan Art 15 is not-evidenceable; report-level it becomes satisfiable.
	//
	// Scanner runs and findings are no longer enough on their own: the article
	// names accuracy, robustness and cybersecurity, and security telemetry
	// speaks to two of the three (F-044). The fixture therefore carries
	// evaluation tooling from the AI-BOM, which is the machine record of the
	// accuracy half; without it the correct answer is partial, asserted in
	// accuracy_evidence_test.go.
	ctx := richReportCtx()
	ctx.Components = append(ctx.Components, Component{
		Name: "ragas", Category: "evaluation", Provider: "explodinggradients",
	})
	a15 := findRep(MapReport(ctx), "Article 15")
	if a15 == nil || a15.Status != StatusSatisfied {
		t.Fatalf("Art 15 report = %+v", a15)
	}
	// evidence must carry links
	linked := false
	for _, e := range a15.Evidence {
		if e.Link != "" {
			linked = true
		}
	}
	if !linked {
		t.Error("Art 15 evidence has no links")
	}
}

func TestReportArt12FromAccessLogs(t *testing.T) {
	a12 := findRep(MapReport(richReportCtx()), "Article 12")
	if a12.Status != StatusSatisfied {
		t.Errorf("Art 12 report = %s, want satisfied", a12.Status)
	}
}

func TestReportGapVsNotApplicable(t *testing.T) {
	empty := ReportContext{OrgName: "x"}
	ms := MapReport(empty)
	// Art 12 with no logs/scans/inventory → gap (evaluated, none found)
	if findRep(ms, "Article 12").Status != StatusGap {
		t.Errorf("empty Art 12 should be gap")
	}
	// Art 13 → informational (not evaluable), distinct from gap.
	//
	// This asserted not-applicable, which claims the obligation is out of
	// scope. It is not: Article 13 applies to every provider, and what is
	// missing is the document. Informational says "no basis to judge", which is
	// what the data supports, and it is what Articles 5 and 6 return for the
	// same reason. The distinction this test exists to protect — an
	// unevaluable article must not read as a gap — still holds.
	a13 := findRep(ms, "Article 13")
	if a13.Status != StatusInformational {
		t.Errorf("Art 13 should be informational, got %s", a13.Status)
	}
	if a13.Rationale == "" {
		t.Error("Art 13 not-applicable needs a rationale")
	}
}

func TestReportArt72Monitoring(t *testing.T) {
	if findRep(MapReport(richReportCtx()), "Article 72").Status != StatusSatisfied {
		t.Error("repeated snapshots should satisfy Art 72")
	}
	single := ReportContext{IngestionSnapshotCount: 1, ScannerRunCount: 1}
	if findRep(MapReport(single), "Article 72").Status != StatusGap {
		t.Error("single record Art 72 should be gap")
	}
}

func TestReportArt15FirewallDowngrade(t *testing.T) {
	// Models inventoried but no runtime gateway → satisfied downgrades to
	// partial with an explicit gap line.
	ctx := richReportCtx()
	ctx.AiFirewallConfigured = false
	ctx.AiFirewallLogsEnabled = false
	ctx.AiFirewallGuardrailCount = 0
	ctx.AiFirewallRequestCount = 0
	a15 := findRep(MapReport(ctx), "Article 15")
	if a15.Status != StatusPartial {
		t.Fatalf("Art 15 without firewall over inventoried models = %s, want partial", a15.Status)
	}
	if len(a15.Gaps) == 0 {
		t.Error("Art 15 downgrade should state the runtime-controls gap")
	}
	// No AI inventory at all → firewall absence must NOT downgrade. It still
	// reads partial, but for the accuracy gap rather than the runtime-controls
	// one: with no inventory there is no evaluation tooling either, and an
	// organisation with no AI systems has evidenced no accuracy (F-044). What
	// this asserts is that the *reason* changed — the missing firewall is not
	// held against an organisation that runs no models.
	ctx.Components = nil
	a15 = findRep(MapReport(ctx), "Article 15")
	for _, g := range a15.Gaps {
		if strings.Contains(g, "runtime input/output controls") {
			t.Errorf("missing firewall is still held against an org with no inventoried models: %q", g)
		}
	}
	if len(a15.Gaps) != 1 || !strings.Contains(a15.Gaps[0], "accuracy") {
		t.Errorf("Art 15 without an inventory should carry exactly the accuracy gap, got %v", a15.Gaps)
	}
}

func TestReportArt12FirewallLoggingDisabled(t *testing.T) {
	ctx := richReportCtx()
	ctx.AiFirewallLogsEnabled = false
	ctx.AiFirewallRequestCount = 0
	a12 := findRep(MapReport(ctx), "Article 12")
	if a12.Status != StatusSatisfied {
		t.Fatalf("Art 12 = %s", a12.Status)
	}
	found := false
	for _, g := range a12.Gaps {
		if g == "AI gateway configured but inference logging is disabled — runtime AI events are not recorded" {
			found = true
		}
	}
	if !found {
		t.Errorf("Art 12 should flag disabled inference logging: %v", a12.Gaps)
	}
	// With logging on, gateway logs must appear as evidence with a link.
	a12 = findRep(MapReport(richReportCtx()), "Article 12")
	linked := false
	for _, e := range a12.Evidence {
		if e.Link == routeAiFirewall {
			linked = true
		}
	}
	if !linked {
		t.Errorf("Art 12 should cite gateway inference logs: %+v", a12.Evidence)
	}
}

func TestReportArt14GuardrailsRescueGap(t *testing.T) {
	// Only guardrails — no agents, no human review → partial, not gap.
	ctx := ReportContext{AiFirewallConfigured: true, AiFirewallGuardrailCount: 2}
	a14 := findRep(MapReport(ctx), "Article 14")
	if a14.Status != StatusPartial {
		t.Fatalf("Art 14 with only guardrails = %s, want partial", a14.Status)
	}
	// Agents without any gateway → gap line about unguarded agents.
	ctx = ReportContext{Components: []Component{{Category: "agent", Name: "bot", EvidenceCount: 1}}}
	a14 = findRep(MapReport(ctx), "Article 14")
	found := false
	for _, g := range a14.Gaps {
		if g == "Detected autonomous agents have no runtime gateway/guardrails" {
			found = true
		}
	}
	if !found {
		t.Errorf("Art 14 should flag unguarded agents: %v", a14.Gaps)
	}
}

func TestReportEvidenceItemLink(t *testing.T) {
	a14 := findRep(MapReport(richReportCtx()), "Article 14")
	hasFindingsLink := false
	for _, e := range a14.Evidence {
		if e.Link == "/resolve/findings" {
			hasFindingsLink = true
		}
	}
	if !hasFindingsLink {
		t.Errorf("Art 14 should link human triage to /resolve/findings: %+v", a14.Evidence)
	}
}

func TestSnapshotRollupAutoResolvedTotal(t *testing.T) {
	s := SnapshotRollup{ReportedResolved: 3, DisappearedResolved: 5, ResolvedByPolicy: 7, Outcomes: 100}
	if got := s.AutoResolvedTotal(); got != 15 {
		t.Fatalf("AutoResolvedTotal = %d, want 15 (reported + disappeared + policy only)", got)
	}
	if got := (SnapshotRollup{}).AutoResolvedTotal(); got != 0 {
		t.Fatalf("zero rollup AutoResolvedTotal = %d, want 0", got)
	}
}

func TestQualityGateBlockEnabled(t *testing.T) {
	c := ReportContext{QualityGateBlocks: []string{"blockOnCritical", "blockOnSecrets"}}
	cases := map[string]bool{"blockOnCritical": true, "blockOnSecrets": true, "blockOnLicense": false, "": false, "blockoncritical": false}
	for name, want := range cases {
		if got := c.QualityGateBlockEnabled(name); got != want {
			t.Errorf("QualityGateBlockEnabled(%q) = %v, want %v", name, got, want)
		}
	}
	if (ReportContext{}).QualityGateBlockEnabled("blockOnCritical") {
		t.Error("no blocks configured must report every gate off")
	}
}

func TestScannerCategoryHelpers(t *testing.T) {
	c := ReportContext{
		// Free-text ScannerRun.category.
		ScannerRunByCategory: map[string]int{"iac": 4, "cloud": 0},
		// Strict IngestionSnapshot.category enum.
		SnapshotByCategory: map[string]int{"iac": 9, "cloud": 2, "oci": 6},
		FindingByCategory:  map[string]int{"iac": 10, "cloud": 5, "infra": 1},
	}

	t.Run("HasScannerCategory", func(t *testing.T) {
		cases := []struct {
			names []string
			want  bool
		}{
			{[]string{"iac"}, true},         // run count
			{[]string{"oci"}, true},         // snapshot enum only
			{[]string{"cloud"}, true},       // zero run count, snapshot present
			{[]string{"sast"}, false},       // neither
			{[]string{"sast", "oci"}, true}, // any alias matches
			{[]string{"sast", "dast"}, false},
			{nil, false},
		}
		for _, tc := range cases {
			if got := c.HasScannerCategory(tc.names...); got != tc.want {
				t.Errorf("HasScannerCategory(%v) = %v, want %v", tc.names, got, tc.want)
			}
		}
	})

	t.Run("FindingCategoryCount", func(t *testing.T) {
		if got := c.FindingCategoryCount("iac", "infra", "cloud"); got != 16 {
			t.Errorf("FindingCategoryCount(iac, infra, cloud) = %d, want 16", got)
		}
		if got := c.FindingCategoryCount("iac"); got != 10 {
			t.Errorf("FindingCategoryCount(iac) = %d, want 10", got)
		}
		if got := c.FindingCategoryCount("sast"); got != 0 {
			t.Errorf("FindingCategoryCount(sast) = %d, want 0", got)
		}
		if got := c.FindingCategoryCount(); got != 0 {
			t.Errorf("FindingCategoryCount() = %d, want 0", got)
		}
	})

	t.Run("ScannerCategoryRuns", func(t *testing.T) {
		cases := []struct {
			names []string
			want  int
		}{
			// A non-zero run count wins; the snapshot count is not added on top.
			{[]string{"iac"}, 4},
			// A zero run count falls back to the snapshot count.
			{[]string{"cloud"}, 2},
			{[]string{"oci"}, 6},
			{[]string{"iac", "cloud", "oci"}, 12},
			{[]string{"sast"}, 0},
			{nil, 0},
		}
		for _, tc := range cases {
			if got := c.ScannerCategoryRuns(tc.names...); got != tc.want {
				t.Errorf("ScannerCategoryRuns(%v) = %d, want %d", tc.names, got, tc.want)
			}
		}
	})
}

func TestItoa64MatchesItoa(t *testing.T) {
	for _, n := range []int64{0, 1, -1, 9, 10, 1234567, -987654, 1 << 40} {
		if got, want := itoa64(n), itoa(int(n)); got != want {
			t.Errorf("itoa64(%d) = %q, itoa = %q", n, got, want)
		}
	}
	if got := itoa64(-42); got != "-42" {
		t.Errorf("itoa64(-42) = %q, want \"-42\"", got)
	}
}

func TestSummarizeReportEqualsSummarizeArticles(t *testing.T) {
	for _, ms := range [][]ArticleMapping{nil, MapReport(ReportContext{}), MapReport(richReportCtx())} {
		if got, want := SummarizeReport(ms), SummarizeArticles(ms); got != want {
			t.Errorf("SummarizeReport = %+v, SummarizeArticles = %+v", got, want)
		}
	}
}

func TestLoadFailuresAndDataIntegrityNote(t *testing.T) {
	var c ReportContext
	if got := c.DataIntegrityNote(); got != "" {
		t.Fatalf("DataIntegrityNote with nothing failed = %q, want empty", got)
	}
	c.NoteLoadFailure("Suppression")
	c.NoteLoadFailure("Alert")
	c.NoteLoadFailure("Suppression")
	if want := []string{"Suppression", "Alert"}; strings.Join(c.LoadFailures, "|") != strings.Join(want, "|") {
		t.Fatalf("LoadFailures = %v, want %v (deduplicated, first-seen order)", c.LoadFailures, want)
	}
	want := "INCOMPLETE DATA: Suppression, Alert could not be read when this report was generated. " +
		"Counts drawn from those sources are zero because the data is missing, not because nothing was found, " +
		"so any conclusion resting on them is unsupported."
	if got := c.DataIntegrityNote(); got != want {
		t.Fatalf("DataIntegrityNote =\n%q\nwant\n%q", got, want)
	}
}

func TestReachabilitySampleLocation(t *testing.T) {
	cases := []struct {
		name string
		s    ReachabilitySample
		want string
	}{
		{"no location", ReachabilitySample{CveID: "CVE-2024-0001", StartLine: 12}, ""},
		{"file only", ReachabilitySample{File: "main.go"}, "main.go"},
		{"start line only", ReachabilitySample{File: "main.go", StartLine: 12}, "main.go:12"},
		{"start and end", ReachabilitySample{File: "main.go", StartLine: 12, EndLine: 20}, "main.go:12-20"},
		{"end equal to start", ReachabilitySample{File: "main.go", StartLine: 12, EndLine: 12}, "main.go:12"},
		{"end before start", ReachabilitySample{File: "main.go", StartLine: 12, EndLine: 3}, "main.go:12"},
		{"routine only", ReachabilitySample{Routine: "parse"}, "parse"},
		{"routine with lines, no file", ReachabilitySample{Routine: "parse", StartLine: 7}, ":7 (parse)"},
		{"all parts", ReachabilitySample{File: "pkg/x.go", Routine: "Decode", StartLine: 5, EndLine: 9}, "pkg/x.go:5-9 (Decode)"},
	}
	for _, tc := range cases {
		if got := tc.s.Location(); got != tc.want {
			t.Errorf("%s: Location() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
