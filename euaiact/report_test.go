package euaiact

import "testing"

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
	// Per-scan Art 15 is not-evidenceable; report-level with scanner runs +
	// findings it becomes satisfied.
	a15 := findRep(MapReport(richReportCtx()), "Article 15")
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
	// Art 13 → not-applicable (not evaluable), distinct from gap
	a13 := findRep(ms, "Article 13")
	if a13.Status != StatusNotApplicable {
		t.Errorf("Art 13 should be not-applicable, got %s", a13.Status)
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

func TestReportEvidenceItemLink(t *testing.T) {
	a14 := findRep(MapReport(richReportCtx()), "Article 14")
	hasFindingsLink := false
	for _, e := range a14.Evidence {
		if e.Link == "/vdb-findings" {
			hasFindingsLink = true
		}
	}
	if !hasFindingsLink {
		t.Errorf("Art 14 should link human triage to /vdb-findings: %+v", a14.Evidence)
	}
}
