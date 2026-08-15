package euaiact

// F-047. Article 73 — serious-incident reporting — was absent from the report
// while every signal it needs sat loaded and unread: the alert count, the
// status and type breakdowns, the acknowledgement and dismissal split, the
// overdue count and the notification routes.
//
// F-055. Article 13 was emitted last, after Article 72, and no consumer sorts.
//
// And the route repointing: every evidence link in this report was a `/vdb-*`
// path, which the console has not served since it moved to `/resolve/*` — so a
// reader following a citation landed on the 404 page.

import (
	"strings"
	"testing"
)

func article73(t *testing.T, ctx ReportContext) ArticleMapping {
	t.Helper()
	for _, a := range MapReport(ctx) {
		if a.Article == "Article 73" {
			return a
		}
	}
	t.Fatal("Article 73 is absent from the report")

	return ArticleMapping{}
}

func TestArticle73ReportsTheIncidentProcess(t *testing.T) {
	quiet := article73(t, ReportContext{})
	if quiet.Status != StatusInformational {
		t.Errorf("status = %q with no alert raised, want informational — there is nothing for the process to have handled", quiet.Status)
	}

	overdue := article73(t, ReportContext{
		AlertCount: 9, AlertsAcknowledged: 4, AlertsOverdue: 3,
		AlertByType: map[string]int{"ransomware": 9},
	})
	if overdue.Status != StatusGap {
		t.Errorf("status = %q with 3 alerts past their due date, want %q", overdue.Status, StatusGap)
	}
	if !strings.Contains(overdue.Rationale, "not worked") {
		t.Errorf("rationale = %q", overdue.Rationale)
	}

	unacked := article73(t, ReportContext{AlertCount: 9})
	if unacked.Status != StatusGap {
		t.Errorf("status = %q with nothing acknowledged, want %q — detection is running, investigation is not evidenced", unacked.Status, StatusGap)
	}

	noRoute := article73(t, ReportContext{AlertCount: 9, AlertsAcknowledged: 9, AlertsAcknowledgers: 2})
	if noRoute.Status != StatusPartial {
		t.Errorf("status = %q with no delivery route, want partial", noRoute.Status)
	}

	full := article73(t, ReportContext{
		AlertCount: 9, AlertsAcknowledged: 9, AlertsAcknowledgers: 2,
		NotifyIntegrations: []string{"slack"},
	})
	if full.Status != StatusPartial {
		t.Errorf("status = %q with the filing unevidenced, want partial — the report to the authority is made outside this system", full.Status)
	}
	if len(full.Gaps) == 0 {
		t.Error("the filing obligation is not named as a gap")
	}

	filed := article73(t, ReportContext{
		AlertCount: 9, AlertsAcknowledged: 9, AlertsAcknowledgers: 2,
		NotifyIntegrations:      []string{"slack"},
		ManualEvidenceByControl: map[string]int{"Article 73": 1},
	})
	if filed.Status != StatusSatisfied {
		t.Errorf("status = %q with the filing attached, want satisfied", filed.Status)
	}
}

// F-055. Articles are read in number order by anyone navigating the document.
func TestArticlesAreEmittedInReadingOrder(t *testing.T) {
	got := []string{}
	for _, a := range MapReport(ReportContext{}) {
		got = append(got, a.Article)
	}
	want := []string{
		"Article 4", "Article 5", "Article 6", "Article 9", "Article 10",
		"Article 11 / Annex IV", "Article 12", "Article 13", "Article 14", "Article 15",
		"Article 17", "Article 18", "Article 19", "Article 20", "Article 26", "Article 50",
		"Articles 51-55", "Article 53", "Article 55", "Article 72", "Article 73",
	}
	if len(got) != len(want) {
		t.Fatalf("articles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Every evidence link has to be a route the console serves. `/vdb-*` has not
// been one since the console moved to `/resolve/*`, and `/vdb-console` is now
// itself a redirect there.
func TestEvidenceLinksPointAtRoutesThatExist(t *testing.T) {
	ctx := maximalCtx()
	for _, a := range MapReport(ctx) {
		for _, e := range a.Evidence {
			if e.Link == "" {
				continue
			}
			if strings.HasPrefix(e.Link, "/vdb-") {
				t.Errorf("%s cites %q — the console has not served /vdb-* since it moved to /resolve/*", a.Article, e.Link)
			}
			if !strings.HasPrefix(e.Link, "/resolve/") {
				t.Errorf("%s cites %q, which is not a console route", a.Article, e.Link)
			}
		}
	}
}

// F-014. A report computed from a capped sample is not wrong; a report that
// does not say so presents the sample as the scope, and every count below it
// reads as a claim about the whole estate.
func TestTruncationIsStatedNotSilent(t *testing.T) {
	var ctx ReportContext
	if ctx.TruncationNote() != "" {
		t.Error("a report that read every row claims a truncation")
	}
	ctx.NoteTruncation("findings", 20000)
	ctx.NoteTruncation("findings", 20000)
	if len(ctx.Truncations) != 1 {
		t.Errorf("truncations = %v, want the same population recorded once", ctx.Truncations)
	}
	note := ctx.TruncationNote()
	if !strings.Contains(note, "20000") {
		t.Errorf("note = %q — does not say what the cap was, which is what tells the reader the size of the sample", note)
	}
	if !strings.Contains(note, "sample") {
		t.Errorf("note = %q — does not say the counts describe a sample", note)
	}
}
