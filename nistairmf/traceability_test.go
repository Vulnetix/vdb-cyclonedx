package nistairmf

// F-065 and F-184: the report's evidence was untraceable and its coverage was
// smaller than the evidence available.
//
//	F-065  no evidence item carried a RefID, six emitters shipped no Link at
//	       all, and every route was a `/vdb-*` path the console stopped serving
//	       when it moved to `/resolve/*`
//	F-184  17 of the 72 subcategories had a mapper; five more were backable
//	       from fields the shared context already carried and two sibling
//	       frameworks already read
//
// F-066 is the reason both survived: the fixture left every one of those fields
// zero, so the deepest branches of this mapper had never executed.

import (
	"strings"
	"testing"
)

func TestEveryEvidenceItemIsDrillable(t *testing.T) {
	ctx := richCtx()
	ctx.MemberCount = 4
	ctx.AccessLogCount = 100
	ctx.ThreatModelCount = 1
	ctx.SarifResultTotal = 10
	ctx.QualityGateConfigured = true
	ctx.QualityGateSeverity = "high"
	ctx.PurgeJobCount = 1
	ctx.CliTestConfigCount = 2

	for _, fn := range MapReport(ctx) {
		for _, sc := range fn.Subcategories {
			for _, e := range sc.Evidence {
				if strings.HasPrefix(e.Link, "/vdb-") {
					t.Errorf("%s cites %q — the console has not served /vdb-* since it moved to /resolve/*", sc.ID, e.Link)
				}
				if e.Link != "" && !strings.HasPrefix(e.Link, "/resolve/") {
					t.Errorf("%s cites %q, which is not a console route", sc.ID, e.Link)
				}
			}
		}
	}
}

// The five subcategories added for F-184, and the signals each rests on.
func TestAddedSubcategoriesCiteTheirEvidence(t *testing.T) {
	ctx := richCtx()
	ctx.MemberCount = 14
	ctx.MfaMemberCount = 14
	ctx.AccessLogCount = 300
	ctx.AccessLogWithIdentity = 300
	ctx.SsvcDecisionByHuman = 4
	ctx.SuppressionWithOwner = 2
	ctx.ThreatModelCount = 2
	ctx.ThreatModelWithAttackPath = 1
	ctx.ThreatModelMethodologies = []string{"STRIDE"}
	ctx.ThreatAnnotationCount = 3
	ctx.SarifResultTotal = 900
	ctx.SarifResultReviewedBy = 900
	ctx.QualityGateConfigured = true
	ctx.QualityGateSeverity = "high"
	ctx.PurgeJobCount = 2
	ctx.PurgeDeletedRows = 40
	ctx.CliTestConfigCount = 3

	byID := map[string]SubcategoryMapping{}
	for _, fn := range MapReport(ctx) {
		for _, sc := range fn.Subcategories {
			byID[sc.ID] = sc
		}
	}
	for _, tc := range []struct{ id, want string }{
		{"GOVERN 1.2", "platform account"},
		{"GOVERN 4.1", "Threat model"},
		{"MAP 3.1", "Automated testing"},
		{"MEASURE 2.7", "Acceptance criteria"},
		{"MANAGE 2.2", "purge job"},
	} {
		sc, ok := byID[tc.id]
		if !ok {
			t.Errorf("%s is absent from the report", tc.id)

			continue
		}
		var found bool
		for _, e := range sc.Evidence {
			if strings.Contains(e.Component, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not cite %q: %+v", tc.id, tc.want, sc.Evidence)
		}
	}
}

// F-064's sharpest instance: MANAGE 4.3 said communicating incidents to
// stakeholders was "a human process no artifact evidences" while the alert
// trail and the notification routes sat on the same struct.
func TestManage43ReadsTheIncidentTrail(t *testing.T) {
	ctx := richCtx()
	ctx.AlertCount = 5
	ctx.AlertsAcknowledged = 5
	ctx.AlertsAcknowledgers = 2
	ctx.NotifyIntegrations = []string{"slack"}

	for _, fn := range MapReport(ctx) {
		for _, sc := range fn.Subcategories {
			if sc.ID != "MANAGE 4.3" {
				continue
			}
			if strings.Contains(sc.Rationale, "no artifact evidences") {
				t.Errorf("MANAGE 4.3 still says no artifact evidences stakeholder communication: %q", sc.Rationale)
			}
			var cited bool
			for _, e := range sc.Evidence {
				if strings.Contains(e.Component, "alert") || strings.Contains(e.Component, "Notification") {
					cited = true
				}
			}
			if !cited {
				t.Errorf("MANAGE 4.3 cites no incident evidence: %+v", sc.Evidence)
			}
		}
	}
}
