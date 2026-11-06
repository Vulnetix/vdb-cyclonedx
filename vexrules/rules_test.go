package vexrules

import "testing"

// These cases are the CLI's internal/suppress cases, so the server and the CLI
// keep matching the same way, plus the anchors VEX adds.
func TestRuleMatches(t *testing.T) {
	cases := []struct {
		name string
		r    Rule
		f    Finding
		want bool
	}{
		{"rule id", Rule{RuleID: "go.sql-injection"}, Finding{RuleID: "GO.SQL-INJECTION"}, true},
		{"rule id mismatch", Rule{RuleID: "go.sql-injection"}, Finding{RuleID: "go.template-injection"}, false},
		{"category gates", Rule{RuleID: "r", Category: "sast"}, Finding{RuleID: "r", Category: "iac"}, false},
		{"finding id", Rule{FindingID: "CVE-1"}, Finding{FindingID: "cve-1"}, true},
		{"finding id mismatch", Rule{FindingID: "CVE-1"}, Finding{FindingID: "CVE-2"}, false},
		{"target value mismatch", Rule{TargetValue: "host-a"}, Finding{Value: "host-b"}, false},
		{"path suffix", Rule{FilePath: "src/app.go"}, Finding{FilePath: "./repo/src/app.go"}, true},
		{"path no partial segment", Rule{FilePath: "app.go"}, Finding{FilePath: "myapp.go"}, false},
		{"line range binds when known", Rule{FilePath: "a.go", LineRange: "10-14"}, Finding{FilePath: "a.go", Line: 20}, false},
		{"line range open when unknown", Rule{FilePath: "a.go", LineRange: "10-14"}, Finding{FilePath: "a.go"}, true},
		{"no anchor matches nothing", Rule{Category: "sca"}, Finding{Category: "sca"}, false},
		{"vuln id via alias", Rule{VulnerabilityID: "GHSA-35jh-r3h4-6jhm"}, Finding{FindingID: "CVE-2021-23337", Aliases: []string{"GHSA-35JH-R3H4-6JHM"}}, true},
		{"vuln id as url", Rule{VulnerabilityID: "https://github.com/advisories/GHSA-x"}, Finding{FindingID: "GHSA-x"}, true},
		{"vuln id no match", Rule{VulnerabilityID: "CVE-1"}, Finding{FindingID: "GHSA-xxxx"}, false},
		{"purl base any version", Rule{VulnerabilityID: "CVE-1", ProductPurlBase: "pkg:npm/lodash"}, Finding{FindingID: "CVE-1", Purl: "pkg:npm/lodash@4.17.21"}, true},
		{"purl base other package", Rule{VulnerabilityID: "CVE-1", ProductPurlBase: "pkg:npm/lodash"}, Finding{FindingID: "CVE-1", Purl: "pkg:npm/underscore@1.0.0"}, false},
		{"repo scope full", Rule{VulnerabilityID: "CVE-1", RepositoryFullName: "acme/app"}, Finding{FindingID: "CVE-1", Repository: "Acme/App"}, true},
		{"repo scope bare", Rule{VulnerabilityID: "CVE-1", RepositoryFullName: "acme/app"}, Finding{FindingID: "CVE-1", Repository: "app"}, true},
		{"repo scope other owner", Rule{VulnerabilityID: "CVE-1", RepositoryFullName: "acme/app"}, Finding{FindingID: "CVE-1", Repository: "evil/app"}, false},
		{"repo scope unknown finding repo", Rule{VulnerabilityID: "CVE-1", RepositoryFullName: "acme/app"}, Finding{FindingID: "CVE-1"}, false},
		{"org wide", Rule{VulnerabilityID: "CVE-1"}, Finding{FindingID: "CVE-1", Repository: "acme/other"}, true},
	}
	for _, c := range cases {
		if got := RuleMatches(c.r, c.f); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSetDropsInactiveAndExpired(t *testing.T) {
	s := NewSet([]Rule{
		{UUID: "a", RuleID: "r", IsActive: false},
		{UUID: "b", RuleID: "r", IsActive: true, ExpiresAt: 100},
		{UUID: "c", RuleID: "r", IsActive: true, ExpiresAt: 300},
		{UUID: "d", RuleID: "r", IsActive: true},
	}, 200)
	got := s.MatchAll(Finding{RuleID: "r"})
	if len(got) != 2 || got[0].UUID != "c" || got[1].UUID != "d" {
		t.Fatalf("MatchAll = %+v", got)
	}
}

func TestSetEmpty(t *testing.T) {
	var nilSet *Set
	if !nilSet.Empty() {
		t.Error("nil *Set is not empty")
	}
	if s := NewSet(nil, 0); !s.Empty() {
		t.Error("NewSet with no rules is not empty")
	}
	if s := NewSet([]Rule{{IsActive: false}}, 0); !s.Empty() {
		t.Error("NewSet with only inactive rules is not empty")
	}
	if s := NewSet([]Rule{{IsActive: true}}, 0); s.Empty() {
		t.Error("NewSet with a live rule reports empty")
	}
}

func TestSetMatch(t *testing.T) {
	var nilSet *Set
	if got, ok := nilSet.Match(Finding{}); ok || got != (Rule{}) {
		t.Errorf("nil *Set.Match = (%+v, %v), want (Rule{}, false)", got, ok)
	}

	s := NewSet([]Rule{
		{UUID: "first", RuleID: "r", IsActive: true},
		{UUID: "second", RuleID: "r", IsActive: true},
	}, 0)
	if got, ok := s.Match(Finding{RuleID: "r"}); !ok || got.UUID != "first" {
		t.Errorf("Match with two covering rules = (%+v, %v), want the first", got, ok)
	}
	if got, ok := s.Match(Finding{RuleID: "other"}); ok || got != (Rule{}) {
		t.Errorf("Match with no covering rule = (%+v, %v), want (Rule{}, false)", got, ok)
	}

	unanchored := NewSet([]Rule{{UUID: "only", Category: "sca", IsActive: true}}, 0)
	if got, ok := unanchored.Match(Finding{Category: "sca"}); ok || got != (Rule{}) {
		t.Errorf("Match with only an unanchored rule = (%+v, %v), want (Rule{}, false)", got, ok)
	}
}

func TestLineInRange(t *testing.T) {
	cases := []struct {
		name string
		spec string
		line int
		want bool
	}{
		{"blank spec", " ", 5, true},
		{"malformed start", "x-10", 5, true},
		{"single line in range", "10", 10, true},
		{"single line out of range", "10", 11, false},
		{"reversed range in", "14-10", 12, true},
		{"reversed range out", "14-10", 9, false},
		{"malformed end on start", "10-x", 10, true},
		{"malformed end off start", "10-x", 11, false},
		{"range in", "10-14", 12, true},
		{"range out", "10-14", 15, false},
	}
	for _, c := range cases {
		if got := lineInRange(c.spec, c.line); got != c.want {
			t.Errorf("%s: lineInRange(%q, %d) = %v, want %v", c.name, c.spec, c.line, got, c.want)
		}
	}
}

func TestPathMatches(t *testing.T) {
	cases := []struct {
		name        string
		rulePath    string
		findingPath string
		want        bool
	}{
		{"empty rule path", "", "src/app.go", false},
		{"empty finding path", "src/app.go", "", false},
		{"exact match", "src/app.go", "src/app.go", true},
		{"suffix after norm", "src/app.go", "./repo/src/app.go", true},
		{"backslash normalised", `src\app.go`, "repo/src/app.go", true},
		{"no partial segment", "app.go", "myapp.go", false},
	}
	for _, c := range cases {
		if got := pathMatches(c.rulePath, c.findingPath); got != c.want {
			t.Errorf("%s: pathMatches(%q, %q) = %v, want %v", c.name, c.rulePath, c.findingPath, got, c.want)
		}
	}
}

func TestStatementRules(t *testing.T) {
	s := Statement{VulnID: "CVE-1", Products: []Product{
		{Purl: "pkg:npm/a@1.0.0"}, {Purl: "pkg:npm/a@2.0.0"},
		{Purl: "pkg:npm/b@1.0.0", Subcomponents: []string{"pkg:npm/c@1.0.0"}},
	}}
	d := Disposition{Kind: KindFalsePositive, Rule: true, Active: true, SuppressionType: "false_positive"}
	rules := StatementRules(s, d, "acme/app")
	if len(rules) != 2 || rules[0].ProductPurlBase != "pkg:npm/a" || rules[1].ProductPurlBase != "pkg:npm/c" {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].RepositoryFullName != "acme/app" || !rules[0].IsActive {
		t.Errorf("scope lost: %+v", rules[0])
	}
	if got := StatementRules(s, Disposition{Kind: KindTriageOnly}, ""); got != nil {
		t.Errorf("triage-only statement made rules: %+v", got)
	}
	if got := StatementRules(Statement{VulnID: "CVE-2"}, d, ""); len(got) != 1 || got[0].VulnerabilityID != "CVE-2" {
		t.Errorf("product-less statement = %+v", got)
	}
}

func TestIdentityPicksStrongestVerified(t *testing.T) {
	id := NewIdentity(
		Evidence{Kind: EvidenceOSUser, ID: "chris@laptop"},
		Evidence{Kind: EvidenceGitConfig, Email: "Alice@Example.com", Label: "Alice"},
		Evidence{Kind: EvidenceGHAOIDC, ID: "alice", Verified: true},
		Evidence{Kind: EvidenceCIEnv, ID: "alice"},
		Evidence{Kind: EvidenceOrgKey},
	)
	if id.Primary.Kind != EvidenceGHAOIDC {
		t.Fatalf("primary = %+v", id.Primary)
	}
	if len(id.Evidence) != 4 || id.Evidence[0].Kind != EvidenceGHAOIDC {
		t.Fatalf("evidence = %+v", id.Evidence)
	}
	if id.Email() != "alice@example.com" {
		t.Errorf("email = %q", id.Email())
	}
	claimed := NewIdentity(Evidence{Kind: EvidenceOSUser, ID: "u@h"}, Evidence{Kind: EvidenceCIEnv, ID: "bob"})
	if claimed.Primary.Kind != EvidenceCIEnv || claimed.Primary.Verified {
		t.Errorf("claimed primary = %+v", claimed.Primary)
	}
}
