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
		{"category gates", Rule{RuleID: "r", Category: "sast"}, Finding{RuleID: "r", Category: "iac"}, false},
		{"finding id", Rule{FindingID: "CVE-1"}, Finding{FindingID: "cve-1"}, true},
		{"path suffix", Rule{FilePath: "src/app.go"}, Finding{FilePath: "./repo/src/app.go"}, true},
		{"path no partial segment", Rule{FilePath: "app.go"}, Finding{FilePath: "myapp.go"}, false},
		{"line range binds when known", Rule{FilePath: "a.go", LineRange: "10-14"}, Finding{FilePath: "a.go", Line: 20}, false},
		{"line range open when unknown", Rule{FilePath: "a.go", LineRange: "10-14"}, Finding{FilePath: "a.go"}, true},
		{"no anchor matches nothing", Rule{Category: "sca"}, Finding{Category: "sca"}, false},
		{"vuln id via alias", Rule{VulnerabilityID: "GHSA-35jh-r3h4-6jhm"}, Finding{FindingID: "CVE-2021-23337", Aliases: []string{"GHSA-35JH-R3H4-6JHM"}}, true},
		{"vuln id as url", Rule{VulnerabilityID: "https://github.com/advisories/GHSA-x"}, Finding{FindingID: "GHSA-x"}, true},
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
