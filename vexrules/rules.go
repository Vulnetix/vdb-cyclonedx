package vexrules

import (
	"strconv"
	"strings"
)

// Rule is a suppression rule in the form the matcher reads. It mirrors the
// saas Suppression row; the CLI builds it from memory.yaml and from
// cli.suppressions-get, the server from the table.
//
// A rule matches a finding when every anchor it sets matches. The anchors are
// the rego rule id, the finding id, an inventory target value, a file path
// (narrowed by a line range), and, for rules that came from VEX, the
// vulnerability id (against the finding's id and aliases) and the product purl
// without its version. Repository scope is checked separately: a rule naming a
// repository covers only findings from that repository. The branch is recorded
// but not matched, as before.
type Rule struct {
	UUID               string
	Type               string
	RuleID             string
	Category           string
	FindingID          string
	TargetValue        string
	FilePath           string
	LineRange          string
	VulnerabilityID    string
	ProductPurlBase    string
	RepositoryFullName string
	Branch             string
	ExpiresAt          int64
	IsActive           bool
}

// Finding is the subset of a finding the matcher inspects.
type Finding struct {
	UUID      string
	Category  string
	RuleID    string
	FindingID string
	// Aliases are other identifiers for the finding's vulnerability.
	Aliases []string
	// Value is the inventory component identity.
	Value    string
	Purl     string
	FilePath string
	// Line is the 1-based line, 0 when unknown (a line range is then not
	// binding).
	Line int
	// Repository is "owner/name" or a bare name. Empty when the finding has
	// no repository, which a repository-scoped rule never covers.
	Repository string
}

// Set is a matchable collection of rules, holding only those active and
// unexpired at the time it was built.
type Set struct {
	rules []Rule
}

// NewSet builds a Set, dropping inactive and expired rules. now and ExpiresAt
// are unix seconds.
func NewSet(rules []Rule, now int64) *Set {
	kept := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !r.IsActive || (r.ExpiresAt > 0 && r.ExpiresAt <= now) {
			continue
		}
		kept = append(kept, r)
	}
	return &Set{rules: kept}
}

// Empty reports whether the set has no live rules.
func (s *Set) Empty() bool { return s == nil || len(s.rules) == 0 }

// Match returns the first rule that covers f.
func (s *Set) Match(f Finding) (Rule, bool) {
	if s == nil {
		return Rule{}, false
	}
	for _, r := range s.rules {
		if RuleMatches(r, f) {
			return r, true
		}
	}
	return Rule{}, false
}

// MatchAll returns every rule that covers f. The engine records an
// application for each, so deactivating one rule leaves the others in force.
func (s *Set) MatchAll(f Finding) []Rule {
	if s == nil {
		return nil
	}
	var out []Rule
	for _, r := range s.rules {
		if RuleMatches(r, f) {
			out = append(out, r)
		}
	}
	return out
}

// RuleMatches reports whether r covers f, ignoring active and expiry.
func RuleMatches(r Rule, f Finding) bool {
	if r.Category != "" && !strings.EqualFold(r.Category, f.Category) {
		return false
	}
	if r.RuleID != "" && !strings.EqualFold(r.RuleID, f.RuleID) {
		return false
	}
	if r.FindingID != "" && !strings.EqualFold(r.FindingID, f.FindingID) {
		return false
	}
	if r.TargetValue != "" && !strings.EqualFold(r.TargetValue, f.Value) {
		return false
	}
	if r.FilePath != "" && !pathMatches(r.FilePath, f.FilePath) {
		return false
	}
	if r.LineRange != "" && f.Line > 0 && !lineInRange(r.LineRange, f.Line) {
		return false
	}
	if r.VulnerabilityID != "" && !vulnMatches(r.VulnerabilityID, f) {
		return false
	}
	if r.ProductPurlBase != "" && !strings.EqualFold(PurlBase(r.ProductPurlBase), PurlBase(f.Purl)) {
		return false
	}
	if r.RepositoryFullName != "" && !RepoMatches(r.RepositoryFullName, f.Repository) {
		return false
	}
	// A rule with no anchor would match everything.
	return r.RuleID != "" || r.FindingID != "" || r.TargetValue != "" || r.FilePath != "" ||
		r.VulnerabilityID != ""
}

func vulnMatches(id string, f Finding) bool {
	id = NormalizeVulnID(id)
	if strings.EqualFold(id, NormalizeVulnID(f.FindingID)) {
		return true
	}
	for _, a := range f.Aliases {
		if strings.EqualFold(id, NormalizeVulnID(a)) {
			return true
		}
	}
	return false
}

// RepoMatches compares repository names the way the server always has: the
// full "owner/name" or the bare name after the slash, case-insensitively. An
// empty finding repository never matches a scoped rule.
func RepoMatches(ruleRepo, findingRepo string) bool {
	a := strings.ToLower(strings.Trim(strings.TrimSpace(ruleRepo), "/"))
	b := strings.ToLower(strings.Trim(strings.TrimSpace(findingRepo), "/"))
	if a == "" {
		return true
	}
	if b == "" {
		return false
	}
	if a == b {
		return true
	}
	return bare(a) == bare(b) && (!strings.Contains(a, "/") || !strings.Contains(b, "/"))
}

func bare(repo string) string {
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		return repo[i+1:]
	}
	return repo
}

func lineInRange(spec string, line int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	lo, hi, found := strings.Cut(spec, "-")
	start, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return true
	}
	if !found {
		return line == start
	}
	end, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return line == start
	}
	if end < start {
		start, end = end, start
	}
	return line >= start && line <= end
}

func pathMatches(rulePath, findingPath string) bool {
	rp := normPath(rulePath)
	fp := normPath(findingPath)
	if rp == "" || fp == "" {
		return false
	}
	return rp == fp || strings.HasSuffix(fp, "/"+rp)
}

func normPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return strings.Trim(p, "/")
}

// StatementRules turns one classified statement into the rules it creates:
// one per product, scoped to repo (empty for org-wide). A statement with no
// product creates one rule anchored on the vulnerability alone.
func StatementRules(s Statement, d Disposition, repo string) []Rule {
	if !d.Rule {
		return nil
	}
	mk := func(purl string) Rule {
		return Rule{
			Type:               d.SuppressionType,
			VulnerabilityID:    s.VulnID,
			ProductPurlBase:    PurlBase(purl),
			RepositoryFullName: repo,
			IsActive:           d.Active,
		}
	}
	var out []Rule
	seen := map[string]bool{}
	for _, p := range s.Products {
		purls := p.Subcomponents
		if len(purls) == 0 {
			purls = []string{p.Purl}
		}
		for _, purl := range purls {
			key := PurlBase(purl)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, mk(purl))
		}
	}
	if len(out) == 0 {
		out = append(out, mk(""))
	}
	return out
}
