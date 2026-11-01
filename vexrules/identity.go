package vexrules

import (
	"sort"
	"strings"
)

// Identity is who made a decision, as every piece of evidence available, from
// strongest to weakest. A CLI API key names an organisation, never a person,
// so for CLI work the person comes from evidence around the key: a signed
// assertion from the device login, a GitHub Actions OIDC token, CI variables,
// git configuration, the commit author, the OS user. Some of that is verified
// by the server and some is only claimed by the client; both are kept, and
// labelled, because a weak attribution is still better than none.
type Identity struct {
	Primary  Evidence   `json:"primary"`
	Evidence []Evidence `json:"evidence"`
}

// Evidence is one rung of the ladder.
type Evidence struct {
	Kind EvidenceKind `json:"kind"`
	// ID is the stable identifier the kind uses: a principal uuid, a GitHub
	// login, an email, "user@host".
	ID    string `json:"id,omitempty"`
	Label string `json:"label,omitempty"`
	Email string `json:"email,omitempty"`
	// Verified is true only when the server checked a signature or a session
	// for this rung. Everything the client sends unsigned is claimed.
	Verified bool `json:"verified"`
	// Source names where the evidence came from, for example
	// "GITHUB_TRIGGERING_ACTOR" or "git config user.email".
	Source string `json:"source,omitempty"`
	// Detail carries rung-specific facts (repository and sha for an OIDC
	// token, the run id for CI).
	Detail map[string]string `json:"detail,omitempty"`
}

// EvidenceKind names a rung.
type EvidenceKind string

const (
	EvidenceConsolePrincipal EvidenceKind = "console_principal"
	EvidenceCLIKeyPrincipal  EvidenceKind = "cli_key_principal"
	EvidenceGHAOIDC          EvidenceKind = "gha_oidc"
	EvidenceCIEnv            EvidenceKind = "ci_env"
	EvidenceGitConfig        EvidenceKind = "git_config"
	EvidenceHeadCommitAuthor EvidenceKind = "head_commit_author"
	EvidenceOSUser           EvidenceKind = "os_user"
	EvidenceOrgKey           EvidenceKind = "org_key"
	EvidenceSystem           EvidenceKind = "system"
	EvidenceUnknownLegacy    EvidenceKind = "unknown_legacy"
)

// rank orders the rungs, strongest first.
var rank = map[EvidenceKind]int{
	EvidenceConsolePrincipal: 1,
	EvidenceCLIKeyPrincipal:  2,
	EvidenceGHAOIDC:          3,
	EvidenceCIEnv:            4,
	EvidenceGitConfig:        5,
	EvidenceHeadCommitAuthor: 6,
	EvidenceOSUser:           7,
	EvidenceOrgKey:           8,
	EvidenceSystem:           9,
	EvidenceUnknownLegacy:    10,
}

// Rank returns the rung's position, 1 strongest. Unknown kinds sort last.
func (k EvidenceKind) Rank() int {
	if r, ok := rank[k]; ok {
		return r
	}
	return 99
}

// NewIdentity orders the evidence and picks the primary: the strongest
// verified rung, otherwise the strongest rung. Empty entries are dropped.
func NewIdentity(evidence ...Evidence) Identity {
	var kept []Evidence
	for _, e := range evidence {
		if e.Kind == "" || (e.ID == "" && e.Email == "" && e.Label == "") {
			continue
		}
		e.Email = strings.ToLower(strings.TrimSpace(e.Email))
		kept = append(kept, e)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Kind.Rank() < kept[j].Kind.Rank() })
	id := Identity{Evidence: kept}
	for _, e := range kept {
		if e.Verified {
			id.Primary = e
			return id
		}
	}
	if len(kept) > 0 {
		id.Primary = kept[0]
	}
	return id
}

// Email returns the first email any rung carries, strongest first. The server
// uses it to resolve a Member; it is a claim unless the rung is verified.
func (id Identity) Email() string {
	if id.Primary.Email != "" {
		return id.Primary.Email
	}
	for _, e := range id.Evidence {
		if e.Email != "" {
			return e.Email
		}
	}
	return ""
}
