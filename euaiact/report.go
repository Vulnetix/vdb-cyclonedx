package euaiact

// report.go adds report-level mapping: instead of one AI-BOM scan, it consumes
// a ReportContext aggregated across an org + period + repo scope, drawing on
// every evidence source (findings/triage, scanner runs + snapshot history,
// VEX/suppression, access logs, SBOM, CBOM, governance policy) — far richer
// than the per-scan inventory. Each evidence item carries a Link to its source
// page. Controls that are evaluated but find nothing return StatusGap (with a
// one-line "no evidence found"); controls that cannot be evaluated from
// available data return StatusNotApplicable with the reason.

import "strings"

// Product route paths for evidence links (stable vdb-* pages).
const (
	routeFindings     = "/vdb-findings"
	routeScans        = "/vdb-scanner-results"
	routeInventory    = "/vdb-ai-inventory"
	routeCrypto       = "/vdb-crypto-inventory"
	routeUploads      = "/vdb-uploads"
	routeLicenses     = "/vdb-licenses"
	routeAiFirewall   = "/vdb-ai-firewall"
	routeRiskStrategy = "/vdb-risk-strategy"
	routePolicies     = "/vdb-suppression-policies"
	routeGate         = "/vdb-quality-gate"
	routeLogs         = "/vdb-logs"
	routeThreatModel  = "/vdb-threat-model"
)

// ReportContext is the aggregated, source-agnostic evidence view for one
// compliance report (org + period + repo scope). Zero values mean "no such
// evidence found" (→ StatusGap for controls that expect it).
type ReportContext struct {
	OrgName     string
	PeriodStart int64
	PeriodEnd   int64
	Repos       []string // in-scope repo names; empty = org-wide

	// LoadFailures names the evidence sources that failed to load.
	//
	// Every counter here defaults to zero, and zero is indistinguishable from a
	// healthy organization: no open exploited findings, nothing overdue,
	// nothing outstanding. A query that fails therefore renders as a clean
	// posture rather than as an error, and the report says "Satisfied" on
	// evidence it never read. Any surface that shows a verdict has to show this
	// too, or the verdict is unfalsifiable.
	LoadFailures []string

	// AI inventory — union of components across in-scope AI-BOM scans.
	Components     []Component
	AibomScanCount int

	// ManualEvidenceByControl is uploaded evidence files per control id.
	//
	// Fourteen rationales across the three AI-governance frameworks tell the
	// customer to attach something — "instructions-for-use are provider-authored
	// documents; upload them as manual evidence" — and nothing consumed it: only
	// ISO 27001 and DSOMM were handed the counts, so in these frameworks an
	// upload changed no status and the instruction was inert. Article 13 in
	// particular was hardwired not-applicable, so the one control whose *only*
	// path is an upload could never move.
	//
	// Attaching a document is a human act, which is why it promotes here as it
	// does in ISO 27001. What it cannot do is verify the document's contents, so
	// the rationale of anything promoted this way says the claim rests on
	// customer-supplied evidence.
	ManualEvidenceByControl map[string]int
	LatestAibomScanUUID     string
	PriorScanCount          int // AI-BOM scans over time (monitoring signal)

	// Findings / risk identification + human triage.
	FindingTotal            int
	FindingByCategory       map[string]int // sast|sca|secrets|iac|oci|license
	FindingBySeverity       map[string]int
	TriagedTotal            int
	AffectedTotal           int
	NotAffectedTotal        int
	UnderInvestigationTotal int
	FixedTotal              int

	// Risk treatment records.
	OpenVexCount     int
	SuppressionCount int

	// Test/eval + continuous monitoring.
	ScannerRunCount        int
	ScannerRunCategories   []string       // distinct ScannerRun.category in scope
	ScannerRunByCategory   map[string]int // ScannerRun.category → run count
	SnapshotByCategory     map[string]int // IngestionSnapshot.category → snapshot count
	ScannerToolNames       []string       // distinct tool names that produced runs
	ScannerRepoCount       int            // distinct repos with at least one run
	LastScanAt             int64          // most recent ScannerRun.createdAt (ms)
	IngestionSnapshotCount int            // per-run history rows (monitoring over time)
	HasEvaluation          bool

	// Snapshot rollup — the triage pipeline's own per-run accounting summed
	// over the period. This is the audit trail of *how* every ingested finding
	// was disposed of, not just the current posture.
	Snapshot SnapshotRollup

	// Technical documentation.
	CycloneDXCount int
	SPDXCount      int

	// Event logging.
	AccessLogCount        int
	AccessLogMemberCount  int // distinct identities that generated events
	AccessLogWithIdentity int // events attributable to a member
	AccessLogWithSource   int // events carrying a source address

	// Crypto posture.
	CbomQuantumVulnerable int
	CbomQuantumSafe       int

	// Penetration tests, from CollectionEvent.eventType = PenTest. This is the
	// only record of a penetration test anywhere in the schema, and no report
	// read it — so PCI 11.4, ISO A.8.29 and CRA II.3 all evidenced "security
	// testing" from automated scanner counts, which is a different activity
	// entirely. A scanner run is not a penetration test, and the requirement
	// that says "penetration test" is not met by one.
	PenTestCount    int
	PenTestLastAt   int64
	PenTestTitles   []string
	PenTestInPeriod int

	// Package Firewall: the install-time supply-chain gate. A BLOCK is a dated
	// record of a malicious or policy-violating package being stopped before it
	// entered the build, which is direct evidence for OWASP A03 — and A03 could
	// not see it, because the posture was loaded separately by the assessor
	// frameworks, by CRA and by Scan Coverage, and never onto the shared
	// context. Config rows are keyed on VdbOrganization, so the loader routes
	// through vdbOrgUuidsForSaas.
	PackageFirewallConfigured   bool
	PackageFirewallToggles      []string
	PackageFirewallRequestCount int
	PackageFirewallBlockCount   int
	PackageFirewallWarnCount    int

	// Threat modelling. A persisted STRIDE/PASTA model with placed elements,
	// trust zones and recorded annotations is textbook evidence for "risk-based
	// design" and "secure architecture" — ISO A.8.27, PCI 12.2, CRA I.1 and EU
	// AI Act Art. 9 all ask for exactly this — and it was read by DSOMM alone,
	// on its own Input, so no other framework could see it.
	ThreatModelCount          int
	ThreatModelsWithZones     int
	ThreatModelWithAttackPath int
	ThreatModelElementCount   int
	ThreatAnnotationCount     int
	ThreatModelMethodologies  []string
	ThreatModelLastBuiltAt    int64

	// Governance / policy configuration.
	HasTriagePolicy  bool
	HasMethodology   bool
	HasLicensePolicy bool

	// AI Firewall (runtime LLM gateway) posture. Configured=false means no
	// gateway policy exists at all; LogsEnabled=false means runtime activity
	// is UNKNOWN (not zero) — mappers must word evidence accordingly.
	AiFirewallConfigured          bool           // any guardrail, provider/model policy, or BYOK key
	AiFirewallLogsEnabled         bool           // inference logging opt-in
	AiFirewallGuardrailCount      int            // enabled guardrails
	AiFirewallGuardrailsByType    map[string]int // blocked_pattern|max_messages|pii_redact (enabled)
	AiFirewallEnforcingGuardrails int            // enabled guardrails with action=block or redact
	AiFirewallProviderPolicyCount int            // provider allow/deny rows with an action set
	AiFirewallModelPolicyCount    int            // model allow/deny rows
	AiFirewallRequestCount        int            // gateway inferences in period (meaningful only when LogsEnabled)
	AiFirewallBlockCount          int            // decision=block in period
	AiFirewallRedactCount         int            // decision=redact in period
	AiFirewallFlagCount           int            // decision=flag in period

	// ── Risk-based remediation policy ─────────────────────────────────────
	// The org's ordered risk-prioritization strategy: the machine-readable
	// expression of "we rank risk this way, and remediate in that order".
	RiskStrategyName      string
	RiskStrategyRuleCount int
	RiskStrategyMetrics   []string // distinct RiskMetric names the rules use
	RiskStrategyIsCustom  bool     // org-authored, not the seeded system default

	// Remediation SLAs from the active triage policy (days per severity).
	TriagePolicyName     string
	RemediationDaysBySev map[string]int // critical|high|medium|low
	TriageThresholdDays  int
	ExposureWindowDays   int
	ThreatWindowDays     int

	// ── Build-time enforcement (CLI quality gate) ─────────────────────────
	QualityGateConfigured bool
	QualityGateBlocks     []string // eol|malware|unpinned
	QualityGateSeverity   string   // fail-on severity floor
	QualityGateExploits   string   // fail-on exploit maturity floor
	QualityGateVersionLag int
	QualityGateCooldown   int
	QualityGateEolTiers   map[string]string // retired|within30days|thisQuarter|nextQuarter → severity

	// Observed CLI runs: how often the gate actually executed and how often it
	// stopped a build.
	CliRunCount        int
	CliBreakBuildCount int // runs configured to break the build
	CliFailedGateCount int // runs that exited non-zero
	CliVersions        []string

	// ── Change control / pre-release review ───────────────────────────────
	SarifResultTotal    int
	SarifResultReviewed int // reviewStatus set to something other than pending
	DependencyTotal     int
	DependencyReviewed  int

	// Human peer review of changes, from GitHubPullRequestReview. Several
	// standards ask for review of changes before release — ISO 27001 A.8.25 and
	// A.8.28, PCI DSS 6.2.3, DSOMM, CRA Annex I Part I 1 — and every one of them
	// fell back to "manual evidence required" while these rows sat unread. A
	// scanner disposition is a tool's opinion; an approval is a person's.
	CodeReviewTotal            int // reviews submitted in the period
	CodeReviewApproved         int // state = APPROVED
	CodeReviewChangesRequested int
	CodeReviewPullRequests     int // distinct pull requests reviewed
	CodeReviewReviewers        int // distinct reviewers
	CodeReviewReposCovered     int // distinct in-scope repos with a review
	// CodeReviewIndependent is approvals whose reviewer is not the pull
	// request's author. PCI DSS 6.2.3 does not ask whether code was reviewed —
	// it asks whether it was reviewed "by individuals other than the
	// originating code author", and that is the part a self-approval fails.
	CodeReviewIndependent int
	// CodeReviewSelfApproved is approvals by the author of the change. Reported
	// rather than hidden: it is the number an assessor samples.
	CodeReviewSelfApproved int

	// SonarQube findings. A second, independent static-analysis tool whose
	// results were read by no report — so every "analysis breadth" and
	// "no weaknesses observed" claim rested on Vulnetix's own SARIF alone,
	// understating the assurance actually performed.
	//
	// SonarqubeFinding carries orgId and createdAt but no repository, so these
	// are organisation-wide even on a repo-scoped report. Controls citing them
	// must say so rather than let the number read as scoped.
	SonarFindingTotal int
	SonarFindingOpen  int
	SonarBlockerHigh  int // blocker/critical severity, still open
	SonarRuleTypes    []string

	// GitHub secret-scanning alerts, from GitHubSecretScanningAlert. Detection
	// by a second, independent tool plus a recorded resolution — which is
	// stronger evidence for a secrets control than Vulnetix's own scan count.
	SecretAlertTotal    int
	SecretAlertResolved int
	SecretAlertOpen     int
	// Cloud posture from Wiz, including the control-framework mapping Wiz
	// supplies with each issue. That mapping is an independent third party
	// tying a cloud finding to the very standards these reports cover, it is
	// already stored, and no control read it — so ISO A.5.23 evidenced cloud
	// security from IaC scan counts while a vendor's framework attribution sat
	// unused beside it.
	// API access to the vulnerability database (VdbAccessLog) and third-party
	// integration calls (IntegrationUsageLog), both carrying an outcome code.
	//
	// The denied counts are the point: PCI 10.2.1.4 enumerates invalid logical
	// access attempts and ISO A.8.16 asks for monitoring that surfaces
	// anomalous behaviour, and both were evidenced from alert counts and
	// scanner activity. A rejected API call is the most literal record of an
	// access attempt that should not have succeeded, and neither log was read.
	ApiAccessTotal        int
	ApiAccessDenied       int
	ApiAccessSourceIPs    int
	IntegrationCallTotal  int
	IntegrationCallFailed int
	IntegrationSources    []string

	// Alert disposition detail, from MissionControlAlert's attribution columns.
	//
	// The status bucket alone cannot separate an alert a person acknowledged
	// from one that aged out, or an alert resolved from one *dismissed* without
	// action — and dismissal is the weakening action here, the same shape as a
	// bypassed push protection or a deactivated firewall entry. `dueDate` gives
	// the overdue count, which the disposition split cannot express at all.
	AlertsAcknowledged  int
	AlertsAcknowledgers int
	AlertsDismissed     int
	AlertsOverdue       int

	// Human curation of malware determinations, from MalwareCurationAudit:
	// analysts marking a detection a false positive, retracting that, or adding
	// and removing indicators — with the actor and the reason.
	//
	// This is the malware control being *operated by people*, which is what
	// ISO A.8.7 and PCI Requirement 5 ask about beyond "a scanner ran". A
	// false-positive marking is the weakening action: a real detection
	// dismissed. Counted apart from the total for the same reason as the
	// firewall list audit.
	MalwareCurationTotal      int
	MalwareFalsePositiveSet   int
	MalwareIocAdded           int
	MalwareCurationActors     int
	MalwareCurationWithReason int

	// Notification delivery, from NotificationDispatchLog: whether anything was
	// actually sent over a configured route, and whether it succeeded.
	//
	// The incident section could say a route was *configured* and not whether
	// it had ever carried anything, so "delivery untested" was as far as it
	// could go. A failed dispatch is the sharper signal: a configured route
	// that silently errors is worse than none, because it reads as covered.
	NotificationDelivered int
	NotificationFailed    int
	NotificationProviders []string

	// Deployment provenance and configuration drift, from CloudResource.
	//
	// `stackDriftStatus` is the running estate compared against its declared
	// infrastructure — the monitoring half of ISO A.8.9, which asks that
	// configurations be established, documented, implemented **and monitored**.
	// A.8.9 evidenced the first three from IaC findings and never the fourth,
	// so an estate that had drifted from its own templates read the same as one
	// that had not. `sourceCommitSha` and `deployedByArn` tie a running
	// resource to the commit and the principal that produced it, which is what
	// change-management controls mean by traceability.
	CloudResourceTotal     int
	CloudResourceDrifted   int
	CloudResourceWithSha   int
	CloudResourceWithActor int

	// The deployed, internet-facing attack surface: resources with a traced
	// path from an ingress (load balancer, API gateway, public subnet) to the
	// resource itself, with the reachable ports.
	//
	// CRA I.2(j) is "attack surface reduction" and evidenced the *supply-chain*
	// surface — package firewall, container scans, call-path reachability. All
	// real, and none of it the surface an attacker meets first. CloudCritFindings
	// is the companion: a CVE scored in its actual cloud context rather than in
	// the abstract.
	CloudExposedResources int
	CloudExposureIngress  []string
	CloudExposedPorts     int
	CloudCritFindings     int

	CloudIssueTotal     int
	CloudIssueOpen      int
	CloudIssueMapped    int // issues carrying a security-framework attribution
	CloudFrameworkNames []string

	// CycloneDX 1.6 attestation payloads. `declarations` carries conformance
	// claims with their evidence and signatories; `formulation` records how the
	// component was built. Both are machine-readable compliance evidence the
	// platform already ingests, and the compliance reports read neither —
	// including the CRA controls that ask for a declaration of conformity and
	// for build provenance.
	SbomWithDeclarations int
	SbomWithFormulation  int

	// Changes to a security control itself, from PackageFirewallListAudit: who
	// added, moved, deactivated or deleted an allow/block entry on the
	// install-time gate, with the reason they gave.
	//
	// PCI 10.2 requires audit logs of changes to security controls, and ISO
	// A.8.15 asks for logging of administrative activity — both were evidenced
	// with *access* records, which are a different thing: access says someone
	// read something, this says someone changed the guard. Weakening actions
	// are counted separately, because "the allowlist changed 40 times" and "the
	// gate was disabled 40 times" are not the same sentence.
	FirewallListChanges       int
	FirewallListWeakened      int
	FirewallChangeActors      int
	FirewallChangesWithReason int

	// Code-host access control, from GitHubOrganization. Distinct from
	// SsoEnforced, which is authentication into *Vulnetix*: the source code
	// lives in the code host, so an organization enforcing SSO here while its
	// GitHub organization requires no second factor has the weaker control on
	// the more valuable asset. ISO A.5.15-A.5.18 and A.8.5, and PCI 7 and 8,
	// ask about access to the systems that hold the data — and every one of
	// these columns was unread.
	GitHubOrgsInScope      int
	GitHubOrgsTwoFactor    int // organizations requiring 2FA of all members
	GitHubDefaultRepoPerms []string
	// The organization's *own* signing posture, from Artifact.signature*.
	//
	// Provenance below is about dependencies — packages someone else signed.
	// This is the manufacturer signing what it publishes, which is what CRA
	// II.7 ("distribute products and updates through controlled channels"),
	// ISO A.8.28 and SLSA actually ask about, and every column of it was
	// unread: II.7 was evidenced with upstream suppliers' attestations.
	//
	// SignedArtifactWitnessed counts signatures with a transparency-log entry —
	// a signature a consumer can confirm was witnessed rather than merely
	// presented, which is the difference between a claim and a verifiable one.
	ArtifactTotal            int
	SignedArtifactCount      int
	SignedArtifactWitnessed  int
	ArtifactSignatureFormats []string

	// Native code-host detectors. Two more independent analyses whose results
	// the reports never counted, so every analysis-breadth claim understated
	// the assurance actually performed — the same defect as the unread
	// SonarQube findings, in two more tools.
	CodeQLAlertTotal     int
	CodeQLAlertOpen      int
	CodeQLHighSeverity   int // open alerts at high or critical security severity
	DependabotAlertTotal int
	DependabotAlertOpen  int
	DependabotAlertCrit  int // open alerts at critical severity
	DependabotEcosystems []string
	// SecretAlertBypassed counts alerts that exist because someone was warned a
	// commit contained a secret and pushed it anyway. A preventive control
	// being *overridden* is among the strongest things an assessor can be
	// handed, and it was unread: a bypassed alert still resolves, so an estate
	// that overrode push protection fourteen times and cleaned up afterwards
	// read exactly like one where the control was never challenged.
	SecretAlertBypassed int

	// ── Supply-chain provenance ───────────────────────────────────────────
	SlsaProvenanceCount   int
	SlsaVerifiedCount     int
	AttestationCount      int
	AttestationVerified   int
	CliManifestCount      int
	CliManifestEcosystems []string
	CliTestConfigCount    int
	TestFrameworks        []string

	// ── Reachability analysis (exploitability qualifier) ──────────────────
	ReachabilityTotal     int
	ReachabilityByVerdict map[string]int // DIRECT|TRANSITIVE|SEMANTIC|UNREACHABLE
	ReachabilityBySource  map[string]int // TREE_SITTER|SEMANTIC_GREP|SYMBOL_FALLBACK

	// ── Technology currency (end-of-life) ─────────────────────────────────
	EolFindingCount int
	EolProducts     []string

	// ── Binary integrity (container/binary hashing) ───────────────────────
	BinaryCount        int
	BinaryHashedCount  int // rows carrying sha256/ssdeep/tlsh fingerprints
	BinaryMalwareCount int // MalwareBazaar hits

	// ── Identity & access posture (Vulnetix platform accounts) ────────────
	MemberCount          int
	MfaCredentialCount   int
	MfaMemberCount       int
	SsoEnforced          []string // github|google|okta
	PasswordMinLength    int
	PasswordComplexity   []string // upper|lower|number|symbol|banned-substrings
	PasswordReuseBlocked int
	ServiceAccountCount  int
	ApiKeyCount          int

	// ── Data retention / secure disposal ──────────────────────────────────
	PurgeJobCount    int
	PurgeDeletedRows int64
	PurgeLastAt      int64

	// ── Incident response & alerting ──────────────────────────────────────
	AlertCount         int
	AlertByStatus      map[string]int
	AlertByType        map[string]int
	NotifyIntegrations []string // slack|googlechat|webhook|github|…

	// ── SSVC decision records (documented decision methodology) ───────────
	SsvcDecisionCount int
	SsvcMethodologies []string
}

// SnapshotRollup sums IngestionSnapshot's per-run counters across the report
// scope. Every field is an auditable record of how the triage pipeline
// classified ingested results.
type SnapshotRollup struct {
	Ingested    int `json:"ingested"`
	Prioritized int `json:"prioritized"`
	Outcomes    int `json:"outcomes"`

	SsvcAct       int `json:"ssvcAct"`
	SsvcAttend    int `json:"ssvcAttend"`
	SsvcTrackStar int `json:"ssvcTrackStar"`
	SsvcTrack     int `json:"ssvcTrack"`

	Suppressed                int `json:"suppressed"`
	PatchAvailable            int `json:"patchAvailable"`
	PatchPlannedInTolerance   int `json:"patchPlannedInTolerance"`
	NoPatchPossibleTransitive int `json:"noPatchPossibleTransitive"`
	PatchNotReported          int `json:"patchNotReported"`

	ReportedResolved    int `json:"reportedResolved"`
	DisappearedResolved int `json:"disappearedResolved"`
	ResolvedByPolicy    int `json:"resolvedByPolicy"`

	FpByVersion      int `json:"fpByVersion"`
	FpByDistribution int `json:"fpByDistribution"`
	AutoRecastScores int `json:"autoRecastScores"`

	MemoryPublicFacing   int `json:"memoryPublicFacing"`
	MemoryReachability   int `json:"memoryReachability"`
	AttributedToTestCode int `json:"attributedToTestCode"`

	InsufficientDetail   int `json:"insufficientDetail"`
	NeedsTriageDeveloper int `json:"needsTriageDeveloper"`
	NeedsTriageSecurity  int `json:"needsTriageSecurity"`

	TicketRoutedOwner    int `json:"ticketRoutedOwner"`
	TicketRoutedSecurity int `json:"ticketRoutedSecurity"`

	DedupByIdentifier int `json:"dedupByIdentifier"`
	DedupByAsset      int `json:"dedupByAsset"`
	DedupByCategory   int `json:"dedupByCategory"`
	DedupByComponent  int `json:"dedupByComponent"`
}

// Any reports whether the rollup carries any signal at all.
func (s SnapshotRollup) Any() bool {
	return s.Ingested+s.Prioritized+s.Outcomes+s.SsvcAct+s.SsvcAttend+s.SsvcTrackStar+s.SsvcTrack > 0
}

// SsvcTotal is the count of results that reached an SSVC decision.
func (s SnapshotRollup) SsvcTotal() int {
	return s.SsvcAct + s.SsvcAttend + s.SsvcTrackStar + s.SsvcTrack
}

// DedupTotal is the count of results collapsed by the dedup stages.
func (s SnapshotRollup) DedupTotal() int {
	return s.DedupByIdentifier + s.DedupByAsset + s.DedupByCategory + s.DedupByComponent
}

// AutoResolvedTotal is the count closed without human triage.
func (s SnapshotRollup) AutoResolvedTotal() int {
	return s.ReportedResolved + s.DisappearedResolved + s.ResolvedByPolicy
}

// ManualEvidenceCount returns how many evidence files the customer attached to
// a control. Zero when none, including when the map itself is absent (the
// per-scan mappers, which have no report to attach anything to).
func (c ReportContext) ManualEvidenceCount(controlID string) int {
	return c.ManualEvidenceByControl[controlID]
}

// HasRiskStrategy reports whether an ordered risk-prioritization strategy backs
// the org's remediation ordering. This is true for the seeded system default,
// which every organization gets without configuring anything — so it answers
// "is a ranking in force", and evidence text that cites it must say which one.
func (c ReportContext) HasRiskStrategy() bool { return c.RiskStrategyRuleCount > 0 }

// HasOrgRiskStrategy reports whether *the organization* authored the ranking.
//
// Controls that ask whether an entity has established, documented or defined a
// risk-evaluation method must use this rather than HasRiskStrategy: a vendor
// default in force is a product behaviour, not a decision the organization
// made, and a report that grades the two the same certifies a customer for
// having done nothing.
func (c ReportContext) HasOrgRiskStrategy() bool {
	return c.RiskStrategyRuleCount > 0 && c.RiskStrategyIsCustom
}

// QualityGateBlockEnabled reports whether a named build-breaking toggle is on.
func (c ReportContext) QualityGateBlockEnabled(name string) bool {
	for _, b := range c.QualityGateBlocks {
		if b == name {
			return true
		}
	}
	return false
}

// HasRemediationSLA reports whether per-severity remediation windows are set.
func (c ReportContext) HasRemediationSLA() bool {
	for _, d := range c.RemediationDaysBySev {
		if d > 0 {
			return true
		}
	}
	return false
}

// ScannerCategoryCount is the number of distinct scanner categories exercised.
func (c ReportContext) ScannerCategoryCount() int { return len(c.ScannerRunByCategory) }

// HasScannerCategory reports whether any run classified into the named
// category (matching either the ScannerRun.category free text or the strict
// IngestionSnapshot.category enum).
func (c ReportContext) HasScannerCategory(names ...string) bool {
	for _, n := range names {
		if c.ScannerRunByCategory[n] > 0 || c.SnapshotByCategory[n] > 0 {
			return true
		}
	}
	return false
}

// ScannerCategoryRuns totals runs across the named category aliases.
func (c ReportContext) ScannerCategoryRuns(names ...string) int {
	total := 0
	for _, n := range names {
		total += c.ScannerRunByCategory[n]
		if c.ScannerRunByCategory[n] == 0 {
			total += c.SnapshotByCategory[n]
		}
	}
	return total
}

// ReachableCount is the count of findings reachability analysis did not rule
// out (anything other than an explicit UNREACHABLE verdict).
func (c ReportContext) ReachableCount() int {
	return c.ReachabilityByVerdict["DIRECT"] + c.ReachabilityByVerdict["TRANSITIVE"] + c.ReachabilityByVerdict["SEMANTIC"]
}

// MapReport returns the EU AI Act article mappings for a whole report.
func MapReport(ctx ReportContext) []ArticleMapping {
	arts := mapReportArticles(ctx)
	for i := range arts {
		StampInventoryRefs(ctx, arts[i].Evidence)
	}

	return arts
}

func mapReportArticles(ctx ReportContext) []ArticleMapping {
	return []ArticleMapping{
		// Articles 5 and 6 were absent from the report entirely, and their
		// absence was not neutral. The six high-risk articles below assert
		// "High-risk AI systems must …" and were emitted for every
		// organization unconditionally, so an estate whose only AI is a coding
		// assistant was reported against the full high-risk obligation set —
		// while the risk pyramid's "Unacceptable risk" apex sat permanently
		// empty, which reads as "no prohibited practices found" when the truth
		// was that Article 5 was never evaluated.
		//
		// Neither is derivable from a component inventory: Annex III turns on
		// what the system is *used for* (biometrics, employment, credit), not
		// on which libraries it imports. So both are emitted as what they are —
		// the organization's determination — and both are promotable by
		// attaching it.
		reportArticle5(ctx),
		reportArticle6(ctx),
		reportArticle9(ctx),
		reportArticle10(ctx),
		reportArticle11(ctx),
		reportArticle12(ctx),
		reportArticle14(ctx),
		reportArticle15(ctx),
		reportArticle50(ctx),
		reportArticle51(ctx),
		reportArticle72(ctx),
		reportArticle13(ctx),
	}
}

// reportArticle5 covers the prohibited practices. Nothing in a software bill of
// materials reveals whether a system does social scoring or untargeted facial
// scraping — those are properties of how it is used — so this is the
// organization's declaration, and the report says so instead of leaving the
// question off the page.
func reportArticle5(ctx ReportContext) ArticleMapping {
	const id = "Article 5"
	m := article(id, "Prohibited AI practices",
		"Certain practices are banned outright: manipulative or exploitative techniques, social scoring, untargeted facial-image scraping, emotion inference at work or school, and real-time remote biometric identification in public spaces.")
	if n := ctx.ManualEvidenceCount(id); n > 0 {
		m.Status = StatusSatisfied
		m.Rationale = "The organization has recorded its assessment against the prohibited practices (" +
			plural(n, "attached document") + "). Vulnetix cannot observe how a system is used — an assessor samples the attachment."
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "Prohibited-practices assessment, supplied by the organization",
		})

		return m
	}
	m.Status = StatusInformational
	m.Rationale = "Not evaluated. Whether a system performs a prohibited practice depends on what it is used for, which no inventory or scan reveals — this is not a finding of compliance, and an empty result here must not be read as one. Record the assessment as manual evidence."
	m.Gaps = append(m.Gaps, "No prohibited-practices assessment on record")

	return m
}

// reportArticle6 covers the classification rules. Annex III turns on the use
// case, so the tier is the organization's to declare; without it the high-risk
// articles in this report are reported unconditionally and say so here.
func reportArticle6(ctx ReportContext) ArticleMapping {
	const id = "Article 6"
	m := article(id, "Classification of high-risk AI systems",
		"A system is high-risk when it is a safety component of a regulated product, or falls within an Annex III use case; the provider must document the classification.")
	if n := ctx.ManualEvidenceCount(id); n > 0 {
		m.Status = StatusSatisfied
		m.Rationale = "The organization has documented its Annex III classification (" +
			plural(n, "attached document") + "), so the high-risk obligations in this report are reported against a declared scope."
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "Annex III classification, supplied by the organization",
		})

		return m
	}
	m.Status = StatusInformational
	m.Rationale = "No Annex III classification is on record. Annex III turns on the system's purpose — biometrics, education, employment, essential services — which is not derivable from a component inventory, so every high-risk article in this report is reported unconditionally: they state what would be required if the system is high-risk, not a finding that it is."
	m.Gaps = append(m.Gaps, "No documented Annex III classification — the high-risk articles below are unscoped")

	return m
}

// reportArticle13 covers instructions for use. Vulnetix holds none of this —
// it is a provider-authored document — so the article's only path is the
// customer attaching it. That path used to be closed: the article was
// hardwired not-applicable while its own rationale asked for an upload.
func reportArticle13(ctx ReportContext) ArticleMapping {
	const id = "Article 13"
	m := article(id, "Instructions for use",
		"Providers must supply deployers with instructions covering the system's characteristics, capabilities and limitations.")
	n := ctx.ManualEvidenceCount(id)
	if n == 0 {
		// Informational, not not-applicable. This article applies to every
		// provider; what is missing is the evidence, and "not applicable" says
		// the obligation is out of scope — a different and stronger claim than
		// the one the data supports. It reads the same as Articles 5 and 6,
		// which are unevidenceable for the same reason.
		m.Status = StatusInformational
		m.Rationale = "Not evaluable from Vulnetix data — instructions-for-use are provider-authored documents. This is not a finding that the obligation does not apply; upload the instructions as manual evidence against this article and it will be assessed."
		m.Gaps = append(m.Gaps, "No instructions-for-use document on record")

		return m
	}
	m.Status = StatusSatisfied
	m.Rationale = "Satisfied on customer-supplied evidence: " + plural(n, "document") +
		" attached to this article. Vulnetix does not read the contents — an assessor samples the attachment itself."
	m.Evidence = append(m.Evidence, EvidenceItem{
		Component: plural(n, "attached document"), Kind: "manual",
		Detail: "Instructions for use, supplied by the organization",
	})

	return m
}

func classifyReport(ctx ReportContext) (models, services, datasets, training, accelerators, agents []Component, gapped int) {
	for _, c := range ctx.Components {
		switch {
		case c.isModel():
			models = append(models, c)
		case c.isAIService() || c.isDeployedAIRuntime():
			services = append(services, c)
		}
		switch c.Category {
		case "training":
			training = append(training, c)
		case "accelerator":
			accelerators = append(accelerators, c)
		}
		if c.isDataset() {
			datasets = append(datasets, c)
		}
		if c.Category == "coding-agent" || c.Category == "agent" {
			agents = append(agents, c)
		}
		if c.ConfidenceGap {
			gapped++
		}
	}
	sortByName(models)
	sortByName(services)
	sortByName(datasets)
	return
}

func invLink(ctx ReportContext) string {
	if ctx.LatestAibomScanUUID != "" {
		return routeInventory + "/" + ctx.LatestAibomScanUUID
	}
	return routeInventory
}

// StampInventoryRefs fills RefID on evidence drawn from the AI inventory, using
// the scan the inventory came from.
//
// RefID was declared in the Go struct, declared in the TypeScript type, and
// populated by nothing. Every AI-report evidence item that links to the
// inventory is derived from one identifiable scan, so the id exists — it was
// simply never carried through, and an assessor sampling a control could not
// name the record they checked.
//
// Applied as one pass over the built evidence rather than threaded through the
// two dozen call sites: the id is the same for all of them, and a post-pass
// cannot be forgotten at a new call site the way an extra argument can.
func StampInventoryRefs(ctx ReportContext, evidence []EvidenceItem) {
	if ctx.LatestAibomScanUUID == "" {
		return
	}
	for i := range evidence {
		if evidence[i].RefID != "" {
			continue
		}
		if strings.HasPrefix(evidence[i].Link, routeInventory) {
			evidence[i].RefID = ctx.LatestAibomScanUUID
		}
	}
}

// reportArticle9 covers the risk-management system: a continuous, iterated
// process that identifies risks, evaluates them, and adopts targeted measures.
// Vulnetix evidences this directly — the risk-prioritization strategy is the
// documented evaluation method, the triage policy sets the treatment windows,
// and the snapshot rollup is the per-iteration record.
func reportArticle9(ctx ReportContext) ArticleMapping {
	m := article("Article 9", "Risk management system",
		"A risk management system must be established, implemented, documented and maintained as a continuous iterative process across the system's lifecycle: identifying risks, estimating and evaluating them, and adopting targeted risk-management measures.")

	identified := ctx.FindingTotal > 0 || ctx.ScannerRunCount > 0
	if !identified && !ctx.HasRiskStrategy() && !ctx.HasTriagePolicy {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no risk-identification activity, ranking strategy or remediation policy exists for the scope."
		m.Gaps = append(m.Gaps, "No risk-management system evidence found")
		return m
	}

	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "risk identification", Kind: "scan",
			Detail: plural(ctx.ScannerRunCount, "assessment run") + " across " + plural(ctx.ScannerCategoryCount(), "analysis category") +
				" identified " + plural(ctx.FindingTotal, "risk"),
			Link: routeScans,
		})
	}
	if ctx.HasRiskStrategy() {
		scope := "the seeded system default"
		if ctx.RiskStrategyIsCustom {
			scope = "organization-authored"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "risk evaluation method", Kind: "policy",
			Detail: quote(ctx.RiskStrategyName) + " (" + scope + "): " + plural(ctx.RiskStrategyRuleCount, "enabled rule") +
				" estimate and evaluate every identified risk in a fixed, reproducible order",
			Link: routeRiskStrategy,
		})
	} else {
		m.Gaps = append(m.Gaps, "No documented risk-ranking method — risk estimation is not reproducible")
	}
	// The strategy is the method; the decisions are the method having been
	// applied, which is what "evaluated" in Article 9 asks for. ISO 27001
	// C.6.1.2, NIST GOVERN 3.1, Exposure and CRA all cite these records —
	// Article 9 cited the strategy and left the decisions themselves unread.
	if ctx.SsvcDecisionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.SsvcDecisionCount, "recorded risk decision"), Kind: "policy",
			Detail: "Each evaluation is reproducible from its recorded inputs" +
				methodologyClause(ctx.SsvcMethodologies),
			Link: routeFindings,
		})
	}
	// Article 9 requires the risk-management system to run "across the
	// lifecycle", which starts at design. A persisted threat model is the only
	// machine record of design-time risk analysis this product holds, and it
	// was visible to DSOMM alone.
	if ctx.ThreatModelCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(ctx.ThreatModelCount, "threat model"), Kind: "policy",
			Detail: joinNames(ctx.ThreatModelMethodologies, "documented") + " methodology across " +
				plural(ctx.ThreatModelElementCount, "placed element") + ", " +
				plural(ctx.ThreatModelWithAttackPath, "model") + " linked to an attack path, " +
				plural(ctx.ThreatAnnotationCount, "recorded annotation") +
				" — risk identified at design time rather than only after a scan",
			Link: routeThreatModel,
		})
	}
	if ctx.HasRemediationSLA() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "targeted risk measures", Kind: "policy",
			Detail: "Policy " + quote(ctx.TriagePolicyName) + " commits to remediation within " +
				itoa(ctx.RemediationDaysBySev["critical"]) + "/" + itoa(ctx.RemediationDaysBySev["high"]) + "/" +
				itoa(ctx.RemediationDaysBySev["medium"]) + "/" + itoa(ctx.RemediationDaysBySev["low"]) +
				" days by severity, with a " + itoa(ctx.TriageThresholdDays) + "-day triage threshold",
			Link: routePolicies,
		})
	} else {
		m.Gaps = append(m.Gaps, "No per-severity remediation window — risk treatment is unbounded in time")
	}
	if ctx.Snapshot.Any() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "iteration record", Kind: "log",
			Detail: itoa(ctx.Snapshot.Ingested) + " risk(s) ingested, " + itoa(ctx.Snapshot.Prioritized) + " prioritized, " +
				itoa(ctx.Snapshot.Outcomes) + " driven to an outcome; " + itoa(ctx.Snapshot.SsvcTotal()) +
				" carry an SSVC disposition — the per-iteration record of the process running",
			Link: routeScans,
		})
	}
	if ctx.QualityGateConfigured {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "enforced measures", Kind: "policy",
			Detail: "Build gate blocks " + joinNames(ctx.QualityGateBlocks, "no categories") + " at severity floor " +
				quote(ctx.QualityGateSeverity) + "; " + itoa(ctx.CliBreakBuildCount) + " of " + itoa(ctx.CliRunCount) +
				" pipeline run(s) set to break the build",
			Link: routeGate,
		})
	}
	if ctx.AiFirewallConfigured {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "runtime measures", Kind: "policy",
			Detail: plural(ctx.AiFirewallGuardrailCount, "guardrail") + " constrain model use at the gateway",
			Link:   routeAiFirewall,
		})
	}

	switch {
	// Satisfied requires the organization to have authored the ranking. The
	// seeded system default is in force for every tenant that configured
	// nothing, and Article 9 obliges the *provider* to establish, implement,
	// document and maintain the system — a vendor default is not that.
	case ctx.HasOrgRiskStrategy() && ctx.HasRemediationSLA() && identified:
		m.Status = StatusSatisfied
		m.Rationale = "The risk-management system is continuous and documented end to end: risks are identified by recurring assessment, evaluated by an ordered ranking strategy the organization authored, and treated within committed per-severity windows."
	case ctx.HasRiskStrategy() && ctx.HasRemediationSLA() && identified:
		m.Status = StatusPartial
		m.Rationale = "Risks are identified continuously and treated within committed windows, but they are evaluated by Vulnetix's seeded default ranking rather than a method this organization established — Article 9 places that obligation on the provider."
		m.Gaps = append(m.Gaps, "The risk-evaluation method in force is the product default, not an organization-authored strategy")
	case identified:
		m.Status = StatusPartial
		m.Rationale = "Risks are identified continuously, but the evaluation method or the treatment commitment is not fully documented."
	default:
		m.Status = StatusPartial
		m.Rationale = "Risk-management policy is configured, but no assessment activity in the period exercised it."
		m.Gaps = append(m.Gaps, "No assessment runs in the period")
	}
	return m
}

func quote(s string) string { return `"` + s + `"` }

func itoa64(n int64) string { return itoa(int(n)) }

func joinNames(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	out := list[0]
	for _, s := range list[1:] {
		out += ", " + s
	}
	return out
}

func reportArticle10(ctx ReportContext) ArticleMapping {
	m := article("Article 10", "Data and data governance",
		"High-risk AI systems trained on data must use datasets subject to appropriate governance; data provenance and use must be documented.")
	_, _, datasets, training, _, _, _ := classifyReport(ctx)
	if len(datasets) == 0 && len(training) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no datasets or training frameworks are recorded in the in-scope AI inventory."
		m.Gaps = append(m.Gaps, "No datasets or training infrastructure found")
		return m
	}
	for _, d := range datasets {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: d.Name, Kind: "dataset", Detail: "Dataset artifact in the AI inventory", Link: invLink(ctx)})
	}
	for _, t := range training {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: t.Name, Kind: "runtime", Detail: "Training framework — in-house training data governance applies", Link: invLink(ctx)})
	}
	if len(datasets) == 0 {
		m.Status = StatusPartial
		m.Rationale = "Training infrastructure is inventoried, but no concrete dataset artifact was resolved."
		m.Gaps = append(m.Gaps, "No dataset artifact resolved")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "Datasets and the infrastructure that consumes them are inventoried."
	}
	return m
}

func reportArticle11(ctx ReportContext) ArticleMapping {
	m := article("Article 11 / Annex IV", "Technical documentation",
		"Providers must draw up technical documentation describing the system's components, architecture, provenance and known limitations.")
	sbom := ctx.CycloneDXCount + ctx.SPDXCount
	if len(ctx.Components) == 0 && sbom == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no AI inventory or SBOM technical documentation is recorded for the scope."
		m.Gaps = append(m.Gaps, "No AI-BOM or SBOM found")
		return m
	}
	if len(ctx.Components) > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(len(ctx.Components), "AI component"), Kind: "provenance", Detail: "Enumerated in a CycloneDX AI-BOM", Link: invLink(ctx)})
	}
	if sbom > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(sbom, "SBOM"), Kind: "sbom", Detail: "CycloneDX/SPDX technical documentation of software components", Link: routeUploads})
	}
	_, _, _, _, _, _, gapped := classifyReport(ctx)
	if gapped > 0 {
		m.Status = StatusPartial
		m.Rationale = "The system is documented; " + plural(gapped, "component") + " carry an explicit limitation (Annex IV §2(g))."
		m.Gaps = append(m.Gaps, plural(gapped, "component")+" with a stated unverifiable value")
	} else {
		m.Status = StatusSatisfied
		m.Rationale = "AI components and software SBOMs together document the system with no unresolved limitations."
	}
	return m
}

func reportArticle12(ctx ReportContext) ArticleMapping {
	m := article("Article 12", "Record-keeping",
		"High-risk AI systems must technically allow automatic recording of events (logs) over their lifetime; maintain an inventory and record changes.")
	if ctx.AccessLogCount == 0 && ctx.ScannerRunCount == 0 && ctx.AibomScanCount == 0 && ctx.AiFirewallRequestCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no event logs, scan records or inventory history are recorded for the scope."
		m.Gaps = append(m.Gaps, "No access-log, scanner-run or inventory records found")
		if ctx.AiFirewallConfigured && !ctx.AiFirewallLogsEnabled {
			m.Gaps = append(m.Gaps, "AI gateway configured but inference logging is disabled — runtime AI events are not recorded")
		}
		return m
	}
	if ctx.AccessLogCount > 0 {
		detail := "Recorded API access events over the period"
		if ctx.AccessLogWithIdentity > 0 {
			detail = itoa(ctx.AccessLogWithIdentity) + " of " + itoa(ctx.AccessLogCount) +
				" event(s) attributable to a named identity across " + plural(ctx.AccessLogMemberCount, "account") +
				"; " + itoa(ctx.AccessLogWithSource) + " carry a source address"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AccessLogCount, "access-log event"), Kind: "log", Detail: detail, Link: routeLogs})
	}
	if ctx.Snapshot.Any() {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "assessment accounting", Kind: "log",
			Detail: itoa(ctx.Snapshot.Ingested) + " result(s) ingested, " + itoa(ctx.Snapshot.Outcomes) +
				" driven to an outcome, " + itoa(ctx.Snapshot.DedupTotal()) + " deduplicated — an automatic, per-run event record",
			Link: routeScans,
		})
	}
	if ctx.PurgeJobCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "retention control", Kind: "policy",
			Detail: plural(ctx.PurgeJobCount, "data-disposal job") + " executed, removing " + itoa64(ctx.PurgeDeletedRows) +
				" stored record(s) — logs are retained under an enforced lifecycle, not indefinitely",
		})
	}
	if ctx.ScannerRunCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "scanner run"), Kind: "scan", Detail: "Recorded assessment runs", Link: routeScans})
	}
	if ctx.AibomScanCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AibomScanCount, "AI-BOM scan"), Kind: "provenance", Detail: "Inventory revisions recorded over time", Link: routeInventory})
	}
	// A counter that can clear this article's guard must also be able to emit
	// evidence, or the article reports satisfied citing nothing.
	if ctx.AiFirewallRequestCount > 0 {
		detail := "Runtime AI events recorded by the AI Firewall gateway (decisions, tokens, latency; no content)"
		if !ctx.AiFirewallLogsEnabled {
			detail = "Gateway inference volume observed; per-inference logging is currently disabled"
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference log"), Kind: "log", Detail: detail, Link: routeAiFirewall})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Events are automatically recorded (access logs, assessment runs and inventory revisions) across the reporting period."
	if ctx.AiFirewallConfigured && !ctx.AiFirewallLogsEnabled {
		m.Gaps = append(m.Gaps, "AI gateway configured but inference logging is disabled — runtime AI events are not recorded")
	}
	return m
}

func reportArticle14(ctx ReportContext) ArticleMapping {
	m := article("Article 14", "Human oversight",
		"High-risk AI systems must be designed so that natural persons can effectively oversee them.")
	_, _, _, _, _, agents, _ := classifyReport(ctx)
	humanReview := ctx.AffectedTotal + ctx.NotAffectedTotal + ctx.UnderInvestigationTotal
	if len(agents) == 0 && humanReview == 0 && ctx.SuppressionCount == 0 && ctx.AiFirewallGuardrailCount == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no autonomous agents and no human triage/oversight records found."
		m.Gaps = append(m.Gaps, "No agent autonomy surface and no human review records")
		return m
	}
	for _, a := range agents {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "agent", Detail: "Autonomous agent requiring oversight", Link: invLink(ctx)})
	}
	if humanReview > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(humanReview, "finding"), Kind: "finding", Detail: "Human-reviewed triage decisions (affected/not-affected/under-investigation)", Link: routeFindings})
	}
	if ctx.SuppressionCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.SuppressionCount, "suppression"), Kind: "vex", Detail: "Human risk-acceptance decisions"})
	}
	if ctx.AiFirewallGuardrailCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallGuardrailCount, "guardrail"), Kind: "policy", Detail: "Human-defined runtime constraints (blocked patterns / PII redaction / message limits) enforced on every gateway inference", Link: routeAiFirewall})
	}
	if len(agents) > 0 && !ctx.AiFirewallConfigured {
		m.Gaps = append(m.Gaps, "Detected autonomous agents have no runtime gateway/guardrails")
	}
	switch {
	case humanReview > 0 || ctx.SuppressionCount > 0:
		m.Status = StatusSatisfied
		m.Rationale = "Human oversight is evidenced by reviewed triage decisions and risk-acceptance records over the period."
	case len(agents) > 0:
		m.Status = StatusInformational
		m.Rationale = plural(len(agents), "autonomous agent") + " detected; the oversight surface is flagged but no human-review records were found in scope."
	default:
		m.Status = StatusPartial
		m.Rationale = "Runtime guardrails constrain model use; no human triage records found in scope."
	}
	return m
}

func reportArticle15(ctx ReportContext) ArticleMapping {
	m := article("Article 15", "Accuracy, robustness & cybersecurity",
		"High-risk systems must achieve appropriate accuracy, robustness and cybersecurity over their lifecycle.")
	securityTesting := ctx.ScannerRunCount
	if securityTesting == 0 && !ctx.HasEvaluation && ctx.FindingTotal == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no security testing runs, evaluation workloads or findings are recorded for the scope."
		m.Gaps = append(m.Gaps, "No assessment runs or findings found")
		return m
	}
	if securityTesting > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(securityTesting, "assessment run"), Kind: "scan", Detail: "Automated security/robustness testing (SAST/SCA/secrets/IaC/container)", Link: routeScans})
	}
	if ctx.FindingTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.FindingTotal, "finding"), Kind: "finding", Detail: "Weaknesses identified and tracked", Link: routeFindings})
	}
	// HasEvaluation is `Finding.isTestSuite` — a security finding located in
	// test code. It says the codebase has a test suite; it says nothing about a
	// model having been evaluated, and calling it "Model evaluation/benchmark
	// workload present" put the only accuracy-shaped sentence in the report on
	// top of a security counter.
	if ctx.HasEvaluation {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "test-suite code", Kind: "finding",
			Detail: "Findings located in test-suite code — the codebase carries automated tests, which is robustness evidence rather than model accuracy evidence",
			Link:   routeFindings,
		})
	}
	if ctx.CliTestConfigCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "test configuration", Kind: "provenance",
			Detail: plural(ctx.CliTestConfigCount, "test configuration") + " detected (" + joinNames(ctx.TestFrameworks, "unclassified frameworks") + ")",
			Link:   routeScans,
		})
	}
	// The real accuracy signal: evaluation tooling recorded in the AI-BOM.
	var evaluations []Component
	for _, c := range ctx.Components {
		if c.Category == "evaluation" {
			evaluations = append(evaluations, c)
		}
	}
	sortByName(evaluations)
	for _, e := range evaluations {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: e.Name, Kind: "evaluation",
			Detail: "AI evaluation tooling in the inventory — the machine record of accuracy/benchmark assessment",
			Link:   invLink(ctx),
		})
	}
	if ctx.ReachabilityTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "reachability analysis", Kind: "analysis",
			Detail: plural(ctx.ReachabilityTotal, "call-path verdict") + ": " + itoa(ctx.ReachableCount()) +
				" reachable, " + itoa(ctx.ReachabilityByVerdict["UNREACHABLE"]) + " ruled unreachable — robustness claims are call-path evidenced",
			Link: routeFindings,
		})
	}
	if ctx.SarifResultTotal > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "result review", Kind: "review",
			Detail: itoa(ctx.SarifResultReviewed) + " of " + itoa(ctx.SarifResultTotal) + " analysis result(s) carry a reviewer disposition",
			Link:   routeFindings,
		})
	}
	if ctx.QualityGateConfigured && ctx.CliBreakBuildCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: "build-time enforcement", Kind: "policy",
			Detail: itoa(ctx.CliBreakBuildCount) + " of " + itoa(ctx.CliRunCount) + " pipeline run(s) set to break the build; " +
				itoa(ctx.CliFailedGateCount) + " stopped a change from shipping",
			Link: routeGate,
		})
	}
	if ctx.AiFirewallConfigured {
		detail := "Runtime input/output controls at the AI gateway: " + plural(ctx.AiFirewallGuardrailCount, "guardrail")
		if pol := ctx.AiFirewallProviderPolicyCount + ctx.AiFirewallModelPolicyCount; pol > 0 {
			detail += ", " + plural(pol, "provider/model policy")
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: "AI Firewall", Kind: "policy", Detail: detail, Link: routeAiFirewall})
		if ctx.AiFirewallLogsEnabled && ctx.AiFirewallRequestCount > 0 {
			m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.AiFirewallRequestCount, "gateway inference"), Kind: "log", Detail: itoa(ctx.AiFirewallBlockCount) + " blocked, " + itoa(ctx.AiFirewallRedactCount) + " redacted, " + itoa(ctx.AiFirewallFlagCount) + " flagged inference(s) over the period", Link: routeAiFirewall})
		}
	}
	models, services, _, _, _, _, _ := classifyReport(ctx)
	if (len(models) > 0 || len(services) > 0) && !ctx.AiFirewallConfigured {
		m.Status = StatusPartial
		m.Rationale = "Cybersecurity and robustness are assessed via automated testing, but the inventoried models run without runtime input/output controls."
		m.Gaps = append(m.Gaps, "No runtime input/output controls in front of inventoried models — prompt-level attacks unmitigated")
		return m
	}
	// Article 15 names three obligations and this telemetry covers two of them.
	// The satisfied claim used to be made on the strength of security testing
	// alone, with a rationale that quietly listed only the two it could speak
	// to while the article's own title leads with accuracy.
	if len(evaluations) == 0 {
		m.Status = StatusPartial
		m.Rationale = "Cybersecurity and robustness are continuously assessed via automated testing runs with tracked findings across the period. Accuracy — the first obligation this article names — is not evidenced: no AI evaluation or benchmark tooling is recorded in the inventory."
		m.Gaps = append(m.Gaps, "No accuracy or benchmark evidence for the inventoried AI systems")

		return m
	}
	m.Status = StatusSatisfied
	m.Rationale = "All three obligations are evidenced: cybersecurity and robustness by continuous automated testing with tracked findings, and accuracy by the evaluation tooling recorded in the AI inventory."
	return m
}

func reportArticle50(ctx ReportContext) ArticleMapping {
	m := article("Article 50", "Transparency obligations",
		"Deployers must disclose the AI they use; GPAI model identity, purpose, provider and provenance must be transparent.")
	models, services, _, _, _, _, _ := classifyReport(ctx)
	if len(models) == 0 && len(services) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no models or AI services are recorded in the in-scope inventory."
		m.Gaps = append(m.Gaps, "No models or AI services found")
		return m
	}
	missing := 0
	for _, mdl := range models {
		detail := "Model identity disclosed"
		if mdl.Provider != "" {
			detail += " (provider " + mdl.Provider + ")"
		}
		if mdl.Task != "" {
			detail += " for " + mdl.Task
		}
		m.Evidence = append(m.Evidence, EvidenceItem{Component: mdl.Name, Kind: "model", Detail: detail, Link: invLink(ctx)})
		if mdl.Provider == "" && mdl.Family == "" {
			missing++
		}
	}
	for _, s := range services {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: s.Name, Kind: "service", Detail: "AI service/runtime dependency disclosed", Link: invLink(ctx)})
	}
	switch {
	case len(models) == 0:
		m.Status = StatusPartial
		m.Rationale = "AI service usage is disclosed, but no concrete model identity was resolved."
		m.Gaps = append(m.Gaps, "Service-level disclosure only")
	case missing > 0:
		m.Status = StatusPartial
		m.Rationale = "Model identities are disclosed; some lack a resolved provider or family."
		m.Gaps = append(m.Gaps, plural(missing, "model")+" without a resolved provider/family")
	default:
		m.Status = StatusSatisfied
		m.Rationale = "Every detected model discloses provider/family and purpose, and AI services are enumerated."
	}
	return m
}

func reportArticle51(ctx ReportContext) ArticleMapping {
	m := article("Articles 51-55", "General-purpose AI & systemic risk",
		"GPAI models, especially those trained with very large compute, carry additional obligations; systemic-risk classification hinges on training compute.")
	models, _, _, _, accelerators, _, _ := classifyReport(ctx)
	var gpai []Component
	for _, mdl := range models {
		if mdl.Family != "" {
			gpai = append(gpai, mdl)
		}
	}
	if len(accelerators) == 0 && len(gpai) == 0 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — no accelerator compute and no identified general-purpose model family found."
		m.Gaps = append(m.Gaps, "No GPAI/compute signals found")
		return m
	}
	for _, a := range accelerators {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: a.Name, Kind: "accelerator", Detail: "Accelerator compute — a systemic-risk classification input", Link: invLink(ctx)})
	}
	for _, g := range gpai {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: g.Name, Kind: "model", Detail: "General-purpose model family " + g.Family, Link: invLink(ctx)})
	}
	// The FLOP figure is the one thing that decides systemic-risk
	// classification and the one thing this product cannot measure, so the
	// customer's own attestation is the only way this article moves.
	if n := ctx.ManualEvidenceCount("Articles 51-55"); n > 0 {
		m.Status = StatusSatisfied
		m.Rationale = "GPAI/compute signals are present, and the systemic-risk assessment is supplied as customer evidence (" +
			plural(n, "attached document") + "). Vulnetix does not measure training compute — an assessor samples the attachment."
		m.Evidence = append(m.Evidence, EvidenceItem{
			Component: plural(n, "attached document"), Kind: "manual",
			Detail: "Systemic-risk / training-compute assessment, supplied by the organization",
		})

		return m
	}
	m.Status = StatusInformational
	m.Rationale = "GPAI/compute signals are present. The systemic-risk threshold is a training-compute (FLOP) figure Vulnetix does not measure — attach the assessment as manual evidence and it will be reported."
	m.Gaps = append(m.Gaps, "Training compute (FLOP) not measured")
	return m
}

func reportArticle72(ctx ReportContext) ArticleMapping {
	m := article("Article 72", "Post-market monitoring",
		"Providers must actively and systematically collect and review information about the system throughout its lifetime.")
	monitoring := ctx.IngestionSnapshotCount + ctx.PriorScanCount
	if monitoring <= 1 && ctx.ScannerRunCount <= 1 {
		m.Status = StatusGap
		m.Rationale = "Evaluated — only a single point-in-time record exists; monitoring requires repeated assessment over time."
		m.Gaps = append(m.Gaps, "No monitoring history yet")
		return m
	}
	if ctx.IngestionSnapshotCount > 0 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.IngestionSnapshotCount, "assessment snapshot"), Kind: "scan", Detail: "Risk posture recorded over time", Link: routeScans})
	}
	if ctx.PriorScanCount > 1 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.PriorScanCount, "AI-BOM scan"), Kind: "provenance", Detail: "AI inventory regenerated over time", Link: routeInventory})
	}
	// ScannerRunCount alone can clear this article's guard, so it must be able
	// to carry the claim too.
	if ctx.ScannerRunCount > 1 {
		m.Evidence = append(m.Evidence, EvidenceItem{Component: plural(ctx.ScannerRunCount, "assessment run"), Kind: "scan", Detail: "Repeated assessment of the estate over the period", Link: routeScans})
	}
	m.Status = StatusSatisfied
	m.Rationale = "Repeated assessments and inventory revisions across the period evidence systematic post-market monitoring."
	return m
}

// SummarizeReport rolls report-level mappings into a Summary (same shape as
// SummarizeArticles).
func SummarizeReport(ms []ArticleMapping) Summary { return SummarizeArticles(ms) }

// NoteLoadFailure records that an evidence source could not be read. Callers
// pass the source name, not the raw driver error: the message reaches an
// auditor-facing document, and "Suppression" is useful to them where
// `SQLSTATE 42703` is not.
func (c *ReportContext) NoteLoadFailure(source string) {
	for _, s := range c.LoadFailures {
		if s == source {
			return
		}
	}
	c.LoadFailures = append(c.LoadFailures, source)
}

// DataIntegrityNote is the sentence a report must carry when any evidence
// source failed to load. Empty when everything loaded.
func (c ReportContext) DataIntegrityNote() string {
	if len(c.LoadFailures) == 0 {
		return ""
	}

	return "INCOMPLETE DATA: " + strings.Join(c.LoadFailures, ", ") +
		" could not be read when this report was generated. Counts drawn from those sources are zero because the data is missing, not because nothing was found, so any conclusion resting on them is unsupported."
}

// methodologyClause names the decision methodologies behind recorded risk
// decisions, so "reproducible from its recorded inputs" says reproducible
// under what.
func methodologyClause(methodologies []string) string {
	if len(methodologies) == 0 {
		return ""
	}

	return " using " + joinNames(methodologies, "the configured methodology")
}
