package cyclonedx

import (
	"encoding/json"
	"testing"
)

func authoringFixture(specVersion string) (*Document, Authorship) {
	doc := NewDocument(specVersion)
	// component.version is required before 1.4, so the fixture carries one; this
	// test is about authorship, not about the subject component.
	doc.Metadata.Component = &Component{Type: "application", BOMRef: "urn:project", Name: "subject", Version: "0.1.0"}
	return doc, Authorship{
		Manufacturer: &OrganizationalEntity{Name: "Acme Corp", URL: []string{"https://github.com/acme"}},
		Tool:         VulnetixTool(ToolSCA, "3.98.0"),
		Phases:       []LifecyclePhase{PhasePreBuild, PhaseBuild},
	}
}

// Every spec version this module bundles must produce a valid document from the
// same authorship. The projection is what makes that true; without it, asking
// for a manufacturer and emitting at 1.5 produces a document that fails its own
// schema, and the failure surfaces at whatever consumer reads it rather than
// here.
func TestAuthorshipValidatesAtEverySupportedSpecVersion(t *testing.T) {
	for _, spec := range SupportedVersionsAscending() {
		t.Run(spec, func(t *testing.T) {
			doc, a := authoringFixture(spec)
			if _, err := ApplyAuthorship(doc, a); err != nil {
				t.Fatalf("ApplyAuthorship: %v", err)
			}
			data, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, violations, err := ValidateCycloneDX(data); err != nil {
				t.Fatalf("validate: %v\n%s", err, data)
			} else if len(violations) > 0 {
				t.Fatalf("author-tier document invalid at %s: %s: %s\n%s",
					spec, violations[0].Path, violations[0].Message, data)
			}

			// And the same document after a transformer has touched it.
			if err := AppendToolParticipation(doc, VulnetixTool(ToolBOMEnrich, "3.98.0")); err != nil {
				t.Fatalf("AppendToolParticipation: %v", err)
			}
			data, err = json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, violations, err := ValidateCycloneDX(data); err != nil {
				t.Fatalf("validate: %v", err)
			} else if len(violations) > 0 {
				t.Fatalf("transformer-tier document invalid at %s: %s: %s\n%s",
					spec, violations[0].Path, violations[0].Message, data)
			}
		})
	}
}

func TestApplyAuthorshipStampsEveryIdentityMember(t *testing.T) {
	doc, a := authoringFixture("1.7")
	if _, err := ApplyAuthorship(doc, a); err != nil {
		t.Fatalf("ApplyAuthorship: %v", err)
	}
	switch {
	case doc.SerialNumber == "":
		t.Error("serialNumber not set")
	case doc.Version != 1:
		t.Errorf("version = %d, want 1", doc.Version)
	case doc.Metadata.Timestamp == "":
		t.Error("timestamp not set")
	case doc.Metadata.Manufacturer == nil || doc.Metadata.Manufacturer.Name != "Acme Corp":
		t.Errorf("manufacturer = %#v", doc.Metadata.Manufacturer)
	case len(doc.Metadata.Lifecycles) != 2:
		t.Errorf("lifecycles = %#v", doc.Metadata.Lifecycles)
	}
	tool := AuthoringTool(doc)
	if tool == nil {
		t.Fatal("no authoring tool")
	}
	if tool.Name != ToolSCA || tool.Version != "3.98.0" || tool.Group != VulnetixToolGroup {
		t.Errorf("tool = %#v", tool)
	}
	if tool.Purl == "" || len(tool.ExternalReferences) == 0 {
		t.Errorf("tool identity is bare: %#v", tool)
	}
	// The version must never be the literal "cli", which four builders used to
	// default to. It is not a version, and a consumer comparing it gets a parse
	// failure rather than an answer.
	if tool.Version == "cli" {
		t.Error(`tool version is the literal "cli"`)
	}
}

// Lifecycles are emitted in the schema's own enum order regardless of the order
// they were requested in, so the same set of phases always serialises the same
// way and a document does not churn between runs.
func TestLifecyclesAreOrderedAndDeduplicated(t *testing.T) {
	doc := NewDocument("1.7")
	_, err := ApplyAuthorship(doc, Authorship{
		Tool:   VulnetixTool(ToolCDX, "3.98.0"),
		Phases: []LifecyclePhase{PhaseOperations, PhaseBuild, PhasePreBuild, PhaseBuild},
	})
	if err != nil {
		t.Fatalf("ApplyAuthorship: %v", err)
	}
	got := make([]string, 0, len(doc.Metadata.Lifecycles))
	for _, l := range doc.Metadata.Lifecycles {
		got = append(got, l.Phase)
	}
	want := []string{"pre-build", "build", "operations"}
	if len(got) != len(want) {
		t.Fatalf("lifecycles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lifecycles = %v, want %v", got, want)
		}
	}
}

func TestApplyAuthorshipIsIdempotent(t *testing.T) {
	doc, a := authoringFixture("1.7")
	if _, err := ApplyAuthorship(doc, a); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := ApplyAuthorship(doc, a); err != nil {
		t.Fatalf("second: %v", err)
	}
	if n := len(ToolParticipants(doc)); n != 1 {
		t.Fatalf("tool entries = %d, want 1: %#v", n, ToolParticipants(doc))
	}
}

// A seed written by an older release names this same command at an older
// version. Leaving both would make the document assert it was produced by two
// versions of one tool, which is not a statement a consumer can act on.
func TestReauthoringSupersedesAnOlderSelfIdentification(t *testing.T) {
	doc := NewDocument("1.7")
	doc.Metadata.Tools = &Tools{Components: []Component{
		VulnetixTool(ToolSCA, "3.1.0"),
		{Type: "application", Name: "syft", Version: "0.9.0", Group: "Anchore"},
	}}
	if _, err := ApplyAuthorship(doc, Authorship{Tool: VulnetixTool(ToolSCA, "3.98.0")}); err != nil {
		t.Fatalf("ApplyAuthorship: %v", err)
	}
	tools := ToolParticipants(doc)
	if len(tools) != 2 {
		t.Fatalf("tool entries = %d, want 2: %#v", len(tools), tools)
	}
	if tools[0].Name != ToolSCA || tools[0].Version != "3.98.0" {
		t.Errorf("author entry = %#v", tools[0])
	}
	if tools[1].Name != "syft" {
		t.Errorf("third-party entry not preserved: %#v", tools[1])
	}
}

// Two different Vulnetix commands are two different tools. The SCA pass
// authoring a document and the licence pass later enriching it is a real
// sequence, and the document should name both.
func TestReauthoringKeepsOtherVulnetixToolEntries(t *testing.T) {
	doc := NewDocument("1.7")
	if _, err := ApplyAuthorship(doc, Authorship{Tool: VulnetixTool(ToolSCA, "3.98.0")}); err != nil {
		t.Fatalf("author: %v", err)
	}
	if err := AppendToolParticipation(doc, VulnetixTool(ToolLicense, "3.98.0")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := ApplyAuthorship(doc, Authorship{Tool: VulnetixTool(ToolSCA, "3.99.0")}); err != nil {
		t.Fatalf("re-author: %v", err)
	}
	tools := ToolParticipants(doc)
	if len(tools) != 2 || tools[0].Name != ToolSCA || tools[1].Name != ToolLicense {
		t.Fatalf("tools = %#v", tools)
	}
	if tools[0].Version != "3.99.0" {
		t.Errorf("author version = %s, want 3.99.0", tools[0].Version)
	}
}

// The whole point of the transformer tier: the document still says who made it.
func TestAppendToolParticipationLeavesAuthorshipAlone(t *testing.T) {
	doc := NewDocument("1.7")
	doc.SerialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
	doc.Version = 4
	doc.Metadata = &Metadata{
		Timestamp:    "2020-01-01T00:00:00Z",
		Manufacturer: &OrganizationalEntity{Name: "Anchore"},
		Authors:      []OrganizationalContact{{Name: "A Person"}},
		Lifecycles:   []Lifecycle{{Phase: "post-build"}},
		Tools:        &Tools{Components: []Component{{Type: "application", Name: "syft", Version: "1.2.3"}}},
	}
	before := *doc.Metadata

	if err := AppendToolParticipation(doc, VulnetixTool(ToolBOMEnrich, "3.98.0")); err != nil {
		t.Fatalf("append: %v", err)
	}
	switch {
	case doc.SerialNumber != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79":
		t.Error("serialNumber changed")
	case doc.Version != 4:
		t.Error("version changed")
	case doc.Metadata.Timestamp != before.Timestamp:
		t.Error("timestamp changed")
	case doc.Metadata.Manufacturer.Name != "Anchore":
		t.Error("manufacturer overwritten")
	case len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "A Person":
		t.Error("authors overwritten")
	case len(doc.Metadata.Lifecycles) != 1:
		t.Error("lifecycles overwritten")
	}
	tools := ToolParticipants(doc)
	if len(tools) != 2 || tools[0].Name != "syft" || tools[1].Name != ToolBOMEnrich {
		t.Fatalf("tools = %#v", tools)
	}
}

// metadata.tools.components carries uniqueItems:true from 1.5, so enriching one
// document twice must not leave two entries for the same tool.
func TestAppendToolParticipationTwiceLeavesOneEntry(t *testing.T) {
	doc := NewDocument("1.7")
	tool := VulnetixTool(ToolBOMEnrich, "3.98.0")
	for i := 0; i < 3; i++ {
		if err := AppendToolParticipation(doc, tool); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if n := len(ToolParticipants(doc)); n != 1 {
		t.Fatalf("tool entries = %d, want 1", n)
	}
}

func TestNextRevisionRemintsAndRecordsLineage(t *testing.T) {
	doc := NewDocument("1.7")
	original := doc.SerialNumber
	if err := NextRevision(doc, ""); err != nil {
		t.Fatalf("NextRevision: %v", err)
	}
	if doc.SerialNumber == original {
		t.Error("serialNumber not reminted")
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if got, ok := doc.Metadata.GetProperty(PropDerivedFrom); !ok || got != original {
		t.Errorf("derived-from = %q (present=%v), want %q", got, ok, original)
	}
}

// An authoring subcommand pointed at an existing BOM file rewrites that file.
// It is the same document, so the serial stays and the version advances —
// otherwise consumers tracking that serial lose sight of it, and two revisions
// of one document cannot be ordered.
func TestReviseInPlaceKeepsIdentityAndAdvancesVersion(t *testing.T) {
	doc := NewDocument("1.7")
	doc.Version = 7
	original := doc.SerialNumber
	if _, err := ApplyAuthorship(doc, Authorship{Tool: VulnetixTool(ToolSCA, "3.1.0")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	doc.Version = 7

	if _, err := ReviseInPlace(doc, Authorship{
		Manufacturer: &OrganizationalEntity{Name: "Acme Corp"},
		Tool:         VulnetixTool(ToolSCA, "3.98.0"),
		Phases:       []LifecyclePhase{PhaseBuild},
	}); err != nil {
		t.Fatalf("ReviseInPlace: %v", err)
	}
	if doc.SerialNumber != original {
		t.Errorf("serialNumber changed: %s -> %s", original, doc.SerialNumber)
	}
	if doc.Version != 8 {
		t.Errorf("version = %d, want 8", doc.Version)
	}
	if doc.Metadata.Manufacturer == nil || doc.Metadata.Manufacturer.Name != "Acme Corp" {
		t.Errorf("re-authoring did not apply manufacturer: %#v", doc.Metadata.Manufacturer)
	}
	if n := len(ToolParticipants(doc)); n != 1 {
		t.Errorf("tool entries = %d, want 1", n)
	}
}

// Editing somebody else's BOM in place does not make us its author. Their
// manufacturer is still true — that organization did create this document — so
// we participate in the tool table and union our capture phase into theirs.
func TestReviseInPlaceOfAThirdPartyDocumentDoesNotClaimAuthorship(t *testing.T) {
	doc := NewDocument("1.7")
	doc.Metadata = &Metadata{
		Manufacturer: &OrganizationalEntity{Name: "Anchore"},
		Lifecycles:   []Lifecycle{{Phase: "post-build"}},
		Tools:        &Tools{Components: []Component{{Type: "application", Name: "syft", Version: "1.2.3"}}},
	}
	original := doc.SerialNumber

	if _, err := ReviseInPlace(doc, Authorship{
		Manufacturer: &OrganizationalEntity{Name: "Acme Corp"},
		Tool:         VulnetixTool(ToolBOMEnrich, "3.98.0"),
		Phases:       []LifecyclePhase{PhaseOperations},
	}); err != nil {
		t.Fatalf("ReviseInPlace: %v", err)
	}
	if doc.SerialNumber != original {
		t.Error("serialNumber changed on an in-place edit")
	}
	if doc.Version != 2 {
		t.Errorf("version = %d, want 2", doc.Version)
	}
	if doc.Metadata.Manufacturer.Name != "Anchore" {
		t.Errorf("stole authorship: manufacturer = %q", doc.Metadata.Manufacturer.Name)
	}
	tools := ToolParticipants(doc)
	if len(tools) != 2 || tools[0].Name != "syft" || tools[1].Name != ToolBOMEnrich {
		t.Fatalf("tools = %#v", tools)
	}
	phases := map[string]bool{}
	for _, l := range doc.Metadata.Lifecycles {
		phases[l.Phase] = true
	}
	if !phases["post-build"] || !phases["operations"] {
		t.Errorf("lifecycles = %#v, want the union", doc.Metadata.Lifecycles)
	}
}

func TestParseLifecyclePhasesRejectsUnknownValues(t *testing.T) {
	if _, err := ParseLifecyclePhases("build, post-build"); err != nil {
		t.Fatalf("valid phases rejected: %v", err)
	}
	if _, err := ParseLifecyclePhases("build, prebuild"); err == nil {
		t.Fatal("typo accepted; a typo silently becoming a custom phase is indistinguishable downstream")
	}
}

func TestIsVulnetixToolNameCoversLegacyAndSARIFSpellings(t *testing.T) {
	for _, name := range []string{
		ToolSCA, ToolCDX, ToolAIBOM, ToolCBOM, ToolContainers, ToolLicense,
		"vulnetix", "vulnetix-sca", "Vulnetix Malscan", "vulnetix ",
	} {
		if !IsVulnetixToolName(name) {
			t.Errorf("IsVulnetixToolName(%q) = false", name)
		}
	}
	for _, name := range []string{"", "syft", "trivy", "grype", "cdxgen"} {
		if IsVulnetixToolName(name) {
			t.Errorf("IsVulnetixToolName(%q) = true", name)
		}
	}
}

func TestNormalizeSerialNumberIsStableForNonURNInput(t *testing.T) {
	// An SPDX DocumentNamespace is a URI but rarely a UUID urn. Minting a random
	// one on each conversion would give the same input file a different identity
	// every run.
	const ns = "https://anchore.com/syft/dir/repo-2f3c"
	first := NormalizeSerialNumber(ns)
	if first != NormalizeSerialNumber(ns) {
		t.Fatal("conversion is not stable")
	}
	if got := NormalizeSerialNumber("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"); got != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Errorf("valid urn altered: %s", got)
	}
}
