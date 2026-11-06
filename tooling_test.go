package cyclonedx

import "testing"

// The tool table is a sequence: the author first, then each transformer in the
// order it touched the document. FindVulnetixTool must return the author even
// when a later Vulnetix command enriched the document, and the returned pointer
// must alias the table entry so a caller can act on the real component.
func TestFindVulnetixToolReturnsTheAuthorEntry(t *testing.T) {
	doc := &Document{
		SpecVersion: "1.7",
		Metadata: &Metadata{Tools: &Tools{Components: []Component{
			{Type: "application", Name: "syft", Version: "0.9.0", Group: "Anchore"},
			VulnetixTool(ToolSCA, "3.98.0"),
			VulnetixTool(ToolLicense, "3.98.0"),
		}}},
	}
	got := FindVulnetixTool(doc)
	if got != &doc.Metadata.Tools.Components[1] {
		t.Fatalf("FindVulnetixTool = %p, want the author entry at index 1 (%p)", got, &doc.Metadata.Tools.Components[1])
	}
	if got.Name != ToolSCA {
		t.Errorf("FindVulnetixTool name = %q, want %q", got.Name, ToolSCA)
	}
}

// A document produced entirely by third-party tools is not ours: the answer
// must be nil, not the nearest lookalike.
func TestFindVulnetixToolReturnsNilWithoutAProductTool(t *testing.T) {
	doc := &Document{
		SpecVersion: "1.7",
		Metadata: &Metadata{Tools: &Tools{Components: []Component{
			{Type: "application", Name: "syft", Version: "0.9.0"},
			{Type: "application", Name: "cdxgen", Version: "10.0.0"},
		}}},
	}
	if got := FindVulnetixTool(doc); got != nil {
		t.Fatalf("FindVulnetixTool = %#v, want nil", got)
	}
}

// A nil document and a document with no tool table are both "not produced by
// us"; the lookup must not panic on either.
func TestFindVulnetixToolNilDocument(t *testing.T) {
	for _, doc := range []*Document{
		nil,
		{SpecVersion: "1.7"},
		{SpecVersion: "1.7", Metadata: &Metadata{}},
	} {
		if got := FindVulnetixTool(doc); got != nil {
			t.Fatalf("FindVulnetixTool(%#v) = %#v, want nil", doc, got)
		}
	}
}

func TestToolMetaFromDocument(t *testing.T) {
	// metaFixture builds a document whose tool table names exactly one tool.
	metaFixture := func(tool Component) *Document {
		return &Document{
			SpecVersion: "1.7",
			Metadata:    &Metadata{Tools: &Tools{Components: []Component{tool}}},
		}
	}

	cases := []struct {
		name string
		doc  *Document
		want ToolMeta
	}{
		{
			name: "nil document yields empty meta",
			doc:  nil,
			want: ToolMeta{},
		},
		{
			name: "no tool table leaves tool fields empty",
			doc:  &Document{SpecVersion: "1.7", Metadata: &Metadata{}},
			want: ToolMeta{SpecVersion: "1.7"},
		},
		{
			name: "publisher wins over supplier and group",
			doc: metaFixture(Component{
				Type: "application", Name: "vulnetix-sca", Version: "3.98.0",
				Publisher: "PubCorp", Supplier: &OrganizationalEntity{Name: "SupCorp"}, Group: "GrpCorp",
			}),
			want: ToolMeta{SpecVersion: "1.7", ToolName: "vulnetix-sca", ToolVersion: "3.98.0", ToolVendor: "PubCorp"},
		},
		{
			name: "supplier name when publisher is absent",
			doc: metaFixture(Component{
				Type: "application", Name: "vulnetix-sca", Version: "3.98.0",
				Supplier: &OrganizationalEntity{Name: "SupCorp"}, Group: "GrpCorp",
			}),
			want: ToolMeta{SpecVersion: "1.7", ToolName: "vulnetix-sca", ToolVersion: "3.98.0", ToolVendor: "SupCorp"},
		},
		{
			name: "group when neither publisher nor supplier names one",
			doc: metaFixture(Component{
				Type: "application", Name: "vulnetix-sca", Version: "3.98.0", Group: "GrpCorp",
			}),
			want: ToolMeta{SpecVersion: "1.7", ToolName: "vulnetix-sca", ToolVersion: "3.98.0", ToolVendor: "GrpCorp"},
		},
		{
			name: "first hash with content wins",
			doc: metaFixture(Component{
				Type: "application", Name: "vulnetix-sca", Version: "3.98.0",
				Hashes: []Hash{{Alg: "SHA-256"}, {Alg: "SHA-1", Content: "abc123"}},
			}),
			want: ToolMeta{SpecVersion: "1.7", ToolName: "vulnetix-sca", ToolVersion: "3.98.0", ToolHash: "abc123"},
		},
		{
			name: "empty hash contents leave the hash empty",
			doc: metaFixture(Component{
				Type: "application", Name: "vulnetix-sca", Version: "3.98.0",
				Hashes: []Hash{{Alg: "SHA-256"}, {Alg: "SHA-1"}},
			}),
			want: ToolMeta{SpecVersion: "1.7", ToolName: "vulnetix-sca", ToolVersion: "3.98.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ToolMetaFromDocument(tc.doc); got != tc.want {
				t.Fatalf("ToolMetaFromDocument = %+v, want %+v", got, tc.want)
			}
		})
	}
}
