package cyclonedx

// ── Properties and document scaffolding ──────────────────────────────────────
//
// Two small things that had been reimplemented once per call site.
//
// The properties upsert existed five times across the CLI, and one of those
// five was a plain append rather than an upsert — so re-running that pass left
// the document asserting the same property twice with different values, which
// a consumer resolves by picking one arbitrarily.
//
// The minimal-document scaffold existed five times too, and two of the copies
// omitted the metadata block entirely, producing documents that named neither
// their producer nor when they were made.

const (
	// PropDerivedFrom records the serialNumber of the document a transformed
	// document came from, so a chain of revisions stays followable after the
	// serial has been reminted.
	PropDerivedFrom = "vulnetix:bom/derived-from"
)

// SetProperty upserts a name/value pair into a properties slice.
//
// CycloneDX properties are a name-value list rather than a map, but the
// convention is that a given name appears once; append does not honour that and
// the difference only shows up on the second run.
func SetProperty(props []Property, name, value string) []Property {
	for i := range props {
		if props[i].Name == name {
			props[i].Value = value
			return props
		}
	}
	return append(props, Property{Name: name, Value: value})
}

// GetProperty returns the value of the named property.
func GetProperty(props []Property, name string) (string, bool) {
	for _, p := range props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// SetProperty upserts a document-level metadata property.
func (m *Metadata) SetProperty(name, value string) {
	if m == nil {
		return
	}
	m.Properties = SetProperty(m.Properties, name, value)
}

// GetProperty reads a document-level metadata property.
func (m *Metadata) GetProperty(name string) (string, bool) {
	if m == nil {
		return "", false
	}
	return GetProperty(m.Properties, name)
}

// SetProperty upserts a component property.
func (c *Component) SetProperty(name, value string) {
	if c == nil {
		return
	}
	c.Properties = SetProperty(c.Properties, name, value)
}

// GetProperty reads a component property.
func (c *Component) GetProperty(name string) (string, bool) {
	if c == nil {
		return "", false
	}
	return GetProperty(c.Properties, name)
}

// NewDocument returns a document with the invariant header members set, ready
// for ApplyAuthorship. An empty specVersion takes the module default.
func NewDocument(specVersion string) *Document {
	if specVersion == "" {
		specVersion = DefaultSpecVersion
	}
	return &Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: NewSerialNumber(),
		Version:      1,
		Metadata:     &Metadata{},
	}
}

// EnsureDocumentHeader backfills the header members on a document read from
// disk that is missing them, without disturbing any it already carries. A
// document with no serialNumber cannot be referred to, and one with no version
// cannot be ordered against its own next revision.
func EnsureDocumentHeader(doc *Document, specVersion string) {
	if doc == nil {
		return
	}
	if doc.BOMFormat == "" {
		doc.BOMFormat = "CycloneDX"
	}
	if doc.SpecVersion == "" {
		if specVersion == "" {
			specVersion = DefaultSpecVersion
		}
		doc.SpecVersion = specVersion
	}
	if doc.SerialNumber == "" {
		doc.SerialNumber = NewSerialNumber()
	}
	if doc.Version <= 0 {
		doc.Version = 1
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}
}
