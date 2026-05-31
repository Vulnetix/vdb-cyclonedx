package cyclonedx

import (
	"bytes"
	"encoding/json"
	"strings"
)

type CDXOrg struct {
	Name string `json:"name"`
}

type CDXComponent struct {
	BomRef       string  `json:"bom-ref"`
	Type         string  `json:"type"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Purl         string  `json:"purl"`
	Group        string  `json:"group"`
	Scope        string  `json:"scope"`
	Author       string  `json:"author"`
	Publisher    string  `json:"publisher"`
	Description  string  `json:"description"`
	Manufacturer *CDXOrg `json:"manufacturer"`
	Supplier     *CDXOrg `json:"supplier"`
	Hashes       []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	ExternalReferences []struct {
		URL  string `json:"url"`
		Type string `json:"type"`
	} `json:"externalReferences"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
	} `json:"licenses"`
}

type CDXVulnRating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Method   string  `json:"method"`
	Vector   string  `json:"vector"`
}

type CDXVulnerability struct {
	BomRef string `json:"bom-ref"`
	ID     string `json:"id"`
	Source *struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"source"`
	Ratings        []CDXVulnRating `json:"ratings"`
	CWEs           []int           `json:"cwes"`
	Description    string          `json:"description"`
	Recommendation string          `json:"recommendation"`
	Published      string          `json:"published"`
	Updated        string          `json:"updated"`
	Affects        []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type CDXMetadata struct {
	Timestamp    string        `json:"timestamp"`
	Component    *CDXComponent `json:"component"`
	Manufacture  *CDXOrg       `json:"manufacture"`
	Manufacturer *CDXOrg       `json:"manufacturer"`
	Supplier     *CDXOrg       `json:"supplier"`
	Authors      []struct {
		Name string `json:"name"`
	} `json:"authors"`
	Tools *CDXTools `json:"tools"`
}

// CDXTools models metadata.tools, whose shape changed across CycloneDX versions:
//   - 1.2–1.4: an array of tool objects, e.g. [{"vendor","name","version","hashes"}]
//   - 1.5+:    an object, e.g. {"components":[...], "services":[...]}
//
// We accept both and tolerate anything else. Tool metadata is ancillary,
// best-effort enrichment (see ExtractToolMeta), so a malformed or unexpected
// tools shape must never fail the whole BOM ingestion — UnmarshalJSON only ever
// returns nil, leaving Components empty when it can't make sense of the input.
type CDXTools struct {
	Components []CDXComponent `json:"components"`
}

func (t *CDXTools) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		// Legacy array form. Decode into CDXComponent directly so name/version/
		// hashes map for free, then backfill the legacy "vendor" into Publisher
		// (CDXComponent has no vendor field) where extractToolMeta looks for it.
		var comps []CDXComponent
		if err := json.Unmarshal(trimmed, &comps); err != nil {
			return nil
		}
		var vendors []struct {
			Vendor string `json:"vendor"`
		}
		_ = json.Unmarshal(trimmed, &vendors)
		for i := range comps {
			if comps[i].Type == "" {
				comps[i].Type = "application"
			}
			if i < len(vendors) && comps[i].Publisher == "" {
				comps[i].Publisher = vendors[i].Vendor
			}
		}
		t.Components = comps
	case '{':
		var obj struct {
			Components []CDXComponent `json:"components"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil
		}
		t.Components = obj.Components
	}
	return nil
}

// CDXDependency represents one entry in the top-level "dependencies" array.
// CycloneDX 1.4+ uses "dependsOn"; 1.2–1.3 used "dependencies" for the same
// nested list. We decode both and coalesce into DependsOn so all downstream
// code can use a single field name.
type CDXDependency struct {
	Ref       string   `json:"-"`
	DependsOn []string `json:"-"`
}

func (d *CDXDependency) UnmarshalJSON(b []byte) error {
	var raw struct {
		Ref          string   `json:"ref"`
		DependsOn    []string `json:"dependsOn"`    // CycloneDX 1.4+
		Dependencies []string `json:"dependencies"` // CycloneDX 1.2–1.3
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	d.Ref = raw.Ref
	d.DependsOn = raw.DependsOn
	// Fall back to the legacy field when the modern one is absent.
	if len(d.DependsOn) == 0 && len(raw.Dependencies) > 0 {
		d.DependsOn = raw.Dependencies
	}
	return nil
}

type CDXBom struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Metadata        CDXMetadata        `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Dependencies    []CDXDependency    `json:"dependencies"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities"`
}

func ParseCDX(data []byte) (*CDXBom, error) {
	var bom CDXBom
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}
	return &bom, nil
}

// ExtractEcosystem parses the ecosystem from a PURL (pkg:<type>/...) or returns "".
func ExtractEcosystem(purl string) string {
	// pkg:npm/lodash@4.17.0 → "npm"
	rest := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(rest, "/"); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// ExtractLicense returns the first license identifier from a component.
func ExtractLicense(comp CDXComponent) string {
	for _, l := range comp.Licenses {
		if l.License.ID != "" {
			return l.License.ID
		}
		if l.License.Name != "" {
			return l.License.Name
		}
	}
	return ""
}
