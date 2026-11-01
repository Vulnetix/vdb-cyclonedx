package vexrules

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Detect identifies the VEX serialisation of a document. A CycloneDX VEX is a
// CycloneDX document, so bomFormat is checked first; CSAF announces itself with
// a document.category containing "vex"; OpenVEX with its @context.
func Detect(data []byte) Format {
	var probe struct {
		Context   json.RawMessage `json:"@context"`
		BOMFormat string          `json:"bomFormat"`
		Document  struct {
			Category string `json:"category"`
		} `json:"document"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return FormatUnknown
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return FormatCycloneDX
	case strings.Contains(string(probe.Context), "openvex.dev"):
		return FormatOpenVEX
	case strings.Contains(strings.ToLower(probe.Document.Category), "vex"):
		return FormatCSAF
	default:
		return FormatUnknown
	}
}

// Parse reads a VEX document of any supported format.
func Parse(data []byte) (*Document, error) {
	switch Detect(data) {
	case FormatOpenVEX:
		return parseOpenVEX(data)
	case FormatCycloneDX:
		return parseCycloneDX(data)
	case FormatCSAF:
		return parseCSAF(data)
	default:
		return nil, fmt.Errorf("not a recognised VEX document: expected OpenVEX, CycloneDX VEX or CSAF VEX")
	}
}

// ── OpenVEX 0.2.0 ───────────────────────────────────────────────────────────

func parseOpenVEX(data []byte) (*Document, error) {
	var raw struct {
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			ID            string `json:"@id"`
			Vulnerability struct {
				Name    string   `json:"name"`
				ID      string   `json:"@id"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Status          string `json:"status"`
			StatusNotes     string `json:"status_notes"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
			Timestamp       string `json:"timestamp"`
			Products        []struct {
				ID          string            `json:"@id"`
				Identifiers map[string]string `json:"identifiers"`
				Versions    []struct {
					Version string `json:"version"`
				} `json:"versions"`
				Subcomponents []struct {
					ID          string            `json:"@id"`
					Identifiers map[string]string `json:"identifiers"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing OpenVEX: %w", err)
	}
	docTime := parseTime(raw.Timestamp)
	doc := &Document{Format: FormatOpenVEX, ID: raw.ID, Author: raw.Author, Timestamp: docTime}
	for i, rs := range raw.Statements {
		id := NormalizeVulnID(firstNonEmpty(rs.Vulnerability.Name, rs.Vulnerability.ID))
		st := Statement{
			VulnID:          id,
			Status:          Status(strings.ToLower(strings.TrimSpace(rs.Status))),
			Justification:   rs.Justification,
			ImpactStatement: rs.ImpactStatement,
			ActionStatement: rs.ActionStatement,
			Timestamp:       firstTime(parseTime(rs.Timestamp), docTime),
			Ref:             firstNonEmpty(rs.ID, "openvex#"+strconv.Itoa(i)),
			Index:           i,
			Raw: RawDisposition{
				Format:                 FormatOpenVEX,
				OpenVEXStatus:          rs.Status,
				OpenVEXJustification:   rs.Justification,
				OpenVEXStatusNotes:     rs.StatusNotes,
				OpenVEXActionStatement: rs.ActionStatement,
				OpenVEXImpactStatement: rs.ImpactStatement,
			},
		}
		st.Aliases = aliases(id, rs.Vulnerability.Aliases)
		for _, rp := range rs.Products {
			p := Product{ID: rp.ID, Purl: purlFrom(rp.ID, rp.Identifiers)}
			for _, v := range rp.Versions {
				if v.Version != "" {
					p.Versions = append(p.Versions, v.Version)
				}
			}
			for _, sc := range rp.Subcomponents {
				if purl := purlFrom(sc.ID, sc.Identifiers); purl != "" {
					p.Subcomponents = append(p.Subcomponents, purl)
				}
			}
			st.Products = append(st.Products, p)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func purlFrom(id string, identifiers map[string]string) string {
	if p, ok := identifiers["purl"]; ok && p != "" {
		return p
	}
	if strings.HasPrefix(id, "pkg:") {
		return id
	}
	return ""
}

// ── CycloneDX VEX ───────────────────────────────────────────────────────────

var cdxStateToStatus = map[string]Status{
	"resolved":               StatusFixed,
	"resolved_with_pedigree": StatusFixed,
	"exploitable":            StatusAffected,
	"in_triage":              StatusUnderInvestigation,
	"false_positive":         StatusNotAffected,
	"not_affected":           StatusNotAffected,
}

func parseCycloneDX(data []byte) (*Document, error) {
	var raw struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Authors   []struct {
				Name string `json:"name"`
			} `json:"authors"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
		Vulns      []struct {
			BOMRef     string `json:"bom-ref"`
			ID         string `json:"id"`
			References []struct {
				ID string `json:"id"`
			} `json:"references"`
			Analysis *struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
				Detail        string   `json:"detail"`
				LastUpdated   string   `json:"lastUpdated"`
				FirstIssued   string   `json:"firstIssued"`
			} `json:"analysis"`
			Affects []struct {
				Ref      string `json:"ref"`
				Versions []struct {
					Version string `json:"version"`
				} `json:"versions"`
			} `json:"affects"`
			Updated    string `json:"updated"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing CycloneDX VEX: %w", err)
	}
	purlByRef := map[string]string{}
	collectCDXComponents(raw.Components, purlByRef)

	author := ""
	if len(raw.Metadata.Authors) > 0 {
		author = raw.Metadata.Authors[0].Name
	}
	docTime := parseTime(raw.Metadata.Timestamp)
	doc := &Document{Format: FormatCycloneDX, ID: raw.SerialNumber, Author: author, Timestamp: docTime}
	for i, v := range raw.Vulns {
		// A vulnerability with no analysis is a finding, not an assertion.
		if v.Analysis == nil || strings.TrimSpace(v.Analysis.State) == "" {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(v.Analysis.State))
		status, ok := cdxStateToStatus[state]
		if !ok {
			status = Status(state)
		}
		props := map[string]string{}
		for _, p := range v.Properties {
			props[p.Name] = p.Value
		}
		id := NormalizeVulnID(v.ID)
		st := Statement{
			VulnID:        id,
			Status:        status,
			Justification: v.Analysis.Justification,
			Timestamp:     firstTime(parseTime(v.Analysis.LastUpdated), parseTime(v.Updated), parseTime(v.Analysis.FirstIssued), docTime),
			Ref:           firstNonEmpty(v.BOMRef, "cyclonedx#"+strconv.Itoa(i)),
			Index:         i,
			Raw: RawDisposition{
				Format:           FormatCycloneDX,
				CDXState:         v.Analysis.State,
				CDXJustification: v.Analysis.Justification,
				CDXResponses:     v.Analysis.Response,
				CDXDetail:        v.Analysis.Detail,
			},
		}
		if len(props) > 0 {
			st.Raw.CDXProperties = props
		}
		if status == StatusAffected {
			st.ActionStatement = v.Analysis.Detail
		} else {
			st.ImpactStatement = v.Analysis.Detail
		}
		refs := make([]string, 0, len(v.References))
		for _, r := range v.References {
			refs = append(refs, r.ID)
		}
		st.Aliases = aliases(id, refs)
		for _, a := range v.Affects {
			p := Product{ID: a.Ref}
			if purl, ok := purlByRef[a.Ref]; ok {
				p.Purl = purl
			} else if strings.HasPrefix(a.Ref, "pkg:") {
				p.Purl = a.Ref
			}
			for _, ver := range a.Versions {
				if ver.Version != "" {
					p.Versions = append(p.Versions, ver.Version)
				}
			}
			st.Products = append(st.Products, p)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Purl       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

func collectCDXComponents(cs []cdxComponent, out map[string]string) {
	for _, c := range cs {
		if c.BOMRef != "" && c.Purl != "" {
			out[c.BOMRef] = c.Purl
		}
		collectCDXComponents(c.Components, out)
	}
}

// ── CSAF 2.0 VEX ────────────────────────────────────────────────────────────

func parseCSAF(data []byte) (*Document, error) {
	var raw struct {
		Document struct {
			Tracking struct {
				ID                 string `json:"id"`
				CurrentReleaseDate string `json:"current_release_date"`
			} `json:"tracking"`
			Publisher struct {
				Name string `json:"name"`
			} `json:"publisher"`
		} `json:"document"`
		ProductTree struct {
			FullProductNames []csafProduct `json:"full_product_names"`
			Branches         []csafBranch  `json:"branches"`
			Relationships    []struct {
				FullProductName csafProduct `json:"full_product_name"`
			} `json:"relationships"`
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
			IDs []struct {
				Text string `json:"text"`
			} `json:"ids"`
			Notes []struct {
				Category string `json:"category"`
				Title    string `json:"title"`
				Text     string `json:"text"`
			} `json:"notes"`
			ProductStatus struct {
				KnownNotAffected   []string `json:"known_not_affected"`
				KnownAffected      []string `json:"known_affected"`
				Fixed              []string `json:"fixed"`
				FirstFixed         []string `json:"first_fixed"`
				UnderInvestigation []string `json:"under_investigation"`
			} `json:"product_status"`
			Threats []struct {
				Category   string   `json:"category"`
				Details    string   `json:"details"`
				ProductIDs []string `json:"product_ids"`
			} `json:"threats"`
			Remediations []struct {
				Category   string   `json:"category"`
				Details    string   `json:"details"`
				ProductIDs []string `json:"product_ids"`
			} `json:"remediations"`
			Flags []struct {
				Label      string   `json:"label"`
				ProductIDs []string `json:"product_ids"`
			} `json:"flags"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing CSAF VEX: %w", err)
	}
	purlByProductID := map[string]string{}
	collectCSAFProducts(raw.ProductTree.FullProductNames, purlByProductID)
	collectCSAFBranches(raw.ProductTree.Branches, purlByProductID)
	for _, rel := range raw.ProductTree.Relationships {
		collectCSAFProducts([]csafProduct{rel.FullProductName}, purlByProductID)
	}

	docTime := parseTime(raw.Document.Tracking.CurrentReleaseDate)
	doc := &Document{
		Format:    FormatCSAF,
		ID:        raw.Document.Tracking.ID,
		Author:    raw.Document.Publisher.Name,
		Timestamp: docTime,
	}
	index := 0
	for vi, v := range raw.Vulnerabilities {
		id := NormalizeVulnID(v.CVE)
		ids := make([]string, 0, len(v.IDs))
		for _, x := range v.IDs {
			ids = append(ids, x.Text)
		}
		if id == "" && len(ids) > 0 {
			id = NormalizeVulnID(ids[0])
		}
		var notes []string
		for _, n := range v.Notes {
			if n.Title == markerNoteTitle || strings.Contains(n.Text, markerPrefix) {
				notes = append(notes, n.Text)
			}
		}
		flagsBy := map[string][]string{}
		for _, f := range v.Flags {
			for _, pid := range f.ProductIDs {
				flagsBy[pid] = append(flagsBy[pid], f.Label)
			}
		}
		impactBy := map[string]string{}
		for _, th := range v.Threats {
			if th.Category != "impact" {
				continue
			}
			for _, pid := range th.ProductIDs {
				impactBy[pid] = th.Details
			}
		}
		remBy := map[string][]Remediation{}
		for _, r := range v.Remediations {
			for _, pid := range r.ProductIDs {
				remBy[pid] = append(remBy[pid], Remediation{Category: r.Category, Details: r.Details})
			}
		}
		add := func(productIDs []string, productStatus string, status Status) {
			for _, pid := range productIDs {
				st := Statement{
					VulnID:          id,
					Aliases:         aliases(id, ids),
					Status:          status,
					ImpactStatement: impactBy[pid],
					Timestamp:       docTime,
					Ref:             fmt.Sprintf("csaf#%d/%s", vi, pid),
					Index:           index,
					Products:        []Product{{ID: pid, Purl: purlByProductID[pid]}},
					Raw: RawDisposition{
						Format:            FormatCSAF,
						CSAFProductStatus: productStatus,
						CSAFFlags:         flagsBy[pid],
						CSAFRemediations:  remBy[pid],
						CSAFNotes:         notes,
					},
				}
				if fl := flagsBy[pid]; len(fl) > 0 {
					st.Justification = fl[0]
				}
				if rs := remBy[pid]; len(rs) > 0 {
					st.ActionStatement = rs[0].Details
				}
				index++
				doc.Statements = append(doc.Statements, st)
			}
		}
		add(v.ProductStatus.KnownNotAffected, "known_not_affected", StatusNotAffected)
		add(v.ProductStatus.KnownAffected, "known_affected", StatusAffected)
		add(v.ProductStatus.Fixed, "fixed", StatusFixed)
		add(v.ProductStatus.FirstFixed, "first_fixed", StatusFixed)
		add(v.ProductStatus.UnderInvestigation, "under_investigation", StatusUnderInvestigation)
	}
	return doc, nil
}

type csafProduct struct {
	ProductID             string `json:"product_id"`
	ProductIdentification struct {
		Purl string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

func collectCSAFProducts(products []csafProduct, out map[string]string) {
	for _, p := range products {
		if p.ProductID == "" {
			continue
		}
		if purl := p.ProductIdentification.Purl; purl != "" {
			out[p.ProductID] = purl
		} else if _, seen := out[p.ProductID]; !seen {
			out[p.ProductID] = ""
		}
	}
}

func collectCSAFBranches(branches []csafBranch, out map[string]string) {
	for _, b := range branches {
		if b.Product != nil {
			collectCSAFProducts([]csafProduct{*b.Product}, out)
		}
		collectCSAFBranches(b.Branches, out)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func aliases(id string, raw []string) []string {
	var out []string
	seen := map[string]bool{strings.ToUpper(id): true}
	for _, r := range raw {
		a := NormalizeVulnID(r)
		if a == "" || seen[strings.ToUpper(a)] {
			continue
		}
		seen[strings.ToUpper(a)] = true
		out = append(out, a)
	}
	return out
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func firstTime(times ...time.Time) time.Time {
	for _, t := range times {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
