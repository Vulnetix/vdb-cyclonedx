package cyclonedx

import (
	"net/url"
	"strings"
)

// ParsePurl splits a Package URL into (ecosystem, fullName, version), matching
// vdb-api's shared.PurlComponents.Ecosystem()/FullName() semantics so the
// DB-backed vuln lookup keys identically to /v2/cli.sca.
//
//	pkg:golang/github.com%2Fcloudflare%2Fcircl@1.6.3 → ("golang", "github.com/cloudflare/circl", "1.6.3")
//	pkg:npm/%40scope%2Fpkg@1.0.0                      → ("npm", "@scope/pkg", "1.0.0")
//	pkg:github-actions/actions%2Fcheckout@v5          → ("github-actions", "actions/checkout", "v5")
func ParsePurl(purl string) (ecosystem, fullName, version string) {
	s := strings.TrimPrefix(purl, "pkg:")
	if s == purl || s == "" {
		return "", "", ""
	}
	// version (last @ — namespaces never contain @)
	if at := strings.LastIndex(s, "@"); at >= 0 {
		version = s[at+1:]
		s = s[:at]
	}
	// drop qualifiers (?...) and subpath (#...)
	if q := strings.IndexAny(s, "?#"); q >= 0 {
		s = s[:q]
	}
	ecoPart, namePart, ok := strings.Cut(s, "/")
	if !ok {
		return "", "", unescape(version)
	}
	ecosystem = ecosystemFromType(ecoPart)
	fullName = unescape(namePart)
	version = unescape(version)
	return ecosystem, fullName, version
}

func unescape(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// ecosystemFromType mirrors vdb-api shared.PurlComponents.Ecosystem(): canonical
// ecosystems pass through, unknown types return verbatim (the DB lookup is
// case-insensitive on ecosystem).
func ecosystemFromType(t string) string {
	switch t {
	case "npm", "pypi", "maven", "cargo", "gem", "nuget", "golang",
		"composer", "deb", "rpm", "apk", "github", "hex", "pub", "swift", "cocoapods":
		return t
	case "docker", "oci":
		return "docker"
	default:
		return t
	}
}
