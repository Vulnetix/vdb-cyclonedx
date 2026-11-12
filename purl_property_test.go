package cyclonedx

import (
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

// TestPropertyParsePurl property-tests ParsePurl (purl.go) on deterministic
// generated inputs. The generators are restricted so every invariant holds on
// every generated input: raw inputs carry no '%', so url.PathUnescape never
// re-introduces '?' or '#' after the strip at purl.go:24-29; round-trip names
// and versions carry no raw '?' or '#', which SBOMPurl would emit escaped and
// ParsePurl would decode back into the returned strings. Valid %-escapes that
// decode to '?' or '#' are excluded for the same reason: purl.go is out of
// scope here.
func TestPropertyParsePurl(t *testing.T) {
	const seed = 42
	const rawRounds = 500
	const roundTripRounds = 500

	rng := rand.New(rand.NewSource(seed))

	rawAlphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@/#? .-_+:~")
	controlRunes := []rune{0x00, 0x01, 0x09, 0x0a, 0x1f, 0x7f}

	// Fixed raw inputs cover the empty, no-prefix, strip-order and
	// invalid %-escape (purl.go:45-50 fallback) paths deterministically.
	fixedRaw := []string{
		"", "pkg", "pkg:", "pkg:x", "Pkg:npm/a@1",
		"pkg:%", "pkg:%2", "pkg:%zz", "pkg:%GG", "pkg:%2G", "pkg:%g2",
		"pkg:%20", "pkg:%2F", "pkg:%40", "pkg:%25",
		"pkg:npm/a?b#c@1.0.0", "pkg:npm/a#b?c@1.0.0", "pkg:npm/a?b@1.0.0",
		"pkg:npm/a\x00b@1", "pkg:\x1f", "pkg:npm/a\x7fb@1",
	}
	for _, in := range fixedRaw {
		eco, name, ver := ParsePurl(in)
		// Invariant 4: empty input and any string without the "pkg:" prefix
		// yield nothing.
		if !strings.HasPrefix(in, "pkg:") && (eco != "" || name != "" || ver != "") {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q), want (\"\",\"\",\"\")", in, eco, name, ver)
		}
		// Invariant 3: no '?' or '#' in any returned string.
		if strings.ContainsAny(eco+name+ver, "?#") {
			t.Errorf("ParsePurl(%q) returned %q/%q/%q containing '?' or '#'", in, eco, name, ver)
		}
	}

	// Invariant 1 (no panic) and 3 (no '?' or '#') on random raw strings,
	// including control characters; every 8th input lacks the "pkg:" prefix
	// so invariant 4 is exercised on generated inputs too.
	for i := 0; i < rawRounds; i++ {
		var in string
		switch rng.Intn(8) {
		case 0:
			in = randomString(rng, rawAlphabet, 0, 40)
		case 1:
			in = "pkg" + randomString(rng, rawAlphabet, 1, 20)
		default:
			in = "pkg:" + randomString(rng, rawAlphabet, 0, 40)
		}
		if rng.Intn(5) == 0 {
			in += string(controlRunes[rng.Intn(len(controlRunes))])
		}
		eco, name, ver := ParsePurl(in)
		if strings.ContainsAny(eco+name+ver, "?#") {
			t.Errorf("ParsePurl(%q) returned %q/%q/%q containing '?' or '#'", in, eco, name, ver)
		}
		if !strings.HasPrefix(in, "pkg:") && (eco != "" || name != "" || ver != "") {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q), want (\"\",\"\",\"\")", in, eco, name, ver)
		}
	}

	// Invariant 2: ParsePurl(SBOMPurl(name, version, eco)) recovers the
	// ecosystem, the unescaped name and the version. The name and version
	// alphabets exclude '?' and '#' (SBOMPurl would escape them, ParsePurl
	// would decode them back, breaking invariant 3) and ':' (the maven
	// branch canonicalizes "group:artifact" into two path segments). Names
	// also exclude '@': url.PathEscape leaves it raw, so a raw '@' in a name
	// shifts the last-@ version split (purl.go:31) when the version is empty.
	// Scoped npm names ("@scope/pkg") exercise '@' through the %40 encoding
	// SBOMPurl emits, in the dedicated loop below. PathEscape/PathUnescape,
	// the same functions SBOMPurl uses, are the oracle.
	ecosystems := []string{
		"npm", "pypi", "golang", "cargo", "gem", "maven", "composer",
		"nuget", "pub", "hex", "swift", "deb", "rpm", "apk", "arch",
		"brew", "chocolatey", "scoop", "winget", "conda", "helm",
		"github", "docker",
	}
	nameAlphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/% ._-+~!$&'()*,;=")
	versionAlphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+% ")
	for i := 0; i < roundTripRounds; i++ {
		eco := ecosystems[rng.Intn(len(ecosystems))]
		name := randomString(rng, nameAlphabet, 1, 30)
		version := randomString(rng, versionAlphabet, 0, 20)
		purl := SBOMPurl(name, version, eco)
		if purl == "" {
			t.Fatalf("SBOMPurl(%q,%q,%q) unexpectedly empty", name, version, eco)
		}
		wantName, err := url.PathUnescape(url.PathEscape(name))
		if err != nil {
			t.Fatalf("PathUnescape(PathEscape(%q)): %v", name, err)
		}
		wantVersion, err := url.PathUnescape(url.PathEscape(version))
		if err != nil {
			t.Fatalf("PathUnescape(PathEscape(%q)): %v", version, err)
		}
		gotEco, gotName, gotVer := ParsePurl(purl)
		if gotEco != eco || gotName != wantName || gotVer != wantVersion {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q), want (%q,%q,%q)",
				purl, gotEco, gotName, gotVer, eco, wantName, wantVersion)
		}
		if strings.ContainsAny(gotEco+gotName+gotVer, "?#") {
			t.Errorf("ParsePurl(%q) returned %q/%q/%q containing '?' or '#'", purl, gotEco, gotName, gotVer)
		}
	}

	// npm scoped names: SBOMPurl emits the scope as %40 (url.PathEscape
	// would drop the leading '@') and escapes the package part; ParsePurl
	// must recover the full "@scope/pkg".
	for i := 0; i < 200; i++ {
		name := "@" + randomString(rng, nameAlphabet, 1, 12) + "/" + randomString(rng, nameAlphabet, 1, 12)
		version := randomString(rng, versionAlphabet, 0, 20)
		purl := SBOMPurl(name, version, "npm")
		wantName, err := url.PathUnescape(url.PathEscape(name))
		if err != nil {
			t.Fatalf("PathUnescape(PathEscape(%q)): %v", name, err)
		}
		wantVersion, err := url.PathUnescape(url.PathEscape(version))
		if err != nil {
			t.Fatalf("PathUnescape(PathEscape(%q)): %v", version, err)
		}
		gotEco, gotName, gotVer := ParsePurl(purl)
		if gotEco != "npm" || gotName != wantName || gotVer != wantVersion {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q), want (%q,%q,%q)",
				purl, gotEco, gotName, gotVer, "npm", wantName, wantVersion)
		}
		if strings.ContainsAny(gotEco+gotName+gotVer, "?#") {
			t.Errorf("ParsePurl(%q) returned %q/%q/%q containing '?' or '#'", purl, gotEco, gotName, gotVer)
		}
	}
}

func randomString(rng *rand.Rand, alphabet []rune, minLen, maxLen int) string {
	n := minLen + rng.Intn(maxLen-minLen+1)
	b := make([]rune, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}
