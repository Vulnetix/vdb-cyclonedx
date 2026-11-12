package cyclonedx

import (
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestPropertyMergeHelpers asserts the invariants of the helpers that decide
// whether a merged SBOM/AIBOM/CBOM carries a component once, twice or not at
// all, and whether every hash, license, contact, reference and property
// survives the merge.
func TestPropertyMergeHelpers(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// Small pools force key collisions between dst, src and within src.
	pick := func(pool ...string) string { return pool[rng.Intn(len(pool))] }

	genHash := func() Hash {
		return Hash{Alg: pick("SHA-256", "SHA-1", ""), Content: pick("aa", "bb", "")}
	}
	genLicense := func() LicenseChoice {
		switch rng.Intn(4) {
		case 0:
			return LicenseChoice{Expression: pick("MIT OR Apache-2.0", "GPL-2.0-only")}
		case 1:
			return LicenseChoice{License: &LicenseData{ID: pick("MIT", "", "Apache-2.0"), Name: pick("", "custom")}}
		case 2:
			// A zero-value choice: keyOf returns "" and mergeLicenses drops it.
			return LicenseChoice{}
		default:
			return LicenseChoice{
				License:    &LicenseData{ID: "MIT"},
				Expression: pick("MIT", "BSD-3-Clause"),
			}
		}
	}
	genContact := func() OrganizationalContact {
		return OrganizationalContact{Name: pick("Ann", "Bob", ""), Email: pick("a@x", "", "b@x"), Phone: pick("", "1")}
	}
	genExtRef := func() ExternalReference {
		return ExternalReference{Type: pick("vcs", "website", ""), URL: pick("https://a", "https://b", "")}
	}
	genProp := func() Property {
		return Property{Name: pick("b", "a", "vulnetix:x", ""), Value: pick("1", "2", "")}
	}

	licenseKey := func(l LicenseChoice) string {
		if l.Expression != "" {
			return "expr:" + l.Expression
		}
		if l.License != nil {
			return "lic:" + l.License.ID + ":" + l.License.Name
		}
		return ""
	}

	t.Run("mergeHashes", func(t *testing.T) {
		checkAppendMerge(t, rng, mergeHashes, genHash, false, func(h Hash) string { return h.Alg + "=" + h.Content })
	})
	t.Run("mergeLicenses", func(t *testing.T) {
		checkAppendMerge(t, rng, mergeLicenses, genLicense, true, licenseKey)
		if got := mergeLicenses(nil, []LicenseChoice{{}, {}}); len(got) != 0 {
			t.Fatalf("zero-value license choices must be dropped, got %v", got)
		}
	})
	t.Run("mergeContacts", func(t *testing.T) {
		// Phone is not part of the key: a contact differing only by phone is a
		// duplicate and the dst entry wins.
		checkAppendMerge(t, rng, mergeContacts, genContact, false, func(c OrganizationalContact) string { return c.Name + "<" + c.Email + ">" })
	})
	t.Run("mergeExtRefs", func(t *testing.T) {
		checkAppendMerge(t, rng, mergeExtRefs, genExtRef, false, func(r ExternalReference) string { return r.Type + "=" + r.URL })
	})

	t.Run("mergeProps", func(t *testing.T) {
		key := func(p Property) string { return p.Name + "=" + p.Value }
		for i := 0; i < 1000; i++ {
			// dst as a merge would leave it: already deduplicated.
			dst := mergeProps(nil, genSlice(rng, genProp))
			src := genSlice(rng, genProp)

			out := mergeProps(slices.Clone(dst), src)
			if !sort.SliceIsSorted(out, func(a, b int) bool {
				if out[a].Name == out[b].Name {
					return out[a].Value < out[b].Value
				}
				return out[a].Name < out[b].Name
			}) {
				t.Fatalf("mergeProps output not sorted by (name, value): %v", out)
			}
			seen := map[string]bool{}
			for _, p := range out {
				if seen[key(p)] {
					t.Fatalf("mergeProps output repeats %q: %v", key(p), out)
				}
				seen[key(p)] = true
			}
			want := map[string]bool{}
			for _, p := range append(slices.Clone(dst), src...) {
				want[key(p)] = true
			}
			if !reflect.DeepEqual(seen, want) {
				t.Fatalf("mergeProps(%v, %v) = %v: lost or invented a property", dst, src, out)
			}
			if again := mergeProps(slices.Clone(out), src); !slices.Equal(again, out) {
				t.Fatalf("mergeProps not idempotent: %v then %v", out, again)
			}
		}
		if got := mergeProps(nil, nil); len(got) != 0 {
			t.Fatalf("mergeProps(nil, nil) = %v", got)
		}
		if got := mergeProps(nil, []Property{{}}); len(got) != 1 {
			t.Fatalf("a zero-value property is a distinct name=value and must be kept, got %v", got)
		}
	})

	t.Run("componentDedupeKey precedence", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			c := Component{
				Type:    pick("library", "Library", "application"),
				Name:    pick("lodash", "LoDash", "x"),
				Version: pick("1.0.0", "1.0.0-RC1", ""),
				Purl:    pick("", "pkg:npm/lodash@1.0.0"),
				BOMRef:  pick("", "ref-1"),
			}
			got := componentDedupeKey(c)
			switch {
			case c.Purl != "":
				if got != "purl:"+c.Purl {
					t.Fatalf("purl must win: %+v -> %q", c, got)
				}
			case c.BOMRef != "":
				if got != "ref:"+c.BOMRef {
					t.Fatalf("bom-ref must win over type:name@version: %+v -> %q", c, got)
				}
			default:
				if want := strings.ToLower(c.Type + ":" + c.Name + "@" + c.Version); got != want {
					t.Fatalf("fallback key for %+v = %q, want %q", c, got, want)
				}
			}
		}
	})

	t.Run("components with equal keys merge rather than duplicate", func(t *testing.T) {
		for i := 0; i < 500; i++ {
			dst := &Document{Metadata: &Metadata{Tools: &Tools{}}}
			index := map[string]int{}
			refs := map[string]bool{}
			deps := map[string][]string{}
			keys := map[string]bool{}
			for s := 0; s < 1+rng.Intn(3); s++ {
				src := &Document{}
				for n, k := 0, rng.Intn(8); n < k; n++ {
					c := Component{
						Type:    pick("library", "LIBRARY"),
						Name:    pick("a", "A", "b"),
						Version: pick("1", "2"),
						Purl:    pick("", "", "pkg:npm/a@1"),
						BOMRef:  pick("", "", "ref-b"),
						Hashes:  []Hash{genHash()},
					}
					src.Components = append(src.Components, c)
					keys[componentDedupeKey(c)] = true
				}
				mergeSubBOM(dst, src, index, refs, deps)
			}
			if len(dst.Components) != len(keys) {
				t.Fatalf("merged %d components for %d distinct keys", len(dst.Components), len(keys))
			}
			// Duplicates share the key, so merging one in never changes which key
			// the surviving component is indexed under.
			for k, idx := range index {
				if got := componentDedupeKey(dst.Components[idx]); got != k {
					t.Fatalf("index key %q points at component keyed %q", k, got)
				}
			}
		}
	})
}

// checkAppendMerge asserts the contract shared by mergeHashes, mergeLicenses,
// mergeContacts and mergeExtRefs: dst is kept verbatim as a prefix, src entries
// whose key is new (and non-empty, for licenses) are appended in order with the
// first occurrence winning, and merging the same src again changes nothing.
func checkAppendMerge[T any](t *testing.T, rng *rand.Rand, merge func(dst, src []T) []T, gen func() T, dropEmptyKey bool, key func(T) string) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		dst, src := genSlice(rng, gen), genSlice(rng, gen)

		out := merge(slices.Clone(dst), src)
		if len(out) < len(dst) || (len(dst) > 0 && !reflect.DeepEqual(out[:len(dst)], dst)) {
			t.Fatalf("dst order or content changed:\ndst %v\nout %v", dst, out)
		}

		seen := map[string]bool{}
		for _, d := range dst {
			seen[key(d)] = true
		}
		var want []T
		for _, s := range src {
			k := key(s)
			if k == "" && dropEmptyKey {
				continue
			}
			if !seen[k] {
				seen[k] = true
				want = append(want, s)
			}
		}
		if appended := out[len(dst):]; len(appended) != len(want) || (len(want) > 0 && !reflect.DeepEqual(appended, want)) {
			t.Fatalf("appended %v, want %v (dst %v, src %v)", appended, want, dst, src)
		}

		if again := merge(slices.Clone(out), src); !reflect.DeepEqual(again, out) {
			t.Fatalf("not idempotent: %v then %v", out, again)
		}
	}
	// Nil and empty inputs never panic.
	_ = merge(nil, nil)
	_ = merge(nil, []T{})
	_ = merge([]T{}, nil)
}

func genSlice[T any](rng *rand.Rand, gen func() T) []T {
	n := rng.Intn(7)
	if n == 0 && rng.Intn(2) == 0 {
		return nil
	}
	out := make([]T, n)
	for i := range out {
		out[i] = gen()
	}
	return out
}
