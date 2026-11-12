package cyclonedx

import (
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// customPhases are lifecycle names outside the schema enum. lifecyclesFor keeps
// them (sorted, after the known phases); ParseLifecyclePhases rejects them.
var customPhases = []LifecyclePhase{"audit", "canary", "zz-custom", "Build"}

// randomPhases draws a phase list with duplicates from the schema enum and,
// when withCustom is set, from customPhases.
func randomPhases(rng *rand.Rand, withCustom bool) []LifecyclePhase {
	pool := LifecyclePhases()
	if withCustom {
		pool = append(pool, customPhases...)
	}
	out := make([]LifecyclePhase, rng.Intn(12))
	for i := range out {
		out[i] = pool[rng.Intn(len(pool))]
	}
	return out
}

// TestPropertyLifecycles asserts lifecyclesFor serialises any set of phases
// identically whatever order or multiplicity it arrives in, and that
// ParseLifecyclePhases inverts joinPhases.
func TestPropertyLifecycles(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	rank := map[string]int{}
	for i, p := range LifecyclePhases() {
		rank[string(p)] = i
	}

	t.Run("order independence, dedupe and ordering", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			phases := randomPhases(rng, true)
			got := lifecyclesFor(phases)

			sorted := slices.Clone(phases)
			slices.Sort(sorted)
			if want := lifecyclesFor(sorted); !slices.Equal(got, want) {
				t.Fatalf("lifecyclesFor(%v) = %v, but its sorted permutation gives %v", phases, got, want)
			}
			shuffled := slices.Clone(phases)
			rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
			if want := lifecyclesFor(shuffled); !slices.Equal(got, want) {
				t.Fatalf("lifecyclesFor(%v) = %v, but permutation %v gives %v", phases, got, shuffled, want)
			}

			distinct := map[LifecyclePhase]bool{}
			for _, p := range phases {
				distinct[p] = true
			}
			if len(got) != len(distinct) {
				t.Fatalf("lifecyclesFor(%v) has %d entries, want %d distinct phases: %v", phases, len(got), len(distinct), got)
			}
			if len(phases) == 0 && got != nil {
				t.Fatalf("lifecyclesFor(empty) = %v, want nil", got)
			}

			// Known phases come first, in schema enum order; custom phases follow,
			// sorted lexicographically.
			var custom []string
			lastKnown := -1
			for _, lc := range got {
				r, known := rank[lc.Phase]
				if known {
					if custom != nil {
						t.Fatalf("known phase %q follows a custom phase in %v", lc.Phase, got)
					}
					if r <= lastKnown {
						t.Fatalf("known phases out of enum order in %v", got)
					}
					lastKnown = r
					continue
				}
				custom = append(custom, lc.Phase)
			}
			if !sort.StringsAreSorted(custom) {
				t.Fatalf("custom phases not sorted in %v", got)
			}
		}
	})

	t.Run("ParseLifecyclePhases inverts joinPhases", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			phases := randomPhases(rng, false)
			parsed, err := ParseLifecyclePhases(joinPhases(phases))
			if err != nil {
				t.Fatalf("ParseLifecyclePhases(joinPhases(%v)): %v", phases, err)
			}
			if !slices.Equal(lifecyclesFor(parsed), lifecyclesFor(phases)) {
				t.Fatalf("round trip of %v gave %v", phases, parsed)
			}
		}
	})

	t.Run("ParseLifecyclePhases never panics and rejects any unknown phase", func(t *testing.T) {
		alphabet := []rune("abcdeiloprstuz-, \t\n\x00é")
		for i := 0; i < 2000; i++ {
			var raw string
			if rng.Intn(2) == 0 {
				raw = genString(rng, alphabet, 0, 40)
			} else {
				// Mix valid phases (in random case and padding) with junk fields.
				fields := make([]string, 1+rng.Intn(6))
				for j := range fields {
					if rng.Intn(3) == 0 {
						fields[j] = genString(rng, alphabet, 0, 8)
					} else {
						p := string(lifecyclePhaseOrder[rng.Intn(len(lifecyclePhaseOrder))])
						if rng.Intn(2) == 0 {
							p = strings.ToUpper(p)
						}
						fields[j] = " " + p + " "
					}
				}
				raw = strings.Join(fields, ",")
			}

			parsed, err := ParseLifecyclePhases(raw)
			if err != nil {
				if parsed != nil {
					t.Fatalf("ParseLifecyclePhases(%q) returned %v alongside error %v", raw, parsed, err)
				}
				continue
			}
			for _, p := range parsed {
				if !p.Valid() {
					t.Fatalf("ParseLifecyclePhases(%q) accepted unknown phase %q", raw, p)
				}
			}
			// Success means every non-blank field named a known phase.
			for _, f := range strings.Split(raw, ",") {
				f = strings.ToLower(strings.TrimSpace(f))
				if f != "" && !LifecyclePhase(f).Valid() {
					t.Fatalf("ParseLifecyclePhases(%q) succeeded despite unknown field %q", raw, f)
				}
			}
		}

		for _, custom := range customPhases[:3] {
			raw := string(PhaseBuild) + "," + string(custom)
			if _, err := ParseLifecyclePhases(raw); err == nil {
				t.Fatalf("ParseLifecyclePhases(%q) mixed a valid and an unknown phase without error", raw)
			}
		}
	})
}

// TestPropertyNormalizeSerialNumber asserts NormalizeSerialNumber always yields
// a parseable urn:uuid, is stable for any non-empty input, and passes a valid
// UUID through with only the prefix and case changed.
func TestPropertyNormalizeSerialNumber(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alphabet := []rune("0123456789abcdefABCDEF-:/{}urnid.? \t\x00\x7fé")

	newUUID := func() uuid.UUID {
		var u uuid.UUID
		for i := range u {
			u[i] = byte(rng.Intn(256))
		}
		u[6] = (u[6] & 0x0f) | 0x40 // version 4
		u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
		return u
	}

	var inputs []string
	for i := 0; i < 300; i++ {
		u := newUUID().String()
		inputs = append(inputs,
			u,
			strings.ToUpper(u),
			"urn:uuid:"+u,
			"URN:UUID:"+strings.ToUpper(u),
			"  "+u+"\t",
			"urn:uuid:"+u[:len(u)-1-rng.Intn(5)],
			"urn:uuid:"+genString(rng, alphabet, 0, 40),
			fmt.Sprintf("https://spdx.org/spdxdocs/doc-%d", rng.Int()),
			genString(rng, alphabet, 1, 60),
		)
	}
	inputs = append(inputs, "", " ", "\t\n", "\x00", "urn:uuid:", "urn:uuid")

	assertURN := func(in, got string) {
		t.Helper()
		if !strings.HasPrefix(got, "urn:uuid:") {
			t.Fatalf("NormalizeSerialNumber(%q) = %q, want a urn:uuid: prefix", in, got)
		}
		if _, err := uuid.Parse(strings.TrimPrefix(got, "urn:uuid:")); err != nil {
			t.Fatalf("NormalizeSerialNumber(%q) = %q, whose uuid does not parse: %v", in, got, err)
		}
	}

	for _, in := range inputs {
		got := NormalizeSerialNumber(in)
		assertURN(in, got)

		if strings.TrimSpace(in) == "" {
			// Only an empty id mints a fresh serial, so two calls must differ.
			if again := NormalizeSerialNumber(in); again == got {
				t.Fatalf("NormalizeSerialNumber(%q) returned %q twice; an empty id must mint a fresh serial", in, got)
			}
			continue
		}
		if again := NormalizeSerialNumber(in); again != got {
			t.Fatalf("NormalizeSerialNumber(%q) is unstable: %q then %q", in, got, again)
		}
	}

	// A valid UUID, bare or already prefixed, differs from the output only by
	// the prefix and case.
	for i := 0; i < 500; i++ {
		u := newUUID().String()
		for _, in := range []string{u, strings.ToUpper(u), "urn:uuid:" + u, "URN:UUID:" + strings.ToUpper(u)} {
			if got, want := NormalizeSerialNumber(in), "urn:uuid:"+u; got != want {
				t.Fatalf("NormalizeSerialNumber(%q) = %q, want %q", in, got, want)
			}
		}
	}

	// The UUIDv5 fallback for non-UUID identifiers is the URL-namespace hash.
	for i := 0; i < 100; i++ {
		in := fmt.Sprintf("https://example.com/spdx/%d", rng.Int())
		want := "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(in)).String()
		if got := NormalizeSerialNumber(in); got != want {
			t.Fatalf("NormalizeSerialNumber(%q) = %q, want the NameSpaceURL v5 id %q", in, got, want)
		}
	}
}

// genString returns a string of minLen..maxLen runes drawn from alphabet.
func genString(rng *rand.Rand, alphabet []rune, minLen, maxLen int) string {
	n := minLen + rng.Intn(maxLen-minLen+1)
	out := make([]rune, n)
	for i := range out {
		out[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(out)
}
