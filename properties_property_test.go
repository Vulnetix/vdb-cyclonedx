package cyclonedx

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

// TestPropertySetProperty asserts the upsert contract of SetProperty and
// GetProperty over generated name/value sequences. The upsert was once
// reimplemented as a plain append, which left a document asserting the same
// property twice with different values; these invariants are what an append
// breaks.
func TestPropertySetProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// A small name pool forces collisions, so most sequences overwrite.
	names := []string{"vulnetix:a", "vulnetix:b", "vulnetix:c", "x", "", "vulnetix:bom/derived-from"}
	pickName := func() string { return names[rng.Intn(len(names))] }
	pickValue := func() string { return fmt.Sprintf("v%d", rng.Intn(5)) }

	t.Run("upsert is idempotent", func(t *testing.T) {
		for i := 0; i < 500; i++ {
			name, value := pickName(), pickValue()
			var props []Property
			for n, k := 0, rng.Intn(6); n < k; n++ {
				props = SetProperty(props, pickName(), pickValue())
			}
			once := SetProperty(append([]Property(nil), props...), name, value)
			many := append([]Property(nil), props...)
			for n, k := 0, 1+rng.Intn(5); n < k; n++ {
				many = SetProperty(many, name, value)
			}
			if !slices.Equal(once, many) {
				t.Fatalf("applying (%q,%q) repeatedly diverged from applying it once:\nonce %v\nmany %v", name, value, once, many)
			}
			if c := countName(many, name); c != 1 {
				t.Fatalf("name %q present %d times after upserts, want 1: %v", name, c, many)
			}
			if got, ok := GetProperty(many, name); !ok || got != value {
				t.Fatalf("GetProperty(%q) = (%q,%v), want (%q,true)", name, got, ok, value)
			}
		}
	})

	t.Run("names stay unique and the last write wins", func(t *testing.T) {
		for i := 0; i < 500; i++ {
			var props []Property
			want := map[string]string{}
			for n, k := 0, 1+rng.Intn(20); n < k; n++ {
				name, value := pickName(), pickValue()
				props = SetProperty(props, name, value)
				want[name] = value
			}
			for _, p := range props {
				if c := countName(props, p.Name); c != 1 {
					t.Fatalf("name %q present %d times: %v", p.Name, c, props)
				}
			}
			if len(props) != len(want) {
				t.Fatalf("got %d properties, want %d distinct names: %v", len(props), len(want), props)
			}
			// Distinct names never clobber each other: each reads back its own
			// last value.
			for name, value := range want {
				if got, ok := GetProperty(props, name); !ok || got != value {
					t.Fatalf("GetProperty(%q) = (%q,%v), want (%q,true): %v", name, got, ok, value, props)
				}
			}
		}
	})

	t.Run("absent names read as not found", func(t *testing.T) {
		for i := 0; i < 200; i++ {
			var props []Property
			for n, k := 0, rng.Intn(10); n < k; n++ {
				props = SetProperty(props, pickName(), pickValue())
			}
			absent := fmt.Sprintf("absent:%d", rng.Int())
			if got, ok := GetProperty(props, absent); ok || got != "" {
				t.Fatalf("GetProperty(%q) = (%q,%v), want (\"\",false)", absent, got, ok)
			}
		}
		if got, ok := GetProperty(nil, "vulnetix:a"); ok || got != "" {
			t.Fatalf("GetProperty(nil) = (%q,%v), want (\"\",false)", got, ok)
		}
	})

	t.Run("Metadata and Component wrappers match the slice helpers", func(t *testing.T) {
		for i := 0; i < 200; i++ {
			m, c := &Metadata{}, &Component{}
			var props []Property
			for n, k := 0, 1+rng.Intn(10); n < k; n++ {
				name, value := pickName(), pickValue()
				m.SetProperty(name, value)
				c.SetProperty(name, value)
				props = SetProperty(props, name, value)
			}
			if !slices.Equal(m.Properties, props) || !slices.Equal(c.Properties, props) {
				t.Fatalf("wrapper diverged:\nmetadata  %v\ncomponent %v\nslice     %v", m.Properties, c.Properties, props)
			}
			for _, p := range props {
				if got, ok := m.GetProperty(p.Name); !ok || got != p.Value {
					t.Fatalf("Metadata.GetProperty(%q) = (%q,%v), want (%q,true)", p.Name, got, ok, p.Value)
				}
				if got, ok := c.GetProperty(p.Name); !ok || got != p.Value {
					t.Fatalf("Component.GetProperty(%q) = (%q,%v), want (%q,true)", p.Name, got, ok, p.Value)
				}
			}
		}
	})

	t.Run("nil receivers are safe", func(t *testing.T) {
		var m *Metadata
		var c *Component
		for i := 0; i < 50; i++ {
			name, value := pickName(), pickValue()
			m.SetProperty(name, value)
			c.SetProperty(name, value)
			if got, ok := m.GetProperty(name); ok || got != "" {
				t.Fatalf("(*Metadata)(nil).GetProperty(%q) = (%q,%v), want (\"\",false)", name, got, ok)
			}
			if got, ok := c.GetProperty(name); ok || got != "" {
				t.Fatalf("(*Component)(nil).GetProperty(%q) = (%q,%v), want (\"\",false)", name, got, ok)
			}
		}
	})
}

func countName(props []Property, name string) int {
	n := 0
	for _, p := range props {
		if p.Name == name {
			n++
		}
	}
	return n
}
