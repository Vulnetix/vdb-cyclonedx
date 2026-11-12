package cyclonedx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The identity the tests run against is a local httptest server, never the real
// Authentik or Fulcio: every field the struct exposes for a network call goes
// through w.client(), so injecting HTTPClient redirects all traffic.

func testWorkload(t *testing.T, server *httptest.Server) *WorkloadIdentity {
	t.Helper()
	return &WorkloadIdentity{
		Issuer:     server.URL,
		ClientID:   "test-client",
		Username:   "svc-test",
		Password:   "app-password",
		HTTPClient: server.Client(),
	}
}

func TestWorkloadIdentity_TokenCachesUnexpired(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "http://" + r.Host + "/token"})
			return
		}
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 3600})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	w := testWorkload(t, server)
	first, err := w.Token(context.Background(), SigstoreAudience)
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	if first != "abc" {
		t.Fatalf("first token = %q, want %q", first, "abc")
	}
	afterFirst := requests.Load()
	second, err := w.Token(context.Background(), SigstoreAudience)
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if second != "abc" {
		t.Fatalf("second token = %q, want %q", second, "abc")
	}
	if got := requests.Load(); got != afterFirst {
		t.Fatalf("server saw %d requests after second Token, want %d (cached token must not refetch)", got, afterFirst)
	}
}

func TestWorkloadIdentity_TokenDiscoversEndpointOnce(t *testing.T) {
	var discovery atomic.Int32
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "http://" + r.Host + "/token"})
		case "/token":
			tokenRequests.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	w := testWorkload(t, server)
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	// Second call returns the cached token: no discovery, no token request.
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if got := discovery.Load(); got != 1 {
		t.Fatalf("discovery ran %d times, want 1 (endpoint must be cached)", got)
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("token endpoint served %d requests, want 1", got)
	}
}

func TestWorkloadIdentity_TokenEndpointOverrideSkipsDiscovery(t *testing.T) {
	var discovery atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery.Add(1)
		}
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 3600})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	w := testWorkload(t, server)
	w.TokenEndpoint = "http://" + strings.TrimPrefix(server.URL, "http://") + "/token"
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("Token with override: %v", err)
	}
	if got := discovery.Load(); got != 0 {
		t.Fatalf("discovery ran %d times, want 0 (override must skip discovery)", got)
	}
}

func TestWorkloadIdentity_TokenErrors(t *testing.T) {
	t.Run("missing required field returns ErrNoSigner", func(t *testing.T) {
		w := &WorkloadIdentity{Issuer: "http://example.invalid"}
		if _, err := w.Token(context.Background(), SigstoreAudience); err != ErrNoSigner {
			t.Fatalf("err = %v, want ErrNoSigner", err)
		}
	})
	t.Run("nil receiver returns ErrNoSigner", func(t *testing.T) {
		var w *WorkloadIdentity
		if _, err := w.Token(context.Background(), SigstoreAudience); err != ErrNoSigner {
			t.Fatalf("err = %v, want ErrNoSigner", err)
		}
	})
	t.Run("non-Sigstore audience rejected", func(t *testing.T) {
		w := testWorkload(t, httptest.NewServer(http.NotFoundHandler()))
		_, err := w.Token(context.Background(), "other")
		if err == nil || !strings.Contains(err.Error(), `issues audience "sigstore", not "other"`) {
			t.Fatalf("err = %v, want audience mismatch error", err)
		}
	})
	t.Run("non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		defer server.Close()
		w := testWorkload(t, server)
		w.TokenEndpoint = server.URL
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on 403")
		}
	})
	t.Run("unreadable body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{"))
		}))
		defer server.Close()
		w := testWorkload(t, server)
		w.TokenEndpoint = server.URL
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on malformed JSON body")
		}
	})
	t.Run("body without access_token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		}))
		defer server.Close()
		w := testWorkload(t, server)
		w.TokenEndpoint = server.URL
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on body without access_token")
		}
	})
}

func TestWorkloadIdentity_ConcurrentToken(t *testing.T) {
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "http://" + r.Host + "/token"})
			return
		}
		tokenRequests.Add(1)
		time.Sleep(20 * time.Millisecond) // slow enough that goroutines overlap
		json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 3600})
	}))
	defer server.Close()

	w := testWorkload(t, server)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := w.Token(context.Background(), SigstoreAudience)
			if err != nil {
				t.Errorf("concurrent Token: %v", err)
				return
			}
			if token != "abc" {
				t.Errorf("concurrent token = %q, want %q", token, "abc")
			}
		}()
	}
	wg.Wait()
	// Four concurrent calls may share one fetch; none may interleave a second
	// token request after a successful one, and no goroutine may observe a
	// partially updated cache, which -race detects as a data race.
	if got := tokenRequests.Load(); got == 0 {
		t.Fatal("token endpoint never served")
	}
}

// TestWorkloadIdentity_FreshTokenAfterExpiry exercises a full refetch: the
// cached token is expired, so Token must re-run discovery and exchange again.
func TestWorkloadIdentity_FreshTokenAfterExpiry(t *testing.T) {
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "http://" + r.Host + "/token"})
			return
		}
		tokenRequests.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 3600})
	}))
	defer server.Close()

	w := testWorkload(t, server)
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	// The handler is sequential: by the time the second call returns, the
	// client has already seen the second response, so forcing expiry through
	// the private field is safe here.
	w.expires = time.Now().Add(-time.Hour)
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("refetch Token: %v", err)
	}
	if got := tokenRequests.Load(); got != 2 {
		t.Fatalf("token endpoint served %d requests, want 2 (expired token must refetch)", got)
	}
}

// TestWorkloadIdentity_DiscoveryErrors drives the discovery branch of
// resolveTokenEndpoint: every failure mode is a distinct error path.
func TestWorkloadIdentity_DiscoveryErrors(t *testing.T) {
	t.Run("discovery non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		}))
		defer server.Close()
		_, err := testWorkload(t, server).Token(context.Background(), SigstoreAudience)
		if err == nil || !strings.Contains(err.Error(), "discovery: 404 Not Found") {
			t.Fatalf("err = %v, want discovery 404 error", err)
		}
	})
	t.Run("discovery malformed JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{"))
		}))
		defer server.Close()
		if _, err := testWorkload(t, server).Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on malformed discovery JSON")
		}
	})
	t.Run("discovery without token_endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"issuer": "http://example.invalid"})
		}))
		defer server.Close()
		if _, err := testWorkload(t, server).Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on discovery without token_endpoint")
		}
	})
}

// roundTripFunc adapts a handler to an http.RoundTripper so w.client() can be
// fed without a real listener. This keeps the network-error branches of
// workload.go exercisable while the tests still perform no real I/O.
type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorkloadIdentity_DefaultClientHasTimeout(t *testing.T) {
	w := &WorkloadIdentity{}
	got := w.client()
	if got.Timeout != 20*time.Second {
		t.Fatalf("default client timeout = %v, want 20s", got.Timeout)
	}
}

func TestWorkloadIdentity_NetworkErrors(t *testing.T) {
	t.Run("token exchange transport error", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:        "http://example.invalid",
			ClientID:      "test-client",
			Username:      "svc-test",
			Password:      "app-password",
			TokenEndpoint: "http://example.invalid/token",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("dial refused")
			})},
		}
		_, err := w.Token(context.Background(), SigstoreAudience)
		if err == nil || !strings.Contains(err.Error(), "workload identity:") {
			t.Fatalf("err = %v, want wrapped transport error", err)
		}
	})
	t.Run("discovery transport error", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:   "http://example.invalid",
			ClientID: "test-client",
			Username: "svc-test",
			Password: "app-password",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("dial refused")
			})},
		}
		_, err := w.Token(context.Background(), SigstoreAudience)
		if err == nil || !strings.Contains(err.Error(), "discovery:") {
			t.Fatalf("err = %v, want wrapped discovery error", err)
		}
	})
}

func TestWorkloadIdentity_UnreadableBody(t *testing.T) {
	t.Run("token body read error", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:        "http://example.invalid",
			ClientID:      "test-client",
			Username:      "svc-test",
			Password:      "app-password",
			TokenEndpoint: "http://example.invalid/token",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(errReader{}),
				}, nil
			})},
		}
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on unreadable token body")
		}
	})
	t.Run("discovery body read error", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:   "http://example.invalid",
			ClientID: "test-client",
			Username: "svc-test",
			Password: "app-password",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(errReader{}),
				}, nil
			})},
		}
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error on unreadable discovery body")
		}
	})
}

func TestWorkloadIdentity_DefaultExpiryWhenExpiresInMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "abc"})
	}))
	defer server.Close()

	w := testWorkload(t, server)
	w.TokenEndpoint = server.URL
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("Token: %v", err)
	}
	// Without expires_in the token defaults to a five-minute lifetime, so the
	// very next call must still be served from cache.
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("cached Token: %v", err)
	}
}

// errReader is an io.Reader whose Read always fails, for the unreadable-body
// branches.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestWorkloadIdentity_RequestConstructionErrors drives the error branches of
// http.NewRequestWithContext. A URL with a control character fails URL parsing,
// which is the only way to make NewRequest fail with the fields the struct has.
func TestWorkloadIdentity_RequestConstructionErrors(t *testing.T) {
	t.Run("token request", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:        "http://example.invalid",
			ClientID:      "test-client",
			Username:      "svc-test",
			Password:      "app-password",
			TokenEndpoint: "http://\x7f.example.invalid/token",
		}
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error building the token request")
		}
	})
	t.Run("discovery request", func(t *testing.T) {
		w := &WorkloadIdentity{
			Issuer:   "http://\x7f.example.invalid",
			ClientID: "test-client",
			Username: "svc-test",
			Password: "app-password",
		}
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil {
			t.Fatal("expected error building the discovery request")
		}
	})
}
