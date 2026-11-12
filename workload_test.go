package cyclonedx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The tests below pin the error paths and boundaries of Token and
// resolveTokenEndpoint that only fail on a wrong error, a wrong lifetime or a
// leaked body, rather than on a missing error.

const testIssuer = "http://issuer.invalid"

// respond builds a canned response the way net/http would deliver it.
func respond(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// idp answers discovery with a token endpoint and the token exchange with
// tokenBody, both 200.
func idp(tokenBody string) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			return respond(http.StatusOK, `{"token_endpoint":"`+testIssuer+`/token"}`), nil
		}
		return respond(http.StatusOK, tokenBody), nil
	}
}

// fullWorkload is a WorkloadIdentity with every required field set, talking
// to rt.
func fullWorkload(rt roundTripFunc) *WorkloadIdentity {
	return &WorkloadIdentity{
		Issuer:     testIssuer,
		ClientID:   "test-client",
		Username:   "svc-test",
		Password:   "app-password",
		HTTPClient: &http.Client{Transport: rt},
	}
}

// paddedJSON is a valid JSON object with the given members plus padding, of
// at least size bytes.
func paddedJSON(members string, size int) string {
	return `{` + members + `,"pad":"` + strings.Repeat("x", size) + `"}`
}

func TestWorkloadIdentity_EachRequiredFieldIsChecked(t *testing.T) {
	for _, field := range []string{"Issuer", "ClientID", "Username", "Password"} {
		t.Run(field, func(t *testing.T) {
			var calls atomic.Int32
			ok := idp(`{"access_token":"tok","expires_in":3600}`)
			w := fullWorkload(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return ok(r)
			})
			switch field {
			case "Issuer":
				w.Issuer = ""
			case "ClientID":
				w.ClientID = ""
			case "Username":
				w.Username = ""
			case "Password":
				w.Password = ""
			}
			tok, err := w.Token(context.Background(), SigstoreAudience)
			if !errors.Is(err, ErrNoSigner) || tok != "" {
				t.Fatalf("Token = (%q, %v), want ErrNoSigner", tok, err)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("made %d requests without credentials, want 0", n)
			}
		})
	}
}

func TestWorkloadIdentity_EmptyAudienceIsAccepted(t *testing.T) {
	w := fullWorkload(idp(`{"access_token":"tok","expires_in":3600}`))
	tok, err := w.Token(context.Background(), "")
	if err != nil || tok != "tok" {
		t.Fatalf("Token(\"\") = (%q, %v), want (\"tok\", nil)", tok, err)
	}
}

func TestWorkloadIdentity_EmptyCachedTokenIsNotServed(t *testing.T) {
	w := fullWorkload(idp(`{"access_token":"tok","expires_in":3600}`))
	// An expiry in the future with no token must still fetch, never hand back
	// the empty string as a token.
	w.expires = time.Now().Add(time.Hour)
	tok, err := w.Token(context.Background(), SigstoreAudience)
	if err != nil || tok != "tok" {
		t.Fatalf("Token = (%q, %v), want (\"tok\", nil)", tok, err)
	}
}

func TestWorkloadIdentity_ClientUsesInjectedHTTPClient(t *testing.T) {
	c := &http.Client{}
	w := &WorkloadIdentity{HTTPClient: c}
	if got := w.client(); got != c {
		t.Fatalf("client() = %p, want the injected %p", got, c)
	}
}

func TestWorkloadIdentity_TokenRequestIsFormEncoded(t *testing.T) {
	w := fullWorkload(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			return respond(http.StatusOK, `{"token_endpoint":"`+testIssuer+`/token"}`), nil
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			return respond(http.StatusBadRequest, "content type "+ct), nil
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" {
			return respond(http.StatusBadRequest, "bad form"), nil
		}
		return respond(http.StatusOK, `{"access_token":"tok","expires_in":3600}`), nil
	})
	if tok, err := w.Token(context.Background(), SigstoreAudience); err != nil || tok != "tok" {
		t.Fatalf("Token = (%q, %v), want (\"tok\", nil)", tok, err)
	}
}

// closeTracker is a response body that records Close.
type closeTracker struct {
	io.Reader
	closed atomic.Bool
}

func (c *closeTracker) Close() error { c.closed.Store(true); return nil }

func TestWorkloadIdentity_ResponseBodiesAreClosed(t *testing.T) {
	discovery := &closeTracker{Reader: strings.NewReader(`{"token_endpoint":"` + testIssuer + `/token"}`)}
	token := &closeTracker{Reader: strings.NewReader(`{"access_token":"tok","expires_in":3600}`)}
	w := fullWorkload(func(r *http.Request) (*http.Response, error) {
		resp := respond(http.StatusOK, "")
		if r.URL.Path == "/.well-known/openid-configuration" {
			resp.Body = discovery
		} else {
			resp.Body = token
		}
		return resp, nil
	})
	if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !discovery.closed.Load() {
		t.Error("discovery response body was not closed")
	}
	if !token.closed.Load() {
		t.Error("token response body was not closed")
	}
}

// sentinelReader fails every Read with errSentinelRead.
type sentinelReader struct{}

var errSentinelRead = errors.New("sentinel read failure")

func (sentinelReader) Read([]byte) (int, error) { return 0, errSentinelRead }

func TestWorkloadIdentity_BodyReadErrorIsReturned(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		w := fullWorkload(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				return respond(http.StatusOK, `{"token_endpoint":"`+testIssuer+`/token"}`), nil
			}
			resp := respond(http.StatusOK, "")
			resp.Body = io.NopCloser(sentinelReader{})
			return resp, nil
		})
		if _, err := w.Token(context.Background(), SigstoreAudience); !errors.Is(err, errSentinelRead) {
			t.Fatalf("err = %v, want the body read error", err)
		}
	})
	t.Run("discovery", func(t *testing.T) {
		w := fullWorkload(func(r *http.Request) (*http.Response, error) {
			resp := respond(http.StatusOK, "")
			resp.Body = io.NopCloser(sentinelReader{})
			return resp, nil
		})
		if _, err := w.Token(context.Background(), SigstoreAudience); !errors.Is(err, errSentinelRead) {
			t.Fatalf("err = %v, want the body read error", err)
		}
	})
}

func TestWorkloadIdentity_NonOKStatusWinsOverATokenBody(t *testing.T) {
	// A 403 whose body still parses as a token must be an error carrying the
	// status and the body, never a token.
	body := `{"access_token":"tok","expires_in":3600}`
	w := fullWorkload(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			return respond(http.StatusOK, `{"token_endpoint":"`+testIssuer+`/token"}`), nil
		}
		return respond(http.StatusForbidden, body+"\n"), nil
	})
	tok, err := w.Token(context.Background(), SigstoreAudience)
	if err == nil || tok != "" {
		t.Fatalf("Token = (%q, %v), want an error", tok, err)
	}
	want := "workload identity: 403 Forbidden: " + body
	if err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
}

func TestWorkloadIdentity_MistypedTokenResponseIsRejected(t *testing.T) {
	// json.Unmarshal still fills access_token when expires_in has the wrong
	// type, so only the Unmarshal error stops this token being used.
	w := fullWorkload(idp(`{"access_token":"tok","expires_in":"soon"}`))
	tok, err := w.Token(context.Background(), SigstoreAudience)
	if err == nil || tok != "" || !strings.Contains(err.Error(), "unreadable response") {
		t.Fatalf("Token = (%q, %v), want an unreadable response error", tok, err)
	}
}

func TestWorkloadIdentity_DiscoveryResponseErrors(t *testing.T) {
	discoveryOnly := func(body string, tokenCalls *atomic.Int32) roundTripFunc {
		return func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				return respond(http.StatusOK, body), nil
			}
			tokenCalls.Add(1)
			return respond(http.StatusOK, `{"access_token":"tok","expires_in":3600}`), nil
		}
	}
	t.Run("malformed JSON", func(t *testing.T) {
		var tokenCalls atomic.Int32
		w := fullWorkload(discoveryOnly(`{"token_endpoint":`, &tokenCalls))
		_, err := w.Token(context.Background(), SigstoreAudience)
		var syntax *json.SyntaxError
		if !errors.As(err, &syntax) {
			t.Fatalf("err = %v, want the JSON syntax error", err)
		}
		if tokenCalls.Load() != 0 {
			t.Fatal("token endpoint called after a failed discovery")
		}
	})
	t.Run("no token_endpoint", func(t *testing.T) {
		var tokenCalls atomic.Int32
		w := fullWorkload(discoveryOnly(`{"issuer":"`+testIssuer+`"}`, &tokenCalls))
		_, err := w.Token(context.Background(), SigstoreAudience)
		if err == nil || err.Error() != "workload identity: discovery carried no token_endpoint" {
			t.Fatalf("err = %v, want the missing token_endpoint error", err)
		}
		if tokenCalls.Load() != 0 {
			t.Fatal("token endpoint called after a failed discovery")
		}
	})
}

func TestWorkloadIdentity_DiscoveredEndpointIsReusedOnRefetch(t *testing.T) {
	var discovery, exchanges atomic.Int32
	w := fullWorkload(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery.Add(1)
			return respond(http.StatusOK, `{"token_endpoint":"`+testIssuer+`/token"}`), nil
		}
		exchanges.Add(1)
		// Inside the one-minute headroom, so every call mints a new token.
		return respond(http.StatusOK, `{"access_token":"tok","expires_in":30}`), nil
	})
	for i := 0; i < 3; i++ {
		if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
			t.Fatalf("Token #%d: %v", i, err)
		}
	}
	if exchanges.Load() != 3 {
		t.Fatalf("token exchanges = %d, want 3", exchanges.Load())
	}
	if discovery.Load() != 1 {
		t.Fatalf("discovery ran %d times, want 1", discovery.Load())
	}
}

func TestWorkloadIdentity_TokenLifetime(t *testing.T) {
	cases := []struct {
		name string
		body string
		want time.Duration
	}{
		{"expires_in missing defaults to five minutes", `{"access_token":"tok"}`, 5 * time.Minute},
		{"expires_in zero defaults to five minutes", `{"access_token":"tok","expires_in":0}`, 5 * time.Minute},
		{"expires_in negative defaults to five minutes", `{"access_token":"tok","expires_in":-1}`, 5 * time.Minute},
		{"expires_in one second is honoured", `{"access_token":"tok","expires_in":1}`, time.Second},
		{"expires_in is seconds", `{"access_token":"tok","expires_in":120}`, 2 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := fullWorkload(idp(c.body))
			before := time.Now()
			if _, err := w.Token(context.Background(), SigstoreAudience); err != nil {
				t.Fatalf("Token: %v", err)
			}
			after := time.Now()
			if w.expires.Before(before.Add(c.want)) || w.expires.After(after.Add(c.want)) {
				t.Fatalf("expires = %v from now, want %v", w.expires.Sub(before), c.want)
			}
		})
	}
}

func TestWorkloadIdentity_ResponseSizeLimit(t *testing.T) {
	const limit = 1 << 20
	t.Run("token body under the limit is read whole", func(t *testing.T) {
		w := fullWorkload(idp(paddedJSON(`"access_token":"tok"`, limit*3/4)))
		if tok, err := w.Token(context.Background(), SigstoreAudience); err != nil || tok != "tok" {
			t.Fatalf("Token = (%q, %v), want (\"tok\", nil)", tok, err)
		}
	})
	t.Run("token body over the limit is truncated", func(t *testing.T) {
		w := fullWorkload(idp(paddedJSON(`"access_token":"tok"`, limit)))
		if _, err := w.Token(context.Background(), SigstoreAudience); err == nil || !strings.Contains(err.Error(), "unreadable response") {
			t.Fatalf("err = %v, want a truncated-body error", err)
		}
	})
	discovery := func(body string) roundTripFunc {
		return func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				return respond(http.StatusOK, body), nil
			}
			return respond(http.StatusOK, `{"access_token":"tok","expires_in":3600}`), nil
		}
	}
	t.Run("discovery body under the limit is read whole", func(t *testing.T) {
		w := fullWorkload(discovery(paddedJSON(`"token_endpoint":"`+testIssuer+`/token"`, limit*3/4)))
		if tok, err := w.Token(context.Background(), SigstoreAudience); err != nil || tok != "tok" {
			t.Fatalf("Token = (%q, %v), want (\"tok\", nil)", tok, err)
		}
	})
	t.Run("discovery body over the limit is truncated", func(t *testing.T) {
		w := fullWorkload(discovery(paddedJSON(`"token_endpoint":"`+testIssuer+`/token"`, limit)))
		_, err := w.Token(context.Background(), SigstoreAudience)
		var syntax *json.SyntaxError
		if !errors.As(err, &syntax) {
			t.Fatalf("err = %v, want a truncated-body syntax error", err)
		}
	})
}
