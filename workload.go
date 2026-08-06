package cyclonedx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The identity a Vulnetix service signs with.
//
// The CLI signs with whatever identity the runner already has, because a scan
// run in a customer's CI should be attested by that customer. A service has no
// ambient identity, so it asks Authentik for one: a client_credentials token
// whose subject is the workload's SPIFFE ID, which is what makes Fulcio willing
// to certify it.
//
// This is a token source and nothing more. It has no opinion about what the
// token is used for, and the SPIFFE ID it carries is set by the Authentik
// blueprint, not here, so adding a workload does not mean changing this code.

// WorkloadIdentity fetches and caches an OIDC token for one workload.
//
// Safe for concurrent use. The four services that publish artifacts each hold
// one of these for the lifetime of the process.
type WorkloadIdentity struct {
	// Issuer is the application's OIDC issuer, for example
	// https://auth.vulnetix.com/application/o/sigstore/. Required.
	Issuer string
	// ClientID is the provider's generated client id. Required.
	ClientID string
	// Username is the service account, for example svc-sigstore-code-scanner.
	Username string
	// Password is that account's app-password token value.
	Password string
	// TokenEndpoint overrides discovery. Left empty, the endpoint is read from
	// the issuer's openid-configuration once and reused.
	TokenEndpoint string
	// HTTPClient defaults to a client with a timeout.
	HTTPClient *http.Client

	mu       sync.Mutex
	token    string
	expires  time.Time
	endpoint string
}

func (w *WorkloadIdentity) client() *http.Client {
	if w.HTTPClient != nil {
		return w.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// Token returns a valid token for the audience, minting a new one when the
// cached one is close to expiry. It satisfies IdentityTokenFunc.
//
// The audience is not sent: Authentik sets it from the scope mapping, to the
// fixed value Fulcio's configuration expects. It is accepted here so this can
// be used wherever an IdentityTokenFunc is wanted, and checked so a caller
// asking for a different audience gets told rather than getting a token that
// Fulcio will silently reject.
func (w *WorkloadIdentity) Token(ctx context.Context, audience string) (string, error) {
	if w == nil || w.Issuer == "" || w.ClientID == "" || w.Username == "" || w.Password == "" {
		return "", ErrNoSigner
	}
	if audience != "" && audience != SigstoreAudience {
		return "", fmt.Errorf("cyclonedx: workload identity issues audience %q, not %q", SigstoreAudience, audience)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// One minute of headroom. A token that expires in transit is rejected by
	// Fulcio with a message that looks like a configuration error, and chasing
	// that costs more than fetching slightly early.
	if w.token != "" && time.Until(w.expires) > time.Minute {
		return w.token, nil
	}

	endpoint, err := w.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {w.ClientID},
		"username":   {w.Username},
		"password":   {w.Password},
		// The SPIFFE claim mapping is bound to openid, which every OIDC request
		// carries, so it cannot go missing because the scope list was trimmed.
		"scope": {"openid"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := w.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("workload identity: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("workload identity: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", fmt.Errorf("workload identity: unreadable response: %w", err)
	}
	if body.AccessToken == "" {
		return "", errors.New("workload identity: response carried no access token")
	}

	// client_credentials returns an access token and no id_token. Fulcio
	// verifies whatever JWT it is handed against the issuer's published keys, so
	// the access token is the token to present.
	w.token = body.AccessToken
	if body.ExpiresIn > 0 {
		w.expires = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	} else {
		w.expires = time.Now().Add(5 * time.Minute)
	}
	return w.token, nil
}

// resolveTokenEndpoint reads token_endpoint from the issuer's discovery
// document, once. Callers must hold w.mu.
func (w *WorkloadIdentity) resolveTokenEndpoint(ctx context.Context) (string, error) {
	if w.TokenEndpoint != "" {
		return w.TokenEndpoint, nil
	}
	if w.endpoint != "" {
		return w.endpoint, nil
	}

	discovery := strings.TrimRight(w.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	if err != nil {
		return "", err
	}

	resp, err := w.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("workload identity: discovery: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("workload identity: discovery: %s", resp.Status)
	}

	var body struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", fmt.Errorf("workload identity: discovery: %w", err)
	}
	if body.TokenEndpoint == "" {
		return "", errors.New("workload identity: discovery carried no token_endpoint")
	}

	w.endpoint = body.TokenEndpoint
	return w.endpoint, nil
}
