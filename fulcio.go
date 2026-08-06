package cyclonedx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Keyless signing against Sigstore, with no Sigstore dependency.
//
// Fulcio's signing-certificate API and Rekor's log-entry API are both plain
// JSON over HTTP, and the whole exchange is: mint an ephemeral key, prove you
// hold it, hand over an OIDC token, get a short-lived certificate back. Pulling
// in the cosign module to do that would add a very large dependency tree to
// every consumer of this package, including the CLI that ships to customers.
//
// The identity is deliberately not fixed here. The CLI signs with whatever
// identity the runner already has, because a scan run in a customer's CI should
// be attested by that customer, not by Vulnetix. Vulnetix services sign with
// the SPIFFE identity Authentik issues them. Both are just a function returning
// a token.

// Public Sigstore. Overridable so the same code can be pointed at a local
// instance, which is how the identity is proven before anything depends on it.
const (
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
	DefaultRekorURL  = "https://rekor.sigstore.dev"
	// SigstoreAudience is the audience Fulcio expects in the token it is given.
	SigstoreAudience = "sigstore"
)

// ErrNoAmbientIdentity is returned when nothing in the environment can mint an
// OIDC token. On a developer laptop this is the normal case, and the caller
// publishes unsigned rather than failing.
var ErrNoAmbientIdentity = errors.New("cyclonedx: no ambient OIDC identity available")

// IdentityTokenFunc returns an OIDC token for the given audience. It is called
// once per signature so a short-lived token is always fresh.
type IdentityTokenFunc func(ctx context.Context, audience string) (string, error)

// FulcioSigner signs with an ephemeral key certified by Fulcio.
//
// The key exists only for the duration of one Sign call and is never written
// anywhere. What makes the signature verifiable later is the certificate, which
// binds the key to the identity in the OIDC token, and the transparency-log
// entry, which proves the signature existed while the certificate was valid.
type FulcioSigner struct {
	// IdentityToken mints the token presented to Fulcio. Required.
	IdentityToken IdentityTokenFunc
	// FulcioURL defaults to public Fulcio.
	FulcioURL string
	// RekorURL defaults to public Rekor. Set to "-" to skip logging entirely,
	// which is only appropriate against a local instance during testing: a
	// keyless signature that was never logged cannot be verified once the
	// certificate expires, which is minutes later.
	RekorURL string
	// Audience defaults to SigstoreAudience.
	Audience string
	// HTTPClient defaults to a client with a timeout. The zero http.Client has
	// none, and a hung Fulcio would otherwise hang a scan.
	HTTPClient *http.Client
}

func (f *FulcioSigner) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Sign implements Signer.
func (f *FulcioSigner) Sign(ctx context.Context, payload []byte) (RawSignature, error) {
	if f == nil || f.IdentityToken == nil {
		return RawSignature{}, ErrNoSigner
	}

	audience := nonEmpty(f.Audience, SigstoreAudience)
	token, err := f.IdentityToken(ctx, audience)
	if err != nil {
		return RawSignature{}, err
	}
	subject, err := tokenSubject(token)
	if err != nil {
		return RawSignature{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RawSignature{}, err
	}

	chain, err := f.signingCertificate(ctx, token, subject, key)
	if err != nil {
		return RawSignature{}, err
	}

	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return RawSignature{}, err
	}

	sig := RawSignature{
		DER:            der,
		Algorithm:      "ES256",
		KeyID:          certificateIdentity(chain, subject),
		CertificatePEM: chain,
	}

	if f.RekorURL != "-" {
		// A failure to log is reported, not swallowed: without the log entry the
		// signature stops being verifiable when the certificate expires, so a
		// caller has to know it got a signature that will not outlive the hour.
		entry, lerr := f.logEntry(ctx, digest[:], der, chain)
		if lerr != nil {
			return sig, fmt.Errorf("cyclonedx: signed but not logged: %w", lerr)
		}
		sig.TlogEntryID = entry
	}

	return sig, nil
}

// signingCertificate performs the Fulcio v2 exchange and returns the PEM chain.
func (f *FulcioSigner) signingCertificate(ctx context.Context, token, subject string, key *ecdsa.PrivateKey) (string, error) {
	// Proof of possession: a signature over the token's subject, made with the
	// key being certified. It is what stops a stolen token being used to certify
	// somebody else's key.
	subjectDigest := sha256.Sum256([]byte(subject))
	proof, err := ecdsa.SignASN1(rand.Reader, key, subjectDigest[:])
	if err != nil {
		return "", err
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})

	body, err := json.Marshal(map[string]any{
		"credentials": map[string]any{"oidcIdentityToken": token},
		"publicKeyRequest": map[string]any{
			"publicKey": map[string]any{
				"algorithm": "ECDSA",
				"content":   string(pubPEM),
			},
			"proofOfPossession": base64.StdEncoding.EncodeToString(proof),
		},
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(nonEmpty(f.FulcioURL, DefaultFulcioURL), "/") + "/api/v2/signingCert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("fulcio: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Fulcio's rejection message is the useful part when an issuer is not
		// yet accepted or a trust domain does not match, so it is passed
		// through rather than reduced to a status code.
		return "", fmt.Errorf("fulcio: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	// Fulcio answers with the chain under one of two keys depending on whether
	// the SCT is embedded in the certificate or returned alongside it. Both are
	// valid responses and which one arrives depends on the instance, so both are
	// read rather than assuming the public deployment's current behaviour.
	var parsed struct {
		Embedded *struct {
			Chain struct {
				Certificates []string `json:"certificates"`
			} `json:"chain"`
		} `json:"signedCertificateEmbeddedSct"`
		Detached *struct {
			Chain struct {
				Certificates []string `json:"certificates"`
			} `json:"chain"`
		} `json:"signedCertificateDetachedSct"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("fulcio: unreadable response: %w", err)
	}

	var certs []string
	switch {
	case parsed.Embedded != nil:
		certs = parsed.Embedded.Chain.Certificates
	case parsed.Detached != nil:
		certs = parsed.Detached.Chain.Certificates
	}
	if len(certs) == 0 {
		return "", errors.New("fulcio: response carried no certificate chain")
	}

	var chain strings.Builder
	for _, cert := range certs {
		cert = strings.TrimSpace(cert)
		chain.WriteString(cert)
		if !strings.HasSuffix(cert, "\n") {
			chain.WriteString("\n")
		}
	}
	return chain.String(), nil
}

// logEntry uploads a hashedrekord to Rekor and returns the log index, which is
// what a consumer needs to look the entry up.
func (f *FulcioSigner) logEntry(ctx context.Context, digest, der []byte, chainPEM string) (string, error) {
	leaf, _ := pem.Decode([]byte(chainPEM))
	if leaf == nil {
		return "", errors.New("rekor: no leaf certificate to log against")
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Bytes})

	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     hex.EncodeToString(digest),
				},
			},
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(der),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(leafPEM),
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(nonEmpty(f.RekorURL, DefaultRekorURL), "/") + "/api/v1/log/entries"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("rekor: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("rekor: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	// The response is keyed by entry UUID, with logIndex inside. Both identify
	// the entry; the UUID is the stable one and the index is the readable one,
	// so they are recorded together.
	var entries map[string]struct {
		LogIndex int64 `json:"logIndex"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return "", fmt.Errorf("rekor: unreadable response: %w", err)
	}
	for uuid, entry := range entries {
		return fmt.Sprintf("%d:%s", entry.LogIndex, uuid), nil
	}
	return "", errors.New("rekor: response carried no entry")
}

// AmbientIdentityToken finds an OIDC token in the environment.
//
// This is what makes the CLI's --sign useful without any Vulnetix credential:
// in a customer's CI the runner already has an identity that public Fulcio
// accepts, and a document attested by whoever ran the scan is a more useful
// claim than one attested by the tool vendor.
func AmbientIdentityToken(ctx context.Context, audience string) (string, error) {
	// The escape hatch cosign documents, and the way GitLab surfaces its own
	// id_token. Checked first so an explicit token always wins.
	if token := strings.TrimSpace(os.Getenv("SIGSTORE_ID_TOKEN")); token != "" {
		return token, nil
	}
	if token, err := githubActionsToken(ctx, audience); err == nil {
		return token, nil
	} else if !errors.Is(err, ErrNoAmbientIdentity) {
		return "", err
	}
	return "", ErrNoAmbientIdentity
}

// githubActionsToken asks the Actions runtime for an OIDC token. Present only
// when the workflow declares `permissions: id-token: write`; without it the
// request variables are unset and this reports no ambient identity rather than
// an error, because a workflow that did not ask to sign is not broken.
func githubActionsToken(ctx context.Context, audience string) (string, error) {
	endpoint := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if endpoint == "" || bearer == "" {
		return "", ErrNoAmbientIdentity
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("audience", audience)
	parsed.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github actions oidc: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", err
	}
	if body.Value == "" {
		return "", ErrNoAmbientIdentity
	}
	return body.Value, nil
}

// tokenSubject reads the `sub` claim without verifying the signature.
//
// Verification is Fulcio's job and it does it properly, against the issuer's
// published keys. All that is needed here is the subject to sign as proof of
// possession, and presenting the wrong one only produces a rejected request.
func tokenSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("cyclonedx: identity token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("cyclonedx: identity token payload is not base64url: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("cyclonedx: identity token payload is not JSON: %w", err)
	}
	// Fulcio's email issuer type proves possession over the email claim; every
	// other type, including spiffe, uses the subject.
	if claims.Subject == "" {
		if claims.Email == "" {
			return "", errors.New("cyclonedx: identity token carries no subject")
		}
		return claims.Email, nil
	}
	return claims.Subject, nil
}

// certificateIdentity reports what the certificate says the signer is: the
// first SAN URI, which for a SPIFFE identity is the SPIFFE ID and for a CI
// runner is the workflow reference. Falls back to the token subject when the
// leaf cannot be parsed, so the recorded identity is never empty.
func certificateIdentity(chainPEM, fallback string) string {
	leaf, _ := pem.Decode([]byte(chainPEM))
	if leaf == nil {
		return fallback
	}
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return fallback
	}
	for _, uri := range cert.URIs {
		return uri.String()
	}
	for _, email := range cert.EmailAddresses {
		return email
	}
	return fallback
}
