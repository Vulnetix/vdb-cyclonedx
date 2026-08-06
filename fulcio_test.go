package cyclonedx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The Fulcio exchange is proven against a stand-in here so the wire format is
// checked without a network, and so the failure that matters most is checked at
// all: a proof of possession over the wrong bytes is accepted by nothing, and
// discovering that against public Fulcio means discovering it in production.

const testSPIFFEID = "spiffe://sigstore.vulnetix.com/code-scanner"

// unsignedJWT builds a token with the given subject. The signature is never
// checked here, because verification is the CA's job and this stands in for the
// CA.
func unsignedJWT(t *testing.T, subject string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"sub": subject,
		"aud": SigstoreAudience,
		"iss": "https://auth.vulnetix.com/application/o/sigstore/",
	})
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

// fakeCA issues a leaf carrying the SPIFFE ID as its SAN URI, which is what
// Fulcio does for a spiffe-type issuer.
func fakeCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test fulcio"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return key, cert
}

// fulcioStub answers /api/v2/signingCert the way Fulcio does, and verifies the
// proof of possession the way Fulcio does, so a signer that gets it wrong fails
// here rather than against the real service.
func fulcioStub(t *testing.T, subject string) *httptest.Server {
	t.Helper()
	caKey, caCert := fakeCA(t)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/signingCert" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}

		var body struct {
			Credentials struct {
				OIDCIdentityToken string `json:"oidcIdentityToken"`
			} `json:"credentials"`
			PublicKeyRequest struct {
				PublicKey struct {
					Algorithm string `json:"algorithm"`
					Content   string `json:"content"`
				} `json:"publicKey"`
				ProofOfPossession string `json:"proofOfPossession"`
			} `json:"publicKeyRequest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if body.Credentials.OIDCIdentityToken == "" {
			http.Error(w, "no identity token", http.StatusBadRequest)
			return
		}
		if body.PublicKeyRequest.PublicKey.Algorithm != "ECDSA" {
			http.Error(w, "unexpected algorithm", http.StatusBadRequest)
			return
		}

		block, _ := pem.Decode([]byte(body.PublicKeyRequest.PublicKey.Content))
		if block == nil {
			http.Error(w, "public key is not PEM", http.StatusBadRequest)
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, "public key is not PKIX", http.StatusBadRequest)
			return
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			http.Error(w, "public key is not ECDSA", http.StatusBadRequest)
			return
		}

		proof, err := base64.StdEncoding.DecodeString(body.PublicKeyRequest.ProofOfPossession)
		if err != nil {
			http.Error(w, "proof is not base64", http.StatusBadRequest)
			return
		}
		// This is the check that matters: the proof must be over the token's
		// subject, signed by the key being certified.
		digest := sha256.Sum256([]byte(subject))
		if !ecdsa.VerifyASN1(pub, digest[:], proof) {
			http.Error(w, "proof of possession does not verify", http.StatusBadRequest)
			return
		}

		uri, err := url.Parse(subject)
		if err != nil {
			http.Error(w, "subject is not a URI", http.StatusBadRequest)
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(10 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			URIs:         []*url.URL{uri},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, pub, caKey)
		if err != nil {
			http.Error(w, "issue failed", http.StatusInternalServerError)
			return
		}

		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
		caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signedCertificateEmbeddedSct": map[string]any{
				"chain": map[string]any{"certificates": []string{leafPEM, caPEM}},
			},
		})
	}))
}

func rekorStub(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if status != http.StatusCreated {
			http.Error(w, "log unavailable", status)
			return
		}
		var body struct {
			Kind string `json:"kind"`
			Spec struct {
				Data struct {
					Hash struct {
						Algorithm string `json:"algorithm"`
						Value     string `json:"value"`
					} `json:"hash"`
				} `json:"data"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad entry", http.StatusBadRequest)
			return
		}
		if body.Kind != "hashedrekord" || body.Spec.Data.Hash.Algorithm != "sha256" {
			http.Error(w, "unexpected entry shape", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"24296fb24b8ad77a": map[string]any{"logIndex": 12345},
		})
	}))
}

func TestFulcioSignerCertifiesTheSPIFFEIdentity(t *testing.T) {
	fulcio := fulcioStub(t, testSPIFFEID)
	defer fulcio.Close()
	rekor := rekorStub(t, http.StatusCreated)
	defer rekor.Close()

	var askedAudience string
	signer := &FulcioSigner{
		IdentityToken: func(_ context.Context, audience string) (string, error) {
			askedAudience = audience
			return unsignedJWT(t, testSPIFFEID), nil
		},
		FulcioURL: fulcio.URL,
		RekorURL:  rekor.URL,
	}

	document := testDocument(t)
	signed, err := SignBytes(context.Background(), document, signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	if askedAudience != SigstoreAudience {
		t.Fatalf("audience = %q, want %q", askedAudience, SigstoreAudience)
	}

	sig, ok := signed.Signature(SignatureFormatCosign)
	if !ok {
		t.Fatal("no cosign signature produced")
	}
	// The recorded identity has to be what the certificate says, not what the
	// caller hoped: this is the value stored in Artifact.signatureKeyId and the
	// one a consumer checks against.
	if sig.KeyID != testSPIFFEID {
		t.Fatalf("keyId = %q, want the SAN URI %q", sig.KeyID, testSPIFFEID)
	}
	if sig.TlogEntryID != "12345:24296fb24b8ad77a" {
		t.Fatalf("tlog entry = %q, want the log index and uuid", sig.TlogEntryID)
	}
	if !strings.Contains(sig.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatal("no certificate chain recorded")
	}

	// And the signature must verify against the published bytes using the key
	// in the certificate, which is the only thing a consumer has.
	leaf, _ := pem.Decode([]byte(sig.CertificatePEM))
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(string(sig.Value))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256(signed.Document)
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], der) {
		t.Fatal("the signature does not verify against the certified key")
	}
}

func TestFulcioSignerReportsAnUnloggedSignature(t *testing.T) {
	fulcio := fulcioStub(t, testSPIFFEID)
	defer fulcio.Close()
	rekor := rekorStub(t, http.StatusServiceUnavailable)
	defer rekor.Close()

	signer := &FulcioSigner{
		IdentityToken: func(context.Context, string) (string, error) {
			return unsignedJWT(t, testSPIFFEID), nil
		},
		FulcioURL: fulcio.URL,
		RekorURL:  rekor.URL,
	}

	// A keyless signature that was never logged stops being verifiable when the
	// certificate expires, minutes later. The caller has to be told.
	_, err := signer.Sign(context.Background(), []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "signed but not logged") {
		t.Fatalf("err = %v, want a signed-but-not-logged report", err)
	}
}

func TestFulcioRejectionMessageReachesTheCaller(t *testing.T) {
	// A different subject than the token carries, so the stub's proof check
	// fails the same way real Fulcio would for a mismatched identity.
	fulcio := fulcioStub(t, "spiffe://sigstore.vulnetix.com/somebody-else")
	defer fulcio.Close()

	signer := &FulcioSigner{
		IdentityToken: func(context.Context, string) (string, error) {
			return unsignedJWT(t, testSPIFFEID), nil
		},
		FulcioURL: fulcio.URL,
		RekorURL:  "-",
	}

	_, err := signer.Sign(context.Background(), []byte("payload"))
	if err == nil {
		t.Fatal("a mismatched identity produced a signature")
	}
	// The rejection text is what tells an operator whether the issuer is not
	// accepted, the trust domain is wrong, or the token is stale.
	if !strings.Contains(err.Error(), "proof of possession") {
		t.Fatalf("err = %v, want Fulcio's own message", err)
	}
}

func TestAmbientIdentityPrefersAnExplicitToken(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "explicit-token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://127.0.0.1:1/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")

	token, err := AmbientIdentityToken(context.Background(), SigstoreAudience)
	if err != nil {
		t.Fatalf("AmbientIdentityToken: %v", err)
	}
	if token != "explicit-token" {
		t.Fatalf("token = %q, want the explicit one", token)
	}
}

func TestAmbientIdentityAbsentIsNotAnError(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	// A developer laptop has no ambient identity, and that must be
	// distinguishable from a broken one so the caller can publish unsigned
	// instead of failing the scan.
	if _, err := AmbientIdentityToken(context.Background(), SigstoreAudience); err != ErrNoAmbientIdentity {
		t.Fatalf("err = %v, want ErrNoAmbientIdentity", err)
	}
}

func TestGitHubActionsTokenIsRequestedWithTheAudience(t *testing.T) {
	var gotAudience, gotAuth string
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience = r.URL.Query().Get("audience")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": unsignedJWT(t, "repo:acme/app:ref:refs/heads/main")})
	}))
	defer runtime.Close()

	t.Setenv("SIGSTORE_ID_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", runtime.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")

	token, err := AmbientIdentityToken(context.Background(), SigstoreAudience)
	if err != nil {
		t.Fatalf("AmbientIdentityToken: %v", err)
	}
	if token == "" {
		t.Fatal("no token returned")
	}
	// Fulcio checks the audience, so requesting the wrong one produces a token
	// that is rejected at signing time rather than here.
	if gotAudience != SigstoreAudience {
		t.Fatalf("audience = %q, want %q", gotAudience, SigstoreAudience)
	}
	if gotAuth != "Bearer runner-bearer" {
		t.Fatalf("authorization = %q, want the runner bearer", gotAuth)
	}
}
