package cyclonedx

import (
	"bytes"
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
	"testing"
	"time"
)

// The `signature` property a JSF verifier parses is a wire contract: its shape
// comes from jsf-0.82.schema.json, and every member a consumer reads must be
// produced the same way. LocalSigner carries no certificate chain, so these
// assertions pin the parts of that contract its tests never exercise: the
// leaf-first certificatePath array and the fixed-width r||s value.

// chainSigner is a Signer stub that returns a certificate chain, which
// LocalSigner cannot express.
type chainSigner struct {
	key   *ecdsa.PrivateKey
	chain string
}

func (s *chainSigner) Sign(_ context.Context, payload []byte) (RawSignature, error) {
	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return RawSignature{}, err
	}
	return RawSignature{
		DER:            der,
		Algorithm:      "ES256",
		CertificatePEM: s.chain,
	}, nil
}

// testCertificateChain returns a leaf certificate and a leaf-first PEM chain of
// two CERTIFICATE blocks. certificatePath reads block.Type and block.Bytes, so
// the certificates only need to be well-formed DER; they are never parsed.
func testCertificateChain(t *testing.T) (leafDER []byte, chainPEM string) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vdb-cyclonedx test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vdb-cyclonedx test leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	chainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	return leafDER, chainPEM
}

func TestJSFSignaturePropertyContract(t *testing.T) {
	t.Run("certificatePath is leaf-first base64 DER and value is a 64-byte r||s pair", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		leafDER, chain := testCertificateChain(t)

		signed, err := SignBytes(context.Background(), testDocument(t),
			&chainSigner{key: key, chain: chain}, SignOptions{})
		if err != nil {
			t.Fatalf("SignBytes: %v", err)
		}

		var doc struct {
			Signature *struct {
				Algorithm       string   `json:"algorithm"`
				Value           string   `json:"value"`
				CertificatePath []string `json:"certificatePath"`
			} `json:"signature"`
		}
		if err := json.Unmarshal(signed.Document, &doc); err != nil {
			t.Fatalf("decode signature property: %v", err)
		}
		if doc.Signature == nil {
			t.Fatal("signed document carries no signature property")
		}
		if doc.Signature.Algorithm != "ES256" {
			t.Fatalf("algorithm = %q, want ES256", doc.Signature.Algorithm)
		}
		if len(doc.Signature.CertificatePath) != 2 {
			t.Fatalf("certificatePath has %d entries, want 2", len(doc.Signature.CertificatePath))
		}

		leaf, err := base64.RawURLEncoding.DecodeString(doc.Signature.CertificatePath[0])
		if err != nil {
			t.Fatalf("first certificatePath entry is not base64url: %v", err)
		}
		if !bytes.Equal(leaf, leafDER) {
			t.Fatal("first certificatePath entry is not the leaf certificate's DER bytes")
		}
		root, err := base64.RawURLEncoding.DecodeString(doc.Signature.CertificatePath[1])
		if err != nil {
			t.Fatalf("second certificatePath entry is not base64url: %v", err)
		}
		if bytes.Equal(root, leafDER) {
			t.Fatal("second certificatePath entry duplicates the leaf, so the chain is not leaf-first")
		}

		value, err := base64.RawURLEncoding.DecodeString(doc.Signature.Value)
		if err != nil {
			t.Fatalf("signature value is not base64url without padding: %v", err)
		}
		if len(value) != 64 {
			t.Fatalf("signature value decodes to %d bytes, want 64 for a P-256 r||s pair", len(value))
		}
	})

	t.Run("derToJWS round trip", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		digest := sha256.Sum256([]byte("jsf contract"))
		der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("SignASN1: %v", err)
		}

		value, err := derToJWS(der)
		if err != nil {
			t.Fatalf("derToJWS: %v", err)
		}
		if len(value) != 64 {
			t.Fatalf("derToJWS returned %d bytes, want 64", len(value))
		}

		// The halves are r and s in order, read back the way VerifyJSF reads them.
		r := new(big.Int).SetBytes(value[:32])
		s := new(big.Int).SetBytes(value[32:])
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Fatal("r||s pair read back from the JWS value does not verify")
		}
	})
}
