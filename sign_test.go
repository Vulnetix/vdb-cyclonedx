package cyclonedx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// These tests exist for one reason: JSF changes the bytes of the document, and
// DSSE and cosign have to sign what JSF produced rather than what was built. Get
// that order wrong and every detached signature covers a document nobody
// receives, which no schema check would catch.

func testSigner(t *testing.T) (*LocalSigner, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &LocalSigner{Key: key, KeyID: "spiffe://sigstore.vulnetix.com/code-scanner"}, &key.PublicKey
}

func testDocument(t *testing.T) []byte {
	t.Helper()
	data, err := BuildCDXVEX([]VEXFinding{{
		CVEID: "CVE-2025-0001", Package: "github.com/charmbracelet/bubbletea",
		Ecosystem: "golang", InstalledVer: "1.3.10",
		Status: "not_affected", Justification: "code_not_reachable",
	}}, VEXOptions{})
	if err != nil {
		t.Fatalf("BuildCDXVEX: %v", err)
	}
	return data
}

func TestJSFSignatureVerifiesAgainstDocumentWithoutIt(t *testing.T) {
	signer, pub := testSigner(t)

	signed, err := SignBytes(context.Background(), testDocument(t), signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	if err := VerifyJSF(signed.Document, pub); err != nil {
		t.Fatalf("the embedded signature does not verify against its own document: %v", err)
	}

	// A signature that verifies against an unchanged document proves nothing on
	// its own. Change one byte of content and it must stop verifying.
	tampered := strings.Replace(string(signed.Document), "1.3.10", "1.3.11", 1)
	if tampered == string(signed.Document) {
		t.Fatal("tamper did not change the document")
	}
	if err := VerifyJSF([]byte(tampered), pub); err == nil {
		t.Fatal("a modified document still verified")
	}
}

func TestJSFPayloadExcludesOnlyTheSignatureProperty(t *testing.T) {
	signer, _ := testSigner(t)
	unsigned := testDocument(t)

	before, err := JSFSigningPayload(unsigned)
	if err != nil {
		t.Fatalf("payload before signing: %v", err)
	}

	signed, err := SignBytes(context.Background(), unsigned, signer, SignOptions{Formats: []string{SignatureFormatJSF}})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	after, err := JSFSigningPayload(signed.Document)
	if err != nil {
		t.Fatalf("payload after signing: %v", err)
	}

	// Signing must add the signature property and touch nothing else. If these
	// differ, the signature covers a document that no longer exists.
	if string(before) != string(after) {
		t.Fatalf("signing changed the signed payload\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestSignedDocumentStillValidates(t *testing.T) {
	signer, _ := testSigner(t)

	signed, err := SignBytes(context.Background(), testDocument(t), signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	// SignBytes validates internally, so reaching here already proves it. Assert
	// the property actually landed, because a validator that silently ignores an
	// unknown property would let an empty signature through.
	var doc struct {
		Signature *struct {
			Algorithm string   `json:"algorithm"`
			Value     string   `json:"value"`
			KeyID     string   `json:"keyId"`
			Excludes  []string `json:"excludes"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(signed.Document, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Signature == nil {
		t.Fatal("signed document carries no signature property")
	}
	if doc.Signature.Algorithm != "ES256" {
		t.Fatalf("algorithm = %q, want ES256", doc.Signature.Algorithm)
	}
	if doc.Signature.KeyID != "spiffe://sigstore.vulnetix.com/code-scanner" {
		t.Fatalf("keyId = %q, want the signer's SPIFFE ID", doc.Signature.KeyID)
	}
	if _, err := base64.RawURLEncoding.DecodeString(doc.Signature.Value); err != nil {
		t.Fatalf("signature value is not base64url: %v", err)
	}
}

// The ordering gate. The DSSE payload is the finished document, so its digest
// must equal the digest of the bytes that get published.
func TestDSSEPayloadIsTheFinishedDocument(t *testing.T) {
	signer, _ := testSigner(t)

	signed, err := SignBytes(context.Background(), testDocument(t), signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	sig, ok := signed.Signature(SignatureFormatDSSE)
	if !ok {
		t.Fatal("no DSSE signature produced")
	}

	var envelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(sig.Value, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.PayloadType != DSSEPayloadType {
		t.Fatalf("payloadType = %q, want %q", envelope.PayloadType, DSSEPayloadType)
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	want := sha256.Sum256(signed.Document)
	got := sha256.Sum256(payload)
	if want != got {
		t.Fatal("the DSSE envelope covers different bytes than the document being published")
	}
}

// The same gate for cosign, which signs the blob directly rather than wrapping
// it. Verified by checking the signature against the published bytes.
func TestCosignSignatureCoversTheFinishedDocument(t *testing.T) {
	signer, pub := testSigner(t)

	// Built once and kept: every document carries a fresh serialNumber, so a
	// second call would not be the same bytes and the comparison below would
	// prove nothing.
	unsigned := testDocument(t)

	signed, err := SignBytes(context.Background(), unsigned, signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	sig, ok := signed.Signature(SignatureFormatCosign)
	if !ok {
		t.Fatal("no cosign signature produced")
	}

	der, err := base64.StdEncoding.DecodeString(string(sig.Value))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	digest := sha256.Sum256(signed.Document)
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("the cosign signature does not verify against the document being published")
	}

	// And it must not verify against the pre-JSF bytes, which is exactly the
	// mistake this ordering exists to prevent.
	unsignedDigest := sha256.Sum256(unsigned)
	if ecdsa.VerifyASN1(pub, unsignedDigest[:], der) {
		t.Fatal("the cosign signature covers the unsigned document")
	}
}

func TestSignBytesWithoutASignerIsNotAFailureToPublish(t *testing.T) {
	_, err := SignBytes(context.Background(), testDocument(t), nil, SignOptions{})
	if err != ErrNoSigner {
		t.Fatalf("err = %v, want ErrNoSigner so callers can publish unsigned", err)
	}
}

func TestSelectedFormatsAreTheOnlyOnesProduced(t *testing.T) {
	signer, _ := testSigner(t)
	unsigned := testDocument(t)

	signed, err := SignBytes(context.Background(), unsigned, signer,
		SignOptions{Formats: []string{SignatureFormatCosign}})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if len(signed.Signatures) != 1 || signed.Signatures[0].Format != SignatureFormatCosign {
		t.Fatalf("signatures = %+v, want cosign only", signed.Signatures)
	}
	// No JSF requested, so the document must be untouched.
	if string(signed.Document) != string(unsigned) {
		t.Fatal("the document changed even though JSF was not requested")
	}
}

func TestSignatureAlgorithmIsRecordedWithItsHash(t *testing.T) {
	signer, _ := testSigner(t)

	signed, err := SignBytes(context.Background(), testDocument(t), signer, SignOptions{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	for _, sig := range signed.Signatures {
		// Artifact.signatureAlgorithm is read by consumers that do not know
		// ES256 implies SHA-256.
		if sig.Algorithm != "ecdsa-p256-sha256" {
			t.Fatalf("%s algorithm = %q, want ecdsa-p256-sha256", sig.Format, sig.Algorithm)
		}
	}
}
