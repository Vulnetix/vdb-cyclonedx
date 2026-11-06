package cyclonedx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// capturingSigner records the exact bytes each Sign call receives, so a test
// can assert which payload a signature covers.
type capturingSigner struct {
	payloads [][]byte
}

func (s *capturingSigner) Sign(_ context.Context, payload []byte) (RawSignature, error) {
	s.payloads = append(s.payloads, payload)
	// DER must be valid ASN.1 for the non-empty assertion, and a fixed byte is
	// enough because the other tests already pin the signer's real output.
	return RawSignature{
		DER:       []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		Algorithm: "ES256",
		KeyID:     "spiffe://sigstore.vulnetix.com/code-scanner",
		// Non-empty so the envelope carries the cert member, which the test
		// pins as part of the wire contract.
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	}, nil
}

// dsseMemberNames lists the JSON member names of the DSSE envelope and its
// signature entry. A renamed member would make decoding fail; an added member
// would make the names differ.
var dsseMemberNames = []string{"payload", "payloadType", "signatures"}

// TestDSSEEnvelopeWireContract pins the DSSE wire shape as a contract, because
// the envelope is parsed by external attestation tooling.
//
// Decoding through Go struct tags would silently follow a renamed member, so
// the envelope is decoded into raw JSON and every assertion is made on the
// literal bytes.
func TestDSSEEnvelopeWireContract(t *testing.T) {
	signer := &capturingSigner{}

	unsigned := testDocument(t)
	signed, err := SignBytes(context.Background(), unsigned, signer,
		SignOptions{Formats: []string{SignatureFormatDSSE}})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	sig, ok := signed.Signature(SignatureFormatDSSE)
	if !ok {
		t.Fatal("no DSSE signature produced")
	}

	// DSSE-only signing means exactly one Sign call, so the captured payload is
	// unambiguous.
	if len(signer.payloads) != 1 {
		t.Fatalf("Sign called %d times, want 1", len(signer.payloads))
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(sig.Value, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	// (a) The envelope members are exactly payload, payloadType, signatures;
	// each signature entry is exactly keyid, sig, cert. The comment in sign.go
	// warns that members are named per the DSSE specification, so a rename is
	// an interop break this test exists to catch.
	if got := memberStrings(envelope); !dsseStringsEqual(got, dsseMemberNames) {
		t.Fatalf("envelope members = %v, want %v", got, dsseMemberNames)
	}
	sigsRaw, ok := envelope["signatures"]
	if !ok {
		t.Fatal("envelope has no signatures member")
	}
	var sigs []map[string]json.RawMessage
	if err := json.Unmarshal(sigsRaw, &sigs); err != nil {
		t.Fatalf("decode signatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("len(signatures) = %d, want 1", len(sigs))
	}
	wantSigMembers := []string{"keyid", "sig", "cert"}
	if got := memberStrings(sigs[0]); !dsseStringsEqual(got, wantSigMembers) {
		t.Fatalf("signature member names = %v, want %v", got, wantSigMembers)
	}

	// (b) The payload is standard base64 with padding, and decodes to exactly
	// the finished document. The padding strictness also pins the deliberate
	// difference from the base64url JSF uses.
	//
	// Padding makes the text length a multiple of four, but the final
	// characters are data when the byte count is divisible by three, so the
	// check is on length, not on a trailing '='.
	payloadText := ""
	if err := json.Unmarshal(envelope["payload"], &payloadText); err != nil {
		t.Fatalf("payload is not a JSON string: %v", err)
	}
	if len(payloadText)%4 != 0 {
		t.Fatalf("payload is not padded standard base64: length %d is not a multiple of 4", len(payloadText))
	}
	payload, err := base64.StdEncoding.DecodeString(payloadText)
	if err != nil {
		t.Fatalf("payload is not standard base64: %v", err)
	}
	if !bytes.Equal(payload, signed.Document) {
		t.Fatal("the envelope payload is not the finished document")
	}

	// (c) The signer is called over the DSSE PAE bytes.
	wantPAE := fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(DSSEPayloadType), DSSEPayloadType, len(signed.Document), signed.Document)
	if string(signer.payloads[0]) != wantPAE {
		t.Fatalf("signer payload = %q, want PAE %q", signer.payloads[0], wantPAE)
	}

	// (d) The signature is standard base64 with padding and decodes to non-empty
	// DER.
	sigText := ""
	if err := json.Unmarshal(sigs[0]["sig"], &sigText); err != nil {
		t.Fatalf("sig is not a JSON string: %v", err)
	}
	if len(sigText)%4 != 0 {
		t.Fatalf("sig is not padded standard base64: length %d is not a multiple of 4", len(sigText))
	}
	der, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("signature decodes to empty DER")
	}
}

func memberStrings(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func dsseStringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
