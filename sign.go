package cyclonedx

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/gowebpki/jcs"
)

// Signing a CycloneDX document, in the three shapes consumers actually ask for.
//
// A TEA conformance run reported that none of the artifacts this organisation
// publishes carried a signature. TEA models one as artifact-format.signatureUrl
// and a consumer follows it to confirm that what it downloaded is what the
// publisher published, so a signature has to cover the exact bytes served, not
// an intermediate form.
//
// That constraint is the whole reason this file exists rather than each service
// signing its own way:
//
//   1. JSF is embedded IN the document, so it changes the bytes.
//   2. DSSE and cosign are detached, so they must sign what JSF produced.
//
// Sign in the wrong order and the detached signatures cover a document nobody
// receives. SignBytes implements the order once so no caller has to know it.

// Signature formats. These are the values stored in Artifact.signatureFormat,
// and a consumer needs to be told which one it is holding because each is
// verified by different tooling.
const (
	// SignatureFormatJSF is JSON Signature Format, embedded in the document as
	// its `signature` property. Verified by re-canonicalising the document
	// without that property.
	SignatureFormatJSF = "jsf"
	// SignatureFormatDSSE is an in-toto style DSSE envelope over the finished
	// document. Verified by attestation tooling.
	SignatureFormatDSSE = "dsse"
	// SignatureFormatCosign is the detached signature/certificate pair that
	// `cosign verify-blob` expects.
	SignatureFormatCosign = "cosign"
)

// DSSEPayloadType is the media type carried in the DSSE envelope and mixed into
// its pre-authentication encoding. It is part of what gets signed, so it cannot
// be changed without invalidating every signature already issued.
const DSSEPayloadType = "application/vnd.cyclonedx+json"

// ErrNoSigner is returned when signing is requested with no signer configured.
// Callers treat this as "publish unsigned", never as a failure to publish: an
// unsigned artifact is still a valid artifact, and the alternative is losing
// scan results because an identity provider was briefly unreachable.
var ErrNoSigner = errors.New("cyclonedx: no signer configured")

// RawSignature is what a Signer returns: one ECDSA signature plus the material
// a consumer needs to decide whether to trust it.
//
// The DER encoding is the common shape. AWS KMS returns DER, Go's
// ecdsa.SignASN1 returns DER, and Fulcio-issued certificates are used with DER
// signatures, so the interface does not have to choose. JSF needs the raw r||s
// pair instead, and that conversion happens here rather than in every Signer.
type RawSignature struct {
	// DER is the ASN.1 DER encoded ECDSA signature over SHA-256 of the payload.
	DER []byte
	// Algorithm is the JWA name of the suite, for example ES256.
	Algorithm string
	// KeyID identifies the signer. For a keyless signature this is the
	// certificate identity, which for Vulnetix workloads is the SPIFFE ID
	// (spiffe://sigstore.vulnetix.com/code-scanner). For a signature made with
	// a held key it is the key alias or ARN.
	KeyID string
	// CertificatePEM is the certificate chain for a keyless signature, leaf
	// first. Empty when signing with a held key.
	CertificatePEM string
	// PublicKeyPEM is the verification key for a held-key signature. Empty when
	// a certificate chain is present, because the chain already carries it.
	PublicKeyPEM string
	// TlogEntryID is the transparency-log index, when the signature was
	// witnessed. A consumer uses it to confirm the signature was logged and not
	// merely presented.
	TlogEntryID string
}

// Signer produces a signature over a payload.
//
// This is the seam. Whether the certificate behind it comes from public Fulcio
// (keyless, via the SPIFFE identity Authentik issues) or from AWS KMS (a held
// key, the fallback if Sigstore declines the issuer) changes the implementation
// and nothing else in this file or in any caller.
type Signer interface {
	// Sign hashes payload with SHA-256 and signs the digest.
	Sign(ctx context.Context, payload []byte) (RawSignature, error)
}

// Signature is one finished signature over a document.
type Signature struct {
	// Format is one of SignatureFormat*.
	Format string
	// Algorithm names the suite, for example ecdsa-p256-sha256.
	Algorithm string
	// KeyID is the certificate identity or key alias, copied from the signer.
	KeyID string
	// Value is the bytes to store beside the artifact: the DSSE envelope as
	// JSON, or the base64 signature cosign expects. Empty for JSF, which lives
	// inside the document rather than beside it.
	Value []byte
	// CertificatePEM is the chain a verifier needs, when the signature is
	// keyless.
	CertificatePEM string
	// TlogEntryID is the transparency-log index, when there is one.
	TlogEntryID string
}

// SignedDocument is the document to publish plus the detached signatures over
// it. Document is authoritative: it is the byte string every signature here
// covers and the byte string a consumer must be served.
type SignedDocument struct {
	Document   []byte
	Signatures []Signature
}

// Signature returns the signature in the requested format.
func (s SignedDocument) Signature(format string) (Signature, bool) {
	for _, sig := range s.Signatures {
		if sig.Format == format {
			return sig, true
		}
	}
	return Signature{}, false
}

// SignOptions configures SignBytes.
type SignOptions struct {
	// Formats to produce. Empty means all three.
	Formats []string
	// Validate re-runs schema validation on the document after the JSF property
	// is inserted. On by default; set SkipValidate to turn it off for a document
	// that is deliberately not a full BOM.
	SkipValidate bool
}

func (o SignOptions) wants(format string) bool {
	if len(o.Formats) == 0 {
		return true
	}
	for _, f := range o.Formats {
		if f == format {
			return true
		}
	}
	return false
}

// SignBytes signs a finished CycloneDX document.
//
// document must already be a complete, valid CycloneDX document, which is what
// BuildCDXVEX and BuildSBOM return. The order below is the point of this
// function:
//
//  1. The JSF signature is computed over the JCS canonicalisation of the
//     document with its `signature` property removed, then inserted as that
//     property. This is what a verifier reverses.
//  2. The document is re-validated, because it now carries a property it did
//     not have when it was built.
//  3. DSSE and cosign then sign the finished bytes, the ones actually served.
//
// So the TEA checksum, the DSSE payload digest and the cosign signature all
// cover exactly what a consumer downloads.
func SignBytes(ctx context.Context, document []byte, signer Signer, opts SignOptions) (SignedDocument, error) {
	if signer == nil {
		return SignedDocument{}, ErrNoSigner
	}
	if len(document) == 0 {
		return SignedDocument{}, errors.New("cyclonedx: nothing to sign")
	}

	out := SignedDocument{Document: document}

	if opts.wants(SignatureFormatJSF) {
		signed, sig, err := signJSF(ctx, document, signer)
		if err != nil {
			return SignedDocument{}, err
		}
		out.Document = signed
		out.Signatures = append(out.Signatures, sig)

		if !opts.SkipValidate {
			if _, violations, verr := ValidateCycloneDX(out.Document); verr != nil {
				return SignedDocument{}, fmt.Errorf("cyclonedx: validation error after signing: %w", verr)
			} else if len(violations) > 0 {
				return SignedDocument{}, fmt.Errorf("cyclonedx: schema violation after signing at %s: %s",
					violations[0].Path, violations[0].Message)
			}
		}
	}

	// Everything below signs out.Document, which is the JSF-signed bytes when
	// JSF was requested and the original bytes when it was not. Either way it is
	// what gets published.
	if opts.wants(SignatureFormatDSSE) {
		sig, err := signDSSE(ctx, out.Document, signer)
		if err != nil {
			return SignedDocument{}, err
		}
		out.Signatures = append(out.Signatures, sig)
	}

	if opts.wants(SignatureFormatCosign) {
		sig, err := signCosign(ctx, out.Document, signer)
		if err != nil {
			return SignedDocument{}, err
		}
		out.Signatures = append(out.Signatures, sig)
	}

	return out, nil
}

// JSFSigningPayload returns the exact bytes a JSF signature covers: the
// document with its `signature` property removed, canonicalised per RFC 8785.
//
// Exported because a verifier needs the identical computation, and the one
// reliable way to guarantee that is for both sides to call the same function.
func JSFSigningPayload(document []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("cyclonedx: document is not a JSON object: %w", err)
	}
	delete(doc, "signature")

	stripped, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	// RFC 8785 JSON Canonicalization Scheme: sorted keys, no insignificant
	// whitespace, ECMAScript number formatting. Verifiers in other languages
	// reach the same bytes from the same document, which is the entire reason
	// to canonicalise rather than sign the serialisation we happen to produce.
	return jcs.Transform(stripped)
}

func signJSF(ctx context.Context, document []byte, signer Signer) ([]byte, Signature, error) {
	payload, err := JSFSigningPayload(document)
	if err != nil {
		return nil, Signature{}, err
	}

	raw, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, Signature{}, fmt.Errorf("cyclonedx: jsf: %w", err)
	}

	jsfValue, err := derToJWS(raw.DER)
	if err != nil {
		return nil, Signature{}, fmt.Errorf("cyclonedx: jsf: %w", err)
	}

	// Field names and shape come from jsf-0.82.schema.json, which CycloneDX
	// references for its `signature` property. Binary values are base64url per
	// JWA, which JSF defers to for signature encoding.
	entry := map[string]any{
		"algorithm": nonEmpty(raw.Algorithm, "ES256"),
		"value":     b64url(jsfValue),
	}
	if raw.KeyID != "" {
		entry["keyId"] = raw.KeyID
	}
	if chain := certificatePath(raw.CertificatePEM); len(chain) > 0 {
		entry["certificatePath"] = chain
	}

	signed, err := insertSignatureProperty(document, entry)
	if err != nil {
		return nil, Signature{}, err
	}

	return signed, Signature{
		Format:         SignatureFormatJSF,
		Algorithm:      algorithmLabel(raw.Algorithm),
		KeyID:          raw.KeyID,
		CertificatePEM: raw.CertificatePEM,
		TlogEntryID:    raw.TlogEntryID,
	}, nil
}

// insertSignatureProperty appends `"signature": {...}` to a JSON object without
// re-serialising the rest of it.
//
// The alternative, unmarshalling into a map and marshalling it back, reorders
// every key in the document because Go sorts map keys. That produces a signed
// document that no longer diffs against the unsigned one it came from, for no
// gain: JCS sorts keys anyway, so key order has no effect on verification.
func insertSignatureProperty(document []byte, entry map[string]any) ([]byte, error) {
	encoded, err := json.MarshalIndent(entry, "  ", "  ")
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimRight(string(document), " \t\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		return nil, errors.New("cyclonedx: document is not a JSON object")
	}
	body := strings.TrimRight(trimmed[:len(trimmed)-1], " \t\r\n")
	if !strings.HasSuffix(body, "{") {
		// The object has at least one property, so the new one needs a comma.
		body += ","
	}

	return []byte(body + "\n  \"signature\": " + string(encoded) + "\n}\n"), nil
}

// dsseEnvelope is the DSSE structure, spelled out rather than pulled from a
// dependency: it is four fields and a fixed encoding, and every consumer that
// reads it does so with its own implementation anyway.
type dsseEnvelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
	Cert  string `json:"cert,omitempty"`
}

func signDSSE(ctx context.Context, document []byte, signer Signer) (Signature, error) {
	raw, err := signer.Sign(ctx, dssePAE(DSSEPayloadType, document))
	if err != nil {
		return Signature{}, fmt.Errorf("cyclonedx: dsse: %w", err)
	}

	envelope, err := json.MarshalIndent(dsseEnvelope{
		// Standard base64 with padding, per the DSSE specification. Not the
		// base64url JSF uses; they are different specifications and mixing them
		// is a silent interop failure.
		Payload:     base64.StdEncoding.EncodeToString(document),
		PayloadType: DSSEPayloadType,
		Signatures: []dsseSignature{{
			KeyID: raw.KeyID,
			Sig:   base64.StdEncoding.EncodeToString(raw.DER),
			Cert:  raw.CertificatePEM,
		}},
	}, "", "  ")
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		Format:         SignatureFormatDSSE,
		Algorithm:      algorithmLabel(raw.Algorithm),
		KeyID:          raw.KeyID,
		Value:          envelope,
		CertificatePEM: raw.CertificatePEM,
		TlogEntryID:    raw.TlogEntryID,
	}, nil
}

// dssePAE is the DSSE pre-authentication encoding:
//
//	"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
//
// It binds the payload type into the signature, so a signature over a CycloneDX
// document cannot be replayed as a signature over some other media type.
func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

func signCosign(ctx context.Context, document []byte, signer Signer) (Signature, error) {
	// cosign sign-blob signs the blob itself and writes the base64 signature to
	// the .sig file with the certificate alongside, which is exactly the pair
	// `cosign verify-blob --signature ... --certificate ...` consumes.
	raw, err := signer.Sign(ctx, document)
	if err != nil {
		return Signature{}, fmt.Errorf("cyclonedx: cosign: %w", err)
	}
	return Signature{
		Format:         SignatureFormatCosign,
		Algorithm:      algorithmLabel(raw.Algorithm),
		KeyID:          raw.KeyID,
		Value:          []byte(base64.StdEncoding.EncodeToString(raw.DER)),
		CertificatePEM: raw.CertificatePEM,
		TlogEntryID:    raw.TlogEntryID,
	}, nil
}

// LocalSigner signs with an in-process ECDSA key.
//
// This is the signer for tests and for local development, and it is also the
// shape the KMS fallback takes: one held key, no certificate, no transparency
// log. It is deliberately not a keyless signer, and a document it signs states
// so by carrying a key alias rather than a certificate chain.
type LocalSigner struct {
	Key   *ecdsa.PrivateKey
	KeyID string
}

// Sign implements Signer.
func (s *LocalSigner) Sign(_ context.Context, payload []byte) (RawSignature, error) {
	if s == nil || s.Key == nil {
		return RawSignature{}, ErrNoSigner
	}
	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, s.Key, digest[:])
	if err != nil {
		return RawSignature{}, err
	}

	pub, err := x509.MarshalPKIXPublicKey(&s.Key.PublicKey)
	if err != nil {
		return RawSignature{}, err
	}

	return RawSignature{
		DER:          der,
		Algorithm:    "ES256",
		KeyID:        s.KeyID,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
	}, nil
}

// VerifyJSF checks the `signature` property of a document against a public key.
//
// Exported because the ordering rule is only worth anything if it is checked,
// and a caller that stores a signed document should be able to confirm what it
// stored before serving it.
func VerifyJSF(document []byte, pub *ecdsa.PublicKey) error {
	var doc struct {
		Signature *struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		return err
	}
	if doc.Signature == nil {
		return errors.New("cyclonedx: document carries no signature property")
	}

	sig, err := base64.RawURLEncoding.DecodeString(doc.Signature.Value)
	if err != nil {
		return fmt.Errorf("cyclonedx: signature value is not base64url: %w", err)
	}
	if len(sig)%2 != 0 {
		return errors.New("cyclonedx: signature value is not an r||s pair")
	}

	payload, err := JSFSigningPayload(document)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)

	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("cyclonedx: signature does not verify")
	}
	return nil
}

// derToJWS converts an ASN.1 DER ECDSA signature to the fixed-width r||s pair
// JWA specifies, which is what JSF carries. The halves are left-padded to the
// curve size: a short r or s is a valid signature and dropping its leading
// zeros produces a value other implementations reject.
func derToJWS(der []byte) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, err
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, errors.New("signature is missing r or s")
	}

	// P-256. The only curve in use here, and the one ES256 names.
	const size = 32
	out := make([]byte, 2*size)
	rb, sb := parsed.R.Bytes(), parsed.S.Bytes()
	if len(rb) > size || len(sb) > size {
		return nil, errors.New("signature component is wider than the curve")
	}
	copy(out[size-len(rb):size], rb)
	copy(out[2*size-len(sb):], sb)
	return out, nil
}

// certificatePath turns a PEM chain into the base64 DER array JSF expects, leaf
// first. A malformed chain yields no path rather than an error: the signature
// itself is still valid and still verifiable against a key, and refusing to
// publish over an unparseable certificate would lose the artifact as well.
func certificatePath(chainPEM string) []string {
	var out []string
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, b64url(block.Bytes))
	}
	return out
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// algorithmLabel reports the suite in the form stored in
// Artifact.signatureAlgorithm, which names the hash as well as the curve so a
// consumer does not have to know that ES256 implies SHA-256.
func algorithmLabel(jwa string) string {
	switch jwa {
	case "", "ES256":
		return "ecdsa-p256-sha256"
	case "ES384":
		return "ecdsa-p384-sha384"
	case "ES512":
		return "ecdsa-p521-sha512"
	default:
		return strings.ToLower(jwa)
	}
}
