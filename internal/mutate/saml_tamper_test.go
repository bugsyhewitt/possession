package mutate

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// minimalSAMLResponse returns a minimal SAML Response XML with a NameID and a
// Signature block, base64-encoded as StandardEncoding (the SAML HTTP POST
// binding uses standard base64).
func minimalSAMLResponse(nameID string) string {
	xml := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Subject>` +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` +
		nameID +
		`</saml:NameID>` +
		`</saml:Subject>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="c14n"/>` +
		`<ds:SignatureMethod Algorithm="rsa-sha256"/>` +
		`</ds:SignedInfo>` +
		`<ds:SignatureValue>AAAA==</ds:SignatureValue>` +
		`</ds:Signature>` +
		`</saml:Assertion>` +
		`</samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// samlFormRequest builds a POST request with a SAMLResponse form-encoded body.
func samlFormRequest(t *testing.T, samlB64, relayState string) *model.CapturedRequest {
	t.Helper()
	vals := url.Values{}
	vals.Set("SAMLResponse", samlB64)
	if relayState != "" {
		vals.Set("RelayState", relayState)
	}
	body := vals.Encode()
	return &model.CapturedRequest{
		Method:      "POST",
		URL:         mustURL(t, "https://sp.example.com/saml/acs"),
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte(body),
	}
}

// decodeSAMLBody decodes the SAMLResponse parameter from a request body.
func decodeSAMLBody(t *testing.T, body []byte) string {
	t.Helper()
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(vals.Get("SAMLResponse"))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	return string(raw)
}

// ─── disabled-by-default ─────────────────────────────────────────────────────

func TestSAMLTamper_DisabledByDefault(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{}.Generate(req, nil)
	if len(got) != 0 {
		t.Fatalf("disabled mutator emitted %d variants, want 0", len(got))
	}
}

// ─── non-form requests are skipped ───────────────────────────────────────────

func TestSAMLTamper_SkipsNonFormBody(t *testing.T) {
	cases := []struct {
		name   string
		method string
		ct     string
		body   string
	}{
		{"GET request", "GET", "application/x-www-form-urlencoded", "SAMLResponse=abc"},
		{"JSON body", "POST", "application/json", `{"SAMLResponse":"abc"}`},
		{"no body", "POST", "application/x-www-form-urlencoded", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &model.CapturedRequest{
				Method:      tc.method,
				URL:         mustURL(t, "https://sp.example.com/saml/acs"),
				ContentType: tc.ct,
				Body:        []byte(tc.body),
			}
			got := SAMLTamper{Enabled: true}.Generate(req, nil)
			if len(got) != 0 {
				t.Fatalf("%s: want 0 variants, got %d", tc.name, len(got))
			}
		})
	}
}

// ─── no SAMLResponse param → no variants ─────────────────────────────────────

func TestSAMLTamper_SkipsBodyWithoutSAMLResponse(t *testing.T) {
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         mustURL(t, "https://sp.example.com/saml/acs"),
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte("RelayState=abc&other=123"),
	}
	got := SAMLTamper{Enabled: true}.Generate(req, nil)
	if len(got) != 0 {
		t.Fatalf("want 0 variants, got %d", len(got))
	}
}

// ─── signature-strip variant ──────────────────────────────────────────────────

func TestSAMLTamper_SigStripVariantMetadata(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "relay123")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	var sigStrip *model.Variant
	for i := range got {
		if got[i].Mutation.Type == mutTypeSAMLSigStrip {
			sigStrip = &got[i]
		}
	}
	if sigStrip == nil {
		t.Fatal("no sig-strip variant emitted")
	}

	// Metadata checks
	if sigStrip.Mutation.Class != "authn-bypass" {
		t.Errorf("class = %q, want authn-bypass", sigStrip.Mutation.Class)
	}
	if sigStrip.Mutation.Detail["finding_id"] != FindingSAMLSigStrip {
		t.Errorf("finding_id = %q, want %q", sigStrip.Mutation.Detail["finding_id"], FindingSAMLSigStrip)
	}
	if sigStrip.Mutation.Detail["severity"] != "critical" {
		t.Errorf("severity = %q, want critical", sigStrip.Mutation.Detail["severity"])
	}
	if sigStrip.Identity != nil {
		t.Errorf("Identity should be nil (same-caller variant), got %v", sigStrip.Identity)
	}
}

func TestSAMLTamper_SigStripRemovesSignatureBlock(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	var sigStrip *model.Variant
	for i := range got {
		if got[i].Mutation.Type == mutTypeSAMLSigStrip {
			sigStrip = &got[i]
		}
	}
	if sigStrip == nil {
		t.Fatal("no sig-strip variant")
	}

	xml := decodeSAMLBody(t, sigStrip.Base.Body)
	if strings.Contains(xml, "<ds:Signature") {
		t.Error("sig-strip variant still contains <ds:Signature>")
	}
	if strings.Contains(xml, "ds:SignatureValue") {
		t.Error("sig-strip variant still contains ds:SignatureValue")
	}
	// Non-signature content should be preserved
	if !strings.Contains(xml, "alice@example.com") {
		t.Error("sig-strip variant dropped NameID content")
	}
}

func TestSAMLTamper_SigStripPreservesRelayState(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "relay123")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	for _, v := range got {
		if v.Mutation.Type != mutTypeSAMLSigStrip {
			continue
		}
		vals, _ := url.ParseQuery(string(v.Base.Body))
		if vals.Get("RelayState") != "relay123" {
			t.Errorf("RelayState not preserved: got %q", vals.Get("RelayState"))
		}
	}
}

// ─── NameID-swap variant ──────────────────────────────────────────────────────

func TestSAMLTamper_NameIDSwapVariantMetadata(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	var nameIDSwap *model.Variant
	for i := range got {
		if got[i].Mutation.Type == mutTypeSAMLNameIDSwap {
			nameIDSwap = &got[i]
		}
	}
	if nameIDSwap == nil {
		t.Fatal("no nameid-swap variant emitted")
	}

	if nameIDSwap.Mutation.Class != "authn-bypass" {
		t.Errorf("class = %q, want authn-bypass", nameIDSwap.Mutation.Class)
	}
	if nameIDSwap.Mutation.Detail["finding_id"] != FindingSAMLNameIDSwap {
		t.Errorf("finding_id = %q, want %q", nameIDSwap.Mutation.Detail["finding_id"], FindingSAMLNameIDSwap)
	}
	if nameIDSwap.Mutation.Detail["original_nameid"] != "alice@example.com" {
		t.Errorf("original_nameid = %q, want alice@example.com", nameIDSwap.Mutation.Detail["original_nameid"])
	}
	if nameIDSwap.Identity != nil {
		t.Errorf("Identity should be nil, got %v", nameIDSwap.Identity)
	}
}

func TestSAMLTamper_NameIDSwapReplacesNameID(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	var nameIDSwap *model.Variant
	for i := range got {
		if got[i].Mutation.Type == mutTypeSAMLNameIDSwap {
			nameIDSwap = &got[i]
		}
	}
	if nameIDSwap == nil {
		t.Fatal("no nameid-swap variant")
	}

	xml := decodeSAMLBody(t, nameIDSwap.Base.Body)
	targetNameID := nameIDSwap.Mutation.Detail["target_nameid"]
	if targetNameID == "" {
		t.Fatal("target_nameid not set in Detail")
	}
	if !strings.Contains(xml, ">"+targetNameID+"<") {
		t.Errorf("NameID not replaced: xml does not contain >%s<", targetNameID)
	}
	// The original value should not remain
	if strings.Contains(xml, ">alice@example.com<") {
		t.Errorf("NameID still contains original value alice@example.com")
	}
}

func TestSAMLTamper_NameIDSwapPreservesSignature(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	for _, v := range got {
		if v.Mutation.Type != mutTypeSAMLNameIDSwap {
			continue
		}
		xml := decodeSAMLBody(t, v.Base.Body)
		if !strings.Contains(xml, "<ds:Signature") {
			t.Error("nameid-swap should preserve signature block")
		}
		if !strings.Contains(xml, "AAAA==") {
			t.Error("nameid-swap should preserve original SignatureValue")
		}
	}
}

// ─── NameID already privileged → skip that target ────────────────────────────

func TestSAMLTamper_NameIDSwapSkipsWhenAlreadyAdmin(t *testing.T) {
	// If the captured NameID is already "admin", we should pick the next target.
	req := samlFormRequest(t, minimalSAMLResponse("admin"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	for _, v := range got {
		if v.Mutation.Type != mutTypeSAMLNameIDSwap {
			continue
		}
		target := v.Mutation.Detail["target_nameid"]
		if strings.EqualFold(target, "admin") {
			t.Errorf("should not swap NameID from admin to admin, got target %q", target)
		}
	}
}

// ─── no Signature in XML → only NameID-swap emitted ──────────────────────────

func TestSAMLTamper_OnlyNameIDSwapWhenNoSignature(t *testing.T) {
	xmlNoSig := `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion></samlp:Response>`
	samlB64 := base64.StdEncoding.EncodeToString([]byte(xmlNoSig))
	req := samlFormRequest(t, samlB64, "")

	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	hasSigStrip := false
	hasNameIDSwap := false
	for _, v := range got {
		switch v.Mutation.Type {
		case mutTypeSAMLSigStrip:
			hasSigStrip = true
		case mutTypeSAMLNameIDSwap:
			hasNameIDSwap = true
		}
	}
	if hasSigStrip {
		t.Error("should not emit sig-strip when no <ds:Signature> present")
	}
	if !hasNameIDSwap {
		t.Error("should emit nameid-swap even when no signature block")
	}
}

// ─── no NameID in XML → only sig-strip emitted ───────────────────────────────

func TestSAMLTamper_OnlySigStripWhenNoNameID(t *testing.T) {
	xmlNoNameID := `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<ds:SignatureValue>AAAA==</ds:SignatureValue></ds:Signature>` +
		`</saml:Assertion></samlp:Response>`
	samlB64 := base64.StdEncoding.EncodeToString([]byte(xmlNoNameID))
	req := samlFormRequest(t, samlB64, "")

	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	hasSigStrip := false
	hasNameIDSwap := false
	for _, v := range got {
		switch v.Mutation.Type {
		case mutTypeSAMLSigStrip:
			hasSigStrip = true
		case mutTypeSAMLNameIDSwap:
			hasNameIDSwap = true
		}
	}
	if !hasSigStrip {
		t.Error("should emit sig-strip even when no NameID present")
	}
	if hasNameIDSwap {
		t.Error("should not emit nameid-swap when no <saml:NameID> present")
	}
}

// ─── determinism ─────────────────────────────────────────────────────────────

func TestSAMLTamper_Deterministic(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "relay")
	m := SAMLTamper{Enabled: true}
	first := m.Generate(req, nil)
	second := m.Generate(req, nil)

	if len(first) != len(second) {
		t.Fatalf("non-deterministic: len %d vs %d", len(first), len(second))
	}
	for i := range first {
		if string(first[i].Base.Body) != string(second[i].Base.Body) {
			t.Errorf("variant[%d] body differs between runs", i)
		}
		if first[i].Mutation.Type != second[i].Mutation.Type {
			t.Errorf("variant[%d] type differs", i)
		}
	}
}

// ─── both variants count ──────────────────────────────────────────────────────

func TestSAMLTamper_EmitsBothVariants(t *testing.T) {
	req := samlFormRequest(t, minimalSAMLResponse("alice@example.com"), "")
	got := SAMLTamper{Enabled: true}.Generate(req, nil)

	if len(got) != 2 {
		t.Fatalf("want 2 variants (sig-strip + nameid-swap), got %d", len(got))
	}
	if got[0].Mutation.Type != mutTypeSAMLSigStrip {
		t.Errorf("got[0].Type = %q, want %q", got[0].Mutation.Type, mutTypeSAMLSigStrip)
	}
	if got[1].Mutation.Type != mutTypeSAMLNameIDSwap {
		t.Errorf("got[1].Type = %q, want %q", got[1].Mutation.Type, mutTypeSAMLNameIDSwap)
	}
}

// ─── invalid base64 → no variants ────────────────────────────────────────────

func TestSAMLTamper_SkipsInvalidBase64(t *testing.T) {
	vals := url.Values{}
	vals.Set("SAMLResponse", "!!!not-valid-base64!!!")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         mustURL(t, "https://sp.example.com/saml/acs"),
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte(vals.Encode()),
	}
	got := SAMLTamper{Enabled: true}.Generate(req, nil)
	if len(got) != 0 {
		t.Fatalf("want 0 variants for invalid base64, got %d", len(got))
	}
}

// ─── looksFormEncoded helper ──────────────────────────────────────────────────

func TestLooksFormEncoded(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"SAMLResponse=abc&RelayState=xyz", true},
		{"other=foo", false},
		{"", false},
	}
	for _, tc := range cases {
		got := looksFormEncoded([]byte(tc.input))
		if got != tc.want {
			t.Errorf("looksFormEncoded(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
