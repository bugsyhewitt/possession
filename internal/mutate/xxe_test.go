package mutate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// xmlBodyReq returns a request authenticated as alice carrying the given XML
// body with the given content type.
func xmlBodyReq(t *testing.T, contentType, body string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/orders")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &model.CapturedRequest{
		ID:          "alice-xml-order",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: contentType,
		Body:        []byte(body),
	}
}

func TestXXE_DisabledByDefault(t *testing.T) {
	req := xmlBodyReq(t, "application/xml", `<?xml version="1.0"?><order><id>5</id></order>`)
	if vs := (XXE{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("XXE must be off by default; got %d variants", len(vs))
	}
}

func TestXXE_EmitsOneVariantPerTechnique(t *testing.T) {
	req := xmlBodyReq(t, "application/xml", `<?xml version="1.0"?><order><id>5</id></order>`)
	vs := XXE{Enabled: true}.Generate(req, nil)

	if len(vs) != len(xxeTechniques) {
		t.Fatalf("want %d variants got %d", len(xxeTechniques), len(vs))
	}

	for _, v := range vs {
		if v.Mutation.Type != "xxe" {
			t.Errorf("mutation type: want xxe got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "xxe-injection" {
			t.Errorf("class: want xxe-injection got %q", v.Mutation.Class)
		}
		// Credentials must be untouched: caller stays alice (Identity nil).
		if v.Identity != nil {
			t.Errorf("identity must be nil (caller unchanged); got %+v", v.Identity)
		}
		if v.Base == nil || len(v.Base.Body) == 0 {
			t.Fatalf("variant must carry a mutated body")
		}
		body := string(v.Base.Body)
		if !strings.Contains(body, "<!DOCTYPE") {
			t.Errorf("variant body must inject a DOCTYPE; got %q", body)
		}
		if !strings.Contains(body, "&xxe;") {
			t.Errorf("variant body must reference the injected entity; got %q", body)
		}
	}
}

func TestXXE_InternalEntityCarriesCanary(t *testing.T) {
	req := xmlBodyReq(t, "application/xml", `<order><id>5</id></order>`)
	vs := XXE{Enabled: true}.Generate(req, nil)

	var internal *model.Variant
	for i := range vs {
		if vs[i].Mutation.Detail["technique"] == "internal-entity" {
			internal = &vs[i]
		}
	}
	if internal == nil {
		t.Fatal("expected an internal-entity variant")
	}

	canary := internal.Mutation.Detail["xxe-canary"]
	if canary == "" {
		t.Fatal("internal-entity variant must carry an xxe-canary detail")
	}
	if !strings.HasPrefix(canary, xxeCanaryPrefix) {
		t.Errorf("canary must use the canary prefix; got %q", canary)
	}
	// The canary must derive from the base ID for per-endpoint uniqueness.
	if !strings.Contains(canary, req.ID) {
		t.Errorf("canary must embed the base request ID; got %q", canary)
	}
	// The canary value must be present in the injected entity definition.
	body := string(internal.Base.Body)
	if !strings.Contains(body, canary) {
		t.Errorf("internal-entity body must define the canary value; got %q", body)
	}
}

func TestXXE_ExternalSystemHasNoCanary(t *testing.T) {
	req := xmlBodyReq(t, "application/xml", `<order><id>5</id></order>`)
	vs := XXE{Enabled: true}.Generate(req, nil)

	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "external-system" {
			if _, ok := v.Mutation.Detail["xxe-canary"]; ok {
				t.Errorf("external-system variant must NOT carry a canary")
			}
			if !strings.Contains(string(v.Base.Body), "SYSTEM") {
				t.Errorf("external-system body must use a SYSTEM entity; got %q", string(v.Base.Body))
			}
		}
	}
}

func TestXXE_SkipsNonXMLBodies(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
	}{
		{"json-object", "application/json", `{"id":5}`},
		{"json-array", "application/json", `[1,2,3]`},
		{"form-encoded", "application/x-www-form-urlencoded", `id=5&name=alice`},
		{"empty", "application/xml", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := xmlBodyReq(t, c.ct, c.body)
			if vs := (XXE{Enabled: true}).Generate(req, nil); len(vs) != 0 {
				t.Errorf("%s: want 0 variants got %d", c.name, len(vs))
			}
		})
	}
}

func TestXXE_DetectsXMLByBodyShape(t *testing.T) {
	// No content type, but the body is clearly XML.
	req := xmlBodyReq(t, "", `<?xml version="1.0"?><order><id>5</id></order>`)
	vs := XXE{Enabled: true}.Generate(req, nil)
	if len(vs) != len(xxeTechniques) {
		t.Fatalf("body-shape XML detection failed: want %d got %d", len(xxeTechniques), len(vs))
	}
	// Content type must be forced to XML when originally absent.
	for _, v := range vs {
		if !strings.Contains(strings.ToLower(v.Base.ContentType), "xml") {
			t.Errorf("content type must be forced to XML; got %q", v.Base.ContentType)
		}
	}
}

func TestXXE_StripsPreExistingDoctype(t *testing.T) {
	req := xmlBodyReq(t, "application/xml",
		`<?xml version="1.0"?><!DOCTYPE order [<!ENTITY foo "bar">]><order><id>5</id></order>`)
	vs := XXE{Enabled: true}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants")
	}
	for _, v := range vs {
		body := string(v.Base.Body)
		// Exactly one DOCTYPE — the injected one, not the original.
		if n := strings.Count(body, "<!DOCTYPE"); n != 1 {
			t.Errorf("want exactly 1 DOCTYPE got %d in %q", n, body)
		}
		if strings.Contains(body, `<!ENTITY foo "bar">`) {
			t.Errorf("original DOCTYPE entity must be stripped; got %q", body)
		}
	}
}

func TestXXE_Deterministic(t *testing.T) {
	req := xmlBodyReq(t, "application/xml", `<order><id>5</id></order>`)
	a := XXE{Enabled: true}.Generate(req, nil)
	b := XXE{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("variant count differs across runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if string(a[i].Base.Body) != string(b[i].Base.Body) {
			t.Errorf("variant %d body differs across runs", i)
		}
		if a[i].Mutation.Detail["technique"] != b[i].Mutation.Detail["technique"] {
			t.Errorf("variant %d technique order differs across runs", i)
		}
	}
}

func TestXXE_SkipsSelfClosingRoot(t *testing.T) {
	// A document whose only element is self-closing has no content to inject.
	req := xmlBodyReq(t, "application/xml", `<?xml version="1.0"?><order/>`)
	if vs := (XXE{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("self-closing-only root: want 0 variants got %d", len(vs))
	}
}

func TestXXE_NilBaseSafe(t *testing.T) {
	if vs := (XXE{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}
