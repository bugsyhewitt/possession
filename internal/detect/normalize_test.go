package detect

import (
	"strings"
	"testing"
)

func TestNormalizeBody_JSONSortedKeys(t *testing.T) {
	a := []byte(`{"b":1,"a":2}`)
	b := []byte(`{"a":2,"b":1}`)
	na := NormalizeBody(a, "application/json")
	nb := NormalizeBody(b, "application/json")
	if na != nb {
		t.Errorf("expected sorted-key canonicalization to make these equal:\n  a=%s\n  b=%s", na, nb)
	}
}

func TestNormalizeBody_JSONVolatileKeysBlanked(t *testing.T) {
	body := []byte(`{"name":"alice","csrfToken":"abc123","data":{"updatedAt":"2024-01-01T00:00:00Z","x":1}}`)
	out := NormalizeBody(body, "application/json")
	if strings.Contains(out, "abc123") {
		t.Errorf("expected csrfToken value blanked, got %s", out)
	}
	if strings.Contains(out, "2024-01-01") {
		t.Errorf("expected updatedAt value blanked, got %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("expected non-volatile name to survive, got %s", out)
	}
}

func TestNormalizeBody_JSONRecursion(t *testing.T) {
	body := []byte(`{"outer":{"inner":{"sessionID":"xyz","keep":"yes"}}}`)
	out := NormalizeBody(body, "application/json")
	if strings.Contains(out, "xyz") {
		t.Errorf("expected nested sessionID blanked, got %s", out)
	}
	if !strings.Contains(out, "yes") {
		t.Errorf("expected nested keep preserved, got %s", out)
	}
}

func TestNormalizeBody_HTMLStripsCSRF(t *testing.T) {
	body := []byte(`<form><input type="hidden" name="csrf" value="abc"/></form>`)
	out := NormalizeBody(body, "text/html")
	if strings.Contains(out, "abc") {
		t.Errorf("expected csrf input stripped, got %s", out)
	}
}

func TestNormalizeBody_HTMLStripsMetaCSRF(t *testing.T) {
	body := []byte(`<meta name="csrf-token" content="abc123"/>`)
	out := NormalizeBody(body, "text/html")
	if strings.Contains(out, "abc123") {
		t.Errorf("expected meta csrf stripped, got %s", out)
	}
}

func TestNormalizeBody_HTMLStripsTimestamp(t *testing.T) {
	body := []byte(`generated at 2024-05-15T10:00:00Z by server`)
	out := NormalizeBody(body, "text/plain")
	if strings.Contains(out, "2024-05-15") {
		t.Errorf("expected ISO-8601 stripped, got %s", out)
	}
	if !strings.Contains(out, "generated at") {
		t.Errorf("expected non-timestamp content preserved, got %s", out)
	}
}

func TestNormalizeBody_HTMLStripsHexAndUUID(t *testing.T) {
	body := []byte(`req 550e8400-e29b-41d4-a716-446655440000 trace deadbeefdeadbeef`)
	out := NormalizeBody(body, "text/plain")
	if strings.Contains(out, "550e8400") {
		t.Errorf("expected UUID stripped, got %s", out)
	}
	if strings.Contains(out, "deadbeefdeadbeef") {
		t.Errorf("expected long-hex stripped, got %s", out)
	}
}

func TestNormalizeBody_HTMLCollapsesWhitespace(t *testing.T) {
	body := []byte("hello   \t\n\n   world")
	out := NormalizeBody(body, "text/plain")
	if out != "hello world" {
		t.Errorf("want %q got %q", "hello world", out)
	}
}

func TestNormalizeBody_Deterministic(t *testing.T) {
	body := []byte(`{"x":1,"y":{"z":2,"w":3},"a":"text"}`)
	out1 := NormalizeBody(body, "application/json")
	out2 := NormalizeBody(body, "application/json")
	if out1 != out2 {
		t.Errorf("non-deterministic: %q vs %q", out1, out2)
	}
}

func TestNormalizeBody_Empty(t *testing.T) {
	if NormalizeBody(nil, "") != "" {
		t.Errorf("nil body should normalize to empty string")
	}
	if NormalizeBody([]byte{}, "application/json") != "" {
		t.Errorf("empty body should normalize to empty string")
	}
}
