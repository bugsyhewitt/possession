package replay

import (
	"encoding/json"
	"testing"
)

func TestDottedPath_Basic(t *testing.T) {
	doc := mustJSON(`{"a":{"b":{"c":"x"}}}`)
	got, err := DottedPath("$.a.b.c", doc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "x" {
		t.Errorf("got %v", got)
	}
}

func TestDottedPath_ArrayIndex(t *testing.T) {
	doc := mustJSON(`{"a":[{"b":1},{"b":42}]}`)
	got, err := DottedPath("$.a[1].b", doc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.(float64) != 42 {
		t.Errorf("got %v", got)
	}
}

func TestDottedPath_MissingKey(t *testing.T) {
	doc := mustJSON(`{"a":{}}`)
	if _, err := DottedPath("$.a.missing", doc); err == nil {
		t.Error("expected error on missing key")
	}
}

func TestDottedPath_BadIndex(t *testing.T) {
	doc := mustJSON(`{"a":[1,2]}`)
	if _, err := DottedPath("$.a[5]", doc); err == nil {
		t.Error("expected out of range error")
	}
}

func TestDottedPath_EmptyAndMalformed(t *testing.T) {
	cases := []string{"", "a.b", "$..b", "$[abc]", "$[1"}
	for _, c := range cases {
		if _, err := DottedPath(c, nil); err == nil {
			t.Errorf("expected error on %q", c)
		}
	}
}

func mustJSON(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}
