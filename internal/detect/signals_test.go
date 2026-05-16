package detect

import (
	"net/http"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func resp(status int, headers map[string]string, errStr string) *model.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &model.Response{Status: status, Headers: h, Err: errStr}
}

func TestClassifyStatus_AllBands(t *testing.T) {
	cases := []struct {
		name string
		r    *model.Response
		want StatusClass
	}{
		{"200 success", resp(200, nil, ""), StatusSuccess},
		{"201 success", resp(201, nil, ""), StatusSuccess},
		{"204 success", resp(204, nil, ""), StatusSuccess},
		{"401 denied", resp(401, nil, ""), StatusDenied},
		{"403 denied", resp(403, nil, ""), StatusDenied},
		{"404 denied", resp(404, nil, ""), StatusDenied},
		{"429 error", resp(429, nil, ""), StatusError},
		{"500 error", resp(500, nil, ""), StatusError},
		{"503 error", resp(503, nil, ""), StatusError},
		{"302 to login = denied", resp(302, map[string]string{"Location": "/login?next=/x"}, ""), StatusDenied},
		{"302 to sso = denied", resp(302, map[string]string{"Location": "https://sso.example.com/oauth/authorize"}, ""), StatusDenied},
		{"302 generic = ambiguous", resp(302, map[string]string{"Location": "/elsewhere"}, ""), StatusAmbiguous},
		{"transport error", resp(0, nil, "connection refused"), StatusError},
		{"nil response", nil, StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyStatus(c.r)
			if got != c.want {
				t.Errorf("want %d got %d", c.want, got)
			}
		})
	}
}

func TestSimilarity_Identical(t *testing.T) {
	s := "the quick brown fox jumps over the lazy dog"
	if got := Similarity(s, s); got != 1.0 {
		t.Errorf("want 1.0 got %v", got)
	}
}

func TestSimilarity_Disjoint(t *testing.T) {
	a := "alpha bravo charlie delta echo"
	b := "one two three four five"
	if got := Similarity(a, b); got != 0.0 {
		t.Errorf("want 0.0 got %v", got)
	}
}

func TestSimilarity_PartialOverlap(t *testing.T) {
	a := "the quick brown fox jumps over the lazy dog"
	b := "the quick brown fox runs over the lazy cat"
	got := Similarity(a, b)
	if got <= 0.0 || got >= 1.0 {
		t.Errorf("expected partial similarity in (0,1), got %v", got)
	}
}

func TestSimilarity_DegenerateTiny(t *testing.T) {
	if got := Similarity("ok", "ok"); got != 1.0 {
		t.Errorf("identical tiny: want 1.0 got %v", got)
	}
	if got := Similarity("ok", "no"); got != 0.0 {
		t.Errorf("disjoint tiny: want 0.0 got %v", got)
	}
}

func TestSizeRatio(t *testing.T) {
	if got := SizeRatio("aaaa", "aaaa"); got != 1.0 {
		t.Errorf("equal length: want 1.0 got %v", got)
	}
	if got := SizeRatio("aa", "aaaaaa"); got != 1.0/3 {
		t.Errorf("2/6: want %v got %v", 1.0/3, got)
	}
	if got := SizeRatio("", ""); got != 1.0 {
		t.Errorf("both empty: want 1.0 got %v", got)
	}
	if got := SizeRatio("", "x"); got != 0.0 {
		t.Errorf("one empty: want 0.0 got %v", got)
	}
}

func TestErrorSignature(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"Access denied for this resource", true},
		{"You are not authorized", true},
		{"please log in to continue", true},
		{`{"error":"Forbidden"}`, true},
		{`{"errorMessage":"nope"}`, true},
		{"Welcome back, alice", false},
		{`{"data":{"id":1}}`, false},
		{"", false},
	}
	for _, c := range cases {
		if got := ErrorSignature(c.body); got != c.want {
			t.Errorf("ErrorSignature(%q) = %v want %v", c.body, got, c.want)
		}
	}
}

func TestReflectedOwner(t *testing.T) {
	owner := &model.Identity{Name: "alice", Markers: []string{"alice@example.com", "Alice L."}}
	if !ReflectedOwner([]byte(`{"email":"alice@example.com"}`), owner) {
		t.Errorf("expected owner reflection match")
	}
	if ReflectedOwner([]byte(`{"email":"bob@example.com"}`), owner) {
		t.Errorf("unexpected owner reflection")
	}
	if ReflectedOwner([]byte(`anything`), nil) {
		t.Errorf("nil owner should never reflect")
	}
}

func TestReflectedActor(t *testing.T) {
	owner := &model.Identity{Name: "alice", Markers: []string{"alice@example.com"}}
	actor := &model.Identity{Name: "bob", Markers: []string{"bob@example.com"}}
	// Body contains only actor's marker ⇒ benign.
	if !ReflectedActor([]byte(`{"email":"bob@example.com"}`), actor, owner) {
		t.Errorf("expected actor reflection match")
	}
	// Body contains both ⇒ owner reflection wins (not actor).
	if ReflectedActor([]byte(`{"emails":["alice@example.com","bob@example.com"]}`), actor, owner) {
		t.Errorf("when both markers present, actor should NOT be returned")
	}
	// Body contains neither.
	if ReflectedActor([]byte(`unrelated`), actor, owner) {
		t.Errorf("no markers should not be actor-reflected")
	}
}
