package mutate

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// jsonBodyReq returns a request authenticated as alice carrying a JSON object
// body with the given fields.
func jsonBodyReq(t *testing.T, fields map[string]interface{}) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/json")
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return &model.CapturedRequest{
		ID:          "alice-put",
		Method:      "PUT",
		URL:         u,
		Headers:     h,
		ContentType: "application/json",
		Body:        body,
	}
}

func TestMassAssign_DisabledByDefault(t *testing.T) {
	req := jsonBodyReq(t, map[string]interface{}{"name": "alice"})
	// Zero-value MassAssign (Enabled == false) must emit nothing.
	if vs := (MassAssign{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("MassAssign must be off by default; got %d variants", len(vs))
	}
}

func TestMassAssign_InjectsEachPrivilegedProperty(t *testing.T) {
	req := jsonBodyReq(t, map[string]interface{}{"name": "alice"})
	vs := MassAssign{Enabled: true}.Generate(req, nil)

	// One variant per built-in privileged property (none collide with "name").
	if len(vs) != len(PrivilegedProperties) {
		t.Fatalf("want %d variants got %d", len(PrivilegedProperties), len(vs))
	}

	for _, v := range vs {
		if v.Mutation.Type != "mass-assign" {
			t.Errorf("mutation type: want mass-assign got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "privesc" {
			t.Errorf("class: want privesc got %q", v.Mutation.Class)
		}
		// Credentials must be untouched: the caller stays alice (Identity nil
		// means the replay engine keeps the captured auth as-is).
		if v.Identity != nil {
			t.Errorf("MassAssign must not swap identity; got %q", v.Identity.Name)
		}
		if got := v.Base.Headers.Get("Authorization"); got != "Bearer alice-token" {
			t.Errorf("auth header altered: %q", got)
		}

		field := v.Mutation.Detail["field"]
		if field == "" {
			t.Fatal("variant missing field detail")
		}
		// The injected field must be present in the body, and the original
		// "name" field preserved.
		var doc map[string]interface{}
		if err := json.Unmarshal(v.Base.Body, &doc); err != nil {
			t.Fatalf("variant body not JSON: %v", err)
		}
		if _, ok := doc[field]; !ok {
			t.Errorf("injected field %q absent from body %s", field, v.Base.Body)
		}
		if doc["name"] != "alice" {
			t.Errorf("original field clobbered: %s", v.Base.Body)
		}
	}
}

func TestMassAssign_SkipsAlreadyPresentField(t *testing.T) {
	// The caller already legitimately sets "role" — injecting it proves
	// nothing, so no variant should target it. Case-insensitive.
	req := jsonBodyReq(t, map[string]interface{}{"name": "alice", "Role": "user"})
	vs := MassAssign{Enabled: true}.Generate(req, nil)

	for _, v := range vs {
		if v.Mutation.Detail["field"] == "role" {
			t.Errorf("must not inject already-present field 'role' (case-insensitive)")
		}
	}
	// Exactly one fewer than the full set (role excluded).
	if len(vs) != len(PrivilegedProperties)-1 {
		t.Fatalf("want %d variants got %d", len(PrivilegedProperties)-1, len(vs))
	}
}

func TestMassAssign_NonJSONBodySkipped(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	req := &model.CapturedRequest{
		ID:          "form",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte("name=alice&role=user"),
	}
	if vs := (MassAssign{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("non-JSON body must be skipped; got %d variants", len(vs))
	}
}

func TestMassAssign_JSONArrayBodySkipped(t *testing.T) {
	// A top-level JSON array is not a model bind target — skip it.
	u, _ := url.Parse("https://api.example.com/api/users")
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	req := &model.CapturedRequest{
		ID:          "arr",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/json",
		Body:        []byte(`["alice","bob"]`),
	}
	if vs := (MassAssign{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("JSON array body must be skipped; got %d variants", len(vs))
	}
}

func TestMassAssign_EmptyBodySkipped(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	req := &model.CapturedRequest{
		ID:          "get",
		Method:      "GET",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "application/json",
	}
	if vs := (MassAssign{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("empty body must be skipped; got %d variants", len(vs))
	}
}

func TestMassAssign_Deterministic(t *testing.T) {
	req := jsonBodyReq(t, map[string]interface{}{"name": "alice"})
	a := MassAssign{Enabled: true}.Generate(req, nil)
	b := MassAssign{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	fieldsA := make([]string, len(a))
	fieldsB := make([]string, len(b))
	for i := range a {
		fieldsA[i] = a[i].Mutation.Detail["field"]
		fieldsB[i] = b[i].Mutation.Detail["field"]
	}
	if !sort.StringsAreSorted(fieldsA) {
		t.Errorf("fields not applied in sorted order: %v", fieldsA)
	}
	for i := range fieldsA {
		if fieldsA[i] != fieldsB[i] {
			t.Errorf("variant %d non-deterministic: %q vs %q", i, fieldsA[i], fieldsB[i])
		}
	}
}

func TestMassAssign_DoesNotAliasBaseBody(t *testing.T) {
	req := jsonBodyReq(t, map[string]interface{}{"name": "alice"})
	orig := append([]byte(nil), req.Body...)
	_ = MassAssign{Enabled: true}.Generate(req, nil)
	if string(req.Body) != string(orig) {
		t.Errorf("base request body mutated: %s", req.Body)
	}
}

func TestMassAssign_NotInDefaultRegistry(t *testing.T) {
	// MassAssign is gated and added only in buildRegistry; it must stay out
	// of DefaultRegistry so the canonical order is unchanged.
	for _, n := range DefaultRegistry().Names() {
		if n == (MassAssign{}).Name() {
			t.Fatalf("mass-assign must NOT be in DefaultRegistry()")
		}
	}
}
