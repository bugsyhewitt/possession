package mutate

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ppJSONBodyReq returns a request authenticated as alice carrying a JSON
// object body with the given fields. Mirrors mass_assign_test.jsonBodyReq so
// the two mutators are exercised against an identical input shape.
func ppJSONBodyReq(t *testing.T, fields map[string]interface{}) *model.CapturedRequest {
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

func TestPrototypePollution_DisabledByDefault(t *testing.T) {
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	if vs := (PrototypePollution{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("PrototypePollution must be off by default; got %d variants", len(vs))
	}
}

func TestPrototypePollution_EmitsEveryPropertyVectorPair(t *testing.T) {
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	vs := PrototypePollution{Enabled: true}.Generate(req, nil)

	// Full cross-product: every privileged property × every pollution
	// vector. None of the privileged keys collide with the caller's "name"
	// field, and none of the vector keys (__proto__, constructor,
	// prototype) collide either.
	want := len(PrivilegedProperties) * len(pollutionVectors)
	if len(vs) != want {
		t.Fatalf("want %d variants (props=%d × vectors=%d) got %d",
			want, len(PrivilegedProperties), len(pollutionVectors), len(vs))
	}

	// Track every (vector, field) cell — each must appear exactly once.
	seen := make(map[string]int, want)
	for _, v := range vs {
		if v.Mutation.Type != "prototype-pollution" {
			t.Errorf("mutation type: want prototype-pollution got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "privesc" {
			t.Errorf("class: want privesc got %q", v.Mutation.Class)
		}
		if v.Identity != nil {
			t.Errorf("must not swap identity; got %q", v.Identity.Name)
		}
		if got := v.Base.Headers.Get("Authorization"); got != "Bearer alice-token" {
			t.Errorf("auth header altered: %q", got)
		}

		vec := v.Mutation.Detail["vector"]
		field := v.Mutation.Detail["field"]
		if vec == "" || field == "" {
			t.Fatalf("variant missing vector/field detail: %+v", v.Mutation.Detail)
		}
		seen[vec+"|"+field]++
	}
	for cell, count := range seen {
		if count != 1 {
			t.Errorf("cell %q emitted %d times; want exactly 1", cell, count)
		}
	}
	if len(seen) != want {
		t.Errorf("only %d unique cells emitted; want %d", len(seen), want)
	}
}

func TestPrototypePollution_PreservesCallerFields(t *testing.T) {
	// Every variant must keep the caller's own top-level fields verbatim —
	// the pollution payload is *added* alongside them, never replaces.
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice", "email": "alice@example.com"})
	vs := PrototypePollution{Enabled: true}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("no variants emitted")
	}
	for _, v := range vs {
		var doc map[string]interface{}
		if err := json.Unmarshal(v.Base.Body, &doc); err != nil {
			t.Fatalf("variant body not JSON: %v", err)
		}
		if doc["name"] != "alice" {
			t.Errorf("name clobbered: %s", v.Base.Body)
		}
		if doc["email"] != "alice@example.com" {
			t.Errorf("email clobbered: %s", v.Base.Body)
		}
	}
}

func TestPrototypePollution_BuriesPayloadUnderVectorKey(t *testing.T) {
	// For each vector, the polluted field must be reachable at the
	// vector-specific path (not at the top level — that's mass-assign's
	// job, the two mutators are disjoint).
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	vs := PrototypePollution{Enabled: true}.Generate(req, nil)

	for _, v := range vs {
		var doc map[string]interface{}
		if err := json.Unmarshal(v.Base.Body, &doc); err != nil {
			t.Fatalf("variant body not JSON: %v", err)
		}
		vec := v.Mutation.Detail["vector"]
		field := v.Mutation.Detail["field"]

		// The polluted field must NOT be at the top level.
		if _, leaked := doc[field]; leaked {
			t.Errorf("vector %q: field %q leaked to top level (overlap with mass-assign): %s",
				vec, field, v.Base.Body)
		}

		switch vec {
		case "__proto__":
			proto, ok := doc["__proto__"].(map[string]interface{})
			if !ok {
				t.Errorf("__proto__ missing or not an object: %s", v.Base.Body)
				continue
			}
			if _, ok := proto[field]; !ok {
				t.Errorf("__proto__.%s missing: %s", field, v.Base.Body)
			}
		case "prototype":
			pr, ok := doc["prototype"].(map[string]interface{})
			if !ok {
				t.Errorf("prototype missing or not an object: %s", v.Base.Body)
				continue
			}
			if _, ok := pr[field]; !ok {
				t.Errorf("prototype.%s missing: %s", field, v.Base.Body)
			}
		case "constructor.prototype":
			ctor, ok := doc["constructor"].(map[string]interface{})
			if !ok {
				t.Errorf("constructor missing or not an object: %s", v.Base.Body)
				continue
			}
			pr, ok := ctor["prototype"].(map[string]interface{})
			if !ok {
				t.Errorf("constructor.prototype missing or not an object: %s", v.Base.Body)
				continue
			}
			if _, ok := pr[field]; !ok {
				t.Errorf("constructor.prototype.%s missing: %s", field, v.Base.Body)
			}
		default:
			t.Errorf("unknown vector %q in variant", vec)
		}
	}
}

func TestPrototypePollution_NonJSONBodySkipped(t *testing.T) {
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
	if vs := (PrototypePollution{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("non-JSON body must be skipped; got %d variants", len(vs))
	}
}

func TestPrototypePollution_JSONArrayBodySkipped(t *testing.T) {
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
	if vs := (PrototypePollution{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("JSON array body must be skipped; got %d variants", len(vs))
	}
}

func TestPrototypePollution_EmptyBodySkipped(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	req := &model.CapturedRequest{
		ID:          "get",
		Method:      "GET",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "application/json",
	}
	if vs := (PrototypePollution{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("empty body must be skipped; got %d variants", len(vs))
	}
}

func TestPrototypePollution_SkipsAlreadyPresentVectorKey(t *testing.T) {
	// If the caller's own body already contains a top-level "__proto__"
	// (vanishingly rare in real traffic, but worth defending), injecting
	// the same vector proves nothing — skip it. The other vectors still
	// fire.
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice", "__proto__": "preexisting"})
	vs := PrototypePollution{Enabled: true}.Generate(req, nil)

	for _, v := range vs {
		if v.Mutation.Detail["vector"] == "__proto__" {
			t.Errorf("must not inject __proto__ when caller already sets it")
		}
	}
	// __proto__ vector dropped, the other two vectors still emit
	// len(PrivilegedProperties) variants each.
	want := len(PrivilegedProperties) * (len(pollutionVectors) - 1)
	if len(vs) != want {
		t.Errorf("want %d variants got %d", want, len(vs))
	}
}

func TestPrototypePollution_Deterministic(t *testing.T) {
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	a := PrototypePollution{Enabled: true}.Generate(req, nil)
	b := PrototypePollution{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	keysA := make([]string, len(a))
	keysB := make([]string, len(b))
	for i := range a {
		keysA[i] = a[i].Mutation.Detail["vector"] + "|" + a[i].Mutation.Detail["field"]
		keysB[i] = b[i].Mutation.Detail["vector"] + "|" + b[i].Mutation.Detail["field"]
	}
	for i := range keysA {
		if keysA[i] != keysB[i] {
			t.Errorf("variant %d non-deterministic: %q vs %q", i, keysA[i], keysB[i])
		}
	}
	// Within the deterministic sweep, fields are the outer dimension (sorted
	// alphabetically by PrivilegedProperties.Key) and vectors are the inner
	// dimension (sorted alphabetically by vector Name). Verify both:
	// consecutive variants share a field while their vector advances, and
	// the field sequence is monotonically non-decreasing.
	var prevField string
	for _, k := range keysA {
		parts := strings.SplitN(k, "|", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed cell key %q", k)
		}
		field := parts[1]
		if prevField != "" && field < prevField {
			t.Errorf("field dimension not monotonic: %v", keysA)
			break
		}
		prevField = field
	}
	// Inner-vector grouping: collect the vector sequence for the first
	// field's run and assert it is sorted.
	firstField := strings.SplitN(keysA[0], "|", 2)[1]
	var firstRunVectors []string
	for _, k := range keysA {
		parts := strings.SplitN(k, "|", 2)
		if parts[1] != firstField {
			break
		}
		firstRunVectors = append(firstRunVectors, parts[0])
	}
	if !sort.StringsAreSorted(firstRunVectors) {
		t.Errorf("vector dimension within a field not sorted: %v", firstRunVectors)
	}
}

func TestPrototypePollution_DoesNotAliasBaseBody(t *testing.T) {
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	orig := append([]byte(nil), req.Body...)
	_ = PrototypePollution{Enabled: true}.Generate(req, nil)
	if string(req.Body) != string(orig) {
		t.Errorf("base request body mutated: %s", req.Body)
	}
}

func TestPrototypePollution_DescriptionMentionsVectorAndField(t *testing.T) {
	// The reporter (and the allowlist) use Description as the human-facing
	// label for the variant; it must name both the vector and the field so
	// triage can match it back to the test.
	req := ppJSONBodyReq(t, map[string]interface{}{"name": "alice"})
	vs := PrototypePollution{Enabled: true}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	for _, v := range vs {
		vec := v.Mutation.Detail["vector"]
		field := v.Mutation.Detail["field"]
		if !strings.Contains(v.Mutation.Description, vec) {
			t.Errorf("description missing vector %q: %q", vec, v.Mutation.Description)
		}
		if !strings.Contains(v.Mutation.Description, field) {
			t.Errorf("description missing field %q: %q", field, v.Mutation.Description)
		}
	}
}

func TestPrototypePollution_NameStable(t *testing.T) {
	if got := (PrototypePollution{}).Name(); got != "prototype-pollution" {
		t.Errorf("Name() must be stable for allowlist matching; got %q", got)
	}
}

func TestPrototypePollution_NotInDefaultRegistry(t *testing.T) {
	// PrototypePollution is gated and added only in buildRegistry; it must
	// stay out of DefaultRegistry so the canonical mutator order is
	// unchanged. Mirrors the equivalent assertion every other
	// off-by-default mutator has against DefaultRegistry.
	for _, n := range DefaultRegistry().Names() {
		if n == (PrototypePollution{}).Name() {
			t.Fatalf("prototype-pollution must NOT be in DefaultRegistry() (off-by-default mutator)")
		}
	}
}
