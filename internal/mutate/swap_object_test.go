package mutate

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// resourceMatrix returns a matrix where alice and bob each own distinct
// resources, so swap-object can substitute one for the other.
func resourceMatrix() *model.RoleMatrix {
	return &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Role: "user", Rank: 10, Creds: &model.Credentials{
				Bearer: "alice-token",
			}, Resources: map[string]string{"user_id": "1001", "order_id": "5523"}},
			{Name: "bob", Role: "user", Rank: 10, Creds: &model.Credentials{
				Bearer: "bob-token",
			}, Resources: map[string]string{"user_id": "2002", "order_id": "6634"}},
		},
	}
}

// aliceReq is a request authenticated as alice that references alice's
// user_id in the path, order_id in the query, and user_id in the JSON body.
func aliceReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/users/1001/orders?order_id=5523")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/json")
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": "1001",
		"note":    "leave me alone",
	})
	return &model.CapturedRequest{
		ID:          "alice-1",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/json",
		Body:        body,
	}
}

func TestSwapObject_SubstitutesAcrossPathQueryBody(t *testing.T) {
	m := resourceMatrix()
	base := aliceReq(t)
	vs := SwapObject{}.Generate(base, m)

	// One target (bob) with shared resource keys ⇒ exactly one variant.
	if len(vs) != 1 {
		t.Fatalf("want 1 swap-object variant got %d", len(vs))
	}
	v := vs[0]

	if v.Mutation.Type != "swap-object" {
		t.Errorf("mutation type: want swap-object got %q", v.Mutation.Type)
	}
	if v.Mutation.Class != "idor" {
		t.Errorf("class: want idor got %q", v.Mutation.Class)
	}

	// Credentials must remain alice's — swap-object never swaps identity.
	if v.Identity == nil || v.Identity.Name != "alice" {
		t.Fatalf("caller identity: want alice got %v", v.Identity)
	}
	if got := v.Base.Headers.Get("Authorization"); got != "Bearer alice-token" {
		t.Errorf("credentials changed: want alice token got %q", got)
	}

	// Path: alice's user_id (1001) → bob's (2002).
	if got := v.Base.URL.Path; got != "/api/users/2002/orders" {
		t.Errorf("path: want /api/users/2002/orders got %q", got)
	}

	// Query: order_id 5523 → 6634.
	if got := v.Base.URL.Query().Get("order_id"); got != "6634" {
		t.Errorf("query order_id: want 6634 got %q", got)
	}

	// Body: user_id 1001 → 2002, note untouched.
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(v.Base.Body, &bodyMap); err != nil {
		t.Fatalf("variant body not valid JSON: %v", err)
	}
	if bodyMap["user_id"] != "2002" {
		t.Errorf("body user_id: want 2002 got %v", bodyMap["user_id"])
	}
	if bodyMap["note"] != "leave me alone" {
		t.Errorf("body note mutated: got %v", bodyMap["note"])
	}

	// Baseline must be untouched (no aliasing through shared URL/body).
	if base.URL.Path != "/api/users/1001/orders" {
		t.Errorf("baseline path mutated: %q", base.URL.Path)
	}
	if base.URL.Query().Get("order_id") != "5523" {
		t.Errorf("baseline query mutated: %q", base.URL.RawQuery)
	}
	var baseBody map[string]interface{}
	_ = json.Unmarshal(base.Body, &baseBody)
	if baseBody["user_id"] != "1001" {
		t.Errorf("baseline body mutated: %v", baseBody["user_id"])
	}

	// Detail records the swap direction.
	if v.Mutation.Detail["object_from"] != "alice" || v.Mutation.Detail["object_to"] != "bob" {
		t.Errorf("detail swap direction wrong: %+v", v.Mutation.Detail)
	}
}

func TestSwapObject_NoResourcesNoVariants(t *testing.T) {
	// Matrix where identities have NO resources defined.
	m := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Role: "user", Rank: 10, Creds: &model.Credentials{Bearer: "alice-token"}},
			{Name: "bob", Role: "user", Rank: 10, Creds: &model.Credentials{Bearer: "bob-token"}},
		},
	}
	if got := (SwapObject{}).Generate(aliceReq(t), m); len(got) != 0 {
		t.Fatalf("want 0 variants when no resources defined, got %d", len(got))
	}

	// Source has resources but target does not ⇒ no variant.
	m2 := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Role: "user", Rank: 10, Creds: &model.Credentials{Bearer: "alice-token"},
				Resources: map[string]string{"user_id": "1001"}},
			{Name: "bob", Role: "user", Rank: 10, Creds: &model.Credentials{Bearer: "bob-token"}},
		},
	}
	if got := (SwapObject{}).Generate(aliceReq(t), m2); len(got) != 0 {
		t.Fatalf("want 0 variants when target has no resources, got %d", len(got))
	}
}

func TestSwapObject_NoOwnerMatchNoVariants(t *testing.T) {
	m := resourceMatrix()
	// Request carries an unknown token — no identity owns it.
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	h := http.Header{}
	h.Set("Authorization", "Bearer stranger-token")
	base := &model.CapturedRequest{ID: "x", Method: "GET", URL: u, Headers: h}
	if got := (SwapObject{}).Generate(base, m); len(got) != 0 {
		t.Fatalf("want 0 variants when caller is unattributable, got %d", len(got))
	}
}

func TestSwapObject_NoMatchingValueNoVariant(t *testing.T) {
	m := resourceMatrix()
	// Alice's request that does NOT contain any of alice's owned values.
	u, _ := url.Parse("https://api.example.com/api/profile")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	base := &model.CapturedRequest{ID: "p", Method: "GET", URL: u, Headers: h}
	if got := (SwapObject{}).Generate(base, m); len(got) != 0 {
		t.Fatalf("want 0 variants when no owned value appears in request, got %d", len(got))
	}
}

func TestSwapObject_MultipleTargetsDeterministicOrder(t *testing.T) {
	m := resourceMatrix()
	// Add carol, a third owner, out of canonical order to verify sorting.
	m.Identities = append([]model.Identity{
		{Name: "carol", Role: "user", Rank: 10, Creds: &model.Credentials{Bearer: "carol-token"},
			Resources: map[string]string{"user_id": "3003", "order_id": "7745"}},
	}, m.Identities...)

	vs := SwapObject{}.Generate(aliceReq(t), m)
	// alice is the caller; bob and carol are targets ⇒ 2 variants.
	if len(vs) != 2 {
		t.Fatalf("want 2 variants (bob, carol) got %d", len(vs))
	}
	// Canonical (rank, name) order: bob before carol.
	if vs[0].Mutation.Detail["object_to"] != "bob" {
		t.Errorf("first target: want bob got %q", vs[0].Mutation.Detail["object_to"])
	}
	if vs[1].Mutation.Detail["object_to"] != "carol" {
		t.Errorf("second target: want carol got %q", vs[1].Mutation.Detail["object_to"])
	}
}

func TestSwapObject_HeaderCredentialOwnerMatch(t *testing.T) {
	// Owner attributed via X-Api-Key rather than bearer.
	m := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Role: "user", Rank: 10, Creds: &model.Credentials{
				Headers: map[string]string{"X-Api-Key": "alice-key"},
			}, Resources: map[string]string{"user_id": "1001"}},
			{Name: "bob", Role: "user", Rank: 10, Creds: &model.Credentials{
				Headers: map[string]string{"X-Api-Key": "bob-key"},
			}, Resources: map[string]string{"user_id": "2002"}},
		},
	}
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	h := http.Header{}
	h.Set("X-Api-Key", "alice-key")
	base := &model.CapturedRequest{ID: "k", Method: "GET", URL: u, Headers: h}

	vs := SwapObject{}.Generate(base, m)
	if len(vs) != 1 {
		t.Fatalf("want 1 variant got %d", len(vs))
	}
	if vs[0].Base.URL.Path != "/api/users/2002" {
		t.Errorf("path: want /api/users/2002 got %q", vs[0].Base.URL.Path)
	}
	if vs[0].Base.Headers.Get("X-Api-Key") != "alice-key" {
		t.Errorf("credentials changed: %q", vs[0].Base.Headers.Get("X-Api-Key"))
	}
}
