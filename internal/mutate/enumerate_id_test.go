package mutate

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// makeReqWithPath returns a CapturedRequest whose URL path is path.
func makeReqWithPath(t *testing.T, path string) *model.CapturedRequest {
	t.Helper()
	u, err := url.Parse("https://api.example.com" + path)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", path, err)
	}
	return &model.CapturedRequest{
		ID:     "test-1",
		Method: "GET",
		URL:    u,
	}
}

func TestEnumerateID_DisabledWhenNZero(t *testing.T) {
	req := makeReqWithPath(t, "/orders/56789")
	vs := EnumerateID{N: 0}.Generate(req, nil)
	if len(vs) != 0 {
		t.Errorf("N=0 should produce no variants, got %d", len(vs))
	}
}

func TestEnumerateID_NilInput(t *testing.T) {
	vs := EnumerateID{N: 5}.Generate(nil, nil)
	if len(vs) != 0 {
		t.Errorf("nil base should produce no variants, got %d", len(vs))
	}
}

func TestEnumerateID_NoNumericSegment(t *testing.T) {
	req := makeReqWithPath(t, "/users/profile/settings")
	vs := EnumerateID{N: 5}.Generate(req, nil)
	if len(vs) != 0 {
		t.Errorf("no numeric segment should produce no variants, got %d", len(vs))
	}
}

func TestEnumerateID_UUIDSegmentSkipped(t *testing.T) {
	req := makeReqWithPath(t, "/orders/550e8400-e29b-41d4-a716-446655440000")
	vs := EnumerateID{N: 5}.Generate(req, nil)
	if len(vs) != 0 {
		t.Errorf("UUID segment should not be enumerated, got %d", len(vs))
	}
}

func TestEnumerateID_NeighborCountCorrect(t *testing.T) {
	// /orders/56789 with N=10 → 10 below + 10 above = 20 neighbors, plus ~5 random
	req := makeReqWithPath(t, "/orders/56789")
	vs := EnumerateID{N: 10}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants, got none")
	}
	// Must have at least 20 variants (the immediate ±10 neighbors).
	if len(vs) < 20 {
		t.Errorf("want at least 20 variants (±10 neighbors), got %d", len(vs))
	}
	// Captured value itself must NOT be in the probe set.
	for _, v := range vs {
		probeID := v.Mutation.Detail["probe_id"]
		if probeID == "56789" {
			t.Error("captured ID 56789 should not be in the probe set")
		}
	}
}

func TestEnumerateID_NearZeroNoNegativeIDs(t *testing.T) {
	// /items/3 with N=10 — negative IDs are invalid; probe set must be ≥ 0.
	req := makeReqWithPath(t, "/items/3")
	vs := EnumerateID{N: 10}.Generate(req, nil)
	for _, v := range vs {
		probeStr := v.Mutation.Detail["probe_id"]
		id, err := strconv.ParseInt(probeStr, 10, 64)
		if err != nil {
			t.Errorf("invalid probe_id %q: %v", probeStr, err)
			continue
		}
		if id < 0 {
			t.Errorf("negative probe ID %d generated", id)
		}
	}
}

func TestEnumerateID_PathModified(t *testing.T) {
	req := makeReqWithPath(t, "/v1/orders/56789/items")
	vs := EnumerateID{N: 3}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants, got none")
	}
	for _, v := range vs {
		path := v.Base.URL.Path
		if !strings.HasPrefix(path, "/v1/orders/") || !strings.HasSuffix(path, "/items") {
			t.Errorf("path structure broken: %q", path)
		}
		// Segment at index 3 (0-indexed split on /) should be the probed ID,
		// not the original 56789.
		parts := strings.Split(path, "/")
		if len(parts) != 5 { // ["", "v1", "orders", "<id>", "items"]
			t.Fatalf("unexpected parts length %d for path %q", len(parts), path)
		}
		if !isEnumerableSegment(parts[3]) {
			t.Errorf("modified segment %q is not numeric", parts[3])
		}
	}
}

func TestEnumerateID_BaselinePreserved(t *testing.T) {
	// The original request must not be mutated.
	req := makeReqWithPath(t, "/orders/100")
	originalPath := req.URL.Path
	EnumerateID{N: 5}.Generate(req, nil)
	if req.URL.Path != originalPath {
		t.Errorf("original request path mutated: got %q want %q", req.URL.Path, originalPath)
	}
}

func TestEnumerateID_Deterministic(t *testing.T) {
	req := makeReqWithPath(t, "/orders/56789")
	vs1 := EnumerateID{N: 5}.Generate(req, nil)
	vs2 := EnumerateID{N: 5}.Generate(req, nil)
	if len(vs1) != len(vs2) {
		t.Fatalf("non-deterministic variant count: %d vs %d", len(vs1), len(vs2))
	}
	for i := range vs1 {
		if vs1[i].Mutation.Detail["probe_id"] != vs2[i].Mutation.Detail["probe_id"] {
			t.Errorf("position %d: probe_id differs between runs", i)
		}
	}
}

func TestEnumerateID_MutationFields(t *testing.T) {
	req := makeReqWithPath(t, "/users/42/profile")
	vs := EnumerateID{N: 2}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants")
	}
	for _, v := range vs {
		if v.Mutation.Type != "enumerate-id" {
			t.Errorf("mutation type: got %q want enumerate-id", v.Mutation.Type)
		}
		if v.Mutation.Class != "idor" {
			t.Errorf("mutation class: got %q want idor", v.Mutation.Class)
		}
		if v.Mutation.Detail["captured_id"] != "42" {
			t.Errorf("captured_id: got %q want 42", v.Mutation.Detail["captured_id"])
		}
		if v.Mutation.Detail["range"] != "2" {
			t.Errorf("range detail: got %q want 2", v.Mutation.Detail["range"])
		}
		if v.Identity != nil {
			t.Error("identity should be nil (original caller's creds preserved in base)")
		}
	}
}

func TestEnumerateID_FirstNumericSegmentOnly(t *testing.T) {
	// /a/10/b/20 — only the first numeric segment (10) should be probed.
	req := makeReqWithPath(t, "/a/10/b/20")
	vs := EnumerateID{N: 1}.Generate(req, nil)
	for _, v := range vs {
		parts := strings.Split(v.Base.URL.Path, "/")
		// parts: ["", "a", "<probed>", "b", "20"]
		if len(parts) != 5 {
			t.Fatalf("unexpected parts %v", parts)
		}
		// Second numeric segment must remain unchanged.
		if parts[4] != "20" {
			t.Errorf("second numeric segment changed to %q, should stay 20", parts[4])
		}
	}
}

func TestEnumerateID_SortedAscending(t *testing.T) {
	req := makeReqWithPath(t, "/orders/1000")
	vs := EnumerateID{N: 5}.Generate(req, nil)
	if len(vs) < 2 {
		t.Skip("need at least 2 variants to check ordering")
	}
	for i := 1; i < len(vs); i++ {
		prev, _ := strconv.ParseInt(vs[i-1].Mutation.Detail["probe_id"], 10, 64)
		curr, _ := strconv.ParseInt(vs[i].Mutation.Detail["probe_id"], 10, 64)
		if curr < prev {
			t.Errorf("probe IDs not sorted ascending at position %d: %d > %d", i, prev, curr)
		}
	}
}

func TestEnumerateID_NameAndMatrix(t *testing.T) {
	m := EnumerateID{N: 5}
	if m.Name() != "enumerate-id" {
		t.Errorf("Name(): got %q want enumerate-id", m.Name())
	}
	// Matrix arg is ignored; passing nil must not panic.
	req := makeReqWithPath(t, "/orders/100")
	vs := m.Generate(req, &model.RoleMatrix{})
	if len(vs) == 0 {
		t.Error("expected variants with non-nil matrix")
	}
}
