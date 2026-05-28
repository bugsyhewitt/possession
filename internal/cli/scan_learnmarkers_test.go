package cli

import (
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/replay"
)

// TestScanLearnMarkers_FlagParseOK verifies that --learn-markers is accepted
// by the scan command (dry-run path, no network).
func TestScanLearnMarkers_FlagParseOK(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--dry-run",
		"--learn-markers",
	)
	if err != nil {
		t.Fatalf("--learn-markers should parse without error: %v", err)
	}
}

// TestLearnMarkers_AugmentsAllIdentityPointers verifies the integration glue:
// learnMarkers must augment the same learned markers across the matrix
// identity, the endpoint OwnerIdentity, and the plan variant identity — which
// are distinct pointers (AttributeOwner copies the matrix) — and must preserve
// any operator-supplied markers.
func TestLearnMarkers_AugmentsAllIdentityPointers(t *testing.T) {
	// alice's baseline body carries a unique, stable email; bob's a different
	// one. The shared "API_VERSION_v2x" token must NOT be learned (not unique).
	aliceMatrix := &model.Identity{Name: "alice", Markers: []string{"hand-entered"}}
	bobMatrix := &model.Identity{Name: "bob"}
	matrix := &model.RoleMatrix{Identities: []model.Identity{*aliceMatrix, *bobMatrix}}

	// Distinct owner/variant pointers, mimicking AttributeOwner's copy.
	aliceOwner := &model.Identity{Name: "alice", Markers: []string{"hand-entered"}}
	bobOwner := &model.Identity{Name: "bob"}
	ep := &model.Endpoint{OwnerIdentity: aliceOwner}
	ep2 := &model.Endpoint{OwnerIdentity: bobOwner}

	aliceVariant := &model.Identity{Name: "alice"}
	plan := replay.Plan{Variants: []model.Variant{{Identity: aliceVariant}}}

	baselinePlan := replay.Plan{Variants: []model.Variant{
		{Identity: &model.Identity{Name: "alice"}},
		{Identity: &model.Identity{Name: "alice"}},
		{Identity: &model.Identity{Name: "bob"}},
		{Identity: &model.Identity{Name: "bob"}},
	}}
	baselineResponses := []model.Response{
		{Body: []byte(`{"email":"alice@example.com","v":"API_VERSION_v2x"}`)},
		{Body: []byte(`{"email":"alice@example.com","v":"API_VERSION_v2x"}`)},
		{Body: []byte(`{"email":"bob@example.com","v":"API_VERSION_v2x"}`)},
		{Body: []byte(`{"email":"bob@example.com","v":"API_VERSION_v2x"}`)},
	}

	total, summary := learnMarkers(baselinePlan, baselineResponses, matrix,
		[]*model.Endpoint{ep, ep2}, plan)

	if total != 2 {
		t.Fatalf("expected 2 markers learned (alice+bob email), got %d (%v)", total, summary)
	}

	// Operator marker preserved, learned email appended — on the OWNER pointer.
	if !markerSet(aliceOwner.Markers)["hand-entered"] {
		t.Errorf("operator marker dropped on owner: %v", aliceOwner.Markers)
	}
	if !markerSet(aliceOwner.Markers)["alice@example.com"] {
		t.Errorf("learned email not applied to owner: %v", aliceOwner.Markers)
	}
	// Variant pointer (distinct) also augmented.
	if !markerSet(aliceVariant.Markers)["alice@example.com"] {
		t.Errorf("learned email not applied to variant identity: %v", aliceVariant.Markers)
	}
	// Matrix identity augmented.
	if !markerSet(matrix.Identities[0].Markers)["alice@example.com"] {
		t.Errorf("learned email not applied to matrix identity: %v", matrix.Identities[0].Markers)
	}
	// bob's owner gets his unique email.
	if !markerSet(bobOwner.Markers)["bob@example.com"] {
		t.Errorf("learned email not applied to bob owner: %v", bobOwner.Markers)
	}
	// Shared token must never be learned.
	for _, id := range []*model.Identity{aliceOwner, bobOwner, aliceVariant} {
		if markerSet(id.Markers)["API_VERSION_v2x"] {
			t.Errorf("shared token wrongly learned for %s: %v", id.Name, id.Markers)
		}
	}
}

// TestLearnMarkers_NoUniqueMarkers verifies that when no unique/stable markers
// exist, nothing is learned and no markers are added.
func TestLearnMarkers_NoUniqueMarkers(t *testing.T) {
	matrix := &model.RoleMatrix{Identities: []model.Identity{{Name: "alice"}, {Name: "bob"}}}
	baselinePlan := replay.Plan{Variants: []model.Variant{
		{Identity: &model.Identity{Name: "alice"}},
		{Identity: &model.Identity{Name: "bob"}},
	}}
	// Both identities share the only candidate token ⇒ not unique ⇒ nothing.
	baselineResponses := []model.Response{
		{Body: []byte(`{"shared":"SHARED_TOKEN_1234"}`)},
		{Body: []byte(`{"shared":"SHARED_TOKEN_1234"}`)},
	}
	total, summary := learnMarkers(baselinePlan, baselineResponses, matrix, nil, replay.Plan{})
	if total != 0 || summary != nil {
		t.Fatalf("expected no markers learned, got total=%d summary=%v", total, summary)
	}
}

func markerSet(ms []string) map[string]bool {
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		out[m] = true
	}
	return out
}
