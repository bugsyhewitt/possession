package detect

import (
	"reflect"
	"testing"
)

func TestExtractCandidateTokens_Email(t *testing.T) {
	body := []byte(`{"email":"alice@example.com","name":"Alice"}`)
	got := ExtractCandidateTokens(body)
	if !sliceHas(got, "alice@example.com") {
		t.Fatalf("expected email token, got %v", got)
	}
}

func TestExtractCandidateTokens_UUID(t *testing.T) {
	body := []byte(`{"id":"550e8400-e29b-41d4-a716-446655440000"}`)
	got := ExtractCandidateTokens(body)
	if !sliceHas(got, "550e8400-e29b-41d4-a716-446655440000") {
		t.Fatalf("expected uuid token, got %v", got)
	}
}

func TestExtractCandidateTokens_LongDigits(t *testing.T) {
	body := []byte(`{"account":1002934, "port":8080, "year":2026}`)
	got := ExtractCandidateTokens(body)
	if !sliceHas(got, "1002934") {
		t.Fatalf("expected long digit token, got %v", got)
	}
	// 8080 and 2026 are 4 digits ⇒ below the 5-digit floor ⇒ rejected.
	if sliceHas(got, "8080") || sliceHas(got, "2026") {
		t.Fatalf("short digit runs should be rejected, got %v", got)
	}
}

func TestExtractCandidateTokens_AccountIDShape(t *testing.T) {
	body := []byte(`{"ref":"ACME_SECRET_DATA_9f3b"}`)
	got := ExtractCandidateTokens(body)
	if !sliceHas(got, "ACME_SECRET_DATA_9f3b") {
		t.Fatalf("expected account-id-shaped token, got %v", got)
	}
}

func TestExtractCandidateTokens_RejectsProseWords(t *testing.T) {
	// Pure-letter words must not be admitted as account-id tokens.
	body := []byte(`the quick brown account holder requested access permissions`)
	got := ExtractCandidateTokens(body)
	for _, w := range []string{"quick", "brown", "account", "holder", "requested", "access", "permissions"} {
		if sliceHas(got, w) {
			t.Fatalf("prose word %q should not be a candidate token, got %v", w, got)
		}
	}
}

func TestExtractCandidateTokens_Empty(t *testing.T) {
	if got := ExtractCandidateTokens(nil); got != nil {
		t.Fatalf("nil body should yield no tokens, got %v", got)
	}
	if got := ExtractCandidateTokens([]byte("")); got != nil {
		t.Fatalf("empty body should yield no tokens, got %v", got)
	}
}

func TestExtractCandidateTokens_Deterministic(t *testing.T) {
	body := []byte(`{"a":"zoe@example.com","b":"alice@example.com"}`)
	g1 := ExtractCandidateTokens(body)
	g2 := ExtractCandidateTokens(body)
	if !reflect.DeepEqual(g1, g2) {
		t.Fatalf("extraction not deterministic: %v vs %v", g1, g2)
	}
	// Sorted: alice before zoe.
	if len(g1) != 2 || g1[0] != "alice@example.com" || g1[1] != "zoe@example.com" {
		t.Fatalf("expected sorted [alice, zoe], got %v", g1)
	}
}

func TestHarvestMarkers_UniqueAndStable(t *testing.T) {
	in := map[string][][]byte{
		"alice": {
			[]byte(`{"email":"alice@example.com","ts":1}`),
			[]byte(`{"email":"alice@example.com","ts":2}`),
		},
		"bob": {
			[]byte(`{"email":"bob@example.com","ts":1}`),
			[]byte(`{"email":"bob@example.com","ts":2}`),
		},
	}
	got := HarvestMarkers(in)
	if !reflect.DeepEqual(got["alice"], []string{"alice@example.com"}) {
		t.Fatalf("alice markers: got %v", got["alice"])
	}
	if !reflect.DeepEqual(got["bob"], []string{"bob@example.com"}) {
		t.Fatalf("bob markers: got %v", got["bob"])
	}
}

func TestHarvestMarkers_RejectsShared(t *testing.T) {
	// A token present for BOTH identities is not unique ⇒ rejected.
	in := map[string][][]byte{
		"alice": {[]byte(`{"app":"COMMON_TOKEN_123","me":"alice@example.com"}`)},
		"bob":   {[]byte(`{"app":"COMMON_TOKEN_123","me":"bob@example.com"}`)},
	}
	got := HarvestMarkers(in)
	if sliceHas(got["alice"], "COMMON_TOKEN_123") || sliceHas(got["bob"], "COMMON_TOKEN_123") {
		t.Fatalf("shared token should be rejected, got %v", got)
	}
	if !sliceHas(got["alice"], "alice@example.com") {
		t.Fatalf("alice unique email should survive, got %v", got["alice"])
	}
}

func TestHarvestMarkers_RejectsUnstable(t *testing.T) {
	// A token that appears in only one of an identity's two bodies is not
	// stable ⇒ rejected. The email is in both ⇒ kept.
	in := map[string][][]byte{
		"alice": {
			[]byte(`{"email":"alice@example.com","nonce":"abcde12345xyz"}`),
			[]byte(`{"email":"alice@example.com","nonce":"zzzzz99999www"}`),
		},
	}
	got := HarvestMarkers(in)
	if sliceHas(got["alice"], "abcde12345xyz") || sliceHas(got["alice"], "zzzzz99999www") {
		t.Fatalf("unstable per-request nonce should be rejected, got %v", got)
	}
	if !sliceHas(got["alice"], "alice@example.com") {
		t.Fatalf("stable email should survive, got %v", got["alice"])
	}
}

func TestHarvestMarkers_Empty(t *testing.T) {
	if got := HarvestMarkers(nil); got != nil {
		t.Fatalf("nil input ⇒ nil, got %v", got)
	}
	if got := HarvestMarkers(map[string][][]byte{}); got != nil {
		t.Fatalf("empty input ⇒ nil, got %v", got)
	}
	// Identity with no bodies ⇒ no markers.
	if got := HarvestMarkers(map[string][][]byte{"alice": {}}); got != nil {
		t.Fatalf("identity with no bodies ⇒ nil, got %v", got)
	}
}

func TestMergeMarkers_PreservesOperatorMarkers(t *testing.T) {
	existing := []string{"hand-entered-1", "hand-entered-2"}
	learned := []string{"learned-b", "learned-a", "hand-entered-1"}
	merged, added := MergeMarkers(existing, learned)
	// Operator markers come first, in original order.
	if merged[0] != "hand-entered-1" || merged[1] != "hand-entered-2" {
		t.Fatalf("operator markers not preserved first: %v", merged)
	}
	// Learned markers appended, sorted, de-duplicated against existing.
	if !reflect.DeepEqual(merged[2:], []string{"learned-a", "learned-b"}) {
		t.Fatalf("learned markers not appended sorted/deduped: %v", merged)
	}
	if added != 2 {
		t.Fatalf("expected 2 added (dup not counted), got %d", added)
	}
}

func TestMergeMarkers_NoExisting(t *testing.T) {
	merged, added := MergeMarkers(nil, []string{"x-token", "a-token"})
	if !reflect.DeepEqual(merged, []string{"a-token", "x-token"}) {
		t.Fatalf("expected sorted learned, got %v", merged)
	}
	if added != 2 {
		t.Fatalf("expected 2 added, got %d", added)
	}
}

func TestMergeMarkers_IgnoresEmptyLearned(t *testing.T) {
	merged, added := MergeMarkers([]string{"keep"}, []string{"", "real"})
	if added != 1 {
		t.Fatalf("empty string should not be added, added=%d merged=%v", added, merged)
	}
	if !sliceHas(merged, "keep") || !sliceHas(merged, "real") {
		t.Fatalf("merge lost a marker: %v", merged)
	}
}

func sliceHas(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
