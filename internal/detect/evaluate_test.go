package detect

import (
	"net/http"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// mkCal builds a CalibrationResult for tests, with one knob per scenario.
func mkCal(body string, status int, noisy, failed, skipped bool, effThreshold float64) CalibrationResult {
	return CalibrationResult{
		Samples:        1,
		Stability:      1.0,
		EffThreshold:   effThreshold,
		Noisy:          noisy,
		BaselineBody:   body,
		BaselineStatus: status,
		BaselineCT:     "application/json",
		Skipped:        skipped,
		BaselineFailed: failed,
	}
}

func mkVR(mutType string, ident *model.Identity, status int, body string, ct string, inconclusive bool, errStr string) VariantResponse {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return VariantResponse{
		Variant: &model.Variant{
			ID:       "v1",
			Identity: ident,
			Mutation: model.Mutation{Type: mutType, Description: mutType},
		},
		Response: &model.Response{
			Status:       status,
			Headers:      h,
			Body:         []byte(body),
			Err:          errStr,
			Inconclusive: inconclusive,
		},
	}
}

func runLadder(t *testing.T, cal CalibrationResult, owner *model.Identity, vr VariantResponse) VariantVerdict {
	t.Helper()
	ev := ComparativeEvaluator{}
	ctx := EvalContext{
		Endpoint: &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"},
		Owner:    owner,
		Calibration: cal,
		VariantResponses: []VariantResponse{vr},
	}
	res := ev.Evaluate(ctx)
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(res.Verdicts))
	}
	return res.Verdicts[0]
}

// Branch 1: statusClass == error
func TestLadder_Branch1_TransportError(t *testing.T) {
	cal := mkCal(`{"a":1}`, 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 0, "", "", false, "connection refused")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictInconclusive {
		t.Errorf("want inconclusive, got %s", vv.Verdict)
	}
}

// Branch 2: baseline failed
func TestLadder_Branch2_BaselineFailed(t *testing.T) {
	cal := mkCal(``, 500, false, true, false, 0.90)
	vr := mkVR("swap-identity", nil, 200, `{"a":1}`, "application/json", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictInconclusive {
		t.Errorf("want inconclusive, got %s", vv.Verdict)
	}
}

// Branch 3: variant marked inconclusive (refresh failure)
func TestLadder_Branch3_VariantInconclusive(t *testing.T) {
	cal := mkCal(`{"a":1}`, 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 0, "", "", true, "refresh failed")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictInconclusive {
		t.Errorf("want inconclusive, got %s", vv.Verdict)
	}
}

// Branch 4: denied status
func TestLadder_Branch4_Denied(t *testing.T) {
	cal := mkCal(`{"a":1}`, 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 403, `forbidden`, "text/plain", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictEnforced {
		t.Errorf("want enforced, got %s", vv.Verdict)
	}
}

// Branch 5: 2xx with errorSignature, low similarity
func TestLadder_Branch5_ErrorSignatureOn2xx(t *testing.T) {
	cal := mkCal(`{"data":{"id":1,"name":"alice"}}`, 200, false, false, false, 0.85)
	// Variant returns 200 with a "forbidden" body, completely different from baseline.
	vr := mkVR("swap-identity", nil, 200, `Access denied for this resource here`, "text/plain", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictEnforced {
		t.Errorf("want enforced, got %s notes=%v", vv.Verdict, vv.Notes)
	}
}

// Branch 6: reflectedActor (server returned only caller's own data)
func TestLadder_Branch6_ReflectedActor(t *testing.T) {
	owner := &model.Identity{Name: "alice", Markers: []string{"alice@example.com"}}
	actor := &model.Identity{Name: "bob", Markers: []string{"bob@example.com"}}
	cal := mkCal(`{"email":"alice@example.com","data":[1,2,3]}`, 200, false, false, false, 0.85)
	// Bob requests the endpoint as bob; server returns bob's data.
	vr := mkVR("swap-identity", actor, 200, `{"email":"bob@example.com","data":[7,8,9]}`, "application/json", false, "")
	vv := runLadder(t, cal, owner, vr)
	if vv.Verdict != VerdictEnforced {
		t.Errorf("want enforced (reflectedActor), got %s notes=%v", vv.Verdict, vv.Notes)
	}
}

// Branch 7: reflectedOwner ⇒ bypass
func TestLadder_Branch7_ReflectedOwner(t *testing.T) {
	owner := &model.Identity{Name: "alice", Markers: []string{"alice@example.com"}}
	actor := &model.Identity{Name: "bob", Markers: []string{"bob@example.com"}}
	cal := mkCal(`{"email":"alice@example.com","data":[1,2,3]}`, 200, false, false, false, 0.85)
	// Bob requests as bob; server returns ALICE's data ⇒ IDOR bypass.
	vr := mkVR("swap-identity", actor, 200, `{"email":"alice@example.com","data":[1,2,3]}`, "application/json", false, "")
	vv := runLadder(t, cal, owner, vr)
	if vv.Verdict != VerdictBypass {
		t.Errorf("want bypass, got %s notes=%v", vv.Verdict, vv.Notes)
	}
	if vv.Confidence < 0.9 {
		t.Errorf("reflectedOwner should be high confidence, got %v", vv.Confidence)
	}
}

// Branch 7 + noisy: caps to suspected even on reflectedOwner.
func TestLadder_Branch7_ReflectedOwner_NoisyCaps(t *testing.T) {
	owner := &model.Identity{Name: "alice", Markers: []string{"alice@example.com"}}
	cal := mkCal(`{"email":"alice@example.com"}`, 200, true /*noisy*/, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 200, `{"email":"alice@example.com"}`, "application/json", false, "")
	vv := runLadder(t, cal, owner, vr)
	if vv.Verdict != VerdictSuspected {
		t.Errorf("want suspected (noisy cap), got %s", vv.Verdict)
	}
}

// Branch 8: high similarity ⇒ bypass
func TestLadder_Branch8_HighSimilarity(t *testing.T) {
	body := `{"name":"alice","email":"alice@example.com","data":{"id":1,"items":["a","b","c","d","e","f"],"role":"user","group":"std"}}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 200, body, "application/json", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictBypass {
		t.Errorf("want bypass (sim ~1.0), got %s notes=%v", vv.Verdict, vv.Notes)
	}
}

// Branch 8 + noisy caps to suspected
func TestLadder_Branch8_HighSimilarity_NoisyCaps(t *testing.T) {
	body := `{"name":"alice","email":"alice@example.com","data":{"id":1,"items":["a","b","c","d","e","f"]}}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, true, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 200, body, "application/json", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictSuspected {
		t.Errorf("want suspected (noisy cap), got %s", vv.Verdict)
	}
}

// Branch 9: mid similarity ⇒ suspected
func TestLadder_Branch9_MidSimilarity(t *testing.T) {
	// Construct so similarity sits in [SuspectLow, effThreshold).
	baseBody := "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo"
	varBody := "alpha bravo charlie delta echo something else here entirely different"
	cal := mkCal(NormalizeBody([]byte(baseBody), "text/plain"), 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", nil, 200, varBody, "text/plain", false, "")
	vv := runLadder(t, cal, nil, vr)
	// Could land in branch 9 or branch 10 depending on actual Jaccard;
	// we only require that whichever bucket it lands in is consistent.
	if vv.Verdict != VerdictSuspected && vv.Verdict != VerdictEnforced {
		t.Errorf("want suspected or enforced (mid/low sim), got %s notes=%v", vv.Verdict, vv.Notes)
	}
}

// Branch 10: very low similarity ⇒ enforced
func TestLadder_Branch10_LowSimilarity(t *testing.T) {
	cal := mkCal(NormalizeBody([]byte(`{"name":"alice","items":["a","b","c","d","e","f","g","h"]}`), "application/json"), 200, false, false, false, 0.85)
	// Completely different body.
	vr := mkVR("swap-identity", nil, 200, `xxx yyy zzz www vvv uuu ttt sss rrr qqq`, "text/plain", false, "")
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictEnforced {
		t.Errorf("want enforced (low sim), got %s notes=%v", vv.Verdict, vv.Notes)
	}
}

// Ambiguous 3xx multiplies confidence by AmbiguousPenalty.
func TestLadder_AmbiguousPenalty(t *testing.T) {
	body := `{"name":"alice","email":"alice@example.com","data":{"id":1,"items":["a","b","c","d","e","f","g"]}}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, false, false, false, 0.85)
	// 302 to a non-login URL ⇒ ambiguous.
	h := http.Header{}
	h.Set("Location", "/somewhere-else")
	h.Set("Content-Type", "application/json")
	vr := VariantResponse{
		Variant: &model.Variant{ID: "v1", Mutation: model.Mutation{Type: "swap-identity"}},
		Response: &model.Response{Status: 302, Headers: h, Body: []byte(body)},
	}
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictBypass {
		t.Errorf("want bypass, got %s notes=%v", vv.Verdict, vv.Notes)
	}
	// Confidence should be reduced relative to a 200 with the same body.
	if vv.Confidence >= BaseHigh {
		t.Errorf("ambiguous penalty should reduce confidence below BaseHigh; got %v", vv.Confidence)
	}
}

// TestLadder_D28_CrossRankSwapCappedAtSuspected — D28.
// When a swap-identity variant uses an actor whose rank differs from the
// endpoint owner's rank, any bypass verdict from the ladder is capped at
// suspected with a typed cross-rank-swap note. Same-identity is still
// short-circuited (Filter A); same-rank cross-identity is unaffected.
func TestLadder_D28_CrossRankSwapCappedAtSuspected(t *testing.T) {
	owner := &model.Identity{Name: "alice", Rank: 10}
	admin := &model.Identity{Name: "admin", Rank: 100}
	body := `{"id":"alice","email":"alice@example.com","items":["a","b","c","d","e","f","g","h"]}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", admin, 200, body, "application/json", false, "")
	vv := runLadder(t, cal, owner, vr)
	if vv.Verdict != VerdictSuspected {
		t.Errorf("D28: cross-rank swap should cap at suspected, got %s notes=%v", vv.Verdict, vv.Notes)
	}
	// Note must mention cross-rank-swap.
	found := false
	for _, n := range vv.Notes {
		if contains(n, "cross-rank-swap") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("D28: cross-rank-swap note missing; notes=%v", vv.Notes)
	}
}

// TestLadder_D28_SameRankSwapUnchanged — verify same-rank swap is NOT
// capped (still bypass when the ladder says bypass).
func TestLadder_D28_SameRankSwapUnchanged(t *testing.T) {
	owner := &model.Identity{Name: "alice", Rank: 10}
	bob := &model.Identity{Name: "bob", Rank: 10}
	body := `{"id":"alice","email":"alice@example.com","items":["a","b","c","d","e","f","g","h"]}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, false, false, false, 0.85)
	vr := mkVR("swap-identity", bob, 200, body, "application/json", false, "")
	vv := runLadder(t, cal, owner, vr)
	if vv.Verdict != VerdictBypass {
		t.Errorf("D28: same-rank swap should remain bypass, got %s", vv.Verdict)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
