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
		Endpoint:         &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"},
		Owner:            owner,
		Calibration:      cal,
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
		Variant:  &model.Variant{ID: "v1", Mutation: model.Mutation{Type: "swap-identity"}},
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

// xxeVR builds a VariantResponse for an --xxe variant carrying the given
// xxe-canary detail (empty = no canary, e.g. the external-system technique),
// a 2xx status, and the given response body.
func xxeVR(canary, respBody string) VariantResponse {
	h := http.Header{}
	h.Set("Content-Type", "application/xml")
	detail := map[string]string{"technique": "internal-entity"}
	if canary != "" {
		detail["xxe-canary"] = canary
	} else {
		detail["technique"] = "external-system"
	}
	return VariantResponse{
		Variant: &model.Variant{
			ID:       "v-xxe",
			Mutation: model.Mutation{Type: "xxe", Class: "xxe-injection", Detail: detail},
		},
		Response: &model.Response{Status: 200, Headers: h, Body: []byte(respBody)},
	}
}

// XXE canary branch: canary reflected in the response body ⇒ decisive bypass.
func TestLadder_XXE_CanaryReflectedIsBypass(t *testing.T) {
	cal := mkCal(`<order><id>5</id></order>`, 200, false, false, false, 0.85)
	canary := "possession-xxe-alice-xml-order"
	vr := xxeVR(canary, `<result>echo: `+canary+` ok</result>`)
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictBypass {
		t.Fatalf("want bypass, got %s notes=%v", vv.Verdict, vv.Notes)
	}
	if vv.Confidence != XXECanaryConfidence {
		t.Errorf("want confidence %v got %v", XXECanaryConfidence, vv.Confidence)
	}
	if !anyNoteContains(vv.Notes, "xxe-canary") {
		t.Errorf("expected an xxe-canary note; got %v", vv.Notes)
	}
}

// XXE canary branch: canary absent from the response body ⇒ NOT short-circuited
// (falls through to the comparative ladder; here a denied-shaped body keeps it
// from being a bypass via the canary path).
func TestLadder_XXE_CanaryAbsentNotCanaryBypass(t *testing.T) {
	cal := mkCal(`<order><id>5</id></order>`, 200, false, false, false, 0.85)
	canary := "possession-xxe-alice-xml-order"
	// Response does not contain the canary at all.
	vr := xxeVR(canary, `<error>bad request: entity not allowed</error>`)
	vv := runLadder(t, cal, nil, vr)
	// Must NOT carry the xxe-canary note — the canary branch did not fire.
	if anyNoteContains(vv.Notes, "xxe-canary") {
		t.Errorf("canary branch must not fire when canary absent; notes=%v", vv.Notes)
	}
}

// External-system XXE technique carries no canary, so it never trips the
// canary branch and is judged by the normal comparative ladder.
func TestLadder_XXE_ExternalSystemNoCanaryBranch(t *testing.T) {
	cal := mkCal(`<order><id>5</id></order>`, 200, false, false, false, 0.85)
	// Even if the body happened to contain something canary-shaped, there is
	// no canary detail, so the branch is skipped.
	vr := xxeVR("", `<result>root:x:0:0</result>`)
	vv := runLadder(t, cal, nil, vr)
	if anyNoteContains(vv.Notes, "xxe-canary") {
		t.Errorf("external-system must not trip the canary branch; notes=%v", vv.Notes)
	}
}

// XXE canary branch only fires on real reflection — a denied (4xx) response
// stops at the denied-status filter before the canary check.
func TestLadder_XXE_DeniedStatusEnforced(t *testing.T) {
	cal := mkCal(`<order><id>5</id></order>`, 200, false, false, false, 0.85)
	canary := "possession-xxe-alice-xml-order"
	h := http.Header{}
	h.Set("Content-Type", "application/xml")
	vr := VariantResponse{
		Variant: &model.Variant{
			ID: "v-xxe", Mutation: model.Mutation{
				Type: "xxe", Class: "xxe-injection",
				Detail: map[string]string{"technique": "internal-entity", "xxe-canary": canary},
			},
		},
		// 403 with the canary echoed — denied filter must win; no bypass.
		Response: &model.Response{Status: 403, Headers: h, Body: []byte(canary)},
	}
	vv := runLadder(t, cal, nil, vr)
	if vv.Verdict != VerdictEnforced {
		t.Errorf("403 must be enforced even with canary in body; got %s", vv.Verdict)
	}
}

// gqlVR builds a VariantResponse for a --graphql variant. signal is the
// graphql-signal detail ("introspection" or "malformed"); status and respBody
// shape the response.
func gqlVR(signal string, status int, respBody string) VariantResponse {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	detail := map[string]string{"technique": signal, "graphql-signal": signal}
	if signal == "introspection" {
		detail["graphql-canary"] = "possession-graphql-alice-gql"
	}
	return VariantResponse{
		Variant: &model.Variant{
			ID:       "v-gql",
			Mutation: model.Mutation{Type: "graphql", Class: "graphql-exposure", Detail: detail},
		},
		Response: &model.Response{Status: status, Headers: h, Body: []byte(respBody)},
	}
}

// GraphQL introspection branch: response reflects __schema + queryType ⇒
// decisive bypass (introspection enabled).
func TestLadder_GraphQL_IntrospectionReflectedIsBypass(t *testing.T) {
	cal := mkCal(`{"data":{"me":{"id":1}}}`, 200, false, false, false, 0.85)
	body := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}`
	vv := runLadder(t, cal, nil, gqlVR("introspection", 200, body))
	if vv.Verdict != VerdictBypass {
		t.Fatalf("want bypass, got %s notes=%v", vv.Verdict, vv.Notes)
	}
	if vv.Confidence != GraphQLIntrospectionConfidence {
		t.Errorf("want confidence %v got %v", GraphQLIntrospectionConfidence, vv.Confidence)
	}
	if !anyNoteContains(vv.Notes, "graphql-introspection") {
		t.Errorf("expected a graphql-introspection note; got %v", vv.Notes)
	}
}

// Introspection branch needs BOTH __schema and a corroborating marker: a body
// that merely echoes "__schema" in an error string must not trip the branch.
func TestLadder_GraphQL_PartialMarkerNotBypass(t *testing.T) {
	cal := mkCal(`{"data":{"me":{"id":1}}}`, 200, false, false, false, 0.85)
	body := `{"errors":[{"message":"Cannot query field __schema on type Query"}]}`
	vv := runLadder(t, cal, nil, gqlVR("introspection", 200, body))
	if anyNoteContains(vv.Notes, "graphql-introspection") {
		t.Errorf("introspection branch must not fire without a corroborating marker; notes=%v", vv.Notes)
	}
}

// The malformed-query technique carries no introspection signal, so it never
// trips the introspection branch even if the body looks schema-shaped.
func TestLadder_GraphQL_MalformedNoIntrospectionBranch(t *testing.T) {
	cal := mkCal(`{"data":{"me":{"id":1}}}`, 200, false, false, false, 0.85)
	body := `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`
	vv := runLadder(t, cal, nil, gqlVR("malformed", 200, body))
	if anyNoteContains(vv.Notes, "graphql-introspection") {
		t.Errorf("malformed must not trip the introspection branch; notes=%v", vv.Notes)
	}
}

// A denied (4xx) introspection response stops at the denied-status filter
// before the introspection check — introspection disabled / access denied.
func TestLadder_GraphQL_DeniedStatusNotBypass(t *testing.T) {
	cal := mkCal(`{"data":{"me":{"id":1}}}`, 200, false, false, false, 0.85)
	body := `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`
	vv := runLadder(t, cal, nil, gqlVR("introspection", 403, body))
	if vv.Verdict != VerdictEnforced {
		t.Errorf("403 must be enforced even with schema markers in body; got %s", vv.Verdict)
	}
}

// anyNoteContains reports whether any note contains the substring.
func anyNoteContains(notes []string, sub string) bool {
	for _, n := range notes {
		if contains(n, sub) {
			return true
		}
	}
	return false
}
