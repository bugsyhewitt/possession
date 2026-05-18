package flow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ─── Validate unit tests ──────────────────────────────────────────────

func TestValidate_Empty(t *testing.T) {
	fd := model.FlowDef{Name: "empty"}
	errs := Validate(fd)
	if len(errs) != 0 {
		t.Errorf("empty flow: unexpected errors: %v", errs)
	}
}

func TestValidate_DuplicateStepName(t *testing.T) {
	fd := model.FlowDef{
		Name: "dup",
		Steps: []model.FlowStep{
			{Name: "login"},
			{Name: "login"},
		},
	}
	errs := Validate(fd)
	if len(errs) == 0 {
		t.Error("expected error for duplicate step name")
	}
}

func TestValidate_UnresolvedReference(t *testing.T) {
	fd := model.FlowDef{
		Name: "bad-ref",
		Steps: []model.FlowStep{
			{
				Name: "step1",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    "/login",
					Body:   `{"csrf":"{csrf_token}"}`,
				},
			},
		},
	}
	errs := Validate(fd)
	found := false
	for _, e := range errs {
		if containsSubstr(e, "csrf_token") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unresolved reference error for {csrf_token}, got: %v", errs)
	}
}

func TestValidate_ValidMultiStep(t *testing.T) {
	fd := model.FlowDef{
		Name: "valid",
		Steps: []model.FlowStep{
			{
				Name:    "get-csrf",
				Request: &model.RawRequest{Method: "GET", URL: "/csrf"},
				Extract: []model.FlowExtraction{
					{Name: "csrf", From: "body-json", Expr: "$.token"},
				},
			},
			{
				Name: "login",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    "/login",
					Body:   `{"csrf":"{csrf}"}`,
				},
				Extract: []model.FlowExtraction{
					{Name: "session", From: "cookie", Expr: "session"},
				},
			},
		},
	}
	errs := Validate(fd)
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestValidate_CyclicDependency(t *testing.T) {
	// step1 extracts "x"; step2 references {x} but tries to re-extract "x" too.
	// Not truly a cycle in this impl, but referencing within the same step is.
	fd := model.FlowDef{
		Name: "self-ref",
		Steps: []model.FlowStep{
			{
				Name: "step1",
				Request: &model.RawRequest{
					Method: "GET",
					URL:    "/start/{x}",
				},
				Extract: []model.FlowExtraction{
					{Name: "x", From: "body-json", Expr: "$.x"},
				},
			},
		},
	}
	errs := Validate(fd)
	// step1 references {x} before extracting it → error
	if len(errs) == 0 {
		t.Error("expected error for self-reference within same step")
	}
}

// ─── Execute integration tests ────────────────────────────────────────

func TestExecute_SingleStep_Cookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-123"})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fd := model.FlowDef{
		Name: "login",
		Steps: []model.FlowStep{
			{
				Name: "do-login",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    "/login",
				},
				Extract: []model.FlowExtraction{
					{Name: "session", From: "cookie", Expr: "session"},
				},
			},
		},
	}
	result := Execute(context.Background(), &http.Client{}, srv.URL, fd, nil)
	if result.Err != nil {
		t.Fatalf("execute: %v", result.Err)
	}
	if result.Vars["session"] != "sess-123" {
		t.Errorf("session: want sess-123, got %q", result.Vars["session"])
	}
}

func TestExecute_MultiStep_Interpolation(t *testing.T) {
	var csrfSeen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/csrf" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"csrf-abc"}`))
			return
		}
		if r.URL.Path == "/login" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			csrfSeen, _ = body["csrf"].(string)
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-xyz"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	fd := model.FlowDef{
		Name: "full-login",
		Steps: []model.FlowStep{
			{
				Name:    "get-csrf",
				Request: &model.RawRequest{Method: "GET", URL: "/csrf"},
				Extract: []model.FlowExtraction{
					{Name: "csrf", From: "body-json", Expr: "$.token"},
				},
			},
			{
				Name: "login",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    "/login",
					Body:   `{"user":"alice","csrf":"{csrf}"}`,
				},
				Extract: []model.FlowExtraction{
					{Name: "session", From: "cookie", Expr: "session", Volatile: true},
				},
			},
		},
	}
	result := Execute(context.Background(), &http.Client{}, srv.URL, fd, nil)
	if result.Err != nil {
		t.Fatalf("execute: %v", result.Err)
	}
	if csrfSeen != "csrf-abc" {
		t.Errorf("csrf not interpolated: want csrf-abc, got %q", csrfSeen)
	}
	if result.Vars["session"] != "sess-xyz" {
		t.Errorf("session: want sess-xyz, got %q", result.Vars["session"])
	}
	if result.VolatileHead != 1 {
		t.Errorf("volatileHead: want 1 (step index of volatile extract), got %d", result.VolatileHead)
	}
}

func TestExecute_StepFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`)) // no token field
	}))
	defer srv.Close()

	fd := model.FlowDef{
		Name: "fail",
		Steps: []model.FlowStep{
			{
				Name:    "get-missing",
				Request: &model.RawRequest{Method: "GET", URL: "/"},
				Extract: []model.FlowExtraction{
					{Name: "x", From: "body-json", Expr: "$.missing_key"},
				},
			},
		},
	}
	result := Execute(context.Background(), &http.Client{}, srv.URL, fd, nil)
	if result.Err == nil {
		t.Error("expected error when extracting missing key")
	}
}

func TestExecuteFrom_VolatileRerun(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"nonce-` + string(rune('A'+callCount-1)) + `"}`))
	}))
	defer srv.Close()

	fd := model.FlowDef{
		Name: "volatile",
		Steps: []model.FlowStep{
			{
				Name:    "get-nonce",
				Request: &model.RawRequest{Method: "GET", URL: "/nonce"},
				Extract: []model.FlowExtraction{
					{Name: "nonce", From: "body-json", Expr: "$.nonce", Volatile: true},
				},
			},
		},
	}
	initialVars := map[string]string{"nonce": "old-nonce"}
	updated, err := ExecuteFrom(context.Background(), &http.Client{}, srv.URL, fd, initialVars, 0)
	if err != nil {
		t.Fatalf("ExecuteFrom: %v", err)
	}
	if updated["nonce"] == "old-nonce" {
		t.Error("volatile re-run should have updated nonce")
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstrInner(s, sub))
}

func containsSubstrInner(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
