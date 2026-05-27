package config

import (
	"strings"
	"testing"
)

func TestLoadExampleYAML(t *testing.T) {
	m, err := LoadFile("../../testdata/matrix/example.yaml")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if m.Version != "1" {
		t.Errorf("version = %q", m.Version)
	}
	if len(m.Identities) != 4 {
		t.Fatalf("identities = %d, want 4", len(m.Identities))
	}
	if m.Identities[0].Name != "anon" || m.Identities[0].Creds != nil {
		t.Errorf("anon identity malformed: %+v", m.Identities[0])
	}
	admin := m.Identities[3]
	if admin.Name != "admin" || admin.Creds.Basic == nil ||
		admin.Refresh == nil || len(admin.Refresh.Extract) != 1 {
		t.Errorf("admin identity malformed: %+v", admin)
	}
	if m.Settings.Timeout.Seconds() != 15 {
		t.Errorf("timeout = %v", m.Settings.Timeout)
	}
}

func TestLoadResourcesField(t *testing.T) {
	const y = `
version: "1"
target:
  base_url: https://api.example.test
identities:
  - name: alice
    role: user
    rank: 10
    creds:
      bearer: alice-token
    resources:
      user_id: "1001"
      order_id: "5523"
  - name: bob
    role: user
    rank: 10
    creds:
      bearer: bob-token
    resources:
      user_id: "2002"
      order_id: "6634"
settings:
  rate_per_host: 1.0
  concurrency: 1
  timeout: 15s
`
	m, err := Load(strings.NewReader(y))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Identities) != 2 {
		t.Fatalf("identities = %d, want 2", len(m.Identities))
	}
	alice := m.Identities[0]
	if alice.Resources["user_id"] != "1001" || alice.Resources["order_id"] != "5523" {
		t.Errorf("alice resources malformed: %+v", alice.Resources)
	}
	bob := m.Identities[1]
	if bob.Resources["user_id"] != "2002" {
		t.Errorf("bob resources malformed: %+v", bob.Resources)
	}
}

func TestLoadInvalidYAMLReportsBothProblems(t *testing.T) {
	_, err := LoadFile("../../testdata/matrix/invalid.yaml")
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "duplicates identities[0].name") {
		t.Errorf("missing duplicate-name error in %q", msg)
	}
	if !strings.Contains(msg, "from must be one of") {
		t.Errorf("missing bad-enum error in %q", msg)
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"/api/**", "/api/users/1", true},
		{"/api/**", "/other", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/1", false},
		{"**/*.js", "/static/app.js", true},
		{"**/*.js", "/api/users.json", false},
		{"/api/health", "/api/health", true},
		{"/api/?", "/api/x", true},
		{"/api/?", "/api/xy", false},
	}
	for _, tc := range cases {
		got := MatchGlob(tc.pat, tc.path)
		if got != tc.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pat, tc.path, got, tc.want)
		}
	}
}
