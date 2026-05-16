package normalize

import "testing"

func TestIsIdentifierSegment(t *testing.T) {
	cases := []struct {
		name string
		seg  string
		want bool
	}{
		{"empty", "", false},
		{"all-digits", "8821", true},
		{"single-digit", "0", true},
		{"uuid-lower", "3f1c2d4e-5678-90ab-cdef-1234567890ab", true},
		{"uuid-upper", "3F1C2D4E-5678-90AB-CDEF-1234567890AB", true},
		{"uuid-malformed", "3f1c2d4e567890abcdef1234567890ab", true /* falls into mongoid or long-hex */},
		{"mongoid", "507f1f77bcf86cd799439011", true},
		{"hex16", "deadbeefcafebabe", true},
		{"hex15", "deadbeefcafebab", false},
		{"base64url-mixed-case", "AbCdEfGhIjKlMnOpQrSt", true},
		{"base64url-with-digit", "abcdefghij0123456789", true},
		{"base64url-pure-lower-long", "internationalization", false},
		{"dictionary", "users", false},
		{"dictionary-orders", "orders", false},
		{"profile", "profile", false},
		{"short-numeric-mixed", "v1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIdentifierSegment(tc.seg)
			if got != tc.want {
				t.Fatalf("IsIdentifierSegment(%q) = %v, want %v", tc.seg, got, tc.want)
			}
		})
	}
}

func TestTemplatePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/", "/"},
		{"/api/users", "/api/users"},
		{"/api/users/8821", "/api/users/{id}"},
		{"/api/users/8821/orders/3f1c2d4e-5678-90ab-cdef-1234567890ab",
			"/api/users/{id}/orders/{id}"},
		{"/api/users/8821/", "/api/users/{id}/"},
		{"api/users/8821", "api/users/{id}"},
		{"/api//users/8821", "/api//users/{id}"},
		{"/health", "/health"},
		{"/v1/profile", "/v1/profile"},
		{"/files/507f1f77bcf86cd799439011/raw", "/files/{id}/raw"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := TemplatePath(tc.in)
			if got != tc.want {
				t.Fatalf("TemplatePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
