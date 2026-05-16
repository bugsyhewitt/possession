package parse

import (
	"strings"
	"testing"
)

func TestCurlSampleFixture(t *testing.T) {
	f, err := openFixture("../../testdata/curl/sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	req, err := Curl(f)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL.Host != "api.example.com" || req.URL.Path != "/api/users/42/orders" {
		t.Errorf("url = %s", req.URL)
	}
	if req.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type header missing: %v", req.Headers)
	}
	if req.Headers.Get("X-Api-Key") != "alice-key-xyz" {
		t.Errorf("X-Api-Key header missing: %v", req.Headers)
	}
	if got := string(req.Body); got != `{"sku":"widget","qty":2}` {
		t.Errorf("body = %q", got)
	}
	if len(req.Cookies) != 1 || req.Cookies[0].Name != "session" {
		t.Errorf("cookies = %+v", req.Cookies)
	}
	if req.Source != "curl" {
		t.Errorf("source = %q", req.Source)
	}
}

func TestCurlDefaultsToGETWithoutBody(t *testing.T) {
	req, err := parseCurl(`curl https://api.example.com/api/profile`)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("method = %q", req.Method)
	}
}

func TestCurlDefaultsToPOSTWithData(t *testing.T) {
	req, err := parseCurl(`curl https://api.example.com/api/x --data 'a=1'`)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q", req.Method)
	}
	if string(req.Body) != "a=1" {
		t.Errorf("body = %q", string(req.Body))
	}
}

func TestCurlBasicAuth(t *testing.T) {
	req, err := parseCurl(`curl -u admin:hunter2 https://api.example.com/api/x`)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	auth := req.Headers.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestCurlUnknownFlagIgnored(t *testing.T) {
	// --bogus-flag should be ignored with a warning; parse still succeeds.
	req, err := parseCurl(`curl --bogus-flag https://api.example.com/api/x`)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	if req.URL.Path != "/api/x" {
		t.Errorf("url = %s", req.URL)
	}
}

func TestCurlLineContinuation(t *testing.T) {
	in := "curl -X POST \\\n  -H 'X-Foo: bar' \\\n  https://api.example.com/api/x"
	req, err := parseCurl(in)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	if req.URL.Path != "/api/x" {
		t.Errorf("url = %s", req.URL)
	}
	if req.Headers.Get("X-Foo") != "bar" {
		t.Errorf("header missing: %v", req.Headers)
	}
}
