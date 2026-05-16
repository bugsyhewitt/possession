package parse

import (
	"strings"
	"testing"
)

func TestHARSimple(t *testing.T) {
	f, err := openFixture("../../testdata/har/simple.har")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := HAR(f)
	if err != nil {
		t.Fatalf("HAR: %v", err)
	}
	if len(reqs) != 3 {
		t.Fatalf("got %d requests, want 3", len(reqs))
	}
	if reqs[0].Source != "har:entries[0]" {
		t.Errorf("source = %q", reqs[0].Source)
	}
	if reqs[2].Method != "POST" || string(reqs[2].Body) != `{"sku":"abc"}` {
		t.Errorf("third entry not parsed correctly: %+v body=%q", reqs[2], string(reqs[2].Body))
	}
}

func TestHARFiltersStaticAndAnalytics(t *testing.T) {
	f, err := openFixture("../../testdata/har/ecommerce.har")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := HAR(f)
	if err != nil {
		t.Fatalf("HAR: %v", err)
	}
	for _, r := range reqs {
		if strings.HasSuffix(r.URL.Path, ".js") {
			t.Errorf("kept a .js asset: %s", r.URL)
		}
		if strings.HasSuffix(r.URL.Path, ".png") {
			t.Errorf("kept a .png asset: %s", r.URL)
		}
		if strings.Contains(r.URL.Host, "google-analytics.com") {
			t.Errorf("kept analytics host: %s", r.URL)
		}
		if r.ContentType != "" && strings.HasPrefix(r.ContentType, "text/css") {
			t.Errorf("kept text/css response: %s", r.URL)
		}
	}
	// Sanity: at least the user/profile + orders requests survive.
	if len(reqs) < 5 {
		t.Errorf("expected ≥5 surviving requests, got %d", len(reqs))
	}
}

func TestHARMalformed(t *testing.T) {
	_, err := HAR(strings.NewReader("not-json"))
	if err == nil {
		t.Fatal("expected error for malformed HAR")
	}
}

func TestHARMissingFields(t *testing.T) {
	// Entry with no URL is silently skipped, not fatal.
	in := `{"log":{"entries":[{"request":{"method":"GET","url":""}}]}}`
	reqs, err := HAR(strings.NewReader(in))
	if err != nil {
		t.Fatalf("HAR: %v", err)
	}
	if len(reqs) != 0 {
		t.Fatalf("expected 0 surviving requests, got %d", len(reqs))
	}
}
