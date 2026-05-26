package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runScanCmd resets scan-specific flags and runs the scan subcommand.
func runScanCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetScanFlags()
	parseFormat = "auto"
	parseScope = ""
	parseJSON = false

	full := append([]string{"scan"}, args...)
	return runCmd(t, full...)
}

// TestScanAllowlist_UpdateRequiresAllowlistFlag verifies that
// --update-allowlist without --allowlist produces a config error.
func TestScanAllowlist_UpdateRequiresAllowlistFlag(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--dry-run",
		"--update-allowlist",
	)
	if err == nil {
		t.Fatal("expected error when --update-allowlist is set without --allowlist")
	}
	if !strings.Contains(err.Error(), "--update-allowlist") {
		t.Errorf("error message should mention --update-allowlist: %v", err)
	}
}

// TestScanAllowlist_MissingAllowlistFileOK verifies that specifying a
// non-existent --allowlist path is silently treated as an empty allowlist
// (because LoadFile returns empty for missing files).
func TestScanAllowlist_MissingAllowlistFileOK(t *testing.T) {
	// dry-run means no network traffic; just verifies flag parsing + allowlist load.
	out, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--dry-run",
		"--allowlist", "/tmp/nonexistent-possession.allowlist",
	)
	if err != nil {
		t.Fatalf("expected no error for missing allowlist in dry-run: %v\noutput: %s", err, out)
	}
}

// TestScanAllowlist_UpdateAllowlistWritesFile verifies that
// --update-allowlist writes (or creates) the allowlist file. We use
// --dry-run so no network is touched; however --dry-run returns before
// findings are computed, so the allowlist update won't be triggered. This
// test instead exercises the flag validation path only (no file is written
// on dry-run because findings don't exist yet). We validate the flag
// parses without error.
func TestScanAllowlist_FlagParseOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "possession.allowlist")

	// dry-run: no findings generated, no allowlist written — but flag
	// parsing must not error.
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--dry-run",
		"--allowlist", p,
		"--update-allowlist",
	)
	if err != nil {
		t.Fatalf("flag parse should succeed: %v", err)
	}

	// File should not exist — dry-run never reaches the findings/allowlist
	// update code path.
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("allowlist file should not be written on dry-run")
	}
}
