package mutate

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// reAllDigitsEnum is a digit-run detector for enumerable numeric path segments.
// UUID, hex, base64url patterns are intentionally excluded — sequential
// enumeration only makes sense for plain decimal identifiers (order IDs,
// user IDs, etc.).
var reAllDigitsEnum = regexp.MustCompile(`^[0-9]+$`)

// isEnumerableSegment returns true when seg is a pure-decimal run (and
// therefore a candidate for sequential ID enumeration).
func isEnumerableSegment(seg string) bool {
	return seg != "" && reAllDigitsEnum.MatchString(seg)
}

// EnumerateID probes neighboring values of numeric path segment identifiers
// to detect horizontal IDOR vulnerabilities where sequential access to
// adjacent IDs is not access-controlled.
//
// For each captured request whose URL path contains one or more numeric
// segments (e.g. /orders/56789), EnumerateID generates:
//   - The 2N immediate neighbors: [captured-N … captured-1, captured+1 … captured+N]
//   - A small set of pseudo-random samples from the ±5N window around the
//     captured value (sampled deterministically per endpoint for reproducibility)
//
// Variants preserve the original caller's credentials and headers unchanged —
// only the numeric path segment changes. The mutation class is "idor".
//
// The mutator is OFF by default (N == 0). Enable with --enumerate N.
// Rate limiting is fully delegated to the existing replay.hostLimiter; no
// new throttle code is added here.
//
// Finding clustering (one idor finding per endpoint rather than N individual
// ones) is performed by the scan command after detection, keyed on
// Mutation.Type == "enumerate-id".
type EnumerateID struct {
	// N is the enumeration range: probe captured±N neighbors. 0 disables the
	// mutator entirely (Generate returns nil immediately).
	N int
}

// Name implements Mutator.
func (e EnumerateID) Name() string { return "enumerate-id" }

// Generate implements Mutator. It is deterministic: given the same base URL
// and the same N, it always returns the same ordered variant slice. Identity
// is always nil (the original caller's creds are preserved unchanged).
func (e EnumerateID) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if e.N <= 0 || base == nil || base.URL == nil {
		return nil
	}

	path := base.URL.Path
	if path == "" {
		return nil
	}

	// Locate the first numeric segment. We only modify the first one so that
	// the variants differ in exactly one position each, keeping the test focused.
	parts := strings.Split(path, "/")
	segIdx := -1
	var capturedVal int64
	for i, seg := range parts {
		if isEnumerableSegment(seg) {
			v, err := strconv.ParseInt(seg, 10, 64)
			if err == nil {
				segIdx = i
				capturedVal = v
				break
			}
		}
	}
	if segIdx < 0 {
		// No enumerable numeric segment in this path.
		return nil
	}

	// Collect probe IDs: immediate neighbors ± N, then random samples in ± 5N
	// window (excluding already-queued values and the captured value itself).
	probeSet := make(map[int64]struct{}, 2*e.N+5)

	for delta := int64(1); delta <= int64(e.N); delta++ {
		if lo := capturedVal - delta; lo >= 0 {
			probeSet[lo] = struct{}{}
		}
		probeSet[capturedVal+delta] = struct{}{}
	}

	// Pseudo-random samples within ± 5N window. Use a fixed seed derived from
	// the captured value so the set is deterministic across runs.
	windowHalf := int64(5 * e.N)
	windowMin := capturedVal - windowHalf
	if windowMin < 0 {
		windowMin = 0
	}
	windowMax := capturedVal + windowHalf
	windowSize := windowMax - windowMin + 1

	// Target ~5 random samples (capped at window size).
	nRandom := 5
	if int64(nRandom) > windowSize {
		nRandom = int(windowSize)
	}
	rng := rand.New(rand.NewSource(capturedVal)) // #nosec G404 — non-security random
	attempts := 0
	for len(probeSet) < 2*e.N+nRandom && attempts < 200 {
		attempts++
		candidate := windowMin + rng.Int63n(windowSize)
		if candidate == capturedVal {
			continue
		}
		probeSet[candidate] = struct{}{}
	}

	if len(probeSet) == 0 {
		return nil
	}

	// Build a deterministically ordered list of probe IDs.
	probeIDs := make([]int64, 0, len(probeSet))
	for id := range probeSet {
		probeIDs = append(probeIDs, id)
	}
	// Sort ascending for deterministic output order.
	sortInt64s(probeIDs)

	out := make([]model.Variant, 0, len(probeIDs))
	for _, probeID := range probeIDs {
		newParts := make([]string, len(parts))
		copy(newParts, parts)
		newParts[segIdx] = strconv.FormatInt(probeID, 10)
		newPath := strings.Join(newParts, "/")

		req := CloneRequest(base)
		cloneURLEnum(req, base)
		req.URL.Path = newPath
		req.URL.RawPath = ""

		// Keep the PathTemplate consistent if set (normalize stage may have
		// already computed it; we leave it alone since the template doesn't
		// change — only the concrete ID does).

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // original caller's creds preserved; we only change the URL
			Mutation: model.Mutation{
				Type: "enumerate-id",
				Description: fmt.Sprintf("sequential ID sweep: probing %s (captured %d, probe %d, range ±%d)",
					newPath, capturedVal, probeID, e.N),
				Detail: map[string]string{
					"captured_id": strconv.FormatInt(capturedVal, 10),
					"probe_id":    strconv.FormatInt(probeID, 10),
					"range":       strconv.Itoa(e.N),
					"seg_index":   strconv.Itoa(segIdx),
				},
				Class: "idor",
			},
		})
	}
	return out
}

// cloneURLEnum deep-copies the URL of base onto req so that path mutations in
// enumerate-id never alias the original.
func cloneURLEnum(req, base *model.CapturedRequest) {
	if base.URL == nil {
		return
	}
	u := *base.URL
	if base.URL.User != nil {
		uu := *base.URL.User
		u.User = &uu
	}
	req.URL = &u
}

// sortInt64s sorts a slice of int64 in ascending order (insertion sort — the
// slices are small, at most 2N+5 elements, so O(n²) is fine and avoids
// importing sort for a trivial case).
func sortInt64s(s []int64) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
