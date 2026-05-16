package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
)

// DefaultMaxVariants is the cap when --max-variants is not set (D11).
const DefaultMaxVariants = 10_000

// Plan is the deterministic, ordered list of Variants for a scan.
type Plan struct {
	Variants    []model.Variant
	Capped      bool
	TotalBefore int // count generated before the cap kicked in (for warn-and-proceed)
}

// Generate produces the canonical variant plan for endpoints under matrix
// using reg. Ordering (D11):
//
//  1. Endpoints sorted by (method, pathTemplate)
//  2. One representative sample per endpoint — the CapturedRequest with the
//     lexicographically smallest stable ID.
//  3. Mutators in registry declaration order
//  4. Identities within a mutator sorted by (rank, name) — owned by the
//     mutator itself.
//
// Each Variant gets a deterministic 16-hex-char ID:
//
//	sha256(endpoint_key + "|" + mutator + "|" + identity_name + "|" + canonical_detail_json)[:16]
//
// max <= 0 ⇒ DefaultMaxVariants. On cap, generation stops and Plan.Capped
// is set; caller is expected to warn and proceed with the partial plan.
func Generate(endpoints []*model.Endpoint, matrix *model.RoleMatrix, reg *mutate.Registry, max int) Plan {
	if max <= 0 {
		max = DefaultMaxVariants
	}
	if reg == nil {
		reg = mutate.DefaultRegistry()
	}

	// (1) sort endpoints
	eps := make([]*model.Endpoint, len(endpoints))
	copy(eps, endpoints)
	sort.SliceStable(eps, func(i, j int) bool {
		if eps[i].Method != eps[j].Method {
			return eps[i].Method < eps[j].Method
		}
		return eps[i].PathTemplate < eps[j].PathTemplate
	})

	var out []model.Variant
	total := 0
	capped := false

	mutators := reg.All()

	for _, ep := range eps {
		sample := pickSample(ep)
		if sample == nil {
			continue
		}
		epKey := endpointKey(ep)
		for _, m := range mutators {
			vs := m.Generate(sample, matrix)
			for _, v := range vs {
				v.ID = variantID(epKey, m.Name(), identityName(v.Identity), v.Mutation.Detail)
				total++
				if len(out) >= max {
					capped = true
					continue
				}
				out = append(out, v)
			}
		}
	}
	return Plan{Variants: out, Capped: capped, TotalBefore: total}
}

// pickSample returns the representative sample for an endpoint — the
// CapturedRequest with the smallest ID. Stable across runs.
func pickSample(ep *model.Endpoint) *model.CapturedRequest {
	if ep == nil || len(ep.Samples) == 0 {
		return nil
	}
	best := ep.Samples[0]
	for _, s := range ep.Samples[1:] {
		if s != nil && (best == nil || s.ID < best.ID) {
			best = s
		}
	}
	return best
}

func endpointKey(ep *model.Endpoint) string {
	if ep == nil {
		return ""
	}
	return ep.Method + " " + ep.Host + ep.PathTemplate
}

func identityName(i *model.Identity) string {
	if i == nil {
		return ""
	}
	return i.Name
}

func variantID(epKey, mutator, identity string, detail map[string]string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|", epKey, mutator, identity)
	h.Write(canonicalJSON(detail))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:16]
}

// canonicalJSON marshals a map[string]string with sorted keys so that
// variant IDs are stable across Go map iteration orders.
func canonicalJSON(m map[string]string) []byte {
	if len(m) == 0 {
		return []byte("{}")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type kv struct {
		K string
		V string
	}
	type pair = [2]string
	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, pair{k, m[k]})
	}
	b, _ := json.Marshal(pairs)
	return b
}
