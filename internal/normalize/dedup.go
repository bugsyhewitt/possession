package normalize

import (
	"sort"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Dedup groups CapturedRequests into Endpoints keyed by
// (Method, Host, PathTemplate). PathTemplate must already be populated —
// call Apply first.
//
// The returned slice is sorted deterministically (host, then path
// template, then method) so that CLI output and tests are stable across
// runs.
func Dedup(reqs []*model.CapturedRequest) []*model.Endpoint {
	type key struct{ method, host, path string }
	groups := make(map[key]*model.Endpoint)
	for _, r := range reqs {
		if r == nil || r.URL == nil {
			continue
		}
		k := key{method: r.Method, host: r.URL.Host, path: r.PathTemplate}
		ep, ok := groups[k]
		if !ok {
			ep = &model.Endpoint{
				Method:       r.Method,
				Host:         r.URL.Host,
				PathTemplate: r.PathTemplate,
			}
			groups[k] = ep
		}
		ep.Samples = append(ep.Samples, r)
	}
	out := make([]*model.Endpoint, 0, len(groups))
	for _, ep := range groups {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].PathTemplate != out[j].PathTemplate {
			return out[i].PathTemplate < out[j].PathTemplate
		}
		return out[i].Method < out[j].Method
	})
	return out
}
