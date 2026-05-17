package mutate

import "github.com/bugsyhewitt/possession/internal/model"

// SwapIdentity emits one variant per identity in the matrix (including the
// baseline-as-self anchor, D9). Identities are iterated in canonical
// (rank, name) order so output is deterministic.
type SwapIdentity struct{}

func (SwapIdentity) Name() string { return "swap-identity" }

func (SwapIdentity) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	if base == nil || m == nil {
		return nil
	}
	ids := sortIdentities(m.Identities)
	out := make([]model.Variant, 0, len(ids))
	for i := range ids {
		ident := ids[i]
		req := CloneRequest(base)
		applyIdentity(req, &ident)
		out = append(out, model.Variant{
			Base:     req,
			Identity: &ids[i],
			Mutation: model.Mutation{
				Type:        "swap-identity",
				Description: "replay as identity " + ident.Name,
				Detail:      map[string]string{"swapped_to": ident.Name},
				Class:       "idor",
			},
		})
	}
	return out
}
