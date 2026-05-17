package mutate

import "github.com/bugsyhewitt/possession/internal/model"

// DowngradeRole emits one variant per identity whose rank is strictly less
// than the request's "apparent owner". When owner is unknown (we have no
// way to attribute a capture to an identity in Packet 2), we treat the
// highest-rank identity in the matrix as the owner — meaning every other
// identity is a downgrade candidate. Mechanically similar to swap-identity
// but framed for privilege-escalation reporting (P3).
type DowngradeRole struct{}

func (DowngradeRole) Name() string { return "downgrade-role" }

func (DowngradeRole) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	if base == nil || m == nil || len(m.Identities) == 0 {
		return nil
	}
	ids := sortIdentities(m.Identities)
	// Owner = highest-rank identity. With ids sorted ascending by rank,
	// that is the last element.
	owner := ids[len(ids)-1]
	out := make([]model.Variant, 0, len(ids))
	for i := range ids {
		ident := ids[i]
		if ident.Rank >= owner.Rank {
			// not a downgrade
			continue
		}
		req := CloneRequest(base)
		applyIdentity(req, &ident)
		out = append(out, model.Variant{
			Base:     req,
			Identity: &ids[i],
			Mutation: model.Mutation{
				Type:        "downgrade-role",
				Description: "downgrade to identity " + ident.Name,
				Detail: map[string]string{
					"downgraded_to": ident.Name,
					"from_owner":    owner.Name,
				},
				Class: "privesc",
			},
		})
	}
	return out
}
