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
	// Resolve the captured request's owner tenant from the owner identity's
	// Tenant field. Used to detect cross-tenant swaps (D31 activated P8).
	ownerTenant := capturedOwnerTenant(base, m)

	ids := sortIdentities(m.Identities)
	out := make([]model.Variant, 0, len(ids))
	for i := range ids {
		ident := ids[i]
		req := CloneRequest(base)
		applyIdentity(req, &ident)

		// Determine finding class: cross-tenant when both identities have
		// different non-empty tenant tags (D31 / P8).
		class := "idor"
		detail := map[string]string{"swapped_to": ident.Name}
		if ownerTenant != "" && ident.Tenant != "" && ident.Tenant != ownerTenant {
			class = "idor-cross-tenant"
			detail["actor_tenant"] = ident.Tenant
			detail["owner_tenant"] = ownerTenant
		}

		out = append(out, model.Variant{
			Base:     req,
			Identity: &ids[i],
			Mutation: model.Mutation{
				Type:        "swap-identity",
				Description: "replay as identity " + ident.Name,
				Detail:      detail,
				Class:       class,
			},
		})
	}
	return out
}

// capturedOwnerTenant returns the Tenant of the identity that best matches the
// captured request's auth headers, using the same first-match logic as the
// owner attribution code in detect. Falls back to empty string.
func capturedOwnerTenant(base *model.CapturedRequest, m *model.RoleMatrix) string {
	if base == nil || m == nil {
		return ""
	}
	bearer := ""
	if auth := base.Headers.Get("Authorization"); len(auth) > 7 {
		bearer = auth[7:]
	}
	for _, id := range m.Identities {
		if id.Creds == nil {
			continue
		}
		if bearer != "" && id.Creds.Bearer == bearer {
			return id.Tenant
		}
	}
	return ""
}
