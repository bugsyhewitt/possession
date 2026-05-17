package mutate

import "github.com/bugsyhewitt/possession/internal/model"

// StripAuth removes every credential from the baseline (all auth headers and
// all auth cookies). Produces exactly one variant per endpoint sample with
// Identity == nil. Probes authn-bypass: does the endpoint require auth at all?
type StripAuth struct{}

func (StripAuth) Name() string { return "strip-auth" }

func (StripAuth) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if base == nil {
		return nil
	}
	v := CloneRequest(base)
	stripAllAuth(v)
	return []model.Variant{{
		Base:     v,
		Identity: nil,
		Mutation: model.Mutation{
			Type:        "strip-auth",
			Description: "remove all credentials (headers + cookies + basic)",
			Detail:      map[string]string{},
			Class:       "authn-bypass",
		},
	}}
}
