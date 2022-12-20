package googleoidcmiddleware

import "golang.org/x/net/context"

type contextKey string

var idTokenClaimsContextKey contextKey = "__google_oidc__id_token_claims"

func withIDTokenClaims(ctx context.Context, idTokenClaims map[string]interface{}) context.Context {
	return context.WithValue(ctx, idTokenClaimsContextKey, idTokenClaims)
}

func IDTokenClaims(ctx context.Context) (map[string]interface{}, bool) {
	idTokenClaims, ok := ctx.Value(idTokenClaimsContextKey).(map[string]interface{})
	return idTokenClaims, ok
}
