package middleware

import (
	"net/http"
)

func AuthZRoles(allowed ...string) func(http.Handler) http.Handler {
	set := map[string]struct{}{}
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claimsVal := r.Context().Value(CtxClaimsKey)
			if claimsVal == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			claims, ok := claimsVal.(map[string]any)
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			role, _ := claims["role"].(string)
			if _, ok := set[role]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
