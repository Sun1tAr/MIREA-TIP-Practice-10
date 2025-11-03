package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
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

			// УНИВЕРСАЛЬНАЯ обработка - пробуем оба типа
			var role string

			switch c := claimsVal.(type) {
			case map[string]any:
				role, _ = c["role"].(string)
			case jwt.MapClaims:
				role, _ = c["role"].(string)
			default:
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			if _, ok := set[role]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
