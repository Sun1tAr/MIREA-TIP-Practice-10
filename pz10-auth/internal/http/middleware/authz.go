package middleware

import (
	"log"
	"net/http"
)

func AuthZRoles(allowed ...string) func(http.Handler) http.Handler {
	set := map[string]struct{}{}
	for _, a := range allowed {
		set[a] = struct{}{}
	}

	log.Printf("AuthZRoles: allowed roles: %v", allowed)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("AuthZRoles: checking access for %s", r.URL.Path)

			claimsVal := r.Context().Value(CtxClaimsKey)
			if claimsVal == nil {
				log.Printf("AuthZRoles: no claims in context")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			claims, ok := claimsVal.(map[string]any)
			if !ok {
				log.Printf("AuthZRoles: invalid claims type: %T", claimsVal)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			role, _ := claims["role"].(string)
			log.Printf("AuthZRoles: user role: %s", role)

			if _, ok := set[role]; !ok {
				log.Printf("AuthZRoles: role %s not in allowed set %v", role, allowed)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			log.Printf("AuthZRoles: access granted for role %s", role)
			next.ServeHTTP(w, r)
		})
	}
}
