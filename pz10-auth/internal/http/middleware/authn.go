package middleware

import (
	"context"
	"net/http"
	"strings"

	"example.com/pz10-auth/internal/platform/jwt"
)

type ctxKey int

const CtxClaimsKey ctxKey = iota

func AuthN(v jwt.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" || !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(h, "Bearer ")
			claims, err := v.Parse(raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Просто сохраняем claims как есть - jwt.MapClaims уже совместим с map[string]any
			ctx := context.WithValue(r.Context(), CtxClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
