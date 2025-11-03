package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"example.com/pz10-auth/internal/platform/jwt"
)

type ctxKey int

const CtxClaimsKey ctxKey = iota

func AuthN(v jwt.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("AuthN: checking authorization header for %s", r.URL.Path)

			h := r.Header.Get("Authorization")
			if h == "" || !strings.HasPrefix(h, "Bearer ") {
				log.Printf("AuthN: missing or invalid authorization header")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			raw := strings.TrimPrefix(h, "Bearer ")
			log.Printf("AuthN: parsing token for path %s", r.URL.Path)

			claims, err := v.Parse(raw)
			if err != nil {
				log.Printf("AuthN: token parse error: %v", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Конвертируем jwt.MapClaims в map[string]any
			claimsMap := make(map[string]any)
			for key, value := range claims {
				claimsMap[key] = value
			}

			log.Printf("AuthN: token valid, user ID: %v, role: %v", claimsMap["sub"], claimsMap["role"])

			ctx := context.WithValue(r.Context(), CtxClaimsKey, claimsMap)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
