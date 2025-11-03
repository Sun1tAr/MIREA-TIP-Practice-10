package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Validator interface {
	Sign(userID int64, email, role string, ttl time.Duration) (string, error) // ← добавим ttl параметр
	Parse(tokenStr string) (jwt.MapClaims, error)
}

type HS256 struct {
	secret []byte
}

func NewHS256(secret []byte) *HS256 { // ← убираем ttl из конструктора
	return &HS256{secret: secret}
}

func (h *HS256) Sign(userID int64, email, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  role,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"iss":   "pz10-auth",
		"aud":   "pz10-clients",
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(h.secret)
}

// Parse остается без изменений
func (h *HS256) Parse(tokenStr string) (jwt.MapClaims, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) { return h.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience("pz10-clients"),
		jwt.WithIssuer("pz10-auth"),
	)
	if err != nil || !t.Valid {
		return nil, err
	}
	return t.Claims.(jwt.MapClaims), nil
}
