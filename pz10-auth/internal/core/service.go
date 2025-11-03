package core

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"example.com/pz10-auth/internal/http/middleware"
	"example.com/pz10-auth/internal/repo"
	"github.com/go-chi/chi/v5"     // ← ДОБАВИТЬ
	"github.com/golang-jwt/jwt/v5" // ← ДОБАВИТЬ
)

type userRepo interface {
	CheckPassword(email, pass string) (repo.UserRecord, error)
	GetUserByID(id int64) (repo.UserRecord, error)
}

type jwtSigner interface {
	Sign(userID int64, email, role string, ttl time.Duration) (string, error)
	Parse(tokenStr string) (jwt.MapClaims, error)
}

type Service struct {
	repo      userRepo
	jwt       jwtSigner
	blacklist *Blacklist
}

func NewService(r userRepo, j jwtSigner) *Service {
	return &Service{
		repo:      r,
		jwt:       j,
		blacklist: NewBlacklist(),
	}
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Password == "" {
		httpError(w, 400, "invalid_credentials")
		return
	}
	u, err := s.repo.CheckPassword(in.Email, in.Password)
	if err != nil {
		httpError(w, 401, "unauthorized")
		return
	}

	// Выдаем два токена с разным TTL
	accessToken, err := s.jwt.Sign(u.ID, u.Email, u.Role, 15*time.Minute)     // 15 минут
	refreshToken, err := s.jwt.Sign(u.ID, u.Email, "refresh", 7*24*time.Hour) // 7 дней

	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	jsonOK(w, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 минут в секундах
	})
}

// Новый эндпоинт для обновления токенов
func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		httpError(w, 400, "invalid_request")
		return
	}

	// Проверяем что refresh токен не отозван
	if s.blacklist.IsRevoked(in.RefreshToken) {
		httpError(w, 401, "token_revoked")
		return
	}

	// Парсим refresh токен
	claims, err := s.jwt.Parse(in.RefreshToken)
	if err != nil {
		httpError(w, 401, "invalid_token")
		return
	}

	// Проверяем что это действительно refresh токен
	if claims["role"] != "refresh" {
		httpError(w, 401, "invalid_token_type")
		return
	}

	// Извлекаем данные пользователя
	userID := int64(claims["sub"].(float64))
	email := claims["email"].(string)

	// НАХОДИМ ИСХОДНУЮ РОЛЬ ПОЛЬЗОВАТЕЛЯ ИЗ БАЗЫ ДАННЫХ
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		httpError(w, 401, "user_not_found")
		return
	}
	userRole := user.Role // ← используем реальную роль из БД

	// Добавляем старый refresh токен в blacklist
	expiry := time.Unix(int64(claims["exp"].(float64)), 0)
	s.blacklist.Add(in.RefreshToken, expiry)

	// Выдаем новую пару токенов с ПРАВИЛЬНОЙ ролью
	accessToken, err := s.jwt.Sign(userID, email, userRole, 15*time.Minute) // ← используем userRole вместо claims["role"]
	newRefreshToken, err := s.jwt.Sign(userID, email, "refresh", 7*24*time.Hour)

	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	jsonOK(w, map[string]any{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}

// Новый эндпоинт для получения пользователя по ID
func (s *Service) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID из URL
	idStr := chi.URLParam(r, "id")
	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, 400, "invalid_user_id")
		return
	}

	// Извлекаем claims из контекста
	claimsVal := r.Context().Value(middleware.CtxClaimsKey)
	if claimsVal == nil {
		httpError(w, 401, "unauthorized")
		return
	}

	claims, ok := claimsVal.(map[string]any)
	if !ok {
		httpError(w, 401, "unauthorized")
		return
	}

	// ABAC правило: user может получать только свои данные
	tokenUserID := int64(claims["sub"].(float64))
	tokenRole := claims["role"].(string)

	if tokenRole == "user" && tokenUserID != userID {
		httpError(w, 403, "forbidden")
		return
	}

	// Получаем данные пользователя (моковые)
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		httpError(w, 404, "user_not_found")
		return
	}

	jsonOK(w, map[string]any{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
	})
}

// LogoutHandler для отзыва refresh токена
func (s *Service) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		httpError(w, 400, "invalid_request")
		return
	}

	// Парсим токен чтобы получить expiry
	claims, err := s.jwt.Parse(in.RefreshToken)
	if err == nil {
		expiry := time.Unix(int64(claims["exp"].(float64)), 0)
		s.blacklist.Add(in.RefreshToken, expiry)
	}

	jsonOK(w, map[string]any{"message": "logged_out"})
}

func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	claimsVal := r.Context().Value(middleware.CtxClaimsKey)
	if claimsVal == nil {
		httpError(w, 401, "unauthorized")
		return
	}

	log.Printf("MeHandler: claimsVal type = %T, value = %+v", claimsVal, claimsVal)

	// УНИВЕРСАЛЬНАЯ обработка claims
	var sub, email, role interface{}
	var ok bool

	switch claims := claimsVal.(type) {
	case map[string]any:
		sub, ok = claims["sub"]
		email, ok = claims["email"]
		role, ok = claims["role"]
	case jwt.MapClaims:
		// Работаем напрямую с jwt.MapClaims
		sub, ok = claims["sub"]
		email, ok = claims["email"]
		role, ok = claims["role"]
	default:
		log.Printf("MeHandler: unsupported type %T", claimsVal)
		httpError(w, 401, "unauthorized")
		return
	}

	if !ok || sub == nil || email == nil || role == nil {
		log.Printf("MeHandler: missing required fields - sub:%v, email:%v, role:%v", sub, email, role)
		httpError(w, 401, "unauthorized")
		return
	}

	jsonOK(w, map[string]any{
		"id":    sub,
		"email": email,
		"role":  role,
	})
}

func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"users": 2, "version": "1.0"})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
