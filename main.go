package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ── 数据库 ────────────────────────────────────────────────────

var (
	pool     *pgxpool.Pool
	poolOnce sync.Once
)

func db() *pgxpool.Pool {
	poolOnce.Do(func() {
		dsn := mustEnv("POSTGRES_URL")
		var err error
		pool, err = pgxpool.New(context.Background(), dsn)
		if err != nil {
			log.Fatalf("数据库连接失败: %v", err)
		}
		_, err = pool.Exec(context.Background(), `
			CREATE TABLE IF NOT EXISTS users (
				id         BIGSERIAL PRIMARY KEY,
				email      TEXT      UNIQUE NOT NULL,
				password   TEXT      NOT NULL,
				is_pro     BOOLEAN   NOT NULL DEFAULT false,
				created_at BIGINT    NOT NULL
			)
		`)
		if err != nil {
			log.Fatalf("建表失败: %v", err)
		}
	})
	return pool
}

// ── JWT ───────────────────────────────────────────────────────

type Claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func signToken(userID int64, email string) (string, error) {
	secret := []byte(mustEnv("JWT_SECRET"))
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func parseToken(tokenStr string) (*Claims, error) {
	secret := []byte(mustEnv("JWT_SECRET"))
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil || !t.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := t.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
}

// ── i18n ──────────────────────────────────────────────────────

var messages = map[string][2]string{
	"method_not_allowed": {"method not allowed", "请求方法不允许"},
	"bad_request":        {"invalid request format", "请求格式有误"},
	"invalid_email_pass": {"invalid email or password format", "邮箱或密码格式有误"},
	"server_error":       {"internal server error", "服务器错误"},
	"email_exists":       {"email already registered", "该邮箱已注册"},
	"wrong_credentials":  {"incorrect email or password", "邮箱或密码错误"},
	"unauthorized":       {"unauthorized", "未登录"},
	"invalid_token":      {"invalid or expired token", "Token 无效或已过期"},
	"user_not_found":     {"user not found", "用户不存在"},
	"forbidden":          {"forbidden", "无权限"},
	"bad_params":         {"invalid parameters", "参数有误"},
}

func t(r *http.Request, key string) string {
	lang := r.Header.Get("Accept-Language")
	isCN := strings.Contains(lang, "zh")
	msg, ok := messages[key]
	if !ok {
		if isCN {
			return key
		}
		return key
	}
	if isCN {
		return msg[1]
	}
	return msg[0]
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("环境变量 %s 未设置", key)
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// ── Handlers ──────────────────────────────────────────────────

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, t(r, "method_not_allowed"))
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, t(r, "bad_request"))
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if body.Email == "" || len(body.Password) < 6 {
		writeErr(w, http.StatusBadRequest, t(r, "invalid_email_pass"))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, t(r, "server_error"))
		return
	}
	var id int64
	err = db().QueryRow(context.Background(),
		`INSERT INTO users (email, password, created_at) VALUES ($1, $2, $3) RETURNING id`,
		body.Email, string(hash), time.Now().Unix(),
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeErr(w, http.StatusConflict, t(r, "email_exists"))
			return
		}
		writeErr(w, http.StatusInternalServerError, t(r, "server_error"))
		return
	}
	token, err := signToken(id, body.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, t(r, "server_error"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "email": body.Email, "is_pro": false})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, t(r, "method_not_allowed"))
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, t(r, "bad_request"))
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	var (
		id    int64
		hash  string
		isPro bool
		email string
	)
	err := db().QueryRow(context.Background(),
		`SELECT id, email, password, is_pro FROM users WHERE email = $1`, body.Email,
	).Scan(&id, &email, &hash, &isPro)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, t(r, "wrong_credentials"))
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		writeErr(w, http.StatusUnauthorized, t(r, "wrong_credentials"))
		return
	}
	token, err := signToken(id, email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, t(r, "server_error"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "email": email, "is_pro": isPro})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, t(r, "method_not_allowed"))
		return
	}
	token := bearerToken(r)
	if token == "" {
		writeErr(w, http.StatusUnauthorized, t(r, "unauthorized"))
		return
	}
	claims, err := parseToken(token)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, t(r, "invalid_token"))
		return
	}
	var isPro bool
	err = db().QueryRow(context.Background(),
		`SELECT is_pro FROM users WHERE id = $1`, claims.UserID,
	).Scan(&isPro)
	if err != nil {
		writeErr(w, http.StatusNotFound, t(r, "user_not_found"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": claims.Email, "is_pro": isPro})
}

func handleSetPro(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, t(r, "method_not_allowed"))
		return
	}
	adminKey := os.Getenv("ADMIN_KEY")
	if adminKey == "" || r.Header.Get("X-Admin-Key") != adminKey {
		writeErr(w, http.StatusForbidden, t(r, "forbidden"))
		return
	}
	var body struct {
		Email string `json:"email"`
		IsPro bool   `json:"is_pro"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeErr(w, http.StatusBadRequest, t(r, "bad_params"))
		return
	}
	tag, err := db().Exec(context.Background(),
		`UPDATE users SET is_pro = $1 WHERE email = $2`, body.IsPro, strings.ToLower(body.Email),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, t(r, "server_error"))
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, t(r, "user_not_found"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── Main ──────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/me", handleMe)
	mux.HandleFunc("/api/admin/set-pro", handleSetPro)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, corsMiddleware(mux)))
}
