package main

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ── 配置 ─────────────────────────────────────────────────────

var jwtSecret = []byte(getEnv("JWT_SECRET", "change-me-in-production"))
var adminKey = getEnv("ADMIN_KEY", "admin-secret")

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── 数据库 ───────────────────────────────────────────────────

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./quickfill.db")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			email     TEXT    UNIQUE NOT NULL,
			password  TEXT    NOT NULL,
			is_pro    INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		panic(err)
	}
}

// ── JWT ──────────────────────────────────────────────────────

type Claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func signToken(userID int64, email string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func parseToken(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
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

// ── Auth Middleware ──────────────────────────────────────────

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
			return
		}
		claims, err := parseToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token 无效或已过期"})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func getClaims(c *gin.Context) *Claims {
	v, _ := c.Get("claims")
	claims, _ := v.(*Claims)
	return claims
}

// ── Handlers ─────────────────────────────────────────────────

type authBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

func handleRegister(c *gin.Context) {
	var body authBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱或密码格式有误"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	res, err := db.Exec(
		`INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)`,
		strings.ToLower(body.Email), string(hash), time.Now().Unix(),
	)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "该邮箱已注册"})
		return
	}
	id, _ := res.LastInsertId()
	token, err := signToken(id, body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "email": body.Email, "is_pro": false})
}

func handleLogin(c *gin.Context) {
	var body authBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱或密码格式有误"})
		return
	}
	var (
		id       int64
		hash     string
		isPro    int
		email    string
	)
	err := db.QueryRow(
		`SELECT id, email, password, is_pro FROM users WHERE email = ?`,
		strings.ToLower(body.Email),
	).Scan(&id, &email, &hash, &isPro)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	token, err := signToken(id, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "email": email, "is_pro": isPro == 1})
}

func handleMe(c *gin.Context) {
	claims := getClaims(c)
	var isPro int
	err := db.QueryRow(`SELECT is_pro FROM users WHERE id = ?`, claims.UserID).Scan(&isPro)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": claims.Email, "is_pro": isPro == 1})
}

// 管理员接口：升级/降级会员（后续接支付 Webhook 时调用此逻辑）
func handleSetPro(c *gin.Context) {
	if c.GetHeader("X-Admin-Key") != adminKey {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限"})
		return
	}
	var body struct {
		Email string `json:"email" binding:"required"`
		IsPro bool   `json:"is_pro"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数有误"})
		return
	}
	isPro := 0
	if body.IsPro {
		isPro = 1
	}
	res, err := db.Exec(`UPDATE users SET is_pro = ? WHERE email = ?`, isPro, strings.ToLower(body.Email))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Main ─────────────────────────────────────────────────────

func main() {
	initDB()

	r := gin.Default()

	// CORS：允许插件扩展访问
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	r.POST("/api/register", handleRegister)
	r.POST("/api/login", handleLogin)
	r.GET("/api/me", authMiddleware(), handleMe)
	r.POST("/api/admin/set-pro", handleSetPro)

	port := getEnv("PORT", "8080")
	r.Run(":" + port)
}
