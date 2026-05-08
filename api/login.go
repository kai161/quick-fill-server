package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	shared "quick-fill-server/shared"

	"golang.org/x/crypto/bcrypt"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if shared.HandleCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		shared.Err(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		shared.Err(w, http.StatusBadRequest, "请求格式有误")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))

	db := shared.DB()
	var (
		id    int64
		hash  string
		isPro bool
		email string
	)
	err := db.QueryRow(context.Background(),
		`SELECT id, email, password, is_pro FROM users WHERE email = $1`,
		body.Email,
	).Scan(&id, &email, &hash, &isPro)
	if err != nil {
		shared.Err(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		shared.Err(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}

	token, err := shared.SignToken(id, email)
	if err != nil {
		shared.Err(w, http.StatusInternalServerError, "服务器错误")
		return
	}
	shared.JSON(w, http.StatusOK, map[string]any{
		"token":  token,
		"email":  email,
		"is_pro": isPro,
	})
}
