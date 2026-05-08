package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

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
	if body.Email == "" || len(body.Password) < 6 {
		shared.Err(w, http.StatusBadRequest, "邮箱或密码格式有误")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		shared.Err(w, http.StatusInternalServerError, "服务器错误")
		return
	}

	db := shared.DB()
	var id int64
	err = db.QueryRow(context.Background(),
		`INSERT INTO users (email, password, created_at) VALUES ($1, $2, $3) RETURNING id`,
		body.Email, string(hash), time.Now().Unix(),
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			shared.Err(w, http.StatusConflict, "该邮箱已注册")
			return
		}
		shared.Err(w, http.StatusInternalServerError, "服务器错误")
		return
	}

	token, err := shared.SignToken(id, body.Email)
	if err != nil {
		shared.Err(w, http.StatusInternalServerError, "服务器错误")
		return
	}
	shared.JSON(w, http.StatusOK, map[string]any{
		"token":  token,
		"email":  body.Email,
		"is_pro": false,
	})
}
