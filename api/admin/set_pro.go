package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	shared "quick-fill-server/shared"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if shared.HandleCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		shared.Err(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	adminKey := os.Getenv("ADMIN_KEY")
	if adminKey == "" || r.Header.Get("X-Admin-Key") != adminKey {
		shared.Err(w, http.StatusForbidden, "无权限")
		return
	}

	var body struct {
		Email string `json:"email"`
		IsPro bool   `json:"is_pro"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		shared.Err(w, http.StatusBadRequest, "参数有误")
		return
	}

	tag, err := shared.DB().Exec(context.Background(),
		`UPDATE users SET is_pro = $1 WHERE email = $2`,
		body.IsPro, strings.ToLower(body.Email),
	)
	if err != nil {
		shared.Err(w, http.StatusInternalServerError, "服务器错误")
		return
	}
	if tag.RowsAffected() == 0 {
		shared.Err(w, http.StatusNotFound, "用户不存在")
		return
	}
	shared.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}
