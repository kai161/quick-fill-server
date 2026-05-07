package handler

import (
	"context"
	"net/http"

	shared "quick-fill-server/api/shared"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if shared.HandleCORS(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		shared.Err(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := shared.BearerToken(r)
	if token == "" {
		shared.Err(w, http.StatusUnauthorized, "未登录")
		return
	}
	claims, err := shared.ParseToken(token)
	if err != nil {
		shared.Err(w, http.StatusUnauthorized, "Token 无效或已过期")
		return
	}

	var isPro bool
	err = shared.DB().QueryRow(context.Background(),
		`SELECT is_pro FROM users WHERE id = $1`, claims.UserID,
	).Scan(&isPro)
	if err != nil {
		shared.Err(w, http.StatusNotFound, "用户不存在")
		return
	}
	shared.JSON(w, http.StatusOK, map[string]any{
		"email":  claims.Email,
		"is_pro": isPro,
	})
}
