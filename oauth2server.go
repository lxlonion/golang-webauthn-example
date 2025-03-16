package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

var OAuthServer *server.Server

// InitOAuthServer 初始化 OAuth2 管理器和服务器
func InitOAuthServer() {
	manager := manage.NewDefaultManager()
	// 使用内存令牌存储
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// 使用数据库客户端存储
	clientStore := store.NewClientStore()

	// 从数据库加载客户端信息
	rows, err := storeInstance.db.Query("SELECT client_id, client_secret, domain FROM oauth2_clients")
	if err != nil {
		log.Fatalf("Failed to query oauth2_clients: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			clientID     string
			clientSecret string
			domain       string
		)
		if err := rows.Scan(&clientID, &clientSecret, &domain); err {
			log.Fatalf("Failed to scan oauth2_clients row: %v", err)
		}

		clientStore.Set(clientID, &models.Client{
			ID:     clientID,
			Secret: clientSecret,
			Domain: domain,
		})
	}

	if err := rows.Err(); err != nil {
		log.Fatalf("Failed to iterate oauth2_clients rows: %v", err)
	}

	manager.MapClientStorage(clientStore)

	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	OAuthServer = srv
}

// userAuthorizeHandler 检查用户是否已登录（调用全局 storeInstance）
func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (string, error) {
	user := storeInstance.AuthRequest(r)
	if user == nil {
		return "", fmt.Errorf("user not logged in")
	}
	return fmt.Sprint(user.ID), nil
}

// OAuthAuthorizeHandler 处理 /oauth2/authorize 请求
func OAuthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// 检查用户是否已登录
	user := storeInstance.AuthRequest(r)
	if user == nil {
		// 如果用户未登录，重定向到 OAuth2 登录页面
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		scope := r.URL.Query().Get("scope")
		state := r.URL.Query().Get("state")

		// 构建重定向 URL，包含 client_id 和 redirect_uri
		loginURL := fmt.Sprintf("/admin/oauth2/login?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))

		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	if err := OAuthServer.HandleAuthorizeRequest(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// OAuthTokenHandler 处理 /oauth2/token 请求
func OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := OAuthServer.HandleTokenRequest(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// UserInfo 用户信息结构体
type UserInfo struct {
	ID        uint32 `json:"id"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// OAuthUserHandler 处理 /oauth2/user 请求，返回用户信息
func OAuthUserHandler(w http.ResponseWriter, r *http.Request) {
	// 从 Authorization 头中获取 access token
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "No Authorization header", http.StatusUnauthorized)
		return
	}

	// 处理 "Bearer <token>" 格式
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	accessToken := parts[1]

	// 验证 access token
	ti, err := OAuthServer.Manager.LoadAccessToken(r.Context(), accessToken)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// 获取用户ID
	userID := ti.GetUserID()
	if userID == "" {
		http.Error(w, "No user ID associated with token", http.StatusUnauthorized)
		return
	}

	// 从 store 中获取用户信息
	uid := uint32(0)
	fmt.Sscanf(userID, "%d", &uid)
	user := storeInstance.GetUserByID(uid)
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 构造用户信息响应
	userInfo := UserInfo{
		ID:        user.ID,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 返回 JSON 响应
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
