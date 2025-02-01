package main

import (
	"fmt"
	"net/http"

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

	// 使用内存客户端存储，示例客户端
	clientStore := store.NewClientStore()
	clientStore.Set("client_1", &models.Client{
		ID:     "client_1",
		Secret: "secret",
		Domain: "http://localhost",
	})
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
