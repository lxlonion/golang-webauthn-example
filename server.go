package main

import (
	_ "embed"
	"log"
	"net/http"

	"github.com/lxlonion/golang-webauthn-example/admin"
	"github.com/lxlonion/golang-webauthn-example/db"
	"github.com/lxlonion/golang-webauthn-example/oauth2"
	"github.com/lxlonion/golang-webauthn-example/users"
	"github.com/lxlonion/golang-webauthn-example/webauthn"
)

var storeInstance *users.Store // 全局 store，用于 OAuth2 模块访问

func main() {
	storeInstance = users.NewStore()
	wa := webauthn.NewWebAuthn(storeInstance,
		"localhost",
		"Golang WebAuthn Example",
		[]string{"https://localhost:2345"},
	)
	const prefix = `/admin/`
	admin := admin.NewAdmin(storeInstance, wa, prefix)

	// 初始化 OAuth2 服务器
	oauth2.InitOAuthServer()

	http.Handle(prefix, admin.Handler())
	http.HandleFunc("/oauth2/authorize", oauth2.OAuthAuthorizeHandler)
	http.HandleFunc("/oauth2/token", oauth2.OAuthTokenHandler)
	http.HandleFunc("/oauth2/user", oauth2.OAuthUserHandler) // 添加新的路由
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir("avatars"))))
	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	log.Fatalln(http.ListenAndServeTLS(":2345", "localhost.crt", "localhost.key", nil))
}
