package main

import (
	_ "embed"
	"log"
	"net/http"

	"github.com/lxlonion/golang-webauthn-example/orderManner"
)

var storeInstance *Store // 全局 store，用于 OAuth2 模块访问

func main() {
	storeInstance = NewStore()
	wa := NewWebAuthn(storeInstance,
		"localhost",
		"Golang WebAuthn Example",
		[]string{"https://localhost:2345"},
	)
	const prefix = `/admin/`
	admin := NewAdmin(storeInstance, wa, prefix)

	// 初始化 OAuth2 服务器
	InitOAuthServer()

	// 初始化订单管理器
	orderMgr, err := orderManner.NewOrderManager(storeInstance.db, func(r *http.Request) (string, bool) {
		user := storeInstance.AuthRequest(r)
		if user == nil {
			return "", false
		}
		return user.Email, true
	})
	if err != nil {
		log.Fatalf("初始化订单管理器失败: %v", err)
	}

	http.Handle(prefix, admin.Handler())
	http.HandleFunc("/oauth2/authorize", OAuthAuthorizeHandler)
	http.HandleFunc("/oauth2/token", OAuthTokenHandler)
	http.HandleFunc("/oauth2/user", OAuthUserHandler)
	http.HandleFunc("/orders/", orderMgr.HandleOrderRequest)
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir("avatars"))))
	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// 添加静态文件服务
	fs := http.FileServer(http.Dir("."))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Fatalln(http.ListenAndServeTLS(":2345", "localhost.crt", "localhost.key", nil))
}
