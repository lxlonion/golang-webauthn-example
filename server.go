package main

import (
	_ "embed"
	"log"
	"net/http"
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

	http.Handle(prefix, admin.Handler())
	http.HandleFunc("/oauth2/authorize", OAuthAuthorizeHandler)
	http.HandleFunc("/oauth2/token", OAuthTokenHandler)
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir("avatars"))))
	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	log.Fatalln(http.ListenAndServeTLS(":2345", "localhost.crt", "localhost.key", nil))
}
