package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-oauth2/oauth2/v4/server"
)

type LoginData struct {
	Name string
}

type Admin struct {
	prefix       string
	wa           *WebAuthn
	store        *Store
	templates    map[string]*template.Template
	oauth2Server *server.Server // OAuth2 服务器
}

func NewAdmin(store *Store, wa *WebAuthn, prefix string) *Admin {
	a := &Admin{
		store:        store,
		prefix:       prefix,
		wa:           wa,
		templates:    make(map[string]*template.Template),
		oauth2Server: OAuthServer, // 初始化 OAuth2 服务器
	}

	for _, f := range []string{`login.html`, `profile.html`, `oauth2_login.html`} {
		a.templates[f] = template.Must(template.ParseFiles(f))
	}

	return a
}

func (a *Admin) Handler() http.Handler {
	m := http.NewServeMux()

	m.Handle(`GET /{$}`, a.requireLogin(a.getRoot))
	m.Handle(`/`, http.FileServer(http.Dir(".")))

	m.HandleFunc(`GET /login`, a.getLogin)
	m.HandleFunc(`GET /logout`, a.getLogout)
	m.HandleFunc(`POST /register`, a.postRegister)
	m.Handle(`POST /avatar`, a.requireLogin(a.postAvatar))
	m.Handle(`GET /profile`, a.requireLogin(a.getProfile))

	const webAuthnPrefix = `/login/webauthn/`
	m.Handle(webAuthnPrefix, a.wa.Handler(webAuthnPrefix))

	m.HandleFunc(`GET /oauth2/login`, a.getOAuth2Login) // 添加 OAuth2 登录处理

	// 添加对 webauthn.js 的单独路由，手动设置 Content-Type
	m.HandleFunc(`GET /webauthn.js`, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		http.ServeFile(w, r, "webauthn.js")
	})

	return http.StripPrefix(strings.TrimSuffix(a.prefix, "/"), m)
}

func (a *Admin) postRegister(w http.ResponseWriter, r *http.Request) {
	email := r.PostFormValue("email")
	// TODO validate email
	// TODO validate dup.
	u, err := a.store.AddNewUser(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.store.MakeCookie(u, w, r)
	http.Redirect(w, r, a.prefixed(`profile`), http.StatusFound)
}

func (a *Admin) prefixed(s string) string {
	return path.Join(a.prefix, s)
}

func (a *Admin) redirectToLogin(w http.ResponseWriter, r *http.Request, to string) {
	args := url.Values{}
	args.Set(`u`, to)

	u, err := url.Parse(a.prefixed(`/login`))
	if err != nil {
		panic(err)
	}

	u.RawQuery = args.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *Admin) requireLogin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := a.store.AuthRequest(r); user == nil {
			a.redirectToLogin(w, r, r.RequestURI)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (a *Admin) getRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, a.prefixed(`/profile`), http.StatusFound)
}

func (a *Admin) executeTemplate(w io.Writer, name string, data any) {
	t := a.templates[name]
	if t == nil {
		panic(`No such template：` + name)
	}
	if err := t.Execute(w, data); err != nil {
		log.Println(err)
	}
}

func (a *Admin) getLogin(w http.ResponseWriter, r *http.Request) {
	if a.store.AuthRequest(r) != nil {
		to := a.prefixed(`/profile`)
		if u := r.URL.Query().Get(`u`); u != "" {
			to = u
		}
		http.Redirect(w, r, to, http.StatusFound)
		return
	}

	d := LoginData{
		Name: "Golang WebAuthn Example",
	}
	a.executeTemplate(w, `login.html`, &d)
}

func (a *Admin) getLogout(w http.ResponseWriter, r *http.Request) {
	a.store.RemoveCookie(w, r)
	http.Redirect(w, r, a.prefixed(`/login`), http.StatusFound)
}

type ProfileData struct {
	User *User
}

func (d *ProfileData) PublicKeys() []string {
	ss := make([]string, 0, len(d.User.WebAuthnCredentials()))
	for _, c := range d.User.WebAuthnCredentials() {
		ss = append(ss, base64.RawURLEncoding.EncodeToString(c.ID))
	}
	return ss
}

func (a *Admin) getProfile(w http.ResponseWriter, r *http.Request) {
	d := &ProfileData{
		User: a.store.AuthRequest(r),
	}
	a.executeTemplate(w, `profile.html`, &d)
}

func (a *Admin) postAvatar(w http.ResponseWriter, r *http.Request) {
	user := a.store.AuthRequest(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "File upload error", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 确保 avatars 目录存在
	if err := os.MkdirAll("avatars", 0755); err != nil {
		http.Error(w, "Cannot create avatars directory", http.StatusInternalServerError)
		return
	}

	// 保存文件
	filename := fmt.Sprintf("avatars/%d_%s", user.ID, header.Filename)
	out, err := os.Create(filename)
	if err != nil {
		http.Error(w, "Cannot save file", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	// 更新数据库中的头像URL
	avatarURL := "/" + filename
	if err := a.store.UpdateUserAvatar(user.ID, avatarURL); err != nil {
		http.Error(w, "Failed to update avatar in database", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, a.prefixed(`/profile`), http.StatusFound)
}

// getOAuth2Login 处理 OAuth2 登录跳转
func (a *Admin) getOAuth2Login(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// 验证 client_id 和 redirect_uri (这里只是简单示例，实际应用中需要更严格的验证)
	if clientID == "" || redirectURI == "" {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}

	// 构建授权 URL
	authURL := fmt.Sprintf("/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))

	// 检查用户是否已登录
	if user := a.store.AuthRequest(r); user != nil {
		// 如果用户已登录，直接跳转到授权页面
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// 如果用户未登录，显示登录页面，并将授权 URL 作为参数传递
	data := map[string]string{
		"authURL":     authURL,
		"clientID":    clientID,    // 添加 clientID
		"redirectURI": redirectURI, // 添加 redirectURI
		"scope":       scope,       // 添加 scope
		"state":       state,       // 添加 state
	}
	a.executeTemplate(w, "oauth2_login.html", data)
}
