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

// LoginData 结构体用于存储登录页面所需的数据
type LoginData struct {
	Name string
}

// Admin 结构体包含管理后台所需的所有依赖和服务
type Admin struct {
	prefix       string                        // URL 前缀，用于管理后台的所有路由
	wa           *WebAuthn                     // WebAuthn 实例，用于处理 WebAuthn 相关的认证
	store        *Store                        // Store 实例，用于存储和管理用户信息
	templates    map[string]*template.Template // 模板缓存，用于存储预加载的 HTML 模板
	oauth2Server *server.Server                // OAuth2 服务器实例
}

// NewAdmin 创建一个新的 Admin 实例
func NewAdmin(store *Store, wa *WebAuthn, prefix string) *Admin {
	a := &Admin{
		store:        store,
		prefix:       prefix,
		wa:           wa,
		templates:    make(map[string]*template.Template),
		oauth2Server: OAuthServer, // 初始化 OAuth2 服务器
	}

	// 预加载 HTML 模板
	for _, f := range []string{`login.html`, `profile.html`, `oauth2_login.html`} {
		a.templates[f] = template.Must(template.ParseFiles(f))
	}

	return a
}

// Handler 配置管理后台的所有路由
func (a *Admin) Handler() http.Handler {
	m := http.NewServeMux()

	// 根路径重定向到 profile 页面
	m.Handle(`GET /{$}`, a.requireLogin(a.getRoot))
	// 静态资源文件服务
	m.Handle(`/`, http.FileServer(http.Dir(".")))

	// 登录、登出、注册处理
	m.HandleFunc(`GET /login`, a.getLogin)
	m.HandleFunc(`GET /logout`, a.getLogout)
	m.HandleFunc(`POST /register`, a.postRegister)
	// 头像上传处理
	m.Handle(`POST /avatar`, a.requireLogin(a.postAvatar))
	// 用户资料页面
	m.Handle(`GET /profile`, a.requireLogin(a.getProfile))

	// WebAuthn 路由
	const webAuthnPrefix = `/login/webauthn/`
	m.Handle(webAuthnPrefix, a.wa.Handler(webAuthnPrefix))

	// OAuth2 登录处理
	m.HandleFunc(`GET /oauth2/login`, a.getOAuth2Login) // 添加 OAuth2 登录处理

	// 添加对 webauthn.js 的单独路由，手动设置 Content-Type
	m.HandleFunc(`GET /webauthn.js`, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		http.ServeFile(w, r, "webauthn.js")
	})

	// 移除 URL 前缀
	return http.StripPrefix(strings.TrimSuffix(a.prefix, "/"), m)
}

// postRegister 处理用户注册
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

// prefixed 添加 URL 前缀
func (a *Admin) prefixed(s string) string {
	return path.Join(a.prefix, s)
}

// redirectToLogin 重定向到登录页面，并传递原始 URL
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

// requireLogin 检查用户是否已登录，如果未登录则重定向到登录页面
func (a *Admin) requireLogin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := a.store.AuthRequest(r); user == nil {
			a.redirectToLogin(w, r, r.RequestURI)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// getRoot 重定向到 profile 页面
func (a *Admin) getRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, a.prefixed(`/profile`), http.StatusFound)
}

// executeTemplate 执行 HTML 模板
func (a *Admin) executeTemplate(w io.Writer, name string, data any) {
	t := a.templates[name]
	if t == nil {
		panic(`No such template：` + name)
	}
	if err := t.Execute(w, data); err != nil {
		log.Println(err)
	}
}

// getLogin 显示登录页面
func (a *Admin) getLogin(w http.ResponseWriter, r *http.Request) {
	// 如果用户已经登录，则重定向到 profile 页面
	if a.store.AuthRequest(r) != nil {
		to := a.prefixed(`/profile`)
		if u := r.URL.Query().Get(`u`); u != "" {
			to = u
		}
		http.Redirect(w, r, to, http.StatusFound)
		return
	}

	d := LoginData{
		Name: "Example",
	}
	a.executeTemplate(w, `login.html`, &d)
}

// getLogout 处理用户登出
func (a *Admin) getLogout(w http.ResponseWriter, r *http.Request) {
	a.store.RemoveCookie(w, r)
	http.Redirect(w, r, a.prefixed(`/login`), http.StatusFound)
}

// ProfileData 结构体用于存储用户资料页面所需的数据
type ProfileData struct {
	User *User
}

// PublicKeys 获取用户的公钥列表
func (d *ProfileData) PublicKeys() []string {
	ss := make([]string, 0, len(d.User.WebAuthnCredentials()))
	for _, c := range d.User.WebAuthnCredentials() {
		ss = append(ss, base64.RawURLEncoding.EncodeToString(c.ID))
	}
	return ss
}

// getProfile 显示用户资料页面
func (a *Admin) getProfile(w http.ResponseWriter, r *http.Request) {
	d := &ProfileData{
		User: a.store.AuthRequest(r),
	}
	a.executeTemplate(w, `profile.html`, &d)
}

// postAvatar 处理用户头像上传
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
