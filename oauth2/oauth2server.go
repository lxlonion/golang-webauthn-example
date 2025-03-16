package oauth2

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
	"github.com/lxlonion/golang-webauthn-example/users"
)

var OAuthServer *server.Server

// InitOAuthServer initializes the OAuth2 manager and server
func InitOAuthServer(storeInstance *users.Store) {
	manager := manage.NewDefaultManager()
	// Use in-memory token storage
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// Use database client storage
	clientStore := store.NewClientStore()

	// Load client information from the database
	rows, err := storeInstance.DB().Query("SELECT client_id, client_secret, domain FROM oauth2_clients")
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
	srv.SetUserAuthorizationHandler(userAuthorizeHandler(storeInstance))

	OAuthServer = srv
}

// userAuthorizeHandler checks if the user is logged in (calls the global storeInstance)
func userAuthorizeHandler(storeInstance *users.Store) func(w http.ResponseWriter, r *http.Request) (string, error) {
	return func(w http.ResponseWriter, r *http.Request) (string, error) {
		user := storeInstance.AuthRequest(r)
		if user == nil {
			return "", fmt.Errorf("user not logged in")
		}
		return fmt.Sprint(user.ID), nil
	}
}

// OAuthAuthorizeHandler handles /oauth2/authorize requests
func OAuthAuthorizeHandler(storeInstance *users.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the user is logged in
		user := storeInstance.AuthRequest(r)
		if user == nil {
			// If the user is not logged in, redirect to the OAuth2 login page
			clientID := r.URL.Query().Get("client_id")
			redirectURI := r.URL.Query().Get("redirect_uri")
			scope := r.URL.Query().Get("scope")
			state := r.URL.Query().Get("state")

			// Build the redirect URL, including client_id and redirect_uri
			loginURL := fmt.Sprintf("/admin/oauth2/login?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))

			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		if err := OAuthServer.HandleAuthorizeRequest(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

// OAuthTokenHandler handles /oauth2/token requests
func OAuthTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := OAuthServer.HandleTokenRequest(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

// UserInfo represents user information
type UserInfo struct {
	ID        uint32 `json:"id"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// OAuthUserHandler handles /oauth2/user requests and returns user information
func OAuthUserHandler(storeInstance *users.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the access token from the Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "No Authorization header", http.StatusUnauthorized)
			return
		}

		// Handle "Bearer <token>" format
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}
		accessToken := parts[1]

		// Validate the access token
		ti, err := OAuthServer.Manager.LoadAccessToken(r.Context(), accessToken)
		if err != nil {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		// Get the user ID
		userID := ti.GetUserID()
		if userID == "" {
			http.Error(w, "No user ID associated with token", http.StatusUnauthorized)
			return
		}

		// Get user information from the store
		uid := uint32(0)
		fmt.Sscanf(userID, "%d", &uid)
		user := storeInstance.GetUserByID(uid)
		if user == nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Construct the user information response
		userInfo := UserInfo{
			ID:        user.ID,
			Email:     user.Email,
			AvatarURL: user.AvatarURL,
		}

		// Set the response header
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Return the JSON response
		if err := json.NewEncoder(w).Encode(userInfo); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}
