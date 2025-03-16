package users

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"

	"database/sql"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lxlonion/golang-webauthn-example/db"
)

// User entity.
type User struct {
	ID          uint32 // Immutable
	Email       string // Mutable
	DisplayName string // Nickname
	AvatarURL   string // URL to avatar image

	webAuthnCredentials []webauthn.Credential
}

// for use as cookie. example only.
func (u *User) login() string {
	return fmt.Sprint(u.ID)
}

var _ webauthn.User = (*User)(nil)

func (u *User) WebAuthnID() []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, u.ID)
	return buf
}
func (u *User) WebAuthnName() string {
	return u.Email
}
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}
func (U *User) WebAuthnAvatar() string {
	return U.AvatarURL
}
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.webAuthnCredentials
}
func (u *User) WebAuthnIcon() string {
	return ""
}

// TODO: concurrency
type Store struct {
	db    *sql.DB
	users map[uint32]*User // 用作缓存
}

func NewStore() *Store {
	db, err := db.InitDB()
	if err != nil {
		panic(err)
	}

	s := &Store{
		db:    db,
		users: make(map[uint32]*User),
	}

	// 初始化时加载所有用户到内存
	if err := s.loadAllUsers(); err != nil {
		panic(err)
	}
	return s
}

func (s *Store) loadAllUsers() error {
	rows, err := s.db.Query("SELECT id, email, display_name, avatar_url, web_authn_credentials FROM users")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		var credsJSON string
		err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &credsJSON)
		if err != nil {
			return err
		}

		creds, err := credentialsFromJSON(credsJSON)
		if err != nil {
			return err
		}
		u.webAuthnCredentials = creds

		s.users[u.ID] = &u
	}
	return rows.Err()
}

func (s *Store) AuthRequest(r *http.Request) *User {
	login, _ := r.Cookie(`login`)
	if login == nil {
		return nil
	}
	for _, u := range s.users {
		if u.login() == login.Value {
			return u
		}
	}
	return nil
}

func (s *Store) AddWebAuthnCredentialFor(u *User, credential *webauthn.Credential) error {
	u.webAuthnCredentials = append(u.webAuthnCredentials, *credential)

	credsJSON, err := credentialsToJSON(u.webAuthnCredentials)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"UPDATE users SET web_authn_credentials = ? WHERE id = ?",
		credsJSON, u.ID,
	)
	return err
}

func (s *Store) MakeCookie(u *User, w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  `login`,
		Value: u.login(),
		Path:  "/",
	})
}

func (s *Store) RemoveCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  `login`,
		Value: "",
		Path:  "/",
	})
}

func (s *Store) GetUserByID(id uint32) *User {
	return s.users[id]
}

func (s *Store) AddNewUser(email string) (*User, error) {
	// 检查邮箱是否已存在
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", email).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("email address taken by someone else")
	}

	// 插入新用户
	result, err := s.db.Exec(
		"INSERT INTO users (email, display_name, avatar_url) VALUES (?, '', '')",
		email,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	u := &User{
		ID:          uint32(id),
		Email:       email,
		DisplayName: "",
	}
	s.users[u.ID] = u
	return u, nil
}

func (s *Store) UpdateUserAvatar(userID uint32, avatarURL string) error {
	_, err := s.db.Exec("UPDATE users SET avatar_url = ? WHERE id = ?", avatarURL, userID)
	if err != nil {
		return err
	}

	if user := s.users[userID]; user != nil {
		user.AvatarURL = avatarURL
	}
	return nil
}
