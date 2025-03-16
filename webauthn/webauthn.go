package webauthn

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lxlonion/golang-webauthn-example/users"
)

type WebAuthn struct {
	wa    *webauthn.WebAuthn
	store *users.Store

	registrationSessions map[uint32]*webauthn.SessionData
	loginSessions        map[string]*webauthn.SessionData
}

func NewWebAuthn(store *users.Store, hostname string, displayName string, origins []string) *WebAuthn {
	config := &webauthn.Config{
		RPID:          hostname,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	}
	wa, err := webauthn.New(config)
	if err != nil {
		panic(err)
	}
	return &WebAuthn{
		store: store,
		wa:    wa,

		registrationSessions: make(map[uint32]*webauthn.SessionData),
		loginSessions:        make(map[string]*webauthn.SessionData),
	}
}

func writeJsonBody(w http.ResponseWriter, data any) error {
	w.Header().Add(`Content-Type`, `application/json`)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(data); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (a *WebAuthn) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(`POST /register:begin`, a.BeginRegistration)
	mux.HandleFunc(`POST /register:finish`, a.FinishRegistration)
	mux.HandleFunc(`POST /login:begin`, a.BeginLogin)
	mux.HandleFunc(`POST /login:finish`, a.FinishLogin)

	mux.HandleFunc(`POST /base64:encode`, a.base64Encode)
	mux.HandleFunc(`POST /base64:decode`, a.base64Decode)

	return http.StripPrefix(strings.TrimSuffix(prefix, "/"), mux)
}

func (a *WebAuthn) base64Encode(w http.ResponseWriter, r *http.Request) {
	var bs []byte
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&bs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	str := base64.RawURLEncoding.EncodeToString(bs)
	w.Write([]byte(str))
}

func (a *WebAuthn) base64Decode(w http.ResponseWriter, r *http.Request) {
	var s string
	if all, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		s = string(all)
	}
	bs, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ibs := make([]int, 0, len(bs))
	for _, b := range bs {
		ibs = append(ibs, int(b))
	}
	if err := json.NewEncoder(w).Encode(ibs); err != nil {
		log.Println(err)
		return
	}
}

func (a *WebAuthn) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user := a.store.AuthRequest(r)
	if user == nil {
		http.Error(w, "You should be logged in before you can register a credential.", http.StatusForbidden)
		return
	}

	options, session, err := a.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeJsonBody(w, options); err != nil {
		return
	}

	a.registrationSessions[user.ID] = session
}

func (a *WebAuthn) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := a.store.AuthRequest(r)
	if user == nil {
		panic(`login first`)
	}

	session, ok := a.registrationSessions[user.ID]
	if !ok {
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}
	delete(a.registrationSessions, user.ID)

	credential, err := a.wa.FinishRegistration(user, *session, r)
	if err != nil {
		http.Error(w, "Registration fail："+err.Error(), http.StatusInternalServerError)
		return
	}

	a.store.AddWebAuthnCredentialFor(user, credential)

	w.WriteHeader(http.StatusOK)
}

func (a *WebAuthn) BeginLogin(w http.ResponseWriter, r *http.Request) {
	options, session, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeJsonBody(w, options); err != nil {
		return
	}
	a.loginSessions[session.Challenge] = session
}

func (a *WebAuthn) FinishLogin(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get(`challenge`)
	session, ok := a.loginSessions[challenge]
	if !ok {
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}
	delete(a.loginSessions, challenge)

	var user *users.User

	credential, err := a.wa.FinishDiscoverableLogin(a.findUser(&user), *session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	a.store.AddWebAuthnCredentialFor(user, credential)

	a.store.MakeCookie(user, w, r)

	w.WriteHeader(http.StatusOK)
}

func (a *WebAuthn) findUser(user **users.User) func(rawID, userHandle []byte) (webauthn.User, error) {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		if *user != nil {
			return nil, fmt.Errorf(`user already found`)
		}
		if len(userHandle) != 4 {
			return nil, fmt.Errorf(`bad user handle length: %v`, len(userHandle))
		}
		id := binary.LittleEndian.Uint32(userHandle)
		u := a.store.GetUserByID(id)
		if u != nil {
			*user = u
			return u, nil
		}
		return nil, fmt.Errorf(`no such user`)
	}
}
