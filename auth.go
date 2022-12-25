package main

import (
	"net/http"
	"strings"

	"github.com/stretchr/gomniauth"
	"github.com/stretchr/objx"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(r.URL.Path, "/")
	action := segs[2]
	provider := segs[3]
	switch action {
	case "login":
		provider, err := gomniauth.Provider(provider)
		if err != nil {
			http.Error(w, "loginHandler can't choose provider", http.StatusInternalServerError)
			return
		}
		authUrl, err := provider.GetBeginAuthURL(nil, nil)
		if err != nil {
			http.Error(w, "loginHandler can't get provider url", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", authUrl)
		w.WriteHeader(http.StatusTemporaryRedirect)
	case "callback":
		provider, err := gomniauth.Provider(provider)
		if err != nil {
			http.Error(w, "loginHandler can't choose provider", http.StatusInternalServerError)
			return
		}
		creds, err := provider.CompleteAuth(objx.MustFromURLQuery(r.URL.RawQuery))
		if err != nil {
			http.Error(w, "loginHandler can't complete login", http.StatusInternalServerError)
			return
		}
		user, err := provider.GetUser(creds)
		if err != nil {
			http.Error(w, "loginHandler can't get user information", http.StatusInternalServerError)
			return
		}
		authCookie := objx.New(map[string]interface{}{
			"email": user.Email(),
			"name":  user.Name(),
		}).MustBase64()
		http.SetCookie(w, &http.Cookie{
			Name:   "auth",
			Value:  authCookie,
			MaxAge: 300,
			Path:   "/",
		})
		w.Header().Set("Location", "/secret")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}

type authMiddleware struct {
	next http.HandlerFunc
}

func (m authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("auth")
	if err == http.ErrNoCookie || c.Value == "" {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	m.next.ServeHTTP(w, r)
}
