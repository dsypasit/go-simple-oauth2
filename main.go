package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/joho/godotenv"
	"github.com/stretchr/gomniauth"
	"github.com/stretchr/gomniauth/providers/google"
	"github.com/stretchr/objx"
	"github.com/stretchr/signature"
)

type templateHandler struct {
	once     sync.Once
	filename string
	tmpl     *template.Template
}

func (t templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.once.Do(func() {
		t.tmpl = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
	})

	data := map[string]interface{}{}
	if authCookie, err := r.Cookie("auth"); err == nil {
		data["userData"] = objx.MustFromJSON(authCookie.Value)
	}
	t.tmpl.Execute(w, data)
}

func main() {
	godotenv.Load()
	gomniauth.SetSecurityKey(signature.RandomKey(64))
	gomniauth.WithProviders(
		google.New(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"), "http://localhost:3000/auth/callback/google"),
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "Hello world")
	})
	mux.Handle("/login", &templateHandler{filename: "login.html"})
	mux.HandleFunc("/auth/", loginHandler)
	mux.Handle("/secret", &authMiddleware{next: func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		if authCookie, err := r.Cookie("auth"); err == nil {
			data = objx.MustFromBase64(authCookie.Value)
		}
		log.Printf("%#v\n", data)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Hi %s", data["email"])
	}})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "auth",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})

	server := http.Server{
		Handler: mux,
		Addr:    ":3000",
	}

	log.Println("serve by port :3000")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
