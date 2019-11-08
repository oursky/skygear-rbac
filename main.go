package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	handlers "skygear-rbac/handlers"

	"github.com/gorilla/mux"

	xormadapter "github.com/casbin/xorm-adapter"

	"github.com/casbin/casbin/v2"
	pq "github.com/lib/pq"
)

// ReloadEnforcer accepts enforcer and reloads model and policy for it
func ReloadEnforcer(e *casbin.Enforcer) (*casbin.Enforcer, error) {
	dbURL := "postgres://postgres:@db?sslmode=disable"

	if len(os.Getenv("DATABASE_URL")) != 0 {
		dbURL = os.Getenv("DATABASE_URL")
	}

	if os.Getenv("ENV") == "development" {
		var err error
		e, err = casbin.NewEnforcer("./model.conf", "./policy.csv")
		if err != nil {
			return e, err
		}
	} else {
		params, _ := pq.ParseURL(dbURL)
		a, err := xormadapter.NewAdapter("postgres", params)
		if err != nil {
			return e, err
		}
		e, err = casbin.NewEnforcer("./model.conf", a)
		if err != nil {
			return e, err
		}
	}

	err := e.LoadPolicy()
	if err != nil {
		return e, err
	}

	return e, nil
}

func main() {
	var e *casbin.Enforcer

	_, err := ReloadEnforcer(e)
	if err != nil {
		log.Panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	// For reloading policy / model if it is updated externally e.g. Directly updated rules in database
	r.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		_, err := ReloadEnforcer(e)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
	})
	r.Handle("/enforce", &handlers.EnforceHandler{Enforcer: e})
	r.Handle("/{domain}/subject/{subject}/role", &handlers.RoleHandler{Enforcer: e})
	r.Handle("/{domain}/role/{role}/policy", &handlers.PolicyHandler{Enforcer: e})
	r.Handle("/{domain}/role/{role}/subject", &handlers.SubjectHandler{Enforcer: e})
	r.Handle("/{domain}/role/{role}/user", &handlers.UserHandler{Enforcer: e})
	r.Handle("/{domain}/role", &handlers.RoleHandler{Enforcer: e})
	r.Handle("/{domain}/policy", &handlers.PolicyHandler{Enforcer: e})
	r.Handle("/{domain}", &handlers.DomainHandler{Enforcer: e})

	log.Println("RBAC listening on 6543 🚀")
	log.Fatal(http.ListenAndServe(":6543", r))
}
