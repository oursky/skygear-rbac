package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"skygear-rbac/config"
	handlers "skygear-rbac/handlers"

	"github.com/gorilla/mux"

	xormadapter "github.com/casbin/xorm-adapter"

	"github.com/casbin/casbin/v2"
	pq "github.com/lib/pq"
)

func newEnforcer() (*casbin.Enforcer, error) {
	if config.LoadFromEnv("ENV", "") == "development" {
		enforcer, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
		if err != nil {
			return nil, err
		}
		return enforcer, nil
	}

	databaseURL := config.LoadFromEnv("DATABASE_URL", "postgres://postgres:@db?sslmode=disable")
	params, _ := pq.ParseURL(databaseURL)
	adapter, err := xormadapter.NewAdapter("postgres", params)
	if err != nil {
		return nil, err
	}
	enforcer, err := casbin.NewEnforcer("./model.conf", adapter)
	if err != nil {
		return nil, err
	}
	return enforcer, nil
}

func reloadEnforcer(enforcer *casbin.Enforcer) error {
	return enforcer.LoadPolicy()
}

func main() {
	enforcer, err := newEnforcer()
	if err != nil {
		log.Panic(err)
	}
	err = reloadEnforcer(enforcer)
	if err != nil {
		log.Panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	// For reloading policy / model if it is updated externally e.g. Directly updated rules in database
	r.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		err := reloadEnforcer(enforcer)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
	})
	r.Handle("/enforce", &handlers.EnforceHandler{Enforcer: enforcer})
	r.Handle("/{domain}/subject/{subject}/role", &handlers.RoleHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/policy", &handlers.PolicyHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/subject", &handlers.SubjectHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/user", &handlers.UserHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role", &handlers.RoleHandler{Enforcer: enforcer})
	r.Handle("/{domain}/policy", &handlers.PolicyHandler{Enforcer: enforcer})
	r.Handle("/{domain}", &handlers.DomainHandler{Enforcer: enforcer})

	log.Println("RBAC listening on 6543 🚀")
	log.Fatal(http.ListenAndServe(":6543", r))
}
