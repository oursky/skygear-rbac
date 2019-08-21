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

func main() {
	dbURL := "postgres://postgres:@db?sslmode=disable"

	if len(os.Getenv("DATABASE_URL")) != 0 {
		dbURL = os.Getenv("DATABASE_URL")
	}

	var e *casbin.Enforcer
	if os.Getenv("ENV") == "development" {
		e, _ = casbin.NewEnforcer("./model.conf", "./policy.csv")
	} else {
		params, _ := pq.ParseURL(dbURL)
		a, err := xormadapter.NewAdapter("postgres", params)
		if err != nil {
			log.Fatal(err)
		}
		e, _ = casbin.NewEnforcer("./model.conf", a)
	}

	e.LoadPolicy()

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	r.Handle("/enforce", &handlers.EnforceHandler{Enforcer: e})
	r.Handle("/{domain}/subject/{subject}/role", &handlers.RoleHandler{Enforcer: e})
	r.Handle("/{domain}/role/{role}/policy", &handlers.PolicyHandler{Enforcer: e})
	r.Handle("/{domain}/role/{role}/subject", &handlers.SubjectHandler{Enforcer: e})
	r.Handle("/{domain}/role", &handlers.RoleHandler{Enforcer: e})
	r.Handle("/{domain}/policy", &handlers.PolicyHandler{Enforcer: e})
	r.Handle("/{domain}", &handlers.DomainHandler{Enforcer: e})

	log.Println("RBAC listening on 6543")
	log.Fatal(http.ListenAndServe(":6543", r))
}
