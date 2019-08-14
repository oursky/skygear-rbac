package main

import (
	"log"
	"net/http"
	handlers "skygear-rbac/handlers"
	"time"

	"github.com/gorilla/mux"

	xormadapter "github.com/casbin/xorm-adapter"

	"github.com/casbin/casbin"
	pq "github.com/lib/pq"
)

func main() {
	params, _ := pq.ParseURL("postgres://postgres:@db?sslmode=disable")
	a, err := xormadapter.NewAdapter("postgres", params)

	if err != nil {
		log.Fatal(err)
	}

	e := casbin.NewEnforcer("./model.conf", a)

	e.LoadPolicy()

	r := mux.NewRouter()
	r.Handle("/enforce", &handlers.EnforceHandler{Enforcer: e})
	r.Handle("/policies", &handlers.PolicyHandler{Enforcer: e})
	// mux.Handle("/domains", &handlers.DomainHandler{Enforcer: e})
	r.Handle("/roles", &handlers.RoleHandler{Enforcer: e})
	srv := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:6543",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("RBAC listening on 6543")
	log.Fatal(srv.ListenAndServe())
}
