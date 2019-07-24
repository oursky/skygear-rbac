package main

import (
	"log"
	"net/http"
	handlers "skygear-rbac/handlers"

	"github.com/casbin/casbin"
)

type Meta struct {
	Entity string `json:"entity,omitempty"`
}

type Subject struct {
	Id   string `json:"id,omitempty"`
	Meta Meta   `json:"meta,omitempty"`
}

type Object struct {
	Id string `json:"id,omitempty"`
}

func main() {
	e := casbin.NewEnforcer("./model.conf", "./policy.csv")

	http.Handle("/policy/enforce", &handlers.EnforceHandler{Enforcer: e})
	http.Handle("/policy", &handlers.PolicyHandler{Enforcer: e})
	http.Handle("/domains", &handlers.DomainHandler{Enforcer: e})
	http.Handle("/roles", &handlers.RoleHandler{Enforcer: e})

	log.Fatal(http.ListenAndServe(":3001", nil))
}
