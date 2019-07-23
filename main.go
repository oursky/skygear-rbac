package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	handlers "skygear-rbac/handlers"
	"strconv"
	"strings"

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

type EnforceRequest struct {
	Subject Subject `json:"subject,omitempty"`
	Action  string  `json:"action,omitempty"`
	Object  Object  `json:"object,omitempty"`
}

func EntityUnder(args ...interface{}) (interface{}, error) {
	subject1 := args[0].(Subject)
	// name2 := args[1].(string)

	return strings.HasPrefix("asia:hk", subject1.Meta.Entity), nil
}

func main() {
	e := casbin.NewEnforcer("./model.conf", "./policy.csv")

	// e.AddFunction("entity_under", EntityUnder)

	http.HandleFunc("/policy/enforce", func(w http.ResponseWriter, r *http.Request) {
		var enforceReq EnforceRequest
		json.NewDecoder(r.Body).Decode(&enforceReq)

		res, err := e.EnforceSafe(enforceReq.Subject, enforceReq.Object, enforceReq.Action)
		if err != nil {
			fmt.Println(err)
		}
		w.Write([]byte(strconv.FormatBool(res)))
	})

	http.Handle("/policy", &handlers.PolicyHandler{})
	log.Fatal(http.ListenAndServe(":3001", nil))
}
