package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/oursky/skygear-rbac/pkg/context"
	filters "robpike.io/filter"
)

type Policy struct {
	Domain  string `json:"domain,omitempty" schema:"domain,omitempty"`
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Object  string `json:"object,omitempty" schema:"object,omitempty"`
	Action  string `json:"action,omitempty" schema:"action,omitempty"`
	Effect  string `json:"effect,omitempty" schema:"effect,omitempty"`
}

func (p Policy) ToRaw() []string {
	return []string{p.Domain, p.Subject, p.Object, p.Action, p.Effect}
}

func (p Policy) ToArgs() []interface{} {
	s := make([]interface{}, len(p.ToRaw()))
	for i, v := range p.ToRaw() {
		s[i] = v
	}
	return s
}

type PolicyInput struct {
	Domain  string `json:"domain,omitempty"`
	Subject string `json:"subject,omitempty"`
	Object  string `json:"object"`
	Action  string `json:"action,omitempty"`
	Effect  string `json:"effect,omitempty"`
}

type PoliciesInput []PolicyInput

func PoliciesFromCasbin(raw [][]string) []Policy {
	ps := []Policy{}

	for _, s := range raw {
		var effect string
		if len(s) >= 5 {
			effect = s[4]
		} else {
			effect = "allow"
		}
		ps = append(ps, Policy{
			Domain:  s[0],
			Subject: s[1],
			Object:  s[2],
			Action:  s[3],
			Effect:  effect,
		})
	}
	return ps
}

type PolicyHandler struct {
	AppContext *context.AppContext
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	role := mux.Vars(r)["role"]

	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := Policy{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(role) != 0 {
			filter.Subject = role
		}

		raw := h.AppContext.Enforcer.GetPolicy()
		policies := filters.Choose(PoliciesFromCasbin(raw), func(p Policy) bool {
			return ((len(filter.Domain) == 0 || filter.Domain == p.Domain) &&
				(len(filter.Object) == 0 || filter.Object == p.Object) &&
				(len(filter.Subject) == 0 || filter.Subject == p.Subject))
		})

		js, _ := json.Marshal(policies)
		w.Write(js)
		break
	case http.MethodPost:
		input := PoliciesInput{}
		json.NewDecoder(r.Body).Decode(&input)

		for _, policy := range input {
			if len(domain) != 0 {
				policy.Domain = domain
			}

			if len(role) != 0 {
				policy.Subject = role
			}

			if policy.Effect == "deny" {
				h.AppContext.Enforcer.RemovePolicy(policy.Domain, policy.Subject, policy.Object, policy.Action)
				h.AppContext.Enforcer.RemovePolicy(policy.Domain, policy.Subject, policy.Object, policy.Action, "allow")
				h.AppContext.Enforcer.AddPolicy(policy.Domain, policy.Subject, policy.Object, policy.Action, "deny")
			} else {
				h.AppContext.Enforcer.RemovePolicy(policy.Domain, policy.Subject, policy.Object, policy.Action, "deny")
				h.AppContext.Enforcer.AddPolicy(policy.Domain, policy.Subject, policy.Object, policy.Action, "allow")
			}
		}
		w.WriteHeader(200)
	case http.MethodDelete:
		decoder := schema.NewDecoder()
		filter := Policy{}
		err := decoder.Decode(&filter, r.URL.Query())

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(role) != 0 {
			filter.Subject = role
		}

		if err != nil {
			panic(err)
		}

		_, err = h.AppContext.Enforcer.RemovePolicy(filter.ToArgs()...)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
	}
}
