package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type Policy struct {
	Domain    string `json:"domain,omitempty"`
	SubjectID string `json:"subjectId,omitempty"`
	ObjectID  string `json:"objectId,omitempty"`
	Action    string `json:"action,omitempty"`
}

func PoliciesFromCasbin(raw [][]string) []Policy {
	ps := []Policy{}

	for _, s := range raw {
		ps = append(ps, Policy{
			Domain:    s[0],
			SubjectID: s[1],
			ObjectID:  s[2],
			Action:    s[3],
		})
	}
	return ps
}

type PolicyFilter struct {
	Domain    string `schema:"domain,omitempty"`
	SubjectID string `schema:"subjectId,omitempty"`
	ObjectID  string `schema:"objectId,omitempty"`
}

type PolicyHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoder := schema.NewDecoder()
	filter := PolicyFilter{}
	decoder.Decode(&filter, r.URL.Query())
	// err := json.NewDecoder(r.Body).Decode(&filter)

	// if err != nil {
	// 	panic(err)
	// }

	// policy := Policy{"Alex", "Form/123", "read"}
	raw := h.Enforcer.GetFilteredPolicy(0, filter.Domain)
	// raw := h.Enforcer.GetPolicy()
	policies := PoliciesFromCasbin(raw)

	js, _ := json.Marshal(policies)
	w.Write(js)
}
