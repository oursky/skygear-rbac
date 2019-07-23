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

func (p Policy) ToCasbin() []string {
	return []string{p.Domain, p.SubjectID, p.ObjectID, p.Action}
}

type PolicyInput struct {
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
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := PolicyFilter{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		raw := h.Enforcer.GetFilteredPolicy(0, filter.Domain)
		policies := PoliciesFromCasbin(raw)

		js, _ := json.Marshal(policies)
		w.Write(js)
		break
	case http.MethodPost:
		input := PolicyInput{}
		json.NewDecoder(r.Body).Decode(&input)
		h.Enforcer.AddPolicy(input.Domain, input.SubjectID, input.ObjectID, input.Action)
		js, _ := json.Marshal(PoliciesFromCasbin(h.Enforcer.GetPolicy()))
		w.Write(js)
	}
}
