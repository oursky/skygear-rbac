package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"
)

type Policy struct {
	Domain    string `json:"domain,omitempty" schema:"domain,omitempty"`
	SubjectID string `json:"subjectId,omitempty" schema:"subjectId,omitempty"`
	ObjectID  string `json:"objectId,omitempty" schema:"objectId,omitempty"`
	Action    string `json:"action,omitempty" schema:"action,omitempty"`
}

func (p Policy) ToRaw() []string {
	return []string{p.Domain, p.SubjectID, p.ObjectID, p.Action}
}

func (p Policy) ToArgs() []interface{} {
	s := make([]interface{}, len(p.ToRaw()))
	for i, v := range p.ToRaw() {
		s[i] = v
	}
	return s
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

type PolicyHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := Policy{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		raw := h.Enforcer.GetFilteredPolicy(0, filter.Domain)
		policies := filters.Choose(PoliciesFromCasbin(raw), func(p Policy) bool {
			return ((len(filter.ObjectID) == 0 || filter.ObjectID == p.ObjectID) &&
				(len(filter.SubjectID) == 0 || filter.ObjectID == p.SubjectID))
		})

		js, _ := json.Marshal(policies)
		w.Write(js)
		break
	case http.MethodPost:
		input := PolicyInput{}
		json.NewDecoder(r.Body).Decode(&input)
		h.Enforcer.AddPolicy(input.Domain, input.SubjectID, input.ObjectID, input.Action)
		js, _ := json.Marshal(PoliciesFromCasbin(h.Enforcer.GetPolicy()))
		w.Write(js)
	case http.MethodDelete:
		decoder := schema.NewDecoder()
		filter := Policy{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		h.Enforcer.RemovePolicy(filter.ToArgs()...)
	}
}
