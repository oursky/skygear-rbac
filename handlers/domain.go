package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type Domain struct {
	SubjectID string `json:"subjectId,omitempty" schema:"subjectId,omitempty"`
	Domain    string `json:"domain,omitempty" schema:"domain,omitempty"`
	SubDomain string `json:"subdomain,omitempty" schema:"subdomain,omitempty"`
}

type DomainInput struct {
	SubjectIDs []string `json:"subjectIds,omitempty" schema:"subjectIds,omitempty"`
	Domain     string   `json:"domain,omitempty" schema:"domain,omitempty"`
	ParentID   string   `json:"parentId,omitempty" schema:"subdomains,omitempty"`
}

type DomainHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *DomainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := Domain{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}

		if len(filter.Domain) != 0 {
			raw := h.Enforcer.GetFilteredNamedGroupingPolicy("g2", 1, filter.Domain)
			subdomains := []string{}
			for _, policy := range raw {
				subdomains = append(subdomains, policy[0])
			}
			js, _ := json.Marshal(subdomains)
			w.Write(js)
		}
	case http.MethodPost:
		input := DomainInput{}
		json.NewDecoder(r.Body).Decode(&input)

		if len(input.ParentID) != 0 {
			h.Enforcer.AddNamedGroupingPolicy("g2", input.Domain, input.ParentID)
		}

		if len(input.SubjectIDs) != 0 {
			for _, subjectID := range input.SubjectIDs {
				h.Enforcer.AddNamedGroupingPolicy("g2", input.Domain, subjectID)
			}
		}

		h.Enforcer.SavePolicy()
	case http.MethodDelete:
		decoder := schema.NewDecoder()
		filter := Domain{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}

		if len(filter.SubjectID) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 1, filter.SubjectID)
		} else if len(filter.Domain) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 0, filter.Domain)
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 1, filter.Domain)
		}
	}
}
