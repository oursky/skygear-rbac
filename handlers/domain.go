package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type Domain struct {
	Subject   string `json:"subject,omitempty" schema:"subject,omitempty"`
	Domain    string `json:"domain,omitempty" schema:"domain,omitempty"`
	SubDomain string `json:"subdomain,omitempty" schema:"subdomain,omitempty"`
}

type DomainInput struct {
	Subjects []string `json:"subjects,omitempty" schema:"subjects,omitempty"`
	Domain   string   `json:"domain,omitempty" schema:"domain,omitempty"`
	Parent string   `json:"parent,omitempty" schema:"subdomains,omitempty"`
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

		if len(input.Parent) != 0 {
			h.Enforcer.AddNamedGroupingPolicy("g2", input.Domain, input.Parent)
		}

		if len(input.Subjects) != 0 {
			for _, subject := range input.Subjects {
				h.Enforcer.AddNamedGroupingPolicy("g2", input.Domain, subject)
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

		if len(filter.Subject) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 1, filter.Subject)
		} else if len(filter.Domain) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 0, filter.Domain)
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g2", 1, filter.Domain)
		}
	}
}
