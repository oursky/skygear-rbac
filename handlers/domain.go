package handlers

import (
	"encoding/json"
	"net/http"
	"os"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"

	"skygear-rbac/constants"
)

type Domain struct {
	Subject    string   `json:"subject,omitempty" schema:"subject,omitempty"`
	Domain     string   `json:"domain,omitempty" schema:"domain,omitempty"`
	SubDomains []string `json:"subdomains,omitempty" schema:"subdomains,omitempty"`
}

type DomainInput struct {
	SubDomains []string `json:"subdomains,omitempty" schema:"subdomains,omitempty"`
	Subjects   []string `json:"subjects,omitempty" schema:"subjects,omitempty"`
	Domain     string   `json:"domain,omitempty" schema:"domain,omitempty"`
	Parent     string   `json:"parent,omitempty" schema:"parent,omitempty"`
}

type DomainHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *DomainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]

	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := Domain{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}
		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(filter.Domain) != 0 {
			raw := h.Enforcer.GetFilteredNamedGroupingPolicy("g", 0, filter.Domain)
			subdomains := []string{}
			for _, policy := range raw {
				if policy[2] == constants.IsDomain {
					subdomains = append(subdomains, policy[1])
				}
			}
			domain := &Domain{
				Domain:     filter.Domain,
				SubDomains: subdomains,
			}
			js, _ := json.Marshal(domain)
			w.Write(js)
		}
	case http.MethodPost:
		input := DomainInput{}
		json.NewDecoder(r.Body).Decode(&input)

		if len(domain) != 0 {
			input.Domain = domain
		}

		if len(input.Parent) == 0 {
			input.Parent = "root"
		}
		h.Enforcer.AddNamedGroupingPolicy("g", input.Parent, input.Domain, constants.IsDomain)

		if len(input.SubDomains) != 0 {
			for _, subdomain := range input.SubDomains {
				h.Enforcer.AddNamedGroupingPolicy("g", input.Domain, subdomain, constants.IsDomain)
			}
		}

		if len(input.Subjects) != 0 {
			for _, subject := range input.Subjects {
				h.Enforcer.AddNamedGroupingPolicy("g", subject, input.Domain, constants.IsDomain)
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
		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(filter.Subject) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g", 0, filter.Subject)
		} else if len(filter.Domain) != 0 {
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g", 0, filter.Domain)
			h.Enforcer.RemoveFilteredNamedGroupingPolicy("g", 1, filter.Domain)
		}
		if os.Getenv("ENV") != "development" {
			h.Enforcer.SavePolicy()
		}
	}
}
