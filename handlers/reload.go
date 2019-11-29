package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	casbin "github.com/casbin/casbin/v2"

	"skygear-rbac/constants"
)

type ReloadHandler struct {
	Enforcer *casbin.Enforcer
}

type ReloadInput struct {
	Domains         []DomainInput        `json:"domains,omitempty" schema:"domains,omitempty"`
	RoleAssignments RoleAssignmentsInput `json:"roleAssignments,omitempty" schema:"roleAssignments,omitempty"`
	Policies        PoliciesInput        `json:"policies,omitempty" schema:"policies,omitempty"`
}

func (h *ReloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := h.Enforcer.LoadPolicy()
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
		log.Println("♻ RBAC reloaded enforcer")
	case http.MethodPost:
		var err error

		input := ReloadInput{}
		json.NewDecoder(r.Body).Decode(&input)

		h.Enforcer.LoadPolicy()

		// Saves domain inheritance
		for _, domainInput := range input.Domains {
			if len(domainInput.Parent) == 0 {
				domainInput.Parent = "root"
			}

			_, err = h.Enforcer.AddNamedGroupingPolicy("g", domainInput.Parent, domainInput.Domain, constants.IsDomain)

			if err != nil {
				log.Fatal(err)
				w.WriteHeader(502)
			}

			if len(domainInput.SubDomains) != 0 {
				for _, subdomain := range domainInput.SubDomains {
					_, err = h.Enforcer.AddNamedGroupingPolicy("g", domainInput.Domain, subdomain, constants.IsDomain)
					if err != nil {
						log.Fatal(err)
						w.WriteHeader(502)
					}
				}
			}
		}

		// Saves role assignment
		for _, roleAssignmentInput := range input.RoleAssignments {
			if len(roleAssignmentInput.Subject) == 0 {
				roleAssignmentInput.Subject = constants.NoSubject
			}

			if roleAssignmentInput.Unassign {
				_, err = h.Enforcer.RemoveNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			} else {
				_, err = h.Enforcer.AddNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			}
		}

		// Saves access rights
		for _, policyInput := range input.Policies {
			if policyInput.Effect == "deny" {
				_, err = h.Enforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "deny")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			} else {
				_, err := h.Enforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "allow")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			}
		}

		h.Enforcer.SavePolicy()
	}
}
