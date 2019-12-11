package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/oursky/skygear-rbac/pkg/constants"
	"github.com/oursky/skygear-rbac/pkg/context"
)

type ReloadHandler struct {
	AppContext *context.AppContext
}

type ReloadInput struct {
	Domains         []DomainInput        `json:"domains,omitempty" schema:"domains,omitempty"`
	RoleAssignments RoleAssignmentsInput `json:"roleAssignments,omitempty" schema:"roleAssignments,omitempty"`
	Policies        PoliciesInput        `json:"policies,omitempty" schema:"policies,omitempty"`
}

func (h *ReloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var err error

		input := ReloadInput{}
		json.NewDecoder(r.Body).Decode(&input)

		h.AppContext.Enforcer.EnableAutoSave(false)
		h.AppContext.Enforcer.ClearPolicy()

		// Saves domain inheritance
		for _, domainInput := range input.Domains {
			if len(domainInput.Parent) == 0 {
				domainInput.Parent = "root"
			}

			_, err = h.AppContext.Enforcer.AddNamedGroupingPolicy("g", domainInput.Parent, domainInput.Domain, constants.IsDomain)

			if err != nil {
				log.Fatal(err)
				w.WriteHeader(502)
			}

			if len(domainInput.SubDomains) != 0 {
				for _, subdomain := range domainInput.SubDomains {
					_, err = h.AppContext.Enforcer.AddNamedGroupingPolicy("g", domainInput.Domain, subdomain, constants.IsDomain)
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
				_, err = h.AppContext.Enforcer.RemoveNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			} else {
				_, err = h.AppContext.Enforcer.AddNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			}
		}

		// Saves access rights
		for _, policyInput := range input.Policies {
			if policyInput.Effect == "deny" {
				_, err = h.AppContext.Enforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "deny")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			} else {
				_, err := h.AppContext.Enforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "allow")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(502)
				}
			}
		}
		h.AppContext.Enforcer.SavePolicy()
	}
}
