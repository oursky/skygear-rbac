package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"

	"skygear-rbac/constants"
)

func RoleAssignmentsFromCasbin(raw [][]string) []RoleAssignment {
	ras := []RoleAssignment{}

	for _, s := range raw {
		ra := RoleAssignment{
			Subject: s[0],
			Role:    s[1],
			Domain:  s[2],
		}

		if ra.Subject == constants.NoSubject {
			ra.Subject = ""
		}
		ras = append(ras, ra)

	}
	return ras
}

type RoleAssignment struct {
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role    string `json:"role,omitempty" schema:"role,omitempty"`
	Domain  string `json:"domain" schema:"domain"`
}

type RoleAssignmentsInput []RoleAssignmentInput

type RoleAssignmentInput struct {
	Subject  string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role     string `json:"role,omitempty" schema:"role,omitempty"`
	Domain   string `json:"domain" schema:"domain"`
	Unassign bool   `json:"unassign,omitempty" schema:"unassign,omitempty"`
}

type RoleHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *RoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	subject := mux.Vars(r)["subject"]

	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(subject) != 0 {
			filter.Subject = subject
		}

		if len(filter.Subject) == 0 {
			filter.Subject = constants.NoSubject
		}

		raw := h.Enforcer.GetFilteredNamedGroupingPolicy("g", 0, filter.Subject)
		roleAssignments := filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
			return (len(filter.Domain) == 0 || filter.Domain == ra.Domain)
		})
		js, _ := json.Marshal(roleAssignments)
		w.Write(js)
	case http.MethodPost:
		inputs := RoleAssignmentsInput{}
		json.NewDecoder(r.Body).Decode(&inputs)

		roleAssignments := []RoleAssignment{}

		for _, input := range inputs {
			if len(domain) != 0 {
				input.Domain = domain
			}

			if len(subject) != 0 {
				input.Subject = subject
			}

			if len(input.Subject) == 0 {
				input.Subject = constants.NoSubject
			}

			if input.Unassign {
				h.Enforcer.RemoveNamedGroupingPolicy("g", input.Subject, input.Role, input.Domain)
			} else {
				h.Enforcer.AddNamedGroupingPolicy("g", input.Subject, input.Role, input.Domain)
			}

			raw := h.Enforcer.GetFilteredNamedGroupingPolicy("g", 0, input.Subject)
			for _, assignment := range filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
				return (len(input.Domain) == 0 || input.Domain == ra.Domain)
			}).([]RoleAssignment) {
				roleAssignments = append(roleAssignments, assignment)
			}
		}
		h.Enforcer.SavePolicy()

		js, _ := json.Marshal(roleAssignments)
		w.Write(js)
	case http.MethodDelete:
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(subject) != 0 {
			filter.Subject = subject
		}

		if len(filter.Subject) == 0 {
			filter.Subject = constants.NoSubject
		}

		h.Enforcer.RemoveNamedGroupingPolicy("g", filter.Subject, filter.Role, filter.Domain)

		if filter.Subject == constants.NoSubject {
			h.Enforcer.AddNamedGroupingPolicy("g4", filter.Subject, "disabled", filter.Domain)
		}

		h.Enforcer.SavePolicy()
	}
}
