package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"
)

func RoleAssignmentsFromCasbin(raw [][]string) []RoleAssignment {
	ras := []RoleAssignment{}

	for _, s := range raw {
		ras = append(ras, RoleAssignment{
			Subject: s[0],
			Role:    s[1],
			Domain:  s[2],
		})
	}
	return ras
}

type RoleAssignment struct {
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role    string `json:"role,omitempty" schema:"role,omitempty"`
	Domain  string `json:"domain" schema:"domain"`
}

type RoleAssignmentInput struct {
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role    string `json:"role,omitempty" schema:"role,omitempty"`
	Domain  string `json:"domain" schema:"domain"`
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

		raw := h.Enforcer.GetFilteredGroupingPolicy(0, filter.Subject)
		roleAssignments := filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
			return (len(filter.Domain) == 0 || filter.Domain == ra.Domain)
		})
		js, _ := json.Marshal(roleAssignments)
		w.Write(js)
	case http.MethodPost:
		input := RoleAssignmentInput{}
		json.NewDecoder(r.Body).Decode(&input)

		if len(domain) != 0 {
			input.Domain = domain
		}

		if len(subject) != 0 {
			input.Subject = subject
		}

		h.Enforcer.AddGroupingPolicy(input.Subject, input.Role, input.Domain)
		// h.Enforcer.AddNamedGroupingPolicy("g3", input.Subject, "user")
		h.Enforcer.AddNamedGroupingPolicy("g3", input.Role, "role")
		raw := h.Enforcer.GetFilteredGroupingPolicy(0, input.Subject)
		roleAssignments := filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
			return (len(input.Domain) == 0 || input.Domain == ra.Domain)
		})
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

		h.Enforcer.RemoveGroupingPolicy(filter.Subject, filter.Role, filter.Domain)
	}
}
