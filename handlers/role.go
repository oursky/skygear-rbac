package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"
)

func RoleAssignmentsFromCasbin(raw [][]string) []RoleAssignment {
	ra := []RoleAssignment{}

	for _, s := range raw {
		ra = append(ra, RoleAssignment{
			Subject: s[0],
			Role:    s[1],
			Domain:  s[2],
		})
	}
	return ra
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
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
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
		h.Enforcer.AddGroupingPolicy(input.Subject, input.Role, input.Domain)
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

		h.Enforcer.RemoveGroupingPolicy(filter.Subject, filter.Role, filter.Domain)
	}
}
