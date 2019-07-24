package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type RoleAssignment struct {
	SubjectID string `json:"subjectId,omitempty" schema:"subjectId,omitempty"`
	Role      string `json:"role,omitempty" schema:"role,omitempty"`
}

type RoleAssignmentInput struct {
	SubjectID string `json:"subjectId,omitempty" schema:"subjectId,omitempty"`
	Role      string `json:"role,omitempty" schema:"role,omitempty"`
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

		roles := h.Enforcer.GetImplicitRolesForUser(filter.SubjectID)
		js, _ := json.Marshal(roles)
		w.Write(js)
	case http.MethodPost:
		input := RoleAssignmentInput{}
		json.NewDecoder(r.Body).Decode(&input)
		h.Enforcer.AddRoleForUser(input.SubjectID, input.Role)
		roles := h.Enforcer.GetImplicitRolesForUser(input.SubjectID)
		js, _ := json.Marshal(roles)
		w.Write(js)
	case http.MethodDelete:
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		h.Enforcer.DeleteRoleForUser(filter.SubjectID, filter.Role)
	}
}
