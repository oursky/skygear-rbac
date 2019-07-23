package handlers

import (
	"encoding/json"
	"net/http"

	casbin "github.com/casbin/casbin"
)

type RoleHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *RoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		roles := h.Enforcer.GetImplicitRolesForUser("alice")
		js, _ := json.Marshal(roles)
		w.Write(js)
	}
}
