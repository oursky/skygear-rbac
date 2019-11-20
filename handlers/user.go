package handlers

import (
	"encoding/json"
	"net/http"
	"skygear-rbac/constants"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"
)

type UserFilter struct {
	Domain string `json:"domain,omitempty" schema:"domain,omitempty"`
	Role   string `json:"role,omitempty" schema:"role,omitempty"`
}

type UserHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	role := mux.Vars(r)["role"]

	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := UserFilter{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(role) != 0 {
			filter.Role = role
		}

		raw := h.Enforcer.GetFilteredNamedGroupingPolicy("g", 2, filter.Domain)
		groups := filters.Choose(GroupsFromCasbin(raw), func(g Group) bool {
			return ((len(filter.Domain) == 0 || filter.Domain == g.Domain) &&
				g.Domain != constants.IsDomain &&
				(len(filter.Role) == 0 || filter.Role == g.Role) &&
				(g.Subject != constants.NoSubject) &&
				(!h.Enforcer.HasNamedGroupingPolicy("g3", g.Subject, "role", g.Domain) || h.Enforcer.HasNamedGroupingPolicy("g3", g.Subject, "user", g.Domain)))
		})
		var Users []string
		for _, group := range groups.([]Group) {
			Users = append(Users, group.Subject)
		}
		js, _ := json.Marshal(Users)
		w.Write(js)
	}
}
