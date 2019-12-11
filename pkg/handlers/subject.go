package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/oursky/skygear-rbac/pkg/constants"
	"github.com/oursky/skygear-rbac/pkg/context"
	filters "robpike.io/filter"
)

type Group struct {
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Domain  string `json:"domain,omitempty" schema:"domain,omitempty"`
	Role    string `json:"role,omitempty" schema:"role,omitempty"`
}

func GroupsFromCasbin(raw [][]string) []Group {
	ss := []Group{}

	for _, s := range raw {
		ss = append(ss, Group{
			Subject: s[0],
			Role:    s[1],
			Domain:  s[2],
		})
	}
	return ss
}

type SubjectFilter struct {
	Domain string `json:"domain,omitempty" schema:"domain,omitempty"`
	Role   string `json:"role,omitempty" schema:"role,omitempty"`
}

type SubjectHandler struct {
	AppContext *context.AppContext
}

func (h *SubjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	role := mux.Vars(r)["role"]

	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := SubjectFilter{}
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

		raw := h.AppContext.Enforcer.GetFilteredNamedGroupingPolicy("g", 2, filter.Domain)

		groups := filters.Choose(GroupsFromCasbin(raw), func(g Group) bool {
			return ((len(filter.Domain) == 0 || filter.Domain == g.Domain) &&
				g.Domain != constants.IsDomain &&
				(len(filter.Role) == 0 || filter.Role == g.Role) &&
				(g.Subject != constants.NoSubject))
		})
		var subjects []string
		for _, group := range groups.([]Group) {
			subjects = append(subjects, group.Subject)
		}
		js, _ := json.Marshal(subjects)
		w.Write(js)
	}
}
