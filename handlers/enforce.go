package handlers

import (
	"net/http"
	"strconv"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type EnforceInput struct {
	Domain    string `json:"domain,omitempty" schema:"domain,omitempty"`
	SubjectID string `json:"subjectId,omitempty" schema:"subjectId,omitempty"`
	ObjectID  string `json:"objectId,omitempty" schema:"objectId,omitempty"`
	Action    string `json:"action,omitempty" schema:"action,omitempty"`
}

type EnforceHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *EnforceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := EnforceInput{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		res := h.Enforcer.Enforce(filter.Domain, filter.SubjectID, filter.ObjectID, filter.Action)
		w.Write([]byte(strconv.FormatBool(res)))
	}
}
