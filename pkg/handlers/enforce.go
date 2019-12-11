package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/schema"
	"github.com/oursky/skygear-rbac/pkg/context"
)

type EnforcesOutput []bool

type EnforcesInput []EnforceInput

type EnforceInput struct {
	Domain  string `json:"domain,omitempty" schema:"domain,omitempty"`
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Object  string `json:"object,omitempty" schema:"object,omitempty"`
	Action  string `json:"action,omitempty" schema:"action,omitempty"`
}

type EnforceHandler struct {
	AppContext *context.AppContext
}

func (h *EnforceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		decoder := schema.NewDecoder()
		filter := EnforceInput{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			log.Fatal(err)
			w.WriteHeader(409)
		}

		res, err := h.AppContext.Enforcer.Enforce(filter.Domain, filter.Subject, filter.Object, filter.Action)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
		w.Write([]byte(strconv.FormatBool(res)))
	case http.MethodPost:
		input := EnforcesInput{}
		err := json.NewDecoder(r.Body).Decode(&input)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(409)
		}

		var output EnforcesOutput

		for _, enforce := range input {
			permit, err := h.AppContext.Enforcer.Enforce(enforce.Domain, enforce.Subject, enforce.Object, enforce.Action)
			if err != nil {
				log.Fatal(err)
			}
			output = append(output, permit)
		}
		js, _ := json.Marshal(output)
		w.Write(js)
	}
}
