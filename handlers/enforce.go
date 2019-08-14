package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	casbin "github.com/casbin/casbin"
	"github.com/gorilla/schema"
)

type EnforcesOutput struct {
	Enforces []EnforceOutput `json:"enforces,omitempty"`
}

type EnforceOutput struct {
	Enforce *EnforceInput `json:"enforce,omitempty"`
	Permit  bool          `json:"permit"`
}

type EnforcesInput struct {
	Enforces []EnforceInput `json:"enforces,omitempty"`
}

type EnforceInput struct {
	Domain  string `json:"domain,omitempty" schema:"domain,omitempty"`
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Object  string `json:"object,omitempty" schema:"object,omitempty"`
	Action  string `json:"action,omitempty" schema:"action,omitempty"`
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

		res := h.Enforcer.Enforce(filter.Domain, filter.Subject, filter.Object, filter.Action)
		w.Write([]byte(strconv.FormatBool(res)))
	case http.MethodPost:
		input := EnforcesInput{}
		json.NewDecoder(r.Body).Decode(&input)

		var output EnforcesOutput

		for _, enforce := range input.Enforces {
			enforced := EnforceOutput{
				Enforce: &enforce,
				Permit:  h.Enforcer.Enforce(enforce.Domain, enforce.Subject, enforce.Object, enforce.Action),
			}
			output.Enforces = append(output.Enforces, enforced)
		}
		js, _ := json.Marshal(output)
		w.Write(js)
	}
}
