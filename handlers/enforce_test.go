package handlers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/casbin/casbin"
)

var cases = []struct {
	Description  string
	Request      EnforceInput
	ExpectPermit bool
}{
	{
		Description: "should pass because alice in asia and hk allows admin to write form",
		Request: EnforceInput{
			Domain:    "domain:hk",
			SubjectID: "alice",
			Action:    "write",
			ObjectID:  "form",
		},
		ExpectPermit: true,
	},
	{
		Description: "should fail because billy is hk and only asia can delete form",
		Request: EnforceInput{
			Domain:    "domain:hk",
			SubjectID: "billy",
			Action:    "delete",
			ObjectID:  "form",
		},
		ExpectPermit: false,
	},
	{
		Description: "should fail because billy is hk and although hk admin can write form, the object is in asia",
		Request: EnforceInput{
			Domain:    "domain:asia",
			SubjectID: "billy",
			Action:    "write",
			ObjectID:  "form",
		},
		ExpectPermit: false,
	},
}

func TestEnforcePolicy(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf", "./enforce_test.policy.csv")

	handler := &EnforceHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	for k, c := range cases {
		t.Run(fmt.Sprintf("case=%d-%s", k, c.Description), func(t *testing.T) {
			req, _ := http.NewRequest("GET", server.URL, nil)
			q := req.URL.Query()
			q.Add("domain", c.Request.Domain)
			q.Add("subjectId", c.Request.SubjectID)
			q.Add("objectId", c.Request.ObjectID)
			q.Add("action", c.Request.Action)
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			res := rec.Result()

			if res.StatusCode != 200 {
				t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
			}
			actual, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strconv.FormatBool(c.ExpectPermit) != string(actual) {
				t.Errorf("Expected the message '%s'\n", strconv.FormatBool(c.ExpectPermit))
				t.Errorf("Received '%s'\n", actual)
			}
		})
	}
}
