package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	enforcer "skygear-rbac/enforcer"
	"strconv"
	"testing"
)

var cases = []struct {
	Description  string
	Request      EnforceInput
	ExpectPermit bool
}{
	{
		Description: "Normal case: should pass because alice is admin in asia and which is allowed to delete form",
		Request: EnforceInput{
			Domain:  "domain:asia",
			Subject: "alice",
			Action:  "delete",
			Object:  "form",
		},
		ExpectPermit: true,
	},
	{
		Description: "Permission-role inheritance case: should fail because alice in asia and only hk allows admin to write form",
		Request: EnforceInput{
			Domain:  "domain:hk",
			Subject: "alice",
			Action:  "write",
			Object:  "form",
		},
		ExpectPermit: false,
	},
	{
		Description: "DISALLOW Role assignment inheritance: should fail because billy is hk admin and only asia admin can delete form",
		Request: EnforceInput{
			Domain:  "domain:hk",
			Subject: "billy",
			Action:  "delete",
			Object:  "form",
		},
		ExpectPermit: false,
	},
	{
		Description: "Resource inheritance: should fail because billy is hk and although hk admin can write form, the object is in asia",
		Request: EnforceInput{
			Domain:  "domain:asia",
			Subject: "billy",
			Action:  "write",
			Object:  "form",
		},
		ExpectPermit: false,
	},
}

func TestEnforcePolicy(t *testing.T) {
	e, _ := enforcer.NewEnforcer(enforcer.Config{
		Model:  "../model.conf",
		Policy: "./enforce_test.policy.csv",
	})

	handler := &EnforceHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	for k, c := range cases {
		t.Run(fmt.Sprintf("case=%d-%s", k, c.Description), func(t *testing.T) {
			req, _ := http.NewRequest("GET", server.URL, nil)
			q := req.URL.Query()
			q.Add("domain", c.Request.Domain)
			q.Add("subject", c.Request.Subject)
			q.Add("object", c.Request.Object)
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

func TestBatchEnforcePolicy(t *testing.T) {
	e, _ := enforcer.NewEnforcer(enforcer.Config{
		Model:  "../model.conf",
		Policy: "./enforce_test.policy.csv",
	})

	handler := &EnforceHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	enforces := EnforcesInput{}
	for _, c := range cases {
		enforces = append(enforces, c.Request)
	}
	body, _ := json.Marshal(enforces)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}

	output := EnforcesOutput{}
	json.NewDecoder(res.Body).Decode(&output)
	for k, c := range cases {
		if output[k] != c.ExpectPermit {
			t.Errorf("Expected the message '%s' for '%s'\n", strconv.FormatBool(c.ExpectPermit), fmt.Sprintf("case=%d-%s", k, c.Description))
			t.Errorf("Received '%s'\n", strconv.FormatBool(output[k]))
		}
	}
}
