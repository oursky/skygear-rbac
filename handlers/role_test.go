package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
)

func TestGetRoles(t *testing.T) {
	e, _ := casbin.NewEnforcer("../model.conf", "./role_test.policy.csv")

	fakeRoleAssignments := []RoleAssignment{
		RoleAssignment{
			Subject: "alice",
			Role:    "role:admin",
			Domain:  "domain:asia",
		},
	}

	handler := &RoleHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	q := req.URL.Query()
	q.Add("subject", "alice")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal(fakeRoleAssignments)
	expected := string(policy)
	actual, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if expected != string(actual) {
		t.Errorf("Expected the message '%s'\n", expected)
		t.Errorf("Received '%s'\n", actual)
	}
}

func TestAssignThenRemoveRole(t *testing.T) {
	e, _ := casbin.NewEnforcer("../model.conf", "./role_test.policy.csv")

	handler := &RoleHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakeRoleAssignments := RoleAssignmentsInput{
		RoleAssignmentInput{
			Role:    "admin",
			Subject: "billy",
			Domain:  "domain:hk",
		},
	}

	body, _ := json.Marshal(fakeRoleAssignments)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal(fakeRoleAssignments)
	expected := string(policy)
	actual, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if expected != string(actual) {
		t.Errorf("Expected the message '%s'\n", expected)
		t.Errorf("Received '%s'\n", actual)
	} else {
		req, _ := http.NewRequest("DELETE", server.URL, nil)
		q := req.URL.Query()
		q.Add("role", fakeRoleAssignments[0].Role)
		q.Add("subject", fakeRoleAssignments[0].Subject)
		q.Add("domain", fakeRoleAssignments[0].Domain)
		req.URL.RawQuery = q.Encode()

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		res := rec.Result()

		if res.StatusCode != 200 {
			t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
		}
		stillHasDeletedRole := e.HasPolicy(fakeRoleAssignments[0].Subject, fakeRoleAssignments[0].Role, fakeRoleAssignments[0].Domain)
		if stillHasDeletedRole {
			t.Errorf("Expected policy to be deleted '%s'\n", expected)
			t.Errorf("But got '%s'\n", e.GetPolicy())
		}
	}
}
