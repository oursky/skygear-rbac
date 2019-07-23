package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin"
)

func TestGetRoles(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf", "./role_test.policy.csv")

	handler := &RoleHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	q := req.URL.Query()
	q.Add("subjectId", "alice")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal([]string{"role:admin", "role:intern"})
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
	e := casbin.NewEnforcer("../model.conf")

	handler := &RoleHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakeRoleAssignment := RoleAssignmentInput{
		Role:      "admin",
		SubjectID: "billy",
	}

	body, _ := json.Marshal(fakeRoleAssignment)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal([]string{fakeRoleAssignment.Role})
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
