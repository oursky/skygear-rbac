package handlers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oursky/skygear-rbac/pkg/context"
	enforcer "github.com/oursky/skygear-rbac/pkg/enforcer"
)

func TestGetSubjects(t *testing.T) {
	e, _ := enforcer.NewEnforcer(nil, enforcer.Config{
		Model: "../../model.conf",
		File:  "./role_test.policy.csv",
	})
	appContext := context.NewAppContext(nil, e)
	handler := &SubjectHandler{&appContext}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/domain:asia/role/role:admin/subject", nil)
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal([]string{"alice", "role:admin"})
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
