package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oursky/skygear-rbac/pkg/context"
	enforcer "github.com/oursky/skygear-rbac/pkg/enforcer"
)

func TestGetDomains(t *testing.T) {
	e, err := enforcer.NewEnforcer(nil, enforcer.Config{
		Model: "../../model.conf",
		File:  "./domain_test.policy.csv",
	})
	appContext := context.NewAppContext(nil, e)
	handler := &DomainHandler{AppContext: &appContext}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	q := req.URL.Query()
	q.Add("domain", "domain:asia")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal(Domain{
		SubDomains: []string{"domain:hk"},
		Domain:     "domain:asia",
	})
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

func TestCreateDomains(t *testing.T) {
	e, _ := enforcer.NewEnforcer(nil, enforcer.Config{
		Model: "../../model.conf",
	})
	appContext := context.NewAppContext(nil, e)
	handler := &DomainHandler{&appContext}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakeDomainInput := DomainInput{
		Parent:   "domain:asia",
		Domain:   "domain:japan",
		Subjects: []string{"role:admin"},
	}

	body, _ := json.Marshal(fakeDomainInput)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}

	req, _ = http.NewRequest("GET", server.URL, nil)
	q := req.URL.Query()
	q.Add("domain", "domain:asia")
	req.URL.RawQuery = q.Encode()

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res = rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal(Domain{
		SubDomains: []string{"domain:japan"},
		Domain:     "domain:asia",
	})
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

func TestDeleteDomainSubject(t *testing.T) {
	e, _ := enforcer.NewEnforcer(nil, enforcer.Config{
		Model: "../../model.conf",
		File:  "./domain_test.policy.csv",
	})
	appContext := context.NewAppContext(nil, e)
	handler := &DomainHandler{&appContext}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("DELETE", server.URL, nil)
	q := req.URL.Query()
	q.Add("subject", "alice")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	aliceDomains := e.GetFilteredNamedGroupingPolicy("g", 1, "alice")
	if len(aliceDomains) != 0 {
		t.Errorf("Expected alice removed from domain groups")
		t.Errorf("Received '%s'\n", aliceDomains)
	}
}

func TestDeleteDomain(t *testing.T) {
	e, _ := enforcer.NewEnforcer(nil, enforcer.Config{
		Model: "../../model.conf",
		File:  "./domain_test.policy.csv",
	})
	appContext := context.NewAppContext(nil, e)
	handler := &DomainHandler{&appContext}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("DELETE", server.URL, nil)
	q := req.URL.Query()
	q.Add("domain", "domain:hk")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	aliceDomains := e.GetFilteredNamedGroupingPolicy("g", 0, "domain:hk")
	if len(aliceDomains) != 0 {
		t.Errorf("Expected domain:hk removed from domain groups")
		t.Errorf("Received '%s'\n", aliceDomains)
	}
}
