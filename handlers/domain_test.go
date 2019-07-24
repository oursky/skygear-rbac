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

func TestGetDomains(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf", "./domain_test.policy.csv")

	handler := &DomainHandler{e}
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
	policy, _ := json.Marshal([]string{"domain:hk"})
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
	e := casbin.NewEnforcer("../model.conf")

	handler := &DomainHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakeDomainInput := DomainInput{
		ParentID:   "domain:asia",
		Domain:     "domain:hk",
		SubjectIDs: []string{"role:admin"},
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
	policy, _ := json.Marshal([]string{"domain:hk"})
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
	e := casbin.NewEnforcer("../model.conf", "./domain_test.policy.csv")

	handler := &DomainHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("DELETE", server.URL, nil)
	q := req.URL.Query()
	q.Add("subjectId", "alice")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	aliceDomains := e.GetFilteredNamedGroupingPolicy("g2", 1, "alice")
	if len(aliceDomains) != 0 {
		t.Errorf("Expected alice removed from domain groups")
		t.Errorf("Received '%s'\n", aliceDomains)
	}
}

func TestDeleteDomain(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf", "./domain_test.policy.csv")

	handler := &DomainHandler{e}
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
	aliceDomains := e.GetFilteredNamedGroupingPolicy("g2", 0, "domain:hk")
	if len(aliceDomains) != 0 {
		t.Errorf("Expected domain:hk removed from domain groups")
		t.Errorf("Received '%s'\n", aliceDomains)
	}
}
