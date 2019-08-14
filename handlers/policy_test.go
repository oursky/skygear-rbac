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

func TestGetAndDeletePolicy(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf")

	fakePolicy := Policy{
		Domain:  "root",
		Subject: "admin",
		Object:  "data1",
		Action:  "write",
		Effect:  "allow",
	}

	e.AddPolicy(fakePolicy.ToArgs()...)

	handler := &PolicyHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	q := req.URL.Query()
	q.Add("domain", "root")
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
	policy, _ := json.Marshal([]Policy{fakePolicy})
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
		q.Add("domain", fakePolicy.Domain)
		q.Add("subject", fakePolicy.Subject)
		q.Add("object", fakePolicy.Object)
		q.Add("action", fakePolicy.Action)
		q.Add("effect", fakePolicy.Effect)
		req.URL.RawQuery = q.Encode()

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		res := rec.Result()

		if res.StatusCode != 200 {
			t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
		}
		if len(e.GetPolicy()) != 0 {
			t.Errorf("Expected policy to be deleted '%s'\n", expected)
			t.Errorf("But got '%s'\n", e.GetPolicy())
		}
	}
}

func TestAddPolicy(t *testing.T) {
	e := casbin.NewEnforcer("../model.conf")

	handler := &PolicyHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakePolicy := []PolicyInput{
		PolicyInput{
			Domain:  "root",
			Subject: "alice",
			Object:  "form",
			Action:  "edit",
		},
	}

	body, _ := json.Marshal(fakePolicy)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}
}
