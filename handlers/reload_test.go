package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"skygear-rbac/constants"
	enforcer "skygear-rbac/enforcer"
	"testing"
)

func TestReload(t *testing.T) {
	e, _ := enforcer.NewEnforcer(enforcer.Config{
		Model: "../model.conf",
	})

	handler := &ReloadHandler{e}
	server := httptest.NewServer(handler)
	defer server.Close()

	fakeReloadInput := ReloadInput{
		Domains: []DomainInput{
			DomainInput{
				Domain:     "domain:asia",
				SubDomains: []string{"domain:hk", "domain:india"},
			},
		},
		Policies: PoliciesInput{
			PolicyInput{
				Subject: "role:admin",
				Object:  "book",
				Action:  "read",
				Domain:  "domain:hk",
			},
		},
		RoleAssignments: RoleAssignmentsInput{
			RoleAssignmentInput{
				Role:    "role:admin",
				Subject: "user:idiot",
				Domain:  "domain:asia",
			},
		},
	}

	body, _ := json.Marshal(fakeReloadInput)

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", res.StatusCode)
	}

	if !e.HasNamedGroupingPolicy("g", "domain:asia", "domain:india", constants.IsDomain) {
		t.Error("Expected domain:asia to have subdomain domain:india\n")
	}

	if !e.HasNamedGroupingPolicy("g", "user:idiot", "role:admin", "domain:asia") {
		t.Error("Expected user:idiot to be assigned role:admin in domain:asia\n")
	}

	allowed, _ := e.Enforce("domain:hk", "role:admin", "book", "read")

	if !allowed {
		t.Error("Expected role:admin to be allowed to write book in domain:hk\n")
	}
}
