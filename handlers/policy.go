package handlers

import (
	"net/http"
)

type PolicyHandler struct {
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Policy CRUD"))
}
