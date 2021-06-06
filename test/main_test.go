package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthRoute(t *testing.T) {
	router := setupServer()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "All good", w.Body.String())
}

func TestStringResponse(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "my key")
	os.Setenv("HEADER", "X-Hub-Signature")
	router := setupServer()

	var body = []byte(`sign this message`)

	json, _ := json.Marshal(string(body))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", bytes.NewBuffer(body))
	req.Header.Set("X-Hub-Signature", "sha256=41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7")
	req.Header.Set("Content-Type", "text/plain")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, string(json), w.Body.String())
}

func TestJSONResponse(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "my key")
	os.Setenv("HEADER", "X-Hub-Signature")
	router := setupServer()

	var body = []byte(`{"test": 123}`)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", bytes.NewBuffer(body))
	req.Header.Set("X-Hub-Signature", "sha256=eff49d9c699ae04340f1a9a6e1800a7d018864c88ca719e0156ca7a9a55b0f67")
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, string(body), w.Body.String())
}
