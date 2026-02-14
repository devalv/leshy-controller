package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewDefaultHealthHandler(t *testing.T) {
	t.Parallel()

	root := New(Options{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	response := httptest.NewRecorder()

	root.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", response.Body.String(), "ok")
	}
}

func TestNewCustomHealthHandler(t *testing.T) {
	t.Parallel()

	root := New(Options{
		HealthPath: "/healthz",
		HealthHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","runtime_attached":true}`))
		}),
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	root.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `"runtime_attached":true`) {
		t.Fatalf("body = %q, expected runtime_attached field", response.Body.String())
	}
}
