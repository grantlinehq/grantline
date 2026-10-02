package platform

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type authTransport func(*http.Request) (*http.Response, error)

func (f authTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEntraApplicationCredentialsAcquireFreshTokens(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: authTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token" {
			t.Fatalf("unexpected authentication request: %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"client_id": "collector-id", "client_secret": "test-only-secret", "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"} {
			if r.PostForm.Get(key) != want {
				t.Fatalf("wrong %s in token request", key)
			}
		}
		if r.PostForm.Get("refresh_token") != "" || r.PostForm.Get("code") != "" {
			t.Fatal("app-only authentication must not require a browser session")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"access_token":"token-%d"}`, calls))), Header: make(http.Header)}, nil
	})}
	for i := 1; i <= 2; i++ {
		token, err := entraAccessToken(context.Background(), client, "tenant-id", "collector-id", "test-only-secret")
		if err != nil || token != fmt.Sprintf("token-%d", i) {
			t.Fatalf("collection %d did not acquire a fresh token: %v", i, err)
		}
	}
	if calls != 2 {
		t.Fatalf("got %d exchanges", calls)
	}
}

func TestEntraRejectedSecretDoesNotLeakProviderResponse(t *testing.T) {
	client := &http.Client{Transport: authTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(`{"error_description":"test-only-sensitive-response"}`)), Header: make(http.Header)}, nil
	})}
	token, err := entraAccessToken(context.Background(), client, "tenant-id", "collector-id", "test-only-secret")
	if token != "" || err == nil || strings.Contains(err.Error(), "test-only-") {
		t.Fatal("rejected credentials must return a sanitized error and no token")
	}
}
