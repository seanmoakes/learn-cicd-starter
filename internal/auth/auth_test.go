package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey_NoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedAuthorizationHeader(t *testing.T) {
	testCases := []struct {
		name   string
		header string
	}{
		{"No ApiKey Prefix", "Bearer token"},
		{"Incomplete Header", "ApiKey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.header)
			_, err := GetAPIKey(headers)
			if err == nil || !strings.Contains(err.Error(), "malformed authorization header") {
				t.Errorf("expected malformed authorization header error, got %v", err)
			}
		})
	}
}

func TestGetAPIKey_ValidAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey valid-api-key")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if apiKey != "valid-api-key" {
		t.Errorf("expected 'valid-api-key', got %s", apiKey)
	}
}
