package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns the API key from a valid Authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key")

		key, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if key != "my-secret-key" {
			t.Fatalf("expected 'my-secret-key', got: %s", key)
		}
	})

	t.Run("returns error when Authorization header is missing", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got: %v", err)
		}
	})

	t.Run("returns error when Authorization header is empty", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "")

		_, err := GetAPIKey(headers)
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got: %v", err)
		}
	})

	t.Run("returns error when scheme is not ApiKey", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer token123")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Fatalf("expected 'malformed authorization header', got: %v", err)
		}
	})

	t.Run("returns error when Authorization header has no space separator", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Fatalf("expected 'malformed authorization header', got: %v", err)
		}
	})

	t.Run("returns error when Authorization header is empty string with space", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", " ")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Fatalf("expected 'malformed authorization header', got: %v", err)
		}
	})

	t.Run("returns only the second element when API key contains spaces", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my key with spaces")

		key, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if key != "my" {
			t.Fatalf("expected 'my' (second element after Split), got: %s", key)
		}
	})

	t.Run("handles lowercase ApiKey scheme", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "apikey my-secret-key")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error for lowercase scheme, got nil")
		}
	})
}
