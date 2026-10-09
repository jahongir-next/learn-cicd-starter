package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid Authorization Header",
			headers:       http.Header{"Authorization": []string{"ApiKey secret-api-key-123"}},
			expectedKey:   "secret-api-key-123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header (Missing ApiKey prefix)",
			headers:       http.Header{"Authorization": []string{"Bearer secret-token"}},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name:          "Malformed Authorization Header (Only prefix)",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Xatolik holatini tekshirish
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Qaytarilgan API Key qiymatini tekshirish
			if gotKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, gotKey)
			}
		})
	}
}
