package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantKey    string
		wantErr    string
		wantNoAuth bool
	}{
		{
			name:    "valid API key",
			header:  "ApiKey my-secret-key",
			wantKey: "my-secret-key",
		},
		{
			name:       "missing authorization header",
			wantNoAuth: true,
		},
		{
			name:    "missing key",
			header:  "ApiKey",
			wantErr: "malformed authorization header",
		},
		{
			name:    "wrong authentication scheme",
			header:  "Bearer my-secret-key",
			wantErr: "malformed authorization header",
		},
		{
			name:    "scheme is case sensitive",
			header:  "apikey my-secret-key",
			wantErr: "malformed authorization header",
		},
		{
			name:    "wrong separator",
			header:  "ApiKey\tmy-secret-key",
			wantErr: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			switch {
			case tt.wantNoAuth:
				if !errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Errorf("GetAPIKey() error = %v, want %v",
						err, ErrNoAuthHeaderIncluded)
				}
			case tt.wantErr != "":
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("GetAPIKey() error = %v, want %q", err, tt.wantErr)
				}
			default:
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error: %v", err)
				}
			}
		})
	}
}
