// internal/client_test.go
package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	username := "test@example.com"
	password := "password123"

	client := NewClient(username, password)

	if client.Username != username {
		t.Errorf("Expected username %q, got %q", username, client.Username)
	}
	if client.Password != password {
		t.Errorf("Expected password %q, got %q", password, client.Password)
	}
	if client.HTTPClient == nil {
		t.Error("Expected HTTPClient to be initialized")
	}
	if client.HTTPClient.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultTimeout, client.HTTPClient.Timeout)
	}
	if client.BaseURL != "https://api.reg.ru/api/regru2" {
		t.Errorf("Expected BaseURL 'https://api.reg.ru/api/regru2', got %q", client.BaseURL)
	}
}

func TestClient_AddTXTRecord(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		subdomain    string
		value        string
		responseCode int
		response     APIResponse
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "successful add",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
			},
			expectError: false,
		},
		{
			name:         "API error with code",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result:    "error",
				ErrorCode: "DOMAIN_NOT_FOUND",
				ErrorText: "Domain not found",
			},
			expectError: true,
			errorMsg:    "DOMAIN_NOT_FOUND",
		},
		{
			name:         "HTTP error",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusInternalServerError,
			response:     APIResponse{},
			expectError:  true,
			errorMsg:     "API request failed with status 500",
		},
		{
			name:         "failed result without error code",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "failed",
			},
			expectError: true,
			errorMsg:    "API request failed with result: failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				if tt.responseCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					w.Write([]byte("HTTP Error"))
				}
			}))
			defer server.Close()

			client := NewClient("test@example.com", "password123")
			client.HTTPClient = server.Client()
			client.BaseURL = server.URL

			ctx := context.Background()
			err := client.AddTXTRecord(ctx, tt.domain, tt.subdomain, tt.value)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClient_RemoveTxtRecord(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		subdomain    string
		value        string
		responseCode int
		response     APIResponse
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "successful remove",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
			},
			expectError: false,
		},
		{
			name:         "API error",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result:    "error",
				ErrorCode: "RECORD_NOT_FOUND",
				ErrorText: "Record not found",
			},
			expectError: true,
			errorMsg:    "RECORD_NOT_FOUND",
		},
		{
			name:         "HTTP bad request",
			domain:       "example.com",
			subdomain:    "test",
			value:        "test-value",
			responseCode: http.StatusBadRequest,
			response:     APIResponse{},
			expectError:  true,
			errorMsg:     "API request failed with status 400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				if tt.responseCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					w.Write([]byte("HTTP Error"))
				}
			}))
			defer server.Close()

			client := NewClient("test@example.com", "password123")
			client.HTTPClient = server.Client()
			client.BaseURL = server.URL

			ctx := context.Background()
			err := client.RemoveTxtRecord(ctx, tt.domain, tt.subdomain, tt.value)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClient_GetZones(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		response      APIResponse
		expectError   bool
		expectedZones []string
		errorMsg      string
	}{
		{
			name:         "successful get zones",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"domains": []interface{}{
						map[string]interface{}{
							"dname": "example.com",
						},
						map[string]interface{}{
							"dname": "test.org",
						},
					},
				},
			},
			expectError:   false,
			expectedZones: []string{"example.com", "test.org"},
		},
		{
			name:         "API error",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result:    "error",
				ErrorCode: "AUTH_ERROR",
				ErrorText: "Authentication failed",
			},
			expectError: true,
			errorMsg:    "AUTH_ERROR",
		},
		{
			name:         "HTTP error",
			responseCode: http.StatusUnauthorized,
			response:     APIResponse{},
			expectError:  true,
			errorMsg:     "API request failed with status 401",
		},
		{
			name:         "empty domains list",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"domains": []interface{}{},
				},
			},
			expectError:   false,
			expectedZones: []string{},
		},
		{
			name:         "nil answer",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: nil,
			},
			expectError:   false,
			expectedZones: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				if tt.responseCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					w.Write([]byte("HTTP Error"))
				}
			}))
			defer server.Close()

			client := NewClient("test@example.com", "password123")
			client.HTTPClient = server.Client()
			client.BaseURL = server.URL

			ctx := context.Background()
			zones, err := client.GetZones(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(zones) != len(tt.expectedZones) {
					t.Errorf("Expected %d zones, got %d", len(tt.expectedZones), len(zones))
				}
				for i, expected := range tt.expectedZones {
					if i < len(zones) && zones[i] != expected {
						t.Errorf("Expected zone %q, got %q", expected, zones[i])
					}
				}
			}
		})
	}
}

func TestClient_makeAPIRequest(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		params       map[string]string
		responseCode int
		responseBody string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "successful request",
			method:       "test/method",
			params:       map[string]string{"param1": "value1"},
			responseCode: http.StatusOK,
			responseBody: `{"result": "success"}`,
			expectError:  false,
		},
		{
			name:         "invalid JSON response",
			method:       "test/method",
			params:       map[string]string{"param1": "value1"},
			responseCode: http.StatusOK,
			responseBody: `invalid json`,
			expectError:  true,
			errorMsg:     "failed to parse API response",
		},
		{
			name:         "HTTP error",
			method:       "test/method",
			params:       map[string]string{"param1": "value1"},
			responseCode: http.StatusInternalServerError,
			responseBody: `error`,
			expectError:  true,
			errorMsg:     "API request failed with status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client := NewClient("test@example.com", "password123")
			client.HTTPClient = server.Client()
			client.BaseURL = server.URL

			ctx := context.Background()
			resp, err := client.makeAPIRequest(ctx, tt.method, tt.params)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if resp == nil {
					t.Error("Expected non-nil response")
				}
				if resp.Result != "success" {
					t.Errorf("Expected result 'success', got %q", resp.Result)
				}
			}
		})
	}
}

func TestClient_makeAPIRequest_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = &http.Client{
		Timeout: 50 * time.Millisecond,
	}
	client.BaseURL = server.URL

	ctx := context.Background()
	_, err := client.makeAPIRequest(ctx, "test", map[string]string{})

	if err == nil {
		t.Error("Expected timeout error but got none")
	}
}

func TestClient_makeAPIRequest_NetworkError(t *testing.T) {
	client := NewClient("test@example.com", "password123")
	client.BaseURL = "http://invalid-url-that-does-not-exist"

	ctx := context.Background()
	_, err := client.makeAPIRequest(ctx, "test", map[string]string{})

	if err == nil {
		t.Error("Expected network error but got none")
	}
	if !strings.Contains(err.Error(), "failed to execute request") {
		t.Errorf("Expected network error message, got: %v", err)
	}
}

func TestClient_makeAPIRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.makeAPIRequest(ctx, "test", map[string]string{})

	if err == nil {
		t.Error("Expected context cancellation error but got none")
	}
}

func TestConstants(t *testing.T) {
	if DefaultTimeout != 30*time.Second {
		t.Errorf("Expected DefaultTimeout 30s, got %v", DefaultTimeout)
	}
}

func TestAPIResponse_Structure(t *testing.T) {
	original := APIResponse{
		Result:    "success",
		ErrorCode: "TEST_ERROR",
		ErrorText: "Test error message",
		Answer: map[string]interface{}{
			"test": "value",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal APIResponse: %v", err)
	}

	var unmarshaled APIResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal APIResponse: %v", err)
	}

	if unmarshaled.Result != original.Result {
		t.Errorf("Expected Result %q, got %q", original.Result, unmarshaled.Result)
	}
	if unmarshaled.ErrorCode != original.ErrorCode {
		t.Errorf("Expected ErrorCode %q, got %q", original.ErrorCode, unmarshaled.ErrorCode)
	}
	if unmarshaled.ErrorText != original.ErrorText {
		t.Errorf("Expected ErrorText %q, got %q", original.ErrorText, unmarshaled.ErrorText)
	}
	if unmarshaled.Answer == nil {
		t.Error("Expected Answer to be non-nil")
	}
}

func BenchmarkClient_AddTXTRecord(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.AddTXTRecord(ctx, "example.com", "test", "value")
	}
}

func BenchmarkClient_RemoveTxtRecord(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.RemoveTxtRecord(ctx, "example.com", "test", "value")
	}
}

func BenchmarkClient_GetZones(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{
			Result: "success",
			Answer: map[string]interface{}{
				"domains": []interface{}{
					map[string]interface{}{"dname": "example.com"},
					map[string]interface{}{"dname": "test.org"},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetZones(ctx)
	}
}
