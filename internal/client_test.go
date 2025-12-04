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
				// Проверяем метод запроса
				if r.Method != "POST" {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				// Проверяем Content-Type
				expectedContentType := "application/x-www-form-urlencoded"
				if r.Header.Get("Content-Type") != expectedContentType {
					t.Errorf("Expected Content-Type %s, got %s", expectedContentType, r.Header.Get("Content-Type"))
				}

				// Проверяем User-Agent
				expectedUserAgent := "caddy-regru-dns-provider/1.0"
				if r.Header.Get("User-Agent") != expectedUserAgent {
					t.Errorf("Expected User-Agent %s, got %s", expectedUserAgent, r.Header.Get("User-Agent"))
				}

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
			name:         "successful get zones with services format",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"services": []interface{}{
						map[string]interface{}{
							"dname":    "example.com",
							"servtype": "domain",
							"state":    "A",
						},
						map[string]interface{}{
							"dname":    "test.org",
							"servtype": "domain",
							"state":    "A",
						},
						map[string]interface{}{
							"dname":    "example.com",
							"servtype": "srv_ssl_certificate",
							"state":    "A",
						},
						map[string]interface{}{
							"dname":    "inactive.com",
							"servtype": "domain",
							"state":    "I",
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
			name:         "empty services list",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"services": []interface{}{},
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
		{
			name:         "malformed services data",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"services": "invalid-data",
				},
			},
			expectError: true,
			errorMsg:    "failed to unmarshal services response",
		},
		{
			name:         "duplicate domains filtered",
			responseCode: http.StatusOK,
			response: APIResponse{
				Result: "success",
				Answer: map[string]interface{}{
					"services": []interface{}{
						map[string]interface{}{
							"dname":    "example.com",
							"servtype": "domain",
							"state":    "A",
						},
						map[string]interface{}{
							"dname":    "example.com",
							"servtype": "domain",
							"state":    "A",
						},
					},
				},
			},
			expectError:   false,
			expectedZones: []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Проверяем что это запрос к service/get_list
				if !strings.Contains(r.URL.Path, "service/get_list") {
					t.Errorf("Expected service/get_list endpoint, got %s", r.URL.Path)
				}

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
		{
			name:         "empty response body",
			method:       "test/method",
			params:       map[string]string{},
			responseCode: http.StatusOK,
			responseBody: ``,
			expectError:  true,
			errorMsg:     "failed to parse API response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Проверяем параметры запроса
				if err := r.ParseForm(); err != nil {
					t.Errorf("Failed to parse form: %v", err)
				}

				for key, value := range tt.params {
					if r.FormValue(key) != value {
						t.Errorf("Expected param %s=%s, got %s", key, value, r.FormValue(key))
					}
				}

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
	client.BaseURL = "http://invalid-url-that-does-not-exist.local"

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
	cancel() // Отменяем контекст сразу

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

func TestService_Structure(t *testing.T) {
	original := Service{
		CreationDate:    "2021-06-03",
		DName:           "example.com",
		ExpirationDate:  "2026-06-03",
		ServiceID:       12345,
		ServType:        "domain",
		State:           "A",
		SubType:         "",
		UplinkServiceID: 0,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal Service: %v", err)
	}

	var unmarshaled Service
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Service: %v", err)
	}

	if unmarshaled.DName != original.DName {
		t.Errorf("Expected DName %q, got %q", original.DName, unmarshaled.DName)
	}
	if unmarshaled.ServType != original.ServType {
		t.Errorf("Expected ServType %q, got %q", original.ServType, unmarshaled.ServType)
	}
	if unmarshaled.State != original.State {
		t.Errorf("Expected State %q, got %q", original.State, unmarshaled.State)
	}
}

func TestServicesResponse_Structure(t *testing.T) {
	original := ServicesResponse{
		Services: []Service{
			{
				DName:    "example.com",
				ServType: "domain",
				State:    "A",
			},
			{
				DName:    "test.org",
				ServType: "domain",
				State:    "A",
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal ServicesResponse: %v", err)
	}

	var unmarshaled ServicesResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal ServicesResponse: %v", err)
	}

	if len(unmarshaled.Services) != len(original.Services) {
		t.Errorf("Expected %d services, got %d", len(original.Services), len(unmarshaled.Services))
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
				"services": []interface{}{
					map[string]interface{}{
						"dname":    "example.com",
						"servtype": "domain",
						"state":    "A",
					},
					map[string]interface{}{
						"dname":    "test.org",
						"servtype": "domain",
						"state":    "A",
					},
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

func BenchmarkAPIResponseParsing(b *testing.B) {
	responseData := `{  
		"result": "success",  
		"error_code": "",  
		"error_text": "",
				"answer": {
			"services": [
				{
					"dname": "example.com",
					"servtype": "domain",
					"state": "A"
				},
				{
					"dname": "test.org",
					"servtype": "domain", 
					"state": "A"
				}
			]
		}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var resp APIResponse
		_ = json.Unmarshal([]byte(responseData), &resp)
	}
}

func TestClient_RequestHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем все необходимые заголовки
		expectedHeaders := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "caddy-regru-dns-provider/1.0",
		}

		for header, expectedValue := range expectedHeaders {
			actualValue := r.Header.Get(header)
			if actualValue != expectedValue {
				t.Errorf("Expected header %s: %s, got: %s", header, expectedValue, actualValue)
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx := context.Background()
	err := client.AddTXTRecord(ctx, "example.com", "test", "value")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestClient_RequestParameters(t *testing.T) {
	expectedParams := map[string]string{
		"username":            "test@example.com",
		"password":            "password123",
		"domain_name":         "example.com",
		"subdomain":           "test",
		"content":             "test-value",
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
			return
		}

		for key, expectedValue := range expectedParams {
			actualValue := r.FormValue(key)
			if actualValue != expectedValue {
				t.Errorf("Expected param %s: %s, got: %s", key, expectedValue, actualValue)
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Result: "success"})
	}))
	defer server.Close()

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = server.Client()
	client.BaseURL = server.URL

	ctx := context.Background()
	err := client.AddTXTRecord(ctx, "example.com", "test", "test-value")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestClient_URLConstruction(t *testing.T) {
	tests := []struct {
		name         string
		baseURL      string
		method       string
		expectedPath string
	}{
		{
			name:         "add TXT record",
			baseURL:      "https://api.reg.ru/api/regru2",
			method:       "zone/add_txt",
			expectedPath: "/zone/add_txt",
		},
		{
			name:         "remove record",
			baseURL:      "https://api.reg.ru/api/regru2",
			method:       "zone/remove_record",
			expectedPath: "/zone/remove_record",
		},
		{
			name:         "get services",
			baseURL:      "https://api.reg.ru/api/regru2",
			method:       "service/get_list",
			expectedPath: "/service/get_list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.expectedPath {
					t.Errorf("Expected path %s, got %s", tt.expectedPath, r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(APIResponse{Result: "success"})
			}))
			defer server.Close()

			client := NewClient("test@example.com", "password123")
			client.HTTPClient = server.Client()
			client.BaseURL = server.URL

			ctx := context.Background()
			_, err := client.makeAPIRequest(ctx, tt.method, map[string]string{})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestClient_EmptyCredentials(t *testing.T) {
	client := NewClient("", "")

	if client.Username != "" {
		t.Errorf("Expected empty username, got %q", client.Username)
	}
	if client.Password != "" {
		t.Errorf("Expected empty password, got %q", client.Password)
	}

	// Клиент должен создаваться даже с пустыми учетными данными
	// Ошибка должна возникать только при попытке использования API
	if client.HTTPClient == nil {
		t.Error("Expected HTTPClient to be initialized")
	}
}

func TestClient_CustomHTTPClient(t *testing.T) {
	customClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	client := NewClient("test@example.com", "password123")
	client.HTTPClient = customClient

	if client.HTTPClient.Timeout != 10*time.Second {
		t.Errorf("Expected custom timeout 10s, got %v", client.HTTPClient.Timeout)
	}
}

func TestClient_CustomBaseURL(t *testing.T) {
	customURL := "https://custom-api.example.com/api"

	client := NewClient("test@example.com", "password123")
	client.BaseURL = customURL

	if client.BaseURL != customURL {
		t.Errorf("Expected custom BaseURL %q, got %q", customURL, client.BaseURL)
	}
}

func TestAPIResponse_ErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		response APIResponse
		isError  bool
	}{
		{
			name: "success response",
			response: APIResponse{
				Result: "success",
			},
			isError: false,
		},
		{
			name: "error response with code",
			response: APIResponse{
				Result:    "error",
				ErrorCode: "DOMAIN_NOT_FOUND",
				ErrorText: "Domain not found",
			},
			isError: true,
		},
		{
			name: "failed response",
			response: APIResponse{
				Result: "failed",
			},
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isError := tt.response.Result != "success"
			if isError != tt.isError {
				t.Errorf("Expected isError %v, got %v", tt.isError, isError)
			}
		})
	}
}
