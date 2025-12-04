package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the default timeout for HTTP requests
	DefaultTimeout = 30 * time.Second
	// DefaultUserAgent is the default User-Agent header for API requests
	DefaultUserAgent = "caddy-regru-dns-provider/1.0"
	// DefaultBaseURL is the default base URL for reg.ru API
	DefaultBaseURL = "https://api.reg.ru/api/regru2"
)

// Client represents a reg.ru API client
type Client struct {
	Username   string
	Password   string
	HTTPClient *http.Client
	BaseURL    string
}

// NewClient creates a new reg.ru API client
func NewClient(username, password string) *Client {
	return &Client{
		Username: username,
		Password: password,
		BaseURL:  DefaultBaseURL,
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// APIResponse represents the standard API response structure
type APIResponse struct {
	Result    string      `json:"result"`
	ErrorCode string      `json:"error_code"`
	ErrorText string      `json:"error_text"`
	Answer    interface{} `json:"answer"`
}

// Service represents a service in the reg.ru API response
type Service struct {
	CreationDate    string `json:"creation_date"`
	DName           string `json:"dname"`
	ExpirationDate  string `json:"expiration_date"`
	ServiceID       int    `json:"service_id"`
	ServType        string `json:"servtype"`
	State           string `json:"state"`
	SubType         string `json:"subtype"`
	UplinkServiceID int    `json:"uplink_service_id"`
}

// ServicesResponse represents the response structure for service/get_list
type ServicesResponse struct {
	Services []Service `json:"services"`
}

// AddTXTRecord adds a TXT record to the specified domain using reg.ru API.
// The subdomain parameter can be empty for root domain records.
func (c *Client) AddTXTRecord(ctx context.Context, domain, subdomain, value string) error {
	// Prepare parameters for API request
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"content":             value,
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	// Execute API request
	resp, err := c.makeAPIRequest(ctx, "zone/add_txt", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

	// Check API response
	if resp.Result != "success" {
		if resp.ErrorCode != "" {
			return fmt.Errorf("API error: %s - %s (domain: %s, subdomain: %s)",
				resp.ErrorCode, resp.ErrorText, domain, subdomain)
		}
		return fmt.Errorf("API request failed with result: %s (domain: %s, subdomain: %s)",
			resp.Result, domain, subdomain)
	}

	return nil
}

// RemoveTxtRecord removes a TXT record from the specified domain using reg.ru API.
// The subdomain parameter can be empty for root domain records.
// The value parameter must match exactly the value of the record to be removed.
func (c *Client) RemoveTxtRecord(ctx context.Context, domain, subdomain, value string) error {
	// Prepare parameters for API request
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"content":             value,
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	// Execute API request
	resp, err := c.makeAPIRequest(ctx, "zone/remove_record", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

	// Check API response
	if resp.Result != "success" {
		if resp.ErrorCode != "" {
			return fmt.Errorf("API error: %s - %s (domain: %s, subdomain: %s)",
				resp.ErrorCode, resp.ErrorText, domain, subdomain)
		}
		return fmt.Errorf("API request failed with result: %s (domain: %s, subdomain: %s)",
			resp.Result, domain, subdomain)
	}

	return nil
}

// makeAPIRequest performs an HTTP POST request to reg.ru API.
// It handles request creation, error checking, and response parsing.
func (c *Client) makeAPIRequest(ctx context.Context, method string, params map[string]string) (*APIResponse, error) {
	// Create URL
	apiURL := fmt.Sprintf("%s/%s", c.BaseURL, method)

	// Prepare form data
	formData := url.Values{}
	for key, value := range params {
		formData.Set(key, value)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", DefaultUserAgent)

	// Execute request
	httpResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check HTTP status
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", httpResp.StatusCode, string(body))
	}

	// Parse JSON response
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w (body: %s)", err, string(body))
	}

	return &apiResp, nil
}

// GetZones retrieves a list of active domains from reg.ru account using service/get_list API.
// Only domains with state "A" (Active) are returned. Duplicate domains are filtered out.
func (c *Client) GetZones(ctx context.Context) ([]string, error) {
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"output_content_type": "json",
	}

	resp, err := c.makeAPIRequest(ctx, "service/get_list", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	if resp.Result != "success" {
		return nil, fmt.Errorf("API error getting services: %s - %s", resp.ErrorCode, resp.ErrorText)
	}

	// Parse response using structured format
	if resp.Answer == nil {
		return []string{}, nil
	}

	var servicesResp struct {
		Services []Service `json:"services"`
	}

	// Convert Answer to JSON bytes and unmarshal
	answerBytes, err := json.Marshal(resp.Answer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal API answer: %w", err)
	}

	if err := json.Unmarshal(answerBytes, &servicesResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal services response: %w", err)
	}

	// Filter active domains and remove duplicates
	uniqueZones := make(map[string]bool)
	var zones []string

	for _, service := range servicesResp.Services {
		if service.ServType == "domain" && service.State == "A" && service.DName != "" {
			if !uniqueZones[service.DName] {
				zones = append(zones, service.DName)
				uniqueZones[service.DName] = true
			}
		}
	}

	return zones, nil
}
