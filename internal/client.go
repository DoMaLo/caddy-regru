package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTimeout is the default timeout for HTTP requests
	DefaultTimeout = 30 * time.Second
	// DefaultUserAgent is the default User-Agent header for API requests
	DefaultUserAgent = "caddy-regru-dns-provider/1.0"
	// DefaultBaseURL is the default base URL for reg.ru API
	DefaultBaseURL = "https://api.reg.ru/api/regru2"

	// DefaultZonesCacheTTL is how long the domain list from service/get_list is cached.
	DefaultZonesCacheTTL = 15 * time.Minute
	// DefaultMaxRetries is the number of retries after the initial API request.
	DefaultMaxRetries = 5
	// DefaultRetryBaseDelay is the initial delay before the first retry.
	DefaultRetryBaseDelay = 1 * time.Second
	// DefaultRetryMaxDelay caps exponential backoff between retries.
	DefaultRetryMaxDelay = 30 * time.Second
)

// Client represents a reg.ru API client
type Client struct {
	Username   string
	Password   string
	HTTPClient *http.Client
	BaseURL    string

	requestMu sync.Mutex

	zonesMu       sync.RWMutex
	zonesFetchMu  sync.Mutex
	zonesCache    []string
	zonesCached   time.Time
	zonesTTL      time.Duration

	maxRetries     int
	retryBaseDelay time.Duration
	retryMaxDelay  time.Duration
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
		zonesTTL:       DefaultZonesCacheTTL,
		maxRetries:     DefaultMaxRetries,
		retryBaseDelay: DefaultRetryBaseDelay,
		retryMaxDelay:  DefaultRetryMaxDelay,
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

type apiHTTPError struct {
	statusCode int
	body       string
}

func (e *apiHTTPError) Error() string {
	return fmt.Sprintf("API request failed with status %d: %s", e.statusCode, e.body)
}

func isRetryableError(err error) bool {
	var httpErr *apiHTTPError
	if errors.As(err, &httpErr) {
		return isRetryableHTTPStatus(httpErr.statusCode)
	}
	return false
}

// AddTXTRecord adds a TXT record to the specified domain using reg.ru API.
// API: zone/add_txt — subdomain, text; service id: domain_name (see REG.RU API 2 docs, zone/add_txt).
// The subdomain parameter can be empty for root domain records.
func (c *Client) AddTXTRecord(ctx context.Context, domain, subdomain, value string) error {
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"text":                value,
		"output_content_type": "json",
	}

	resp, err := c.makeAPIRequest(ctx, "zone/add_txt", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

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
// API: zone/remove_record — subdomain, record_type (required), content (optional; we pass it for exact match).
func (c *Client) RemoveTxtRecord(ctx context.Context, domain, subdomain, value string) error {
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"content":             value,
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	resp, err := c.makeAPIRequest(ctx, "zone/remove_record", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

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

func (c *Client) cachedZones() ([]string, bool) {
	c.zonesMu.RLock()
	defer c.zonesMu.RUnlock()

	if len(c.zonesCache) == 0 || c.zonesCached.IsZero() {
		return nil, false
	}

	ttl := c.zonesTTL
	if ttl <= 0 {
		ttl = DefaultZonesCacheTTL
	}
	if time.Since(c.zonesCached) >= ttl {
		return nil, false
	}

	zones := make([]string, len(c.zonesCache))
	copy(zones, c.zonesCache)
	return zones, true
}

func (c *Client) setZonesCache(zones []string) {
	c.zonesMu.Lock()
	defer c.zonesMu.Unlock()

	c.zonesCache = make([]string, len(zones))
	copy(c.zonesCache, zones)
	c.zonesCached = time.Now()
}

// GetZones retrieves a list of active domains from reg.ru account using service/get_list API.
// Results are cached to avoid hitting reg.ru rate limits during parallel ACME challenges.
func (c *Client) GetZones(ctx context.Context) ([]string, error) {
	if zones, ok := c.cachedZones(); ok {
		return zones, nil
	}

	c.zonesFetchMu.Lock()
	defer c.zonesFetchMu.Unlock()

	if zones, ok := c.cachedZones(); ok {
		return zones, nil
	}

	zones, err := c.fetchZones(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(zones))
	copy(result, zones)
	return result, nil
}

func (c *Client) fetchZones(ctx context.Context) ([]string, error) {
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

	if resp.Answer == nil {
		c.setZonesCache([]string{})
		return []string{}, nil
	}

	var servicesResp struct {
		Services []Service `json:"services"`
	}

	answerBytes, err := json.Marshal(resp.Answer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal API answer: %w", err)
	}

	if err := json.Unmarshal(answerBytes, &servicesResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal services response: %w", err)
	}

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

	c.setZonesCache(zones)
	return zones, nil
}

func isRetryableHTTPStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable
}

func isRetryableAPIError(resp *APIResponse) bool {
	switch resp.ErrorCode {
	case "IP_EXCEEDED_ALLOWED_CONNECTION_RATE", "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE":
		return true
	default:
		return false
	}
}

func (c *Client) retryDelay(attempt int) time.Duration {
	base := c.retryBaseDelay
	if base <= 0 {
		base = DefaultRetryBaseDelay
	}
	maxDelay := c.retryMaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultRetryMaxDelay
	}

	delay := base * time.Duration(1<<uint(attempt-1))
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// makeAPIRequest performs an HTTP POST request to reg.ru API with serialization and retries.
func (c *Client) makeAPIRequest(ctx context.Context, method string, params map[string]string) (*APIResponse, error) {
	maxRetries := c.maxRetries
	if maxRetries < 0 {
		maxRetries = DefaultMaxRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := waitForRetry(ctx, c.retryDelay(attempt)); err != nil {
				return nil, err
			}
		}

		c.requestMu.Lock()
		resp, err := c.doAPIRequest(ctx, method, params)
		c.requestMu.Unlock()

		if err != nil {
			lastErr = err
			if isRetryableError(err) && attempt < maxRetries {
				continue
			}
			return nil, err
		}

		if resp.Result != "success" && isRetryableAPIError(resp) && attempt < maxRetries {
			lastErr = fmt.Errorf("API error: %s - %s", resp.ErrorCode, resp.ErrorText)
			continue
		}

		return resp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("API request failed after %d retries", maxRetries)
}

func (c *Client) doAPIRequest(ctx context.Context, method string, params map[string]string) (*APIResponse, error) {
	apiURL := fmt.Sprintf("%s/%s", c.BaseURL, method)

	formData := url.Values{}
	for key, value := range params {
		formData.Set(key, value)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", DefaultUserAgent)

	httpResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, &apiHTTPError{
			statusCode: httpResp.StatusCode,
			body:       string(body),
		}
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w (body: %s)", err, string(body))
	}

	return &apiResp, nil
}
