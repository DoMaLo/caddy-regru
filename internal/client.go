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

// DefaultTimeout is the default timeout for HTTP requests
const DefaultTimeout = 30 * time.Second

// Client represents a reg.ru API client
type Client struct {
	Username   string
	Password   string
	HTTPClient *http.Client
	BaseURL    string // Делаем BaseURL полем структуры
}

// NewClient creates a new reg.ru API client
func NewClient(username, password string) *Client {
	return &Client{
		Username: username,
		Password: password,
		BaseURL:  "https://api.reg.ru/api/regru2", // Значение по умолчанию
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

// AddTXTRecord adds a TXT record to the specified domain
func (c *Client) AddTXTRecord(ctx context.Context, domain, subdomain, value string) error {
	// Подготавливаем параметры для API запроса
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"content":             value,
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	// Выполняем API запрос
	resp, err := c.makeAPIRequest(ctx, "zone/add_txt", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

	// Проверяем ответ API
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

// RemoveTxtRecord removes a TXT record from the specified domain
func (c *Client) RemoveTxtRecord(ctx context.Context, domain, subdomain, value string) error {
	// Подготавливаем параметры для API запроса
	params := map[string]string{
		"username":            c.Username,
		"password":            c.Password,
		"domain_name":         domain,
		"subdomain":           subdomain,
		"content":             value,
		"record_type":         "TXT",
		"output_content_type": "json",
	}

	// Выполняем API запрос
	resp, err := c.makeAPIRequest(ctx, "zone/remove_record", params)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}

	// Проверяем ответ API
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

// makeAPIRequest выполняет HTTP запрос к API reg.ru
func (c *Client) makeAPIRequest(ctx context.Context, method string, params map[string]string) (*APIResponse, error) {
	// Создаем URL
	apiURL := fmt.Sprintf("%s/%s", c.BaseURL, method)

	// Подготавливаем form data
	formData := url.Values{}
	for key, value := range params {
		formData.Set(key, value)
	}

	// Создаем HTTP запрос
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "caddy-regru-dns-provider/1.0")

	// Выполняем запрос
	httpResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer httpResp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Проверяем HTTP статус
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", httpResp.StatusCode, string(body))
	}

	// Парсим JSON ответ
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w (body: %s)", err, string(body))
	}

	return &apiResp, nil
}

// GetZones получает список доменов через service/get_list
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

	// Парсим ответ для получения списка доменов
	var zones []string
	var uniqueZones = make(map[string]bool)

	if resp.Answer != nil {
		if answerMap, ok := resp.Answer.(map[string]interface{}); ok {
			if services, ok := answerMap["services"].([]interface{}); ok {
				for _, service := range services {
					if serviceMap, ok := service.(map[string]interface{}); ok {
						// Проверяем что это домен и он активен
						if servType, ok := serviceMap["servtype"].(string); ok && servType == "domain" {
							if state, ok := serviceMap["state"].(string); ok && state == "A" {
								if dname, ok := serviceMap["dname"].(string); ok && dname != "" {
									// Добавляем только уникальные домены
									if !uniqueZones[dname] {
										zones = append(zones, dname)
										uniqueZones[dname] = true
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return zones, nil
}
