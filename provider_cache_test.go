package regru

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DoMaLo/caddy-regru/internal"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestResolveRootZone(t *testing.T) {
	tests := []struct {
		name         string
		zone         string
		available    []string
		expectedZone string
		expectError  bool
	}{
		{
			name:         "exact match",
			zone:         "fivegen.ru",
			available:    []string{"fivegen.ru"},
			expectedZone: "fivegen.ru",
		},
		{
			name:         "subdomain",
			zone:         "nvr-cloud.fivegen.ru",
			available:    []string{"fivegen.ru"},
			expectedZone: "fivegen.ru",
		},
		{
			name:         "wildcard zone",
			zone:         "*.fivegen.ru",
			available:    []string{"fivegen.ru"},
			expectedZone: "fivegen.ru",
		},
		{
			name:         "longest suffix match",
			zone:         "app.local.example.com",
			available:    []string{"example.com", "local.example.com"},
			expectedZone: "local.example.com",
		},
		{
			name:        "not found",
			zone:        "missing.com",
			available:   []string{"fivegen.ru"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootZone, err := resolveRootZone(tt.zone, tt.available)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedZone, rootZone)
		})
	}
}

func TestProvider_ZoneCacheReducesAPIRequests(t *testing.T) {
	var getListCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "service/get_list"):
			getListCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": "success",
				"answer": map[string]interface{}{
					"services": []interface{}{
						map[string]interface{}{
							"dname":    "fivegen.ru",
							"servtype": "domain",
							"state":    "A",
						},
					},
				},
			})
		case strings.Contains(r.URL.Path, "zone/add_txt"):
			json.NewEncoder(w).Encode(map[string]interface{}{"result": "success"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	apiClient := internal.NewClient("test@example.com", "password123")
	apiClient.HTTPClient = server.Client()
	apiClient.BaseURL = server.URL

	provider := &Provider{
		Username: "test@example.com",
		Password: "password123",
		logger:   zaptest.NewLogger(t),
		client:   apiClient,
	}

	ctx := context.Background()
	record := &libdns.TXT{
		Name: "_acme-challenge.nvr-cloud",
		Text: "challenge-token",
	}

	sites := []string{
		"nvr-cloud.fivegen.ru",
		"nvr-wiz.fivegen.ru",
		"streamseek-sil-demo-01.fivegen.ru",
	}

	for _, site := range sites {
		_, err := provider.AppendRecords(ctx, site, []libdns.Record{record})
		assert.NoError(t, err, "AppendRecords failed for %s", site)
	}

	assert.Equal(t, int32(1), getListCalls.Load(), "service/get_list should be called once and cached")
}

func TestProvider_ReusesSingleClient(t *testing.T) {
	provider := &Provider{
		Username: "test@example.com",
		Password: "password123",
	}

	client1, err := provider.getClient()
	assert.NoError(t, err)

	client2, err := provider.getClient()
	assert.NoError(t, err)

	assert.Same(t, client1, client2)
}
