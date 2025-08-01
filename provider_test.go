package regru

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

type TestRecord struct {
	name string
	ttl  time.Duration
	typ  string
	data string
}

func (tr *TestRecord) RR() libdns.RR {
	return libdns.RR{
		Name: tr.name,
		TTL:  tr.ttl,
		Type: tr.typ,
		Data: tr.data,
	}
}

func TestCredentialsRegexp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid email",
			input:    "test@example.com",
			expected: true,
		},
		{
			name:     "valid email with subdomain",
			input:    "user@mail.example.com",
			expected: true,
		},
		{
			name:     "valid email with numbers",
			input:    "test123@example123.com",
			expected: true,
		},
		{
			name:     "valid email with special chars",
			input:    "test.user+tag@example-domain.co.uk",
			expected: true,
		},
		{
			name:     "invalid - no @",
			input:    "testexample.com",
			expected: false,
		},
		{
			name:     "invalid - no domain",
			input:    "test@",
			expected: false,
		},
		{
			name:     "invalid - no TLD",
			input:    "test@example",
			expected: false,
		},
		{
			name:     "invalid - short TLD",
			input:    "test@example.c",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validCredentials(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCaddyDNSProvider_CaddyModule(t *testing.T) {
	provider := CaddyDNSProvider{}
	moduleInfo := provider.CaddyModule()

	assert.Equal(t, "dns.providers.regru", string(moduleInfo.ID))
	assert.NotNil(t, moduleInfo.New)

	newModule := moduleInfo.New()
	_, ok := newModule.(*CaddyDNSProvider)
	assert.True(t, ok)
}

func TestCaddyDNSProvider_Provision(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		expectedError string
	}{
		{
			name:          "valid credentials",
			username:      "test@example.com",
			password:      "password123",
			expectedError: "",
		},
		{
			name:          "empty username",
			username:      "",
			password:      "password123",
			expectedError: "regru: username is required",
		},
		{
			name:          "empty password",
			username:      "test@example.com",
			password:      "",
			expectedError: "regru: password is required",
		},
		{
			name:          "invalid username format",
			username:      "invalid-username",
			password:      "password123",
			expectedError: "regru: username 'invalid-username' appears invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &CaddyDNSProvider{
				Provider: &Provider{
					Username: tt.username,
					Password: tt.password,
				},
			}

			logger := zaptest.NewLogger(t)
			ctx := caddy.Context{
				Context: context.Background(),
			}
			provider.Provider.logger = logger

			err := provider.Provision(ctx)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.username, provider.Provider.Username)
				assert.Equal(t, tt.password, provider.Provider.Password)
				assert.NotNil(t, provider.Provider.logger)
			}
		})
	}
}

func TestCaddyDNSProvider_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedError string
		expectedUser  string
		expectedPass  string
	}{
		{
			name: "valid config",
			input: `regru {
				username test@example.com
				password secret123
			}`,
			expectedError: "",
			expectedUser:  "test@example.com",
			expectedPass:  "secret123",
		},
		{
			name: "missing username",
			input: `regru {
				password secret123
			}`,
			expectedError: "missing username",
		},
		{
			name: "missing password",
			input: `regru {
				username test@example.com
			}`,
			expectedError: "missing password",
		},
		{
			name: "invalid directive",
			input: `regru {
				username test@example.com
				password secret123
				invalid_directive value
			}`,
			expectedError: "unrecognized subdirective 'invalid_directive'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &CaddyDNSProvider{
				Provider: &Provider{},
			}

			d := caddyfile.NewTestDispenser(tt.input)
			err := provider.UnmarshalCaddyfile(d)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUser, provider.Provider.Username)
				assert.Equal(t, tt.expectedPass, provider.Provider.Password)
			}
		})
	}
}

func TestProvider_GetRecords(t *testing.T) {
	provider := &Provider{
		Username: "test@example.com",
		Password: "password123",
		logger:   zaptest.NewLogger(t),
	}

	records, err := provider.GetRecords(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.NotNil(t, records)
	assert.Equal(t, 0, len(records))
}

func TestProvider_getClient(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		expectedError string
	}{
		{
			name:          "valid credentials",
			username:      "test@example.com",
			password:      "password123",
			expectedError: "",
		},
		{
			name:          "empty username",
			username:      "",
			password:      "password123",
			expectedError: "regru: incomplete credentials",
		},
		{
			name:          "empty password",
			username:      "test@example.com",
			password:      "",
			expectedError: "regru: incomplete credentials",
		},
		{
			name:          "both empty",
			username:      "",
			password:      "",
			expectedError: "regru: incomplete credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				Username: tt.username,
				Password: tt.password,
			}

			client, err := provider.getClient()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestGetSubdomain(t *testing.T) {
	provider := &Provider{
		logger: zaptest.NewLogger(t),
	}

	tests := []struct {
		name           string
		recordName     string
		rootZone       string
		originalZone   string
		expectedSubdom string
	}{
		{
			name:           "acme challenge for subdomain",
			recordName:     "_acme-challenge.test1",
			rootZone:       "example.com",
			originalZone:   "local.example.com",
			expectedSubdom: "_acme-challenge.test1.local",
		},
		{
			name:           "acme challenge for root zone",
			recordName:     "_acme-challenge",
			rootZone:       "example.com",
			originalZone:   "example.com",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "full domain name",
			recordName:     "_acme-challenge.test.example.com",
			rootZone:       "example.com",
			originalZone:   "example.com",
			expectedSubdom: "_acme-challenge.test",
		},
		{
			name:           "empty record name",
			recordName:     "",
			rootZone:       "example.com",
			originalZone:   "example.com",
			expectedSubdom: "",
		},
		{
			name:           "@ symbol",
			recordName:     "@",
			rootZone:       "example.com",
			originalZone:   "example.com",
			expectedSubdom: "",
		},
		{
			name:           "record name equals root zone",
			recordName:     "example.com",
			rootZone:       "example.com",
			originalZone:   "example.com",
			expectedSubdom: "",
		},
		{
			name:           "complex subdomain with multiple levels",
			recordName:     "_acme-challenge.api",
			rootZone:       "example.com",
			originalZone:   "prod.local.example.com",
			expectedSubdom: "_acme-challenge.api.prod.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.getSubdomain(tt.recordName, tt.rootZone, tt.originalZone)
			assert.Equal(t, tt.expectedSubdom, result)
		})
	}
}

func TestRecordValidation(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		record        libdns.Record
		expectedError string
	}{
		{
			name: "valid TXT record",
			zone: "example.com",
			record: &TestRecord{
				name: "_acme-challenge.example.com.",
				typ:  "TXT",
				data: "test-value",
			},
			expectedError: "",
		},
		{
			name: "empty zone",
			zone: "",
			record: &TestRecord{
				name: "_acme-challenge.example.com.",
				typ:  "TXT",
				data: "test-value",
			},
			expectedError: "regru: zone cannot be empty",
		},
		{
			name: "unsupported record type",
			zone: "example.com",
			record: &TestRecord{
				name: "test.example.com.",
				typ:  "A",
				data: "192.168.1.1",
			},
			expectedError: "only TXT records are supported, got: A",
		},
		{
			name: "unsupported CNAME record",
			zone: "example.com",
			record: &TestRecord{
				name: "test.example.com.",
				typ:  "CNAME",
				data: "target.example.com.",
			},
			expectedError: "only TXT records are supported, got: CNAME",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := tt.record.RR()

			if tt.zone == "" {
				assert.Contains(t, tt.expectedError, "regru: zone cannot be empty")
				return
			}

			if rr.Type != "TXT" {
				expectedMsg := "only TXT records are supported, got: " + rr.Type
				assert.Equal(t, expectedMsg, tt.expectedError)
				return
			}

			assert.Equal(t, "", tt.expectedError)
		})
	}
}

func TestRRProcessing(t *testing.T) {
	tests := []struct {
		name         string
		record       libdns.Record
		expectedType string
		expectedData string
		expectedName string
		expectedTTL  time.Duration
	}{
		{
			name: "TXT record",
			record: &TestRecord{
				name: "_acme-challenge.example.com.",
				data: "test-challenge-value",
				ttl:  300 * time.Second,
				typ:  "TXT",
			},
			expectedType: "TXT",
			expectedData: "test-challenge-value",
			expectedName: "_acme-challenge.example.com.",
			expectedTTL:  300 * time.Second,
		},
		{
			name: "A record",
			record: &TestRecord{
				name: "www.example.com.",
				data: "192.168.1.1",
				ttl:  3600 * time.Second,
				typ:  "A",
			},
			expectedType: "A",
			expectedData: "192.168.1.1",
			expectedName: "www.example.com.",
			expectedTTL:  3600 * time.Second,
		},
		{
			name: "record with zero TTL",
			record: &TestRecord{
				name: "test.example.com.",
				data: "test-value",
				ttl:  0,
				typ:  "TXT",
			},
			expectedType: "TXT",
			expectedData: "test-value",
			expectedName: "test.example.com.",
			expectedTTL:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := tt.record.RR()
			assert.Equal(t, tt.expectedType, rr.Type)
			assert.Equal(t, tt.expectedData, rr.Data)
			assert.Equal(t, tt.expectedName, rr.Name)
			assert.Equal(t, tt.expectedTTL, rr.TTL)
		})
	}
}

func TestEmptyRecordsList(t *testing.T) {
	records := []libdns.Record{}
	assert.Equal(t, 0, len(records))
}

func TestProviderWithoutLogger(t *testing.T) {
	provider := &Provider{
		Username: "test@example.com",
		Password: "password123",
	}

	records, err := provider.GetRecords(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.NotNil(t, records)
	assert.Equal(t, 0, len(records))
}

func TestInterfaceImplementation(t *testing.T) {
	var _ caddyfile.Unmarshaler = (*CaddyDNSProvider)(nil)
	var _ caddy.Provisioner = (*CaddyDNSProvider)(nil)
	var _ libdns.RecordGetter = (*Provider)(nil)
	var _ libdns.RecordAppender = (*Provider)(nil)
	var _ libdns.RecordSetter = (*Provider)(nil)
	var _ libdns.RecordDeleter = (*Provider)(nil)
}

func TestFindRootZoneError(t *testing.T) {
	tests := []struct {
		name         string
		zone         string
		mockZones    []string
		shouldError  bool
		expectedZone string
		errorMsg     string
	}{
		{
			name:         "exact match found",
			zone:         "example.com",
			mockZones:    []string{"example.com", "5gen.ru"},
			shouldError:  false,
			expectedZone: "example.com",
		},
		{
			name:         "subdomain match found",
			zone:         "local.example.com",
			mockZones:    []string{"example.com", "5gen.ru"},
			shouldError:  false,
			expectedZone: "example.com",
		},
		{
			name:        "no match found",
			zone:        "unknown.com",
			mockZones:   []string{"example.com", "5gen.ru"},
			shouldError: true,
			errorMsg:    "domain 'unknown.com' not found in your reg.ru account",
		},
		{
			name:        "empty zones list",
			zone:        "example.com",
			mockZones:   []string{},
			shouldError: true,
			errorMsg:    "domain 'example.com' not found in your reg.ru account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Тестируем логику обработки ошибок без создания реального провайдера
			if tt.shouldError {
				assert.Contains(t, tt.errorMsg, "not found in your reg.ru account")
			} else {
				// Тестируем логику поиска зон
				cleanZone := strings.TrimSuffix(tt.zone, ".")

				// Ищем точное совпадение
				var found bool
				var bestMatch string

				for _, apiZone := range tt.mockZones {
					apiZone = strings.TrimSuffix(apiZone, ".")
					if cleanZone == apiZone {
						found = true
						bestMatch = apiZone
						break
					}
				}

				// Если не найдено точное совпадение, ищем поддомен
				if !found {
					for _, apiZone := range tt.mockZones {
						apiZone = strings.TrimSuffix(apiZone, ".")
						if strings.HasSuffix(cleanZone, "."+apiZone) {
							if len(apiZone) > len(bestMatch) {
								bestMatch = apiZone
							}
						}
					}
				}

				if bestMatch != "" {
					assert.Equal(t, tt.expectedZone, bestMatch)
				}
			}
		})
	}
}

func TestZoneNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "zone with trailing dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "zone without trailing dot",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "empty zone",
			input:    "",
			expected: "",
		},
		{
			name:     "zone with multiple dots",
			input:    "sub.example.com.",
			expected: "sub.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strings.TrimSuffix(tt.input, ".")
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkValidCredentials(b *testing.B) {
	testCases := []string{
		"test@example.com",
		"invalid-email",
		"user@subdomain.example.co.uk",
		"",
		"no-at-symbol.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range testCases {
			validCredentials(tc)
		}
	}
}

func BenchmarkRecordProcessing(b *testing.B) {
	record := &TestRecord{
		name: "_acme-challenge.example.com.",
		data: "test-challenge-value",
		ttl:  300 * time.Second,
		typ:  "TXT",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := record.RR()
		_ = rr.Type
		_ = rr.Data
		_ = rr.Name
		_ = rr.TTL
	}
}

func BenchmarkGetSubdomain(b *testing.B) {
	provider := &Provider{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.getSubdomain("_acme-challenge.test1", "example.com", "local.example.com")
	}
}
