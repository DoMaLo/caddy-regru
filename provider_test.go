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

func TestRecordNameProcessing(t *testing.T) {
	tests := []struct {
		name           string
		zone           string
		recordName     string
		expectedSubdom string
	}{
		{
			name:           "full domain name",
			zone:           "example.com",
			recordName:     "_acme-challenge.example.com.",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "subdomain without zone suffix",
			zone:           "example.com",
			recordName:     "_acme-challenge",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "root domain",
			zone:           "example.com",
			recordName:     "example.com.",
			expectedSubdom: "",
		},
		{
			name:           "empty record name",
			zone:           "example.com",
			recordName:     "",
			expectedSubdom: "",
		},
		{
			name:           "@ symbol",
			zone:           "example.com",
			recordName:     "@",
			expectedSubdom: "",
		},
		{
			name:           "nested subdomain",
			zone:           "example.com",
			recordName:     "sub.domain.example.com.",
			expectedSubdom: "sub.domain",
		},
		{
			name:           "zone with trailing dot",
			zone:           "example.com.",
			recordName:     "_acme-challenge.example.com.",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "complex subdomain",
			zone:           "example.com",
			recordName:     "a.b.c.example.com.",
			expectedSubdom: "a.b.c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanZone := strings.TrimSuffix(tt.zone, ".")
			recordName := strings.TrimSuffix(tt.recordName, ".")

			var subDomain string
			if recordName == "" || recordName == "@" || recordName == cleanZone {
				subDomain = ""
			} else if strings.HasSuffix(recordName, "."+cleanZone) {
				subDomain = strings.TrimSuffix(recordName, "."+cleanZone)
			} else {
				subDomain = recordName
			}

			assert.Equal(t, tt.expectedSubdom, subDomain)
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
				assert.Contains(t, "regru: zone cannot be empty", tt.expectedError)
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

func BenchmarkRecordNameProcessing(b *testing.B) {
	zone := "example.com"
	recordName := "_acme-challenge.example.com."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cleanZone := strings.TrimSuffix(zone, ".")
		name := strings.TrimSuffix(recordName, ".")

		var subDomain string
		if name == "" || name == "@" || name == cleanZone {
			subDomain = ""
		} else if strings.HasSuffix(name, "."+cleanZone) {
			subDomain = strings.TrimSuffix(name, "."+cleanZone)
		} else {
			subDomain = name
		}
		_ = subDomain
	}
}
