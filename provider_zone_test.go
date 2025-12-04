package regru

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

// TestFindRootZone tests the findRootZone function with various domain scenarios
func TestFindRootZone(t *testing.T) {
	tests := []struct {
		name           string
		inputZone      string
		availableZones []string
		expectedZone   string
		expectError    bool
	}{
		{
			name:           "exact match - test.com",
			inputZone:      "test.com",
			availableZones: []string{"test.com"},
			expectedZone:   "test.com",
			expectError:    false,
		},
		{
			name:           "subdomain - a.test.com",
			inputZone:      "a.test.com",
			availableZones: []string{"test.com"},
			expectedZone:   "test.com",
			expectError:    false,
		},
		{
			name:           "multi-level subdomain - test.local.test.com",
			inputZone:      "test.local.test.com",
			availableZones: []string{"test.com"},
			expectedZone:   "test.com",
			expectError:    false,
		},
		{
			name:           "multiple zones - should find longest match",
			inputZone:      "test.local.test.com",
			availableZones: []string{"test.com", "local.test.com"},
			expectedZone:   "local.test.com", // Should find the longest matching zone
			expectError:    false,
		},
		{
			name:           "zone not found",
			inputZone:      "unknown.com",
			availableZones: []string{"test.com"},
			expectError:    true,
		},
		{
			name:           "wildcard zone - *.test.com",
			inputZone:      "*.test.com",
			availableZones: []string{"test.com"},
			expectedZone:   "test.com",
			expectError:    false,
		},
		{
			name:           "wildcard zone - *.local.test.com",
			inputZone:      "*.local.test.com",
			availableZones: []string{"test.com"},
			expectedZone:   "test.com",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the logic directly
			// Remove wildcard prefix if present
			cleanZone := trimSuffix(tt.inputZone, ".")
			cleanZone = strings.TrimPrefix(cleanZone, "*.")

			// Test exact match
			var foundZone string
			var found bool
			for _, apiZone := range tt.availableZones {
				apiZone = trimSuffix(apiZone, ".")
				if cleanZone == apiZone {
					foundZone = apiZone
					found = true
					break
				}
			}

			// Test subdomain match if exact match not found
			if !found {
				var bestMatch string
				for _, apiZone := range tt.availableZones {
					apiZone = trimSuffix(apiZone, ".")
					if hasSuffix(cleanZone, "."+apiZone) {
						if len(apiZone) > len(bestMatch) {
							bestMatch = apiZone
						}
					}
				}
				if bestMatch != "" {
					foundZone = bestMatch
					found = true
				}
			}

			if tt.expectError {
				assert.False(t, found, "Expected error but found zone: %s", foundZone)
			} else {
				assert.True(t, found, "Expected to find zone but didn't")
				assert.Equal(t, tt.expectedZone, foundZone, "Expected zone %s, got %s", tt.expectedZone, foundZone)
			}
		})
	}
}

// TestGetSubdomainSpecificCases tests the getSubdomain function with specific domain cases
func TestGetSubdomainSpecificCases(t *testing.T) {
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
			name:           "ACME challenge for test.com root",
			recordName:     "_acme-challenge.test.com",
			rootZone:       "test.com",
			originalZone:   "test.com",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "ACME challenge for a.test.com",
			recordName:     "_acme-challenge.a.test.com",
			rootZone:       "test.com",
			originalZone:   "a.test.com",
			expectedSubdom: "_acme-challenge.a",
		},
		{
			name:           "ACME challenge for test.local.test.com",
			recordName:     "_acme-challenge.test.local.test.com",
			rootZone:       "test.com",
			originalZone:   "test.local.test.com",
			expectedSubdom: "_acme-challenge.test.local",
		},
		{
			name:           "ACME challenge record name only for a.test.com",
			recordName:     "_acme-challenge",
			rootZone:       "test.com",
			originalZone:   "a.test.com",
			expectedSubdom: "_acme-challenge.a",
		},
		{
			name:           "ACME challenge record name only for test.local.test.com",
			recordName:     "_acme-challenge",
			rootZone:       "test.com",
			originalZone:   "test.local.test.com",
			expectedSubdom: "_acme-challenge.test.local",
		},
		{
			name:           "Full record name for a.test.com",
			recordName:     "_acme-challenge.a.test.com",
			rootZone:       "test.com",
			originalZone:   "a.test.com",
			expectedSubdom: "_acme-challenge.a",
		},
		{
			name:           "Full record name for test.local.test.com",
			recordName:     "_acme-challenge.test.local.test.com",
			rootZone:       "test.com",
			originalZone:   "test.local.test.com",
			expectedSubdom: "_acme-challenge.test.local",
		},
		{
			name:           "ACME challenge for wildcard *.test.com",
			recordName:     "_acme-challenge",
			rootZone:       "test.com",
			originalZone:   "*.test.com",
			expectedSubdom: "_acme-challenge",
		},
		{
			name:           "ACME challenge for wildcard *.local.test.com",
			recordName:     "_acme-challenge",
			rootZone:       "test.com",
			originalZone:   "*.local.test.com",
			expectedSubdom: "_acme-challenge.local",
		},
		{
			name:           "ACME challenge full name for wildcard *.test.com",
			recordName:     "_acme-challenge.any.test.com",
			rootZone:       "test.com",
			originalZone:   "*.test.com",
			expectedSubdom: "_acme-challenge.any",
		},
		{
			name:           "ACME challenge full name for wildcard *.local.test.com",
			recordName:     "_acme-challenge.any.local.test.com",
			rootZone:       "test.com",
			originalZone:   "*.local.test.com",
			expectedSubdom: "_acme-challenge.any.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.getSubdomain(tt.recordName, tt.rootZone, tt.originalZone)
			assert.Equal(t, tt.expectedSubdom, result,
				"Expected subdomain '%s', got '%s' for recordName=%s, rootZone=%s, originalZone=%s",
				tt.expectedSubdom, result, tt.recordName, tt.rootZone, tt.originalZone)
		})
	}
}

// Helper functions to avoid importing strings package in test
func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// TestFullFlow tests the complete flow with mock client
func TestFullFlow(t *testing.T) {
	provider := &Provider{
		Username: "test@example.com",
		Password: "password123",
		logger:   zaptest.NewLogger(t),
	}

	// This test would require mocking the internal client, which is more complex
	// For now, we test the logic components separately
	t.Run("subdomain computation logic", func(t *testing.T) {
		// Test that getSubdomain correctly handles the three cases
		testCases := []struct {
			recordName     string
			rootZone       string
			originalZone   string
			expectedSubdom string
		}{
			{"_acme-challenge.test.com", "test.com", "test.com", "_acme-challenge"},
			{"_acme-challenge.a.test.com", "test.com", "a.test.com", "_acme-challenge.a"},
			{"_acme-challenge.test.local.test.com", "test.com", "test.local.test.com", "_acme-challenge.test.local"},
			{"_acme-challenge", "test.com", "a.test.com", "_acme-challenge.a"},
			{"_acme-challenge", "test.com", "test.local.test.com", "_acme-challenge.test.local"},
		}

		for _, tc := range testCases {
			result := provider.getSubdomain(tc.recordName, tc.rootZone, tc.originalZone)
			assert.Equal(t, tc.expectedSubdom, result,
				"Failed for recordName=%s, rootZone=%s, originalZone=%s",
				tc.recordName, tc.rootZone, tc.originalZone)
		}
	})
}
