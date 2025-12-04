package regru

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/DoMaLo/caddy-regru/internal"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

const (
	// defaultTTL is the default TTL for DNS records when not specified
	defaultTTL = 5 * time.Minute
)

// credentialsRegexp matches basic email format for username
var credentialsRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// Provider implements the libdns interfaces for reg.ru
type Provider struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	logger *zap.Logger
}

// CaddyDNSProvider wraps the provider implementation as a Caddy module.
type CaddyDNSProvider struct{ *Provider }

func init() {
	caddy.RegisterModule(CaddyDNSProvider{})
}

// CaddyModule returns the Caddy module information.
func (CaddyDNSProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.regru",
		New: func() caddy.Module { return &CaddyDNSProvider{new(Provider)} },
	}
}

// Provision implements caddy.Provisioner.
func (p *CaddyDNSProvider) Provision(ctx caddy.Context) error {
	p.Provider.logger = ctx.Logger()

	// Environment variables are replaced automatically during Caddyfile parsing
	// If using JSON config, use caddy.NewReplacer() to replace variables
	if p.Provider.Username == "" {
		return fmt.Errorf("regru: username is required")
	}
	if p.Provider.Password == "" {
		return fmt.Errorf("regru: password is required")
	}

	if !validCredentials(p.Provider.Username) {
		return fmt.Errorf("regru: username '%s' appears invalid; ensure it's a valid email address", p.Provider.Username)
	}

	if p.Provider.logger != nil {
		p.Provider.logger.Info("reg.ru DNS provider configured",
			zap.String("username", p.Provider.Username))
	}

	return nil
}

// validCredentials validates if the provided credentials match expected email format
func validCredentials(cred string) bool {
	return credentialsRegexp.MatchString(cred)
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens.
func (p *CaddyDNSProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "username":
			if d.NextArg() {
				p.Provider.Username = d.Val()
			} else {
				return d.ArgErr()
			}
		case "password":
			if d.NextArg() {
				p.Provider.Password = d.Val()
			} else {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	if d.NextArg() {
		return d.Errf("unexpected argument '%s'", d.Val())
	}

	if p.Provider.Username == "" {
		return d.Err("missing username")
	}
	if p.Provider.Password == "" {
		return d.Err("missing password")
	}

	return nil
}

// findRootZone finds the root zone for the given zone name by querying reg.ru API.
// It handles both exact matches and subdomain matches (e.g., "sub.example.com" -> "example.com").
func (p *Provider) findRootZone(ctx context.Context, zone string) (string, error) {
	client, err := p.getClient()
	if err != nil {
		return "", fmt.Errorf("failed to create client: %w", err)
	}

	zones, err := client.GetZones(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get zones from reg.ru API: %w", err)
	}

	cleanZone := strings.TrimSuffix(zone, ".")
	// Remove wildcard prefix if present (e.g., "*.test.com" -> "test.com")
	cleanZone = strings.TrimPrefix(cleanZone, "*.")

	if p.logger != nil {
		p.logger.Debug("Finding root zone",
			zap.String("input_zone", cleanZone),
			zap.Strings("available_zones", zones))
	}
	for _, apiZone := range zones {
		apiZone = strings.TrimSuffix(apiZone, ".")
		if cleanZone == apiZone {
			if p.logger != nil {
				p.logger.Info("Found exact root zone match",
					zap.String("input_zone", cleanZone),
					zap.String("root_zone", apiZone))
			}
			return apiZone, nil
		}
	}

	var bestMatch string
	for _, apiZone := range zones {
		apiZone = strings.TrimSuffix(apiZone, ".")
		if strings.HasSuffix(cleanZone, "."+apiZone) {
			if len(apiZone) > len(bestMatch) {
				bestMatch = apiZone
			}
		}
	}

	if bestMatch != "" {
		if p.logger != nil {
			p.logger.Info("Found root zone for subdomain",
				zap.String("input_zone", cleanZone),
				zap.String("root_zone", bestMatch))
		}
		return bestMatch, nil
	}

	return "", fmt.Errorf("domain '%s' not found in your reg.ru account. Available domains: %v", cleanZone, zones)
}

// getSubdomain computes the subdomain name for a DNS record, taking into account
// the root zone and original zone. It handles various edge cases like empty record names,
// "@" symbols, and multi-level subdomains.
func (p *Provider) getSubdomain(recordName, rootZone, originalZone string) string {
	recordName = strings.TrimSuffix(recordName, ".")
	rootZone = strings.TrimSuffix(rootZone, ".")
	originalZone = strings.TrimSuffix(originalZone, ".")

	// Remove wildcard prefix from originalZone if present (e.g., "*.test.com" -> "test.com")
	originalZone = strings.TrimPrefix(originalZone, "*.")

	if p.logger != nil {
		p.logger.Debug("Computing subdomain",
			zap.String("record_name", recordName),
			zap.String("root_zone", rootZone),
			zap.String("original_zone", originalZone))
	}

	if recordName == "" || recordName == "@" || recordName == rootZone {
		return ""
	}

	if strings.HasSuffix(recordName, "."+rootZone) {
		return strings.TrimSuffix(recordName, "."+rootZone)
	}

	if originalZone != rootZone {
		if strings.HasSuffix(originalZone, "."+rootZone) {
			zonePrefix := strings.TrimSuffix(originalZone, "."+rootZone)
			if recordName == zonePrefix {
				return recordName
			}
			if zonePrefix != "" {
				return recordName + "." + zonePrefix
			}
		}
	}

	return recordName
}

// GetRecords lists DNS records for the given zone.
//
// NOTE: This method is not fully implemented because reg.ru API 2.0 does not
// provide a method to retrieve DNS records from a zone. The API only supports
// adding (zone/add_txt) and removing (zone/remove_record) records.
//
// This method is required by the libdns.RecordGetter interface but is not used
// by Certmagic for ACME DNS-01 challenges, which only require AppendRecords
// and DeleteRecords. Returning an empty list satisfies the interface contract.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("GetRecords called", zap.String("zone", zone))
	}

	return []libdns.Record{}, nil
}

// AppendRecords adds DNS records to the given zone.
//
// This method is used by Certmagic to add TXT records for ACME DNS-01 challenges.
// Only TXT records are supported. The method automatically finds the root zone
// for subdomains and computes the correct subdomain name for the DNS record.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("AppendRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	if zone == "" {
		return nil, fmt.Errorf("regru: zone cannot be empty")
	}

	// Find root zone through reg.ru API
	rootZone, err := p.findRootZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	var results []libdns.Record
	for i, record := range records {
		if p.logger != nil {
			p.logger.Info("Processing record",
				zap.Int("index", i),
				zap.Any("record", record))
		}

		// Get RR from Record
		rr := record.RR()

		// Validate record type
		if rr.Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported, got: %s", rr.Type)
		}

		// Compute subdomain taking into account originalZone
		subDomain := p.getSubdomain(rr.Name, rootZone, zone)

		if p.logger != nil {
			p.logger.Info("Adding TXT record",
				zap.String("root_zone", rootZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data),
				zap.String("original_name", rr.Name),
				zap.String("original_zone", zone))
		}

		err := client.AddTXTRecord(ctx, rootZone, subDomain, rr.Data)
		if err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to add TXT record",
					zap.String("root_zone", rootZone),
					zap.String("subdomain", subDomain),
					zap.String("value", rr.Data),
					zap.Error(err))
			}
			return nil, fmt.Errorf("failed to add TXT record for %s: %w", rr.Name, err)
		}

		resultRecord := record
		resultRR := resultRecord.RR()

		if resultRR.TTL == 0 {
			resultRR.TTL = defaultTTL
		}

		if txtRecord, ok := resultRecord.(*libdns.TXT); ok {
			newTXT := *txtRecord
			newTXT.TTL = resultRR.TTL
			results = append(results, &newTXT)
		} else {
			results = append(results, resultRecord)
		}

		if p.logger != nil {
			p.logger.Info("Successfully added TXT record",
				zap.String("root_zone", rootZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data))
		}
	}

	return results, nil
}

// SetRecords replaces DNS records in the given zone.
//
// For reg.ru API, SetRecords works the same as AppendRecords because the API
// doesn't support querying existing records. This method is used by Certmagic
// to ensure DNS records are set correctly for ACME challenges.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("SetRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	// For reg.ru API, SetRecords works the same as AppendRecords
	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords removes DNS records from the given zone.
//
// This method is used by Certmagic to clean up TXT records after ACME DNS-01
// challenge validation. Only TXT records are supported. The method automatically
// finds the root zone for subdomains and computes the correct subdomain name.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("DeleteRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	if zone == "" {
		return nil, fmt.Errorf("regru: zone cannot be empty")
	}

	// Find root zone through reg.ru API
	rootZone, err := p.findRootZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	var results []libdns.Record
	for i, record := range records {
		if p.logger != nil {
			p.logger.Info("Processing record for deletion",
				zap.Int("index", i),
				zap.Any("record", record))
		}

		// Get RR from Record
		rr := record.RR()

		// Validate record type
		if rr.Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported, got: %s", rr.Type)
		}

		// Compute subdomain taking into account originalZone
		subDomain := p.getSubdomain(rr.Name, rootZone, zone)

		if p.logger != nil {
			p.logger.Info("Removing TXT record",
				zap.String("root_zone", rootZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data),
				zap.String("original_name", rr.Name),
				zap.String("original_zone", zone))
		}

		err := client.RemoveTxtRecord(ctx, rootZone, subDomain, rr.Data)
		if err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to remove TXT record",
					zap.String("root_zone", rootZone),
					zap.String("subdomain", subDomain),
					zap.String("value", rr.Data),
					zap.Error(err))
			}
			return nil, fmt.Errorf("failed to remove TXT record for %s: %w", rr.Name, err)
		}

		results = append(results, record)

		if p.logger != nil {
			p.logger.Info("Successfully removed TXT record",
				zap.String("root_zone", rootZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data))
		}
	}

	return results, nil
}

// getClient creates and returns a new HTTP client configured for reg.ru API.
// It validates that both username and password are provided before creating the client.
func (p *Provider) getClient() (*internal.Client, error) {
	if p.Username == "" || p.Password == "" {
		return nil, errors.New("regru: incomplete credentials, missing username and/or password")
	}

	client := internal.NewClient(p.Username, p.Password)

	return client, nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*CaddyDNSProvider)(nil)
	_ caddy.Provisioner     = (*CaddyDNSProvider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
