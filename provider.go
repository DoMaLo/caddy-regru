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

// credentialsRegexp matches basic email format for username
var credentialsRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// Provider implements the libdns interfaces for reg.ru
type Provider struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TLSCert  string `json:"tls_cert,omitempty"`
	TLSKey   string `json:"tls_key,omitempty"`

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

	replacer := caddy.NewReplacer()
	p.Provider.Username = replacer.ReplaceAll(p.Provider.Username, "")
	p.Provider.Password = replacer.ReplaceAll(p.Provider.Password, "")

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

// GetRecords lists DNS records for the given zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("GetRecords called", zap.String("zone", zone))
	}

	return []libdns.Record{}, nil
}

// AppendRecords adds DNS records to the given zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("AppendRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	if zone == "" {
		return nil, fmt.Errorf("regru: zone cannot be empty")
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

		// Получаем RR из Record
		rr := record.RR()

		if rr.Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported, got: %s", rr.Type)
		}

		// Нормализуем зону
		cleanZone := strings.TrimSuffix(zone, ".")

		// Обрабатываем имя записи
		recordName := strings.TrimSuffix(rr.Name, ".")
		var subDomain string

		if recordName == "" || recordName == "@" || recordName == cleanZone {
			subDomain = ""
		} else if strings.HasSuffix(recordName, "."+cleanZone) {
			subDomain = strings.TrimSuffix(recordName, "."+cleanZone)
		} else {
			subDomain = recordName
		}

		if p.logger != nil {
			p.logger.Info("Adding TXT record",
				zap.String("zone", cleanZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data),
				zap.String("original_name", recordName))
		}

		err := client.AddTXTRecord(ctx, cleanZone, subDomain, rr.Data)
		if err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to add TXT record",
					zap.String("zone", cleanZone),
					zap.String("subdomain", subDomain),
					zap.String("value", rr.Data),
					zap.Error(err))
			}
			return nil, fmt.Errorf("failed to add TXT record for %s: %w", recordName, err)
		}

		resultRecord := record
		resultRR := resultRecord.RR()

		if resultRR.TTL == 0 {
			resultRR.TTL = 5 * time.Minute
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
				zap.String("zone", cleanZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data))
		}
	}

	return results, nil
}

// SetRecords replaces DNS records in the given zone.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("SetRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	// Для reg.ru SetRecords работает так же, как AppendRecords
	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords removes DNS records from the given zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.logger != nil {
		p.logger.Info("DeleteRecords called",
			zap.String("zone", zone),
			zap.Int("record_count", len(records)))
	}

	if zone == "" {
		return nil, fmt.Errorf("regru: zone cannot be empty")
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

		// Получаем RR из Record
		rr := record.RR()

		if rr.Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported, got: %s", rr.Type)
		}

		// Нормализуем зону
		cleanZone := strings.TrimSuffix(zone, ".")

		// Обрабатываем имя записи
		recordName := strings.TrimSuffix(rr.Name, ".")
		var subDomain string

		if recordName == "" || recordName == "@" || recordName == cleanZone {
			subDomain = ""
		} else if strings.HasSuffix(recordName, "."+cleanZone) {
			subDomain = strings.TrimSuffix(recordName, "."+cleanZone)
		} else {
			subDomain = recordName
		}

		if p.logger != nil {
			p.logger.Info("Removing TXT record",
				zap.String("zone", cleanZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data),
				zap.String("original_name", recordName))
		}

		err := client.RemoveTxtRecord(ctx, cleanZone, subDomain, rr.Data)
		if err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to remove TXT record",
					zap.String("zone", cleanZone),
					zap.String("subdomain", subDomain),
					zap.String("value", rr.Data),
					zap.Error(err))
			}
			return nil, fmt.Errorf("failed to remove TXT record for %s: %w", recordName, err)
		}

		results = append(results, record)

		if p.logger != nil {
			p.logger.Info("Successfully removed TXT record",
				zap.String("zone", cleanZone),
				zap.String("subdomain", subDomain),
				zap.String("value", rr.Data))
		}
	}

	return results, nil
}

// getClient creates an HTTP client configured for reg.ru API
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
