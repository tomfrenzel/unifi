// Package unifi implements a DNS record management client compatible
// with the libdns interfaces for UniFi
package unifi

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
	"github.com/libdns/unifi/internal"
)

// Provider facilitates DNS record management for Unifi Network.
// It implements the libdns record management interfaces.
type Provider struct {
	// APIKey is the Unifi API authentication key.
	APIKey string `json:"api_key,omitempty"`

	// SiteId is the UUID of the Unifi site containing the DNS policies.
	SiteId string `json:"site_id,omitempty"`

	// BaseUrl is the base URL of the Unifi controller API.
	// Example: https://192.168.1.1/proxy/network/integration/v1
	BaseUrl string `json:"base_url,omitempty"`

	client *internal.Client
	mu     sync.Mutex
}

// GetRecords lists all the records in the zone.
// The zone parameter is not used for Unifi (all records for the site are returned).
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, p.SiteId, zone)
	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, len(policies))
	for i, policy := range policies {
		record, err := internal.PolicyToLibdns(policy)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy to libdns record: %w", err)
		}
		records[i] = record
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Record, 0, len(records))

	for _, record := range records {
		policy, err := internal.LibdnsToPolicy(record)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record to policy: %w", err)
		}

		created, err := client.CreatePolicy(ctx, p.SiteId, policy)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS policy: %w", err)
		}

		createdRecord, err := internal.PolicyToLibdns(created)
		if err != nil {
			return nil, fmt.Errorf("failed to convert created policy to libdns record: %w", err)
		}

		result = append(result, createdRecord)
	}

	return result, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	// Get existing records to match them with incoming records
	existing, err := client.ListPolicies(ctx, p.SiteId, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing policies: %w", err)
	}

	result := make([]libdns.Record, 0, len(records))

	for _, record := range records {
		policy, err := internal.LibdnsToPolicy(record)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record to policy: %w", err)
		}

		// Find existing record by domain name
		var existingPolicy *internal.DNSPolicy
		for i := range existing {
			if existing[i].Domain == policy.Domain {
				existingPolicy = &existing[i]
				break
			}
		}

		var result_policy internal.DNSPolicy
		var setErr error

		if existingPolicy != nil {
			// Update existing policy
			result_policy, setErr = client.UpdatePolicy(ctx, p.SiteId, existingPolicy.ID, policy)
			if setErr != nil {
				return nil, fmt.Errorf("failed to update DNS policy: %w", setErr)
			}
		} else {
			// Create new policy
			result_policy, setErr = client.CreatePolicy(ctx, p.SiteId, policy)
			if setErr != nil {
				return nil, fmt.Errorf("failed to create DNS policy: %w", setErr)
			}
		}

		createdRecord, err := internal.PolicyToLibdns(result_policy)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy to libdns record: %w", err)
		}

		result = append(result, createdRecord)
	}

	return result, nil
}

// DeleteRecords deletes the specified records from the zone and returns the deleted records.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	// Get existing records to find IDs for deletion
	existing, err := client.ListPolicies(ctx, p.SiteId, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing policies: %w", err)
	}

	result := make([]libdns.Record, 0, len(records))

	for _, record := range records {
		policy, err := internal.LibdnsToPolicy(record)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record to policy: %w", err)
		}

		// Find existing record by domain name
		var existingPolicy *internal.DNSPolicy
		for i := range existing {
			if existing[i].Domain == policy.Domain {
				existingPolicy = &existing[i]
				break
			}
		}

		if existingPolicy == nil {
			continue // Record doesn't exist, skip it
		}

		if err := client.DeletePolicy(ctx, p.SiteId, existingPolicy.ID); err != nil {
			return nil, fmt.Errorf("failed to delete DNS policy: %w", err)
		}

		result = append(result, record)
	}

	return result, nil
}

// getClient lazily initializes and returns the API client.
func (p *Provider) getClient() (*internal.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client == nil {
		if p.APIKey == "" {
			return nil, fmt.Errorf("API key is required")
		}
		if p.SiteId == "" {
			return nil, fmt.Errorf("site ID is required")
		}
		if p.BaseUrl == "" {
			return nil, fmt.Errorf("base URL is required")
		}
		p.client = internal.NewClient(p.APIKey, p.BaseUrl)
	}

	return p.client, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
