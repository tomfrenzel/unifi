package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
)

const DefaultTimeout = 30 * time.Second

// RecordType constants represent the Unifi DNS policy types.
const (
	RecordTypeA       = "A_RECORD"
	RecordTypeAAAA    = "AAAA_RECORD"
	RecordTypeCNAME   = "CNAME_RECORD"
	RecordTypeMX      = "MX_RECORD"
	RecordTypeTXT     = "TXT_RECORD"
	RecordTypeSRV     = "SRV_RECORD"
	RecordTypeForward = "FORWARD_DOMAIN"
)

func LibdnsToPolicy(record libdns.Record) (DNSPolicy, error) {
	ttl := int32(record.RR().TTL.Seconds())

	switch r := record.(type) {
	case libdns.Address:
		if r.IP.Is4() {
			return DNSPolicy{
				Type:        RecordTypeA,
				Domain:      r.Name,
				IPv4Address: r.IP.String(),
				TTLSeconds:  ttl,
				Enabled:     true,
			}, nil
		} else {
			return DNSPolicy{
				Type:        RecordTypeAAAA,
				Domain:      r.Name,
				IPv6Address: r.IP.String(),
				TTLSeconds:  ttl,
				Enabled:     true,
			}, nil
		}

	case libdns.CNAME:
		return DNSPolicy{
			Type:         RecordTypeCNAME,
			Domain:       r.Name,
			TargetDomain: r.Target,
			TTLSeconds:   ttl,
			Enabled:      true,
		}, nil

	case libdns.TXT:
		return DNSPolicy{
			Type:       RecordTypeTXT,
			Domain:     r.Name,
			Text:       r.Text,
			TTLSeconds: ttl,
			Enabled:    true,
		}, nil

	case libdns.MX:
		return DNSPolicy{
			Type:             RecordTypeMX,
			Domain:           r.Name,
			MailServerDomain: r.Target,
			Priority:         r.Preference,
			TTLSeconds:       ttl,
			Enabled:          true,
		}, nil
	case libdns.SRV:
		return DNSPolicy{
			Type:         RecordTypeSRV,
			Domain:       r.Name,
			ServerDomain: r.Target,
			Service:      r.Service,
			Protocol:     r.Transport,
			Port:         r.Port,
			Weight:       r.Weight,
			Priority:     r.Priority,
			TTLSeconds:   ttl,
			Enabled:      true,
		}, nil
	default:
		return DNSPolicy{}, fmt.Errorf("unsupported record type: %T", record)
	}
}

func PolicyToLibdns(policy DNSPolicy) (libdns.Record, error) {
	ttl := time.Duration(policy.TTLSeconds) * time.Second

	switch policy.Type {
	case RecordTypeA:
		if policy.IPv4Address == "" {
			return nil, fmt.Errorf("IPv4 address is required for A_RECORD")
		}
		ip, err := netip.ParseAddr(policy.IPv4Address)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 address: %w", err)
		}
		return libdns.Address{
			Name: policy.Domain,
			IP:   ip,
			TTL:  ttl,
		}, nil

	case RecordTypeAAAA:
		if policy.IPv6Address == "" {
			return nil, fmt.Errorf("IPv6 address is required for AAAA_RECORD")
		}
		ip, err := netip.ParseAddr(policy.IPv6Address)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %w", err)
		}
		return libdns.Address{
			Name: policy.Domain,
			IP:   ip,
			TTL:  ttl,
		}, nil

	case RecordTypeCNAME:
		if policy.TargetDomain == "" {
			return nil, fmt.Errorf("data (target) is required for CNAME_RECORD")
		}
		return libdns.CNAME{
			Name:   policy.Domain,
			Target: policy.TargetDomain,
			TTL:    ttl,
		}, nil

	case RecordTypeTXT:
		if policy.Text == "" {
			return nil, fmt.Errorf("text is required for TXT_RECORD")
		}
		return libdns.TXT{
			Name: policy.Domain,
			Text: policy.Text,
			TTL:  ttl,
		}, nil

	case RecordTypeMX:
		if policy.MailServerDomain == "" {
			return nil, fmt.Errorf("mail server domain and priority are required for MX_RECORD")
		}
		// Use the Priority field if available, otherwise use 0
		preference := policy.Priority
		if preference == 0 {
			preference = 10 // Default preference value
		}
		return libdns.MX{
			Name:       policy.Domain,
			Preference: preference,
			Target:     policy.MailServerDomain,
			TTL:        ttl,
		}, nil

	case RecordTypeSRV:
		if policy.ServerDomain == "" {
			return nil, fmt.Errorf("server domain is required for SRV_RECORD")
		}
		return libdns.SRV{
			Name:      policy.Domain,
			Service:   policy.Service,
			Transport: policy.Protocol,
			Priority:  policy.Priority,
			Weight:    policy.Weight,
			Port:      policy.Port,
			Target:    policy.ServerDomain,
			TTL:       ttl,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported DNS policy type: %s", policy.Type)
	}
}

// DNSPolicy represents a DNS policy record from the API.
// It supports multiple record types with type-specific fields.
type DNSPolicy struct {
	// Common fields for all record types
	Type       string `json:"type"`
	ID         string `json:"id,omitempty"`
	Enabled    bool   `json:"enabled"`
	Domain     string `json:"domain"`
	TTLSeconds int32  `json:"ttlSeconds,omitempty"`

	// Address record fields (A_RECORD, AAAA_RECORD)
	IPv4Address string `json:"ipv4Address,omitempty"`
	IPv6Address string `json:"ipv6Address,omitempty"`

	// CNAME and target-based record fields
	TargetDomain string `json:"targetDomain,omitempty"`

	// TXT record fields
	Text string `json:"text,omitempty"`

	// MX record fields
	MailServerDomain string `json:"mailServerDomain,omitempty"`
	Priority         uint16 `json:"priority,omitempty"`

	// SRV record fields
	ServerDomain string `json:"serverDomain,omitempty"`
	Service      string `json:"service,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Weight       uint16 `json:"weight,omitempty"`
}

// ListResponse represents the response from the list DNS policies endpoint
type ListResponse struct {
	Offset     int32       `json:"offset"`
	Limit      int32       `json:"limit"`
	Count      int32       `json:"count"`
	TotalCount int32       `json:"totalCount"`
	Data       []DNSPolicy `json:"data"`
}

// Client provides methods to interact with the Unifi DNS API.
// It handles HTTP communication and request/response serialization.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new API client for the Unifi DNS API.
// It configures the client to accept self-signed/invalid SSL certificates,
// which is common for local Unifi installations.
func NewClient(apiKey, baseURL string) *Client {
	// Create a custom TLS configuration that skips certificate verification
	// This is necessary for Unifi controllers with self-signed certificates
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create a custom HTTP transport with the TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   DefaultTimeout,
			Transport: transport,
		},
	}
}

// ListPolicies retrieves all DNS policies for a site from the Unifi API.
// It fetches up to 1000 policies using pagination, making multiple requests as needed.
func (c *Client) ListPolicies(ctx context.Context, siteID string, zone string) ([]DNSPolicy, error) {
	const maxRecords = 1000
	const pageSize = 25

	var allPolicies []DNSPolicy
	offset := 0

	for {
		url := fmt.Sprintf("%s/sites/%s/dns/policies?offset=%d&limit=%d&filter=or(domain.eq('%s'),domain.like('*%s'))", c.baseURL, siteID, offset, pageSize, zone, zone)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := c.do(req)
		if err != nil {
			return nil, err
		}

		var listResp ListResponse
		if err := json.Unmarshal(resp, &listResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		// If no data returned, we've fetched all available policies
		if len(listResp.Data) == 0 {
			break
		}

		allPolicies = append(allPolicies, listResp.Data...)

		// Stop if we've reached the maximum records or fetched all available
		if len(allPolicies) >= maxRecords || int32(len(allPolicies)) >= listResp.TotalCount {
			break
		}

		offset += pageSize
	}

	return allPolicies, nil
}

// CreatePolicy creates a new DNS policy in the Unifi API.
func (c *Client) CreatePolicy(ctx context.Context, siteID string, policy DNSPolicy) (DNSPolicy, error) {
	url := fmt.Sprintf("%s/sites/%s/dns/policies", c.baseURL, siteID)

	body, err := json.Marshal(policy)
	if err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return DNSPolicy{}, err
	}

	var created DNSPolicy
	if err := json.Unmarshal(resp, &created); err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return created, nil
}

// UpdatePolicy updates an existing DNS policy in the Unifi API.
func (c *Client) UpdatePolicy(ctx context.Context, siteID, policyID string, policy DNSPolicy) (DNSPolicy, error) {
	url := fmt.Sprintf("%s/sites/%s/dns/policies/%s", c.baseURL, siteID, policyID)

	body, err := json.Marshal(policy)
	if err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return DNSPolicy{}, err
	}

	var updated DNSPolicy
	if err := json.Unmarshal(resp, &updated); err != nil {
		return DNSPolicy{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return updated, nil
}

// DeletePolicy deletes a DNS policy from the Unifi API.
func (c *Client) DeletePolicy(ctx context.Context, siteID, policyID string) error {
	url := fmt.Sprintf("%s/sites/%s/dns/policies/%s", c.baseURL, siteID, policyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	_, err = c.do(req)
	return err
}

// do sends an HTTP request and returns the response body or an error
func (c *Client) do(req *http.Request) ([]byte, error) {
	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return bodyBytes, nil
}
