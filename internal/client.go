package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const DefaultTimeout = 30 * time.Second

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
func NewClient(apiKey, baseURL string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// ListPolicies retrieves all DNS policies for a site from the Unifi API.
// It fetches up to 1000 policies using pagination.
func (c *Client) ListPolicies(ctx context.Context, siteID string) ([]DNSPolicy, error) {
	url := fmt.Sprintf("%s/sites/%s/dns/policies?offset=0&limit=1000", c.baseURL, siteID)

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

	return listResp.Data, nil
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
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
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
