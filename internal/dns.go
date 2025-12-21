package internal

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
)

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
