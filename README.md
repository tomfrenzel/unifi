# UniFi for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/unifi.svg)](https://pkg.go.dev/github.com/libdns/unifi)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [UniFi Network](https://developer.ui.com), allowing you to manage DNS records through the UniFi Network's DNS policy API.

## Supported Record Types

This provider supports the following DNS record types:
- **A** - IPv4 address records
- **AAAA** - IPv6 address records
- **CNAME** - Canonical name (alias) records
- **MX** - Mail exchange records
- **TXT** - Text records
- **SRV** - Service records

## Configuration

The provider requires three pieces of configuration:

1. **API Key** - Your UniFi API authentication key
2. **Site ID** - The UUID of the UniFi site containing the DNS policies
3. **Host URL** - The base URL of your UniFi controller API

### Example Usage

```go
package main

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/unifi"
)

func main() {
	provider := unifi.Provider{
		APIKey:  "your-api-key",
		SiteId:  "your-site-uuid",
		BaseUrl: "https://192.168.1.1/proxy/network/integration/v1",
	}

	// List existing records
	records, err := provider.GetRecords(context.Background(), "example.com")
	if err != nil {
		log.Fatal(err)
	}

	// Add a new A record
	newRecords, err := provider.AppendRecords(context.Background(), "example.com", []libdns.Record{
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

## Getting Your Credentials

### UniFi API Key

1. Log into your UniFi Network Console 
2. Navigate to **Integrations**
3. Create a new API token
4. Copy the token value as your `UNIFI_API_KEY`

### Site ID

Execute the following request to retrive the ID of your sites:
```curl
curl -k -X GET 'https://192.168.1.1/proxy/network/integration/v1/sites' -H 'X-API-KEY: YOUR_API_KEY' -H 'Accept: application/json'
```

### Host URL

The host URL is the base path of your UniFi Network API endpoint:

- **Dream Machine**: `https://192.168.1.1/proxy/network/integration/v1` (replace IP with your device IP)
- **CloudKey/Controller**: `https://your-controller-ip:8443/proxy/network/integration/v1`