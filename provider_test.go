package unifi_test

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/unifi"
)

var (
	apiKey  = flag.String("api-key", os.Getenv("UNIFI_API_KEY"), "UniFi API key (or set UNIFI_API_KEY env var)")
	siteID  = flag.String("site-id", os.Getenv("UNIFI_SITE_ID"), "UniFi site UUID (or set UNIFI_SITE_ID env var)")
	baseURL = flag.String("base-url", os.Getenv("UNIFI_BASE_URL"), "UniFi API base URL (or set UNIFI_BASE_URL env var)")
	zone    = flag.String("zone", os.Getenv("UNIFI_TEST_ZONE"), "DNS zone to test with (or set UNIFI_TEST_ZONE env var)")
)

// setup performs test setup and returns a provider or skips the test if credentials are not set
func setup(t *testing.T) (*unifi.Provider, context.Context) {
	t.Helper()

	if *apiKey == "" || *siteID == "" || *baseURL == "" || *zone == "" {
		t.Skip("skipping integration test; -api-key, -site-id, -base-url, and -zone must be set")
	}

	ctx := context.Background()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		t.Cleanup(cancel)
	}

	provider := &unifi.Provider{
		APIKey:  *apiKey,
		SiteId:  *siteID,
		BaseUrl: *baseURL,
	}

	// Clean up any existing records in the zone before test
	records, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Logf("Warning: could not get existing records: %v", err)
	}
	if len(records) > 0 {
		// Delete all existing records to start fresh
		_, _ = provider.DeleteRecords(ctx, *zone, records)
	}

	return provider, ctx
}

// TestGetRecords tests reading DNS records
func TestGetRecords(t *testing.T) {
	provider, ctx := setup(t)

	// Create some test records first
	testRecords := []libdns.Record{
		libdns.Address{
			Name: "test-a",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "test-b",
			IP:   netip.MustParseAddr("192.0.2.2"),
			TTL:  3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, testRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != len(testRecords) {
		t.Errorf("Expected %d created records, got %d", len(testRecords), len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, testRecords)
	})

	// Now test getting records
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	if len(got) < len(testRecords) {
		t.Errorf("Expected at least %d records, got %d", len(testRecords), len(got))
	}

	// Verify our created records are in the response
	for _, record := range testRecords {
		addr := record.(libdns.Address)
		found := false
		for _, gotRecord := range got {
			if gotAddr, ok := gotRecord.(libdns.Address); ok && gotAddr.Name == addr.Name && gotAddr.IP == addr.IP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected record %s -> %s not found in GetRecords", addr.Name, addr.IP)
		}
	}
}

// TestSetRecords tests setting DNS records (overwrite existing)
func TestSetRecords(t *testing.T) {
	provider, ctx := setup(t)

	// Create initial records
	initialRecords := []libdns.Record{
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, initialRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		// Clean up all records at the end
		records, _ := provider.GetRecords(ctx, *zone)
		_, _ = provider.DeleteRecords(ctx, *zone, records)
	})

	// Now set (overwrite) the record with a new IP
	updatedRecords := []libdns.Record{
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("192.0.2.100"),
			TTL:  7200 * time.Second,
		},
	}

	updated, err := provider.SetRecords(ctx, *zone, updatedRecords)
	if err != nil {
		t.Fatalf("SetRecords failed: %v", err)
	}

	if len(updated) != 1 {
		t.Errorf("Expected 1 updated record, got %d", len(updated))
	}

	// Verify the record was actually updated
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if addr, ok := record.(libdns.Address); ok && addr.Name == "www" {
			if addr.IP.String() == "192.0.2.100" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("Updated record not found or IP not changed")
	}
}

// TestAppendRecords tests appending DNS records
func TestAppendRecords(t *testing.T) {
	provider, ctx := setup(t)

	// Create initial records
	records1 := []libdns.Record{
		libdns.Address{
			Name: "app1",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
	}

	created1, err := provider.AppendRecords(ctx, *zone, records1)
	if err != nil {
		t.Fatalf("First AppendRecords failed: %v", err)
	}

	if len(created1) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created1))
	}

	t.Cleanup(func() {
		// Clean up all records at the end
		records, _ := provider.GetRecords(ctx, *zone)
		_, _ = provider.DeleteRecords(ctx, *zone, records)
	})

	// Append another record
	records2 := []libdns.Record{
		libdns.Address{
			Name: "app2",
			IP:   netip.MustParseAddr("192.0.2.2"),
			TTL:  3600 * time.Second,
		},
	}

	created2, err := provider.AppendRecords(ctx, *zone, records2)
	if err != nil {
		t.Fatalf("Second AppendRecords failed: %v", err)
	}

	if len(created2) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created2))
	}

	// Verify both records exist
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	if len(got) < 2 {
		t.Errorf("Expected at least 2 records, got %d", len(got))
	}

	app1Found := false
	app2Found := false
	for _, record := range got {
		if addr, ok := record.(libdns.Address); ok {
			if addr.Name == "app1" && addr.IP.String() == "192.0.2.1" {
				app1Found = true
			}
			if addr.Name == "app2" && addr.IP.String() == "192.0.2.2" {
				app2Found = true
			}
		}
	}

	if !app1Found {
		t.Error("First appended record not found")
	}
	if !app2Found {
		t.Error("Second appended record not found")
	}
}

// TestDeleteRecords tests deleting DNS records
func TestDeleteRecords(t *testing.T) {
	provider, ctx := setup(t)

	// Create records to delete
	recordsToCreate := []libdns.Record{
		libdns.Address{
			Name: "delete-me",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "keep-me",
			IP:   netip.MustParseAddr("192.0.2.2"),
			TTL:  3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, recordsToCreate)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 2 {
		t.Errorf("Expected 2 created records, got %d", len(created))
	}

	t.Cleanup(func() {
		// Clean up any remaining records
		records, _ := provider.GetRecords(ctx, *zone)
		_, _ = provider.DeleteRecords(ctx, *zone, records)
	})

	// Delete one record
	recordToDelete := []libdns.Record{
		libdns.Address{
			Name: "delete-me",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  3600 * time.Second,
		},
	}

	deleted, err := provider.DeleteRecords(ctx, *zone, recordToDelete)
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	if len(deleted) != 1 {
		t.Errorf("Expected 1 deleted record, got %d", len(deleted))
	}

	// Verify the record was deleted but the other remains
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	deletedFound := false
	keptFound := false
	for _, record := range got {
		if addr, ok := record.(libdns.Address); ok {
			if addr.Name == "delete-me" {
				deletedFound = true
			}
			if addr.Name == "keep-me" {
				keptFound = true
			}
		}
	}

	if deletedFound {
		t.Error("Deleted record still exists")
	}
	if !keptFound {
		t.Error("Record that should be kept was deleted")
	}
}

// TestAAAARecords tests creating and managing IPv6 address records
func TestAAAARecords(t *testing.T) {
	provider, ctx := setup(t)

	aaaRecords := []libdns.Record{
		libdns.Address{
			Name: "ipv6-test",
			IP:   netip.MustParseAddr("2001:db8::1"),
			TTL:  3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, aaaRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, aaaRecords)
	})

	// Verify the record exists
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if addr, ok := record.(libdns.Address); ok && addr.Name == "ipv6-test" && addr.IP.String() == "2001:db8::1" {
			found = true
			break
		}
	}

	if !found {
		t.Error("IPv6 record not found")
	}
}

// TestCNAMERecords tests creating and managing CNAME records
func TestCNAMERecords(t *testing.T) {
	provider, ctx := setup(t)

	cnameRecords := []libdns.Record{
		libdns.CNAME{
			Name:   "alias",
			Target: "www.example.com",
			TTL:    3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, cnameRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, cnameRecords)
	})

	// Verify the record exists
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if cname, ok := record.(libdns.CNAME); ok && cname.Name == "alias" && cname.Target == "www.example.com" {
			found = true
			break
		}
	}

	if !found {
		t.Error("CNAME record not found")
	}
}

// TestTXTRecords tests creating and managing TXT records
func TestTXTRecords(t *testing.T) {
	provider, ctx := setup(t)

	txtRecords := []libdns.Record{
		libdns.TXT{
			Name: "txt-test",
			Text: "v=spf1 include:example.com ~all",
			TTL:  3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, txtRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, txtRecords)
	})

	// Verify the record exists
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if txt, ok := record.(libdns.TXT); ok && txt.Name == "txt-test" && txt.Text == "v=spf1 include:example.com ~all" {
			found = true
			break
		}
	}

	if !found {
		t.Error("TXT record not found")
	}
}

// TestMXRecords tests creating and managing MX records
func TestMXRecords(t *testing.T) {
	provider, ctx := setup(t)

	mxRecords := []libdns.Record{
		libdns.MX{
			Name:       "mx-test",
			Preference: 10,
			Target:     "mail.example.com",
			TTL:        3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, mxRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, mxRecords)
	})

	// Verify the record exists
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if mx, ok := record.(libdns.MX); ok && mx.Name == "mx-test" && mx.Target == "mail.example.com" && mx.Preference == 10 {
			found = true
			break
		}
	}

	if !found {
		t.Error("MX record not found")
	}
}

// TestSRVRecords tests creating and managing SRV records
func TestSRVRecords(t *testing.T) {
	provider, ctx := setup(t)

	srvRecords := []libdns.Record{
		libdns.SRV{
			Name:      "exmaple.com",
			Service:   "_service",
			Transport: "tcp",
			Port:      5060,
			Priority:  10,
			Weight:    60,
			Target:    "server.example.com",
			TTL:       3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, srvRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != 1 {
		t.Errorf("Expected 1 created record, got %d", len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, srvRecords)
	})

	// Verify the record exists
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, record := range got {
		if srv, ok := record.(libdns.SRV); ok && srv.Name == "example.com" && srv.Target == "server.example.com" && srv.Port == 5060 {
			found = true
			break
		}
	}

	if !found {
		t.Error("SRV record not found")
	}
}

// TestMixedRecordTypes tests creating and managing multiple record types together
func TestMixedRecordTypes(t *testing.T) {
	provider, ctx := setup(t)

	mixedRecords := []libdns.Record{
		libdns.Address{
			Name: "mixed-a",
			IP:   netip.MustParseAddr("192.0.2.100"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "mixed-aaaa",
			IP:   netip.MustParseAddr("2001:db8::100"),
			TTL:  3600 * time.Second,
		},
		libdns.CNAME{
			Name:   "mixed-cname",
			Target: "www.example.com",
			TTL:    3600 * time.Second,
		},
		libdns.TXT{
			Name: "mixed-txt",
			Text: "test text record",
			TTL:  3600 * time.Second,
		},
		libdns.MX{
			Name:       "mixed-mx",
			Preference: 20,
			Target:     "mail.example.com",
			TTL:        3600 * time.Second,
		},
	}

	created, err := provider.AppendRecords(ctx, *zone, mixedRecords)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(created) != len(mixedRecords) {
		t.Errorf("Expected %d created records, got %d", len(mixedRecords), len(created))
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, *zone, mixedRecords)
	})

	// Verify all records exist
	got, err := provider.GetRecords(ctx, *zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	if len(got) < len(mixedRecords) {
		t.Errorf("Expected at least %d records, got %d", len(mixedRecords), len(got))
	}

	// Check for each record type
	typeCount := map[string]int{
		"A":     0,
		"AAAA":  0,
		"CNAME": 0,
		"TXT":   0,
		"MX":    0,
	}

	for _, record := range got {
		switch r := record.(type) {
		case libdns.Address:
			if r.IP.Is4() && r.Name == "mixed-a" {
				typeCount["A"]++
			} else if r.IP.Is6() && r.Name == "mixed-aaaa" {
				typeCount["AAAA"]++
			}
		case libdns.CNAME:
			if r.Name == "mixed-cname" {
				typeCount["CNAME"]++
			}
		case libdns.TXT:
			if r.Name == "mixed-txt" {
				typeCount["TXT"]++
			}
		case libdns.MX:
			if r.Name == "mixed-mx" {
				typeCount["MX"]++
			}
		}
	}

	if typeCount["A"] == 0 {
		t.Error("A record not found in mixed records")
	}
	if typeCount["AAAA"] == 0 {
		t.Error("AAAA record not found in mixed records")
	}
	if typeCount["CNAME"] == 0 {
		t.Error("CNAME record not found in mixed records")
	}
	if typeCount["TXT"] == 0 {
		t.Error("TXT record not found in mixed records")
	}
	if typeCount["MX"] == 0 {
		t.Error("MX record not found in mixed records")
	}
}

// ExampleProvider demonstrates basic usage of the unifi provider
func ExampleProvider() {
	provider := unifi.Provider{
		APIKey:  "your-api-key",
		SiteId:  "your-site-uuid",
		BaseUrl: "https://192.168.1.1/proxy/network/integration/v1",
	}

	ctx := context.Background()

	// List all records
	records, err := provider.GetRecords(ctx, "example.com")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Found %d records\n", len(records))

	// Add a new record
	newRecord := libdns.Address{
		Name: "www",
		IP:   netip.MustParseAddr("192.0.2.1"),
		TTL:  3600 * time.Second,
	}

	created, err := provider.AppendRecords(ctx, "example.com", []libdns.Record{newRecord})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Created %d records\n", len(created))
}

// BenchmarkGetRecords benchmarks the GetRecords method
func BenchmarkGetRecords(b *testing.B) {
	if *apiKey == "" || *siteID == "" || *baseURL == "" || *zone == "" {
		b.Skip("skipping benchmark; -api-key, -site-id, -base-url, and -zone must be set")
	}

	provider := unifi.Provider{
		APIKey:  *apiKey,
		SiteId:  *siteID,
		BaseUrl: *baseURL,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.GetRecords(ctx, *zone)
	}
}
