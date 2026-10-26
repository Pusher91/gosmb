package main

import (
	"context"
	"strings"
	"testing"
)

func TestScanTargetValidatesNegotiationBeforeEnumeration(t *testing.T) {
	for _, mode := range []string{"user", "guest", "changed_server_guid", "tampered_validation"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false, "map_guest")
			fixture.options.Guest = mode == "guest"
			fixture.guard.mu.Lock()
			fixture.guard.mismatchedNegotiation = mode == "changed_server_guid"
			fixture.guard.mu.Unlock()
			target := fixture.target
			if mode == "tampered_validation" {
				target, _, _ = newTamperedSMBReplyProxy(t, target, 11, 1, 112)
			}
			result := scanTarget(context.Background(), target, fixture.options)
			identity, validations, opens := "authenticated", 1, 1
			if mode == "guest" {
				identity, validations = "guest", 0
			}
			if result.Authentication != identity || result.TimedOut {
				t.Fatalf("negotiation validation changed session identity or became a timeout: %+v", result)
			}
			if mode == "changed_server_guid" || mode == "tampered_validation" {
				opens = 0
				if result.Enumeration != "error" || len(result.Shares) != 0 || !strings.Contains(result.Error, "negotiat") {
					t.Fatalf("untrusted negotiation reached share enumeration or became a permission denial: %+v", result)
				}
			} else if result.Enumeration != "ok" || len(result.Shares) != 3 || result.Error != "" {
				t.Fatalf("valid session did not finish scanning: %+v", result)
			}
			fixture.guard.mu.Lock()
			gotValidations := fixture.guard.validationRequests
			fixture.guard.mu.Unlock()
			if gotValidations != validations {
				t.Fatalf("negotiation validation requests = %d; want %d", gotValidations, validations)
			}
			fixture.assertUnchanged(t, opens)
		})
	}
}
