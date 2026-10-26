package main

import (
	"fmt"
	"reflect"
	"testing"

	"gosmb/internal/smbwire"
)

func BenchmarkDiscoveredShares(b *testing.B) {
	shares := make([]smbwire.Share, 1000)
	for i := range shares {
		shares[i] = smbwire.Share{Name: fmt.Sprintf("Department-%04d-Archives", (i*37)%len(shares))}
	}
	b.ReportAllocs()
	for b.Loop() {
		discoveredShares(shares)
	}
}

func TestDiscoveredSharesPreservesNamesMetadataAndStableOrder(t *testing.T) {
	shares := []smbwire.Share{
		{Name: "Zebra", Type: 1, Comment: "printer"},
		{Name: "équipe", Type: 0x80000000, Comment: "first equivalent name"},
		{Name: "alpha", Type: 3, Comment: "pipe"},
		{Name: "ÉQUIPE", Type: 0x40000000, Comment: "second equivalent name"},
		{Name: "ALPHA", Type: 2, Comment: "device"},
		{Name: "Ω", Type: 9, Comment: "other"},
	}
	original := append([]smbwire.Share(nil), shares...)
	want := []discoveredShare{
		{Name: "alpha", Type: "ipc", Comment: "pipe"},
		{Name: "ALPHA", Type: "device", Comment: "device"},
		{Name: "Zebra", Type: "printer", Comment: "printer"},
		{Name: "équipe", Type: "disk", Comment: "first equivalent name"},
		{Name: "ÉQUIPE", Type: "disk", Comment: "second equivalent name"},
		{Name: "Ω", Type: "other", Comment: "other"},
	}
	if got := discoveredShares(shares); !reflect.DeepEqual(got, want) {
		t.Fatalf("share ordering or metadata changed: got %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(shares, original) {
		t.Fatal("share preparation changed the protocol results")
	}
}

func TestInvalidServerShareNamesAreNotProbed(t *testing.T) {
	for _, name := range []string{"", ".", "..", `..\data`, "host/share", "a:b", "bad\x1bname"} {
		if validShareName(name) {
			t.Errorf("accepted invalid share %q", name)
		}
	}
	for _, name := range []string{"C$", "IPC$", "Shared Documents", "données"} {
		if !validShareName(name) {
			t.Errorf("rejected valid share %q", name)
		}
	}
}
