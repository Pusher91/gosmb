package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestRedactionPreservesGeneratedShareValues(t *testing.T) {
	for _, tc := range []struct {
		password, shareType, basis string
	}{
		{"disk", "disk", "share_and_root_metadata"},
		{"print", "printer", "unavailable"},
		{"vice", "device", "unavailable"},
		{"ipc", "ipc", "not_a_disk_share"},
		{"other", "other", "unavailable"},
		{"meta", "disk", "share_and_root_metadata"},
		{"share", "disk", "share_metadata"},
		{"root", "disk", "root_metadata"},
		{"available", "disk", "unavailable"},
		{"disk", "ipc", "not_a_disk_share"},
		{"denied", "disk", "share_connection_denied"},
	} {
		t.Run(tc.shareType+"/"+tc.basis+"/"+tc.password, func(t *testing.T) {
			original := Result{Error: tc.password, Shares: []ShareResult{
				{Name: tc.password, Type: tc.shareType, WriteBasis: tc.basis, Comment: tc.password, Error: tc.password},
				{Name: "unrecognized", Type: "custom-" + tc.password, WriteBasis: "custom-" + tc.password},
			}}
			got := redactResult(original, tc.password)
			if got.Shares[0].Type != tc.shareType || got.Shares[0].WriteBasis != tc.basis {
				t.Errorf("generated share values were changed: %+v", got.Shares[0])
			}
			if got.Error != "[REDACTED]" || got.Shares[0].Name != "[REDACTED]" ||
				got.Shares[0].Comment != "[REDACTED]" || got.Shares[0].Error != "[REDACTED]" ||
				got.Shares[1].Type != "custom-[REDACTED]" || got.Shares[1].WriteBasis != "custom-[REDACTED]" {
				t.Errorf("free text or unrecognized values escaped redaction: %+v", got)
			}
			if original.Shares[0].Name != tc.password || original.Shares[1].Type != "custom-"+tc.password {
				t.Error("redaction modified caller-owned shares")
			}
		})
	}
}

func TestCLIJSONKeepsGeneratedValuesWhenPasswordMatches(t *testing.T) {
	for _, password := range []string{"disk", "meta"} {
		t.Run(password, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				return Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok",
					Shares: []ShareResult{{Name: "archive-" + password, Type: "disk", Comment: "server reflected " + password,
						Accessible: Allowed, Read: Allowed, Write: Allowed, WriteBasis: "share_and_root_metadata"}}}
			}
			if code := runCLI(context.Background(), []string{"host", "-u", "alice", "-p", password, "--json"}, deps); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("scan failed: code=%d stderr=%q", code, diagnostics.String())
			}
			var report []Result
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report) != 1 || len(report[0].Shares) != 1 {
				t.Fatalf("invalid JSON report: %v; %q", err, out.String())
			}
			share := report[0].Shares[0]
			if share.Type != "disk" || share.WriteBasis != "share_and_root_metadata" || share.Write != Allowed ||
				share.Name != "archive-[REDACTED]" || share.Comment != "server reflected [REDACTED]" {
				t.Errorf("JSON metadata was corrupted or server text was not redacted: %+v", share)
			}
		})
	}
}
