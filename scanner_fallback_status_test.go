package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeniedFallbackStatusDependsOnRequiredMetadata(t *testing.T) {
	for _, fallback := range []struct {
		name           string
		metadata       string
		denyAttributes bool
	}{
		{"denied attributes", "success", true},
		{"unsupported context then denied list", "unsupported", false},
	} {
		for _, share := range []struct {
			name       string
			mask       uint32
			wantWrite  string
			wantText   string
			wantStatus string
		}{
			{"share allows write", 0x001f01ff, Unknown, "UNKNOWN", "CHECK_FAILED"},
			{"share denies write", 0x00120089, Denied, "FALSE", "OK"},
		} {
			t.Run(fallback.name+"/"+share.name, func(t *testing.T) {
				fixture := newEnumerationFixture(t, share.mask, 0x001f01ff, fallback.metadata, true)
				fixture.guard.mu.Lock()
				fixture.guard.denyAttributes = fallback.denyAttributes
				fixture.guard.mu.Unlock()
				result := scanTarget(context.Background(), fixture.target, fixture.options)
				if !result.Reachable || result.Authentication != "authenticated" || result.Enumeration != "ok" ||
					result.Error != "" || result.TimedOut || len(result.Shares) != 3 {
					t.Fatalf("permission fallback changed completed host outcomes: %+v", result)
				}
				wantDisk := ShareResult{
					Name: "data$", Type: "disk", Comment: "fixture disk", Accessible: Allowed,
					Read: Denied, Write: share.wantWrite, WriteBasis: "share_metadata",
					Error: "root access query: request: SMB status 0xc0000022",
				}
				for _, got := range result.Shares {
					if got.Type != "disk" {
						if status := tableStatus(result, &got); status != "OK" {
							t.Errorf("unrelated share %q changed status to %s", got.Name, status)
						}
						continue
					}
					if status := tableStatus(result, &got); status != share.wantStatus || !got.probeComplete {
						t.Errorf("completed fallback status = %s; want %s (%+v)", status, share.wantStatus, got)
					}
					got.status, got.probeComplete = statusUnset, false
					if got != wantDisk {
						t.Errorf("permission values or diagnostic changed: got %+v; want %+v", got, wantDisk)
					}
				}
				fixture.assertUnchanged(t, 2)

				// Feed the observed result through both machine-readable CLI modes
				// without another connection or authentication attempt. Share-only
				// incomplete metadata keeps the existing successful exit behavior.
				for _, mode := range []string{"--json", "--tsv"} {
					var out, errOut bytes.Buffer
					deps := testCLIDeps(&out, &errOut)
					deps.scan = func(context.Context, Target, Options) Result { return result }
					code := runCLI(context.Background(), []string{fixture.target.String(), "-u", fixture.options.Username,
						"-p", fixture.options.Password, mode}, deps)
					if code != 0 {
						t.Errorf("%s exit code = %d; want 0: %s", mode, code, errOut.String())
					}
					if mode == "--json" {
						var decoded []Result
						if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || len(decoded) != 1 {
							t.Fatalf("invalid JSON report: %q (%v)", out.String(), err)
						}
						found := false
						for _, got := range decoded[0].Shares {
							if got.Name == wantDisk.Name {
								found = true
								if got != wantDisk {
									t.Errorf("JSON permission result changed: %+v", got)
								}
							}
						}
						if !found || strings.Contains(out.String(), `"status":`) {
							t.Errorf("JSON result or schema changed: %s", out.String())
						}
					} else {
						wantRow := fixture.target.String() + "\tdata$\tFALSE\t" + share.wantText + "\tFALSE\t-\n"
						if !strings.Contains(out.String(), wantRow) || !strings.Contains(errOut.String(), wantDisk.Error) {
							t.Errorf("TSV permission row or diagnostic changed: stdout=%q stderr=%q", out.String(), errOut.String())
						}
					}
				}
			})
		}
	}
}
