package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	smb "gosmb/internal/smbwire"
)

func TestScanTargetExplainsAuthenticationRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status uint32
		reason string
	}{
		{"wrong password", 0, "username or password was rejected"},
		{"locked account", smb.StatusAccountLockedOut, "account is locked out"},
		{"disabled account", smb.StatusAccountDisabled, "account is disabled"},
		{"expired password", smb.StatusPasswordExpired, "password has expired"},
		{"password change required", smb.StatusPasswordMustChange, "password must be changed"},
		{"expired account", smb.StatusAccountExpired, "account has expired"},
		{"account restriction", smb.StatusAccountRestriction, "account restrictions prevent logon"},
		{"logon hours", smb.StatusInvalidLogonHours, "logon is not allowed at this time"},
		{"workstation restriction", smb.StatusInvalidWorkstation, "logon is not allowed from this workstation"},
		{"access denied", smb.StatusAccessDenied, "server denied logon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			status := tc.status
			if status == 0 {
				fixture.options.Password = "incorrect-test-password"
				status = smb.StatusLogonFailure
			} else {
				fixture.guard.mu.Lock()
				fixture.guard.authenticationStatus = status
				fixture.guard.mu.Unlock()
			}
			result := scanTarget(context.Background(), fixture.target, fixture.options)
			want := fmt.Sprintf("authentication failed: %s (SMB status 0x%08x)", tc.reason, status)
			if result.Error != want {
				t.Errorf("diagnostic = %q; want %q", result.Error, want)
			}
			if !result.Reachable || result.Authentication != "failed" || result.Enumeration != "not_attempted" ||
				result.GuestFallback || result.TimedOut || len(result.Shares) != 0 {
				t.Errorf("diagnostic changed authentication outcome: %+v", result)
			}
			// Checks one TCP connection, one authentication attempt, no disk opens,
			// and unchanged filesystem contents and metadata.
			fixture.assertUnchanged(t, 0)
		})
	}
}

func TestAuthenticationFailureRequiresRecognizedSessionStatus(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("connection refused"),
		&smb.NTStatusError{Command: 0, Status: smb.StatusLogonFailure},
		&smb.NTStatusError{Command: 3, Status: smb.StatusAccessDenied},
		&smb.NTStatusError{Command: smb.SessionSetupCommand, Status: smb.StatusNotSupported},
	} {
		if status, reason := authenticationFailure(err); status != statusUnset || reason != "" {
			t.Errorf("non-authentication rejection %v became %d, %q", err, status, reason)
		}
	}
	err := fmt.Errorf("session setup: %w", &smb.NTStatusError{Command: smb.SessionSetupCommand, Status: smb.StatusLogonFailure})
	if status, reason := authenticationFailure(err); status != statusAuthFailed || reason != "username or password was rejected" {
		t.Errorf("wrapped authentication failure = %d, %q", status, reason)
	}
}

func TestConnectionFailureMessagesPreserveStageAndDetail(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reachable bool
		err       error
		want      string
	}{
		{"unreachable", false, errors.New("dial tcp 192.0.2.1:445: connection refused"),
			"connection failed: dial tcp 192.0.2.1:445: connection refused"},
		{"negotiation rejection", true, fmt.Errorf("negotiate response: %w", &smb.NTStatusError{Command: 0, Status: smb.StatusLogonFailure}),
			"SMB negotiation failed: negotiate response: request: SMB status 0xc000006d"},
		{"unrecognized session rejection", true, &smb.NTStatusError{Command: smb.SessionSetupCommand, Status: smb.StatusNotSupported},
			"SMB session setup failed: request: SMB status 0xc00000bb"},
		{"generic protocol failure", true, errors.New("malformed SMB response"),
			"SMB connection: malformed SMB response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionFailureMessage(tc.err, tc.reachable); got != tc.want {
				t.Errorf("diagnostic = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestAuthenticationDiagnosticsPreserveReportFormat(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	fixture.options.Password = "incorrect-test-password"
	result := scanTarget(context.Background(), fixture.target, fixture.options)
	const diagnostic = "authentication failed: username or password was rejected (SMB status 0xc000006d)"
	if result.Error != diagnostic {
		t.Fatalf("wrong-password diagnostic = %q; want %q", result.Error, diagnostic)
	}
	fixture.assertUnchanged(t, 0)
	legacy := result
	legacy.Error = "SMB connection: request: SMB status 0xc000006d"
	for _, format := range []struct {
		name                  string
		terminal, color, json bool
	}{
		{name: "TSV"},
		{name: "aligned", terminal: true},
		{name: "colored", terminal: true, color: true},
		{name: "JSON", json: true},
	} {
		t.Run(format.name, func(t *testing.T) {
			run := func(scanResult Result) (string, string) {
				t.Helper()
				var out, diagnostics bytes.Buffer
				deps := testCLIDeps(&out, &diagnostics)
				deps.stdoutIsTerminal = format.terminal
				if format.color {
					deps.enableColor = func() (func(), bool) { return func() {}, true }
				}
				deps.scan = func(context.Context, Target, Options) Result { return scanResult }
				args := []string{fixture.target.String(), "-u", fixture.options.Username, "-p", fixture.options.Password}
				if format.name == "TSV" {
					args = append(args, "--tsv")
				}
				if format.json {
					args = append(args, "--json")
				}
				if code := runCLI(context.Background(), args, deps); code != 1 {
					t.Fatalf("authentication failure exit = %d; want 1", code)
				}
				return out.String(), diagnostics.String()
			}
			out, diagnostics := run(result)
			legacyOut, _ := run(legacy)
			if format.json {
				var report, oldReport []map[string]any
				if err := json.Unmarshal([]byte(out), &report); err != nil || len(report) != 1 {
					t.Fatalf("invalid JSON report: %q; %v", out, err)
				}
				if err := json.Unmarshal([]byte(legacyOut), &oldReport); err != nil || len(oldReport) != 1 {
					t.Fatalf("invalid legacy JSON report: %q; %v", legacyOut, err)
				}
				want := map[string]any{
					"target": result.Target, "server_ip": result.ServerIP, "reachable": true,
					"authentication": "failed", "guest_fallback": false, "enumeration": "not_attempted",
					"shares": []any{}, "error": diagnostic,
				}
				if !reflect.DeepEqual(report[0], want) {
					t.Errorf("JSON keys, types, or outcome changed: %#v; want %#v", report[0], want)
				}
				oldReport[0]["error"] = diagnostic
				if !reflect.DeepEqual(report, oldReport) {
					t.Error("JSON changed outside the error text")
				}
				return
			}
			if out != legacyOut {
				t.Errorf("diagnostic changed stdout: %q; legacy %q", out, legacyOut)
			}
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			const columns = 7
			if len(lines) != 2 || len(strings.Fields(lines[0])) != columns || len(strings.Fields(lines[1])) != columns {
				t.Fatalf("expected one %d-column header and row: %q", columns, out)
			}
			status := "AUTH_FAILED"
			if format.color {
				status = "\x1b[31mAUTH_FAILED\x1b[0m"
			}
			if strings.Fields(lines[0])[5] != "STATUS" || strings.Fields(lines[1])[5] != status {
				t.Errorf("authentication failure missing from status: %q", out)
			}
			if format.color && !strings.Contains(out, "\x1b[31mFALSE\x1b[0m") {
				t.Errorf("diagnostic changed the colored status cell: %q", out)
			}
			if diagnostics != "" {
				t.Errorf("unexpected separate scan diagnostic: %q", diagnostics)
			}
			if strings.Contains(out+diagnostics, fixture.options.Password) {
				t.Error("diagnostic exposed the supplied password")
			}
		})
	}
}
