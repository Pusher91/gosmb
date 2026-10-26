package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	smb "gosmb/internal/smbwire"
)

func TestEveryStatusLabelFitsTable(t *testing.T) {
	if len(statusLabels) != int(statusCount) {
		t.Fatalf("status label count = %d; want %d", len(statusLabels), statusCount)
	}
	valid := regexp.MustCompile(`^[A-Z]+(?:_[A-Z]+)*$`)
	seen := make(map[string]bool)
	for status := statusOK; status < statusCount; status++ {
		label := statusLabels[status]
		if len(label) > alignedWidths[5] || len(label) > 18 || !valid.MatchString(label) || seen[label] {
			t.Errorf("invalid, duplicate or overlong status %d: %q", status, label)
		}
		seen[label] = true
	}
}

func TestConnectionStatusUsesTypedErrorsAndRequestStage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		transport error
		reachable bool
		want      scanStatus
	}{
		{"refused", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}, nil, false, statusConnectRefused},
		{"winsock refused", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connectex", Err: syscall.Errno(10061)}}, nil, false, statusConnectRefused},
		{"DNS", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}, nil, false, statusDNSFailed},
		{"DNS timeout", &net.DNSError{Err: "lookup timed out", IsTimeout: true}, nil, false, statusDNSFailed},
		{"dial deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), nil, false, statusConnectTimeout},
		{"canceled dial", context.Canceled, nil, false, statusCanceled},
		{"handshake timeout", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, nil, true, statusSMBTimeout},
		{"closed on deadline", net.ErrClosed, context.DeadlineExceeded, true, statusSMBTimeout},
		{"closed on cancel", net.ErrClosed, context.Canceled, true, statusCanceled},
		{"typed wrong stage", &smb.NTStatusError{Command: 0, Status: smb.StatusLogonFailure}, nil, true, statusNegotiateFailed},
		{"unsupported session", &smb.NTStatusError{Command: 1, Status: smb.StatusNotSupported}, nil, true, statusSMBFailed},
		{"unrelated command", &smb.NTStatusError{Command: 3, Status: smb.StatusAccessDenied}, nil, true, statusSMBFailed},
		{"misleading dial message", errors.New("account locked, timeout, connection refused"), nil, false, statusConnectFailed},
		{"misleading SMB message", errors.New("authentication failed: timeout"), nil, true, statusSMBFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionStatus(tc.err, tc.transport, tc.reachable); got != tc.want {
				t.Errorf("status = %q; want %q", statusLabels[got], statusLabels[tc.want])
			}
		})
	}
	for _, tc := range []struct {
		code uint32
		want scanStatus
	}{
		{smb.StatusLogonFailure, statusAuthFailed},
		{smb.StatusAccessDenied, statusAuthFailed},
		{smb.StatusAccountLockedOut, statusAccountLocked},
		{smb.StatusAccountDisabled, statusAccountDisabled},
		{smb.StatusPasswordExpired, statusPasswordExpired},
		{smb.StatusPasswordMustChange, statusPasswordChange},
		{smb.StatusAccountExpired, statusAccountExpired},
		{smb.StatusAccountRestriction, statusAccountRestricted},
		{smb.StatusInvalidLogonHours, statusLogonHours},
		{smb.StatusInvalidWorkstation, statusWorkstationDenied},
	} {
		err := fmt.Errorf("session response: %w", &smb.NTStatusError{Command: 1, Status: tc.code})
		if got := connectionStatus(err, context.DeadlineExceeded, true); got != tc.want {
			t.Errorf("session status 0x%08x = %q; want %q despite later deadline", tc.code, statusLabels[got], statusLabels[tc.want])
		}
	}
}

func TestEnumerationStatusRetainsPrimaryFailureAndPartialPages(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enumerated smb.ShareEnumeration
		err        error
		transport  error
		want       scanStatus
	}{
		{"denied", smb.ShareEnumeration{}, smb.ErrRPCDenied, nil, statusEnumDenied},
		{"failed", smb.ShareEnumeration{}, errors.New("invalid RPC response"), nil, statusEnumFailed},
		{"timeout", smb.ShareEnumeration{}, net.ErrClosed, context.DeadlineExceeded, statusEnumTimeout},
		{"canceled", smb.ShareEnumeration{}, net.ErrClosed, context.Canceled, statusCanceled},
		{"denial before cleanup timeout", smb.ShareEnumeration{Failure: smb.ErrRPCDenied}, smb.ErrRPCDenied, context.DeadlineExceeded, statusEnumDenied},
		{"failure before cleanup timeout", smb.ShareEnumeration{Failure: errors.New("invalid response")}, errors.New("invalid response"), context.DeadlineExceeded, statusEnumFailed},
		{"partial before denial", smb.ShareEnumeration{Shares: []smb.Share{{Name: "kept"}}}, smb.ErrRPCDenied, nil, statusEnumPartial},
		{"partial before timeout", smb.ShareEnumeration{Shares: []smb.Share{{Name: "kept"}}}, net.ErrClosed, context.DeadlineExceeded, statusEnumPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := enumerationStatus(tc.enumerated, tc.err, tc.transport); got != tc.want {
				t.Errorf("status = %q; want %q", statusLabels[got], statusLabels[tc.want])
			}
		})
	}
}

func TestTableStatusScopeAndSerializedSchema(t *testing.T) {
	result := Result{Reachable: true, Authentication: "authenticated", Enumeration: "ok", status: statusOK,
		Shares: []ShareResult{
			{Name: "known", Accessible: Allowed, Read: Allowed, Write: Denied, status: statusOK},
			{Name: "failed", Accessible: Allowed, Read: Allowed, Write: Unknown, status: statusCheckFailed},
			{Name: "cleanup", Accessible: Allowed, Read: Allowed, Write: Allowed, status: statusCleanupFailed},
			{Name: "denied", Accessible: Denied, Read: Denied, Write: Denied, Error: "access denied", status: statusOK},
		}}
	for i, want := range []string{"OK", "CHECK_FAILED", "CLEANUP_FAILED", "OK"} {
		if got := tableStatus(result, &result.Shares[i]); got != want {
			t.Errorf("share %q status = %q; want %q", result.Shares[i].Name, got, want)
		}
	}
	result.status = statusEnumPartial
	for i := range result.Shares {
		if got := tableStatus(result, &result.Shares[i]); got != "ENUM_PARTIAL" {
			t.Errorf("partial enumeration did not affect every row: %q", got)
		}
	}
	result.status, result.cleanupStatus = statusOK, statusCleanupTimeout
	if got := tableStatus(result, &result.Shares[0]); got != "CLEANUP_TIMEOUT" {
		t.Errorf("completed row lost host cleanup timeout: %q", got)
	}
	if got := tableStatus(result, &result.Shares[1]); got != "CHECK_FAILED" {
		t.Errorf("cleanup erased primary share failure: %q", got)
	}
	withStatus, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	result.status, result.cleanupStatus = statusUnset, statusUnset
	for i := range result.Shares {
		result.Shares[i].status = statusUnset
	}
	withoutStatus, err := json.Marshal(result)
	if err != nil || string(withStatus) != string(withoutStatus) {
		t.Errorf("private statuses changed JSON schema: %s versus %s (%v)", withStatus, withoutStatus, err)
	}
	for _, tc := range []struct {
		result Result
		want   string
	}{
		{Result{Authentication: "failed"}, "AUTH_FAILED"},
		{Result{Authentication: "unverified"}, "AUTH_UNVERIFIED"},
		{Result{Authentication: "anonymous"}, "AUTH_UNVERIFIED"},
		{Result{Authentication: "authenticated", explicitGuest: true}, "GUEST_MISMATCH"},
		{Result{Authentication: "authenticated", Enumeration: "ok"}, "NO_SHARES"},
		{Result{Error: "authentication failed: account locked timeout"}, "CONNECT_FAILED"},
	} {
		if got := tableStatus(tc.result, nil); got != tc.want {
			t.Errorf("placeholder status = %q; want %q", got, tc.want)
		}
	}
}

func TestScanTargetRecordsStatusAtFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		metadata  string
		configure func(*enumerationFixture)
		wantDisk  string
		wantOther string
		wantOpens int
	}{
		{"permission denied", "success", func(f *enumerationFixture) { f.guard.denyList = true }, "OK", "OK", 2},
		{"missing metadata", "absent", nil, "CHECK_FAILED", "OK", 1},
		{"malformed metadata", "malformed", nil, "CHECK_FAILED", "OK", 1},
		{"disk cleanup denied", "success", func(f *enumerationFixture) { f.guard.deniedDiskCleanup = 6 }, "CLEANUP_FAILED", "OK", 1},
		{"enumeration cleanup denied", "success", func(f *enumerationFixture) { f.guard.deniedIPCCleanup = 6 }, "CLEANUP_FAILED", "CLEANUP_FAILED", 1},
		{"enumeration denied", "success", func(f *enumerationFixture) { f.guard.enumerationStatus = 5 }, "ENUM_DENIED", "", 0},
		{"wrong password", "success", func(f *enumerationFixture) { f.options.Password = "wrong-synthetic-password" }, "AUTH_FAILED", "", 0},
		{"negotiation denied", "success", func(f *enumerationFixture) { f.guard.negotiationStatus = smb.StatusLogonFailure }, "NEGOTIATE_FAILED", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, tc.metadata, false)
			fixture.guard.mu.Lock()
			if tc.configure != nil {
				tc.configure(fixture)
			}
			fixture.guard.mu.Unlock()
			result := scanTarget(context.Background(), fixture.target, fixture.options)
			if tc.wantOther == "" {
				if got := tableStatus(result, nil); got != tc.wantDisk || len(result.Shares) != 0 {
					t.Errorf("host status = %q; want %q without shares: %+v", got, tc.wantDisk, result)
				}
			} else {
				if len(result.Shares) != 3 {
					t.Fatalf("lost enumerated shares: %+v", result)
				}
				for _, share := range result.Shares {
					want := tc.wantOther
					if share.Type == "disk" {
						want = tc.wantDisk
					}
					if got := tableStatus(result, &share); got != want {
						t.Errorf("share %q status = %q; want %q (%+v)", share.Name, got, want, share)
					}
				}
			}
			fixture.assertUnchanged(t, tc.wantOpens)
		})
	}
}

func TestScanTargetStatusSeparatesCheckAndCleanupTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command uint16
		want    string
	}{
		{"check", 5, "CHECK_TIMEOUT"},
		{"logoff", 2, "CLEANUP_TIMEOUT"},
		{"enumeration", 9, "ENUM_TIMEOUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			fixture.options.HostTimeout = 300 * time.Millisecond
			target, stalled, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) < 64 || binary.LittleEndian.Uint16(raw[12:14]) != tc.command {
					return false
				}
				return tc.command != 5 || len(raw) >= 112 && binary.LittleEndian.Uint16(raw[110:112]) == 0
			})
			result := scanTarget(context.Background(), target, fixture.options)
			select {
			case <-stalled:
			default:
				t.Fatalf("did not reach intended stall: %+v", result)
			}
			var disk *ShareResult
			for i := range result.Shares {
				if result.Shares[i].Type == "disk" {
					disk = &result.Shares[i]
				} else if tc.name == "check" && tableStatus(result, &result.Shares[i]) != "OK" {
					t.Error("a disk probe timeout changed an unrelated non-disk row")
				}
			}
			if got := tableStatus(result, disk); got != tc.want {
				t.Errorf("timeout status = %q; want %q (%+v)", got, tc.want, result)
			}
			if disk != nil && (disk.Accessible != Allowed || tc.name == "logoff" && (disk.Read != Allowed || disk.Write != Allowed)) {
				t.Errorf("timeout erased known permissions: %+v", disk)
			}
		})
	}
}

func TestCanceledScanStatusDoesNotReadDiagnosticText(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := scanTarget(ctx, Target{Host: "127.0.0.1", Port: 445}, Options{})
	result.Error = strings.Repeat("account locked timeout connection refused", 3)
	if got := tableStatus(result, nil); got != "CANCELED" {
		t.Errorf("canceled scan status depended on diagnostic text: %q", got)
	}
}

func TestPoisonedShareConnectionDoesNotChangeOtherRowStatuses(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	fixture.options.HostTimeout = time.Second
	target, injected, _ := newTamperedSMBReplyProxy(t, fixture.target, 3, 2, 76)
	result := scanTarget(context.Background(), target, fixture.options)
	select {
	case <-injected:
	default:
		t.Fatalf("did not reach disk TREE_CONNECT response: %+v", result)
	}
	if len(result.Shares) != 3 || result.cleanupStatus != statusUnset {
		t.Fatalf("failed share connection became a host cleanup failure: %+v", result)
	}
	for _, share := range result.Shares {
		want := "OK"
		if share.Type == "disk" {
			want = "CHECK_FAILED"
		}
		if got := tableStatus(result, &share); got != want {
			t.Errorf("share %q status = %q; want %q", share.Name, got, want)
		}
	}
	fixture.assertUnchanged(t, 0)
}
