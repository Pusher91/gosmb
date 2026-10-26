package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	smb "gosmb/internal/smbwire"
)

func scanTarget(ctx context.Context, target Target, opts Options) (result Result) {
	if opts.HostTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
		defer cancel()
	}
	result = Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Shares: []ShareResult{}, explicitGuest: opts.Guest, status: statusOK}
	// A literal target IP is known before dialing, even if the scan fails or
	// is canceled. Keep it as the result's identity throughout the scan.
	if _, err := netip.ParseAddr(target.Host); err == nil {
		result.ServerIP = target.Host
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.status = connectionStatus(err, nil, false)
		if errors.Is(err, context.DeadlineExceeded) {
			markHostTimeout(&result)
		}
		return
	}
	wire := &boundedDialer{ctx: ctx, target: target.String(), timeout: opts.Timeout}
	stop := context.AfterFunc(ctx, wire.close)
	var conn *smb.Connection
	defer func() {
		if recover() != nil {
			wire.close()
			result.Error = "invalid SMB response; scan aborted"
			result.status = statusSMBFailed
			if result.Enumeration == "not_attempted" {
				result.Enumeration = "error"
			}
		}
		if conn != nil {
			// The native exchange arms deadlines and refuses a closed transport.
			// A transport already lost during a share check is not an additional
			// host-wide cleanup failure on every successfully checked share.
			reportCleanup := wire.err() == nil
			if err := conn.Logoff(); err != nil {
				if result.Error == "" {
					result.Error = fmt.Sprintf("SMB logoff: %v", err)
				}
				if reportCleanup && result.cleanupStatus == statusUnset {
					result.cleanupStatus = operationStatus(err, wire.err(), statusCleanupFailed, statusCleanupTimeout)
				}
			}
		}
		stop()
		wire.close()
		result.Reachable = wire.reachable()
		if result.ServerIP == "" {
			result.ServerIP = wire.serverIP()
		}
		if wire.timedOut() {
			markHostTimeout(&result)
		}
	}()

	var err error
	conn, err = smb.NewConnection(smb.Options{
		Host: target.Host, Dial: wire.Dial, BeforeIO: wire.arm,
		Username: opts.Username, Password: opts.Password, Domain: opts.Domain,
		Guest: opts.Guest,
	})
	result.Reachable = wire.reachable()
	if err != nil {
		result.status = connectionStatus(err, wire.err(), result.Reachable)
		if result.Reachable {
			result.Authentication = "error"
			if authenticationFailureReason(err) != "" {
				result.Authentication = "failed"
			}
		}
		result.Error = connectionFailureMessage(err, result.Reachable)
		result.authenticationComplete = !wire.timedOut() || result.Authentication == "failed"
		return
	}
	result.authenticationComplete = true
	switch conn.AuthResult() {
	case smb.AuthResultGuest:
		// This is the server's verdict on the original login, not a second
		// authentication attempt. Every reported permission belongs to Guest.
		result.Authentication = "guest"
		result.GuestFallback = !opts.Guest
	case smb.AuthResultAnonymous:
		result.Authentication, result.Error = "anonymous", "server established an anonymous session; not treated as user or guest authentication"
		result.status = statusAuthUnverified
		return
	case smb.AuthResultUser:
		result.Authentication = "authenticated"
		if opts.Guest {
			result.Error = "server did not identify this as a guest session"
			result.status = statusGuestMismatch
			return
		}
	default:
		result.Authentication = "unverified"
		result.Error = "server returned an unsigned or unkeyed session without identifying it as Guest"
		result.status = statusAuthUnverified
		return
	}
	enumerated, err := conn.EnumerateShares()
	shares := discoveredShares(enumerated.Shares)
	result.Enumeration = "ok"
	result.enumerationComplete = enumerated.Complete || enumerated.Failure != nil || !wire.timedOut()
	if err != nil {
		// Cleanup can fail after every page has arrived. Keep enumeration and
		// its share list complete while reporting the cleanup as a host error.
		if !enumerated.Complete {
			result.status = enumerationStatus(enumerated, err, wire.err())
			result.Enumeration = "error"
			if accessDenied(err) {
				result.Enumeration = "denied"
			}
		} else {
			result.cleanupStatus = operationStatus(err, wire.err(), statusCleanupFailed, statusCleanupTimeout)
		}
		result.Error = fmt.Sprintf("share enumeration: %v", err)
	}
	// Preserve any successfully enumerated page even if a later page failed.
	result.Shares = make([]ShareResult, 0, len(shares))
	for _, share := range shares {
		if err := wire.err(); err != nil {
			if result.Error == "" {
				result.Error = "share checks incomplete: " + err.Error()
			}
			unprobed := unprobedShare(share, err.Error())
			if !unprobed.probeComplete {
				unprobed.status = operationStatus(err, nil, statusCheckFailed, statusCheckTimeout)
			}
			result.Shares = append(result.Shares, unprobed)
			continue
		}
		inspected, cleanupErr := inspectShare(conn, wire, share)
		result.Shares = append(result.Shares, inspected)
		if cleanupErr != nil && result.Error == "" {
			result.Error = fmt.Sprintf("share %s cleanup: %v", share.Name, cleanupErr)
		}
	}
	return
}

// markHostTimeout also normalizes results returned by the CLI's scan hook.
// A completed probe can legitimately lack metadata; only unanswered checks
// become TIMEOUT. Known decisions and authenticated identities are retained.
func markHostTimeout(result *Result) {
	result.TimedOut = true
	if !result.authenticationComplete {
		switch result.Authentication {
		case "", "not_attempted", "error", Unknown:
			result.Authentication = TimedOut
		}
	}
	if !result.enumerationComplete {
		switch result.Enumeration {
		case "", "not_attempted", "error", Unknown:
			result.Enumeration = TimedOut
		}
	}
	for i := range result.Shares {
		markShareTimeout(&result.Shares[i])
	}
	if result.Error == "" {
		result.Error = "scan timed out"
	}
}

func markShareTimeout(share *ShareResult) {
	if share.probeComplete {
		return
	}
	changed := false
	for _, permission := range []*string{&share.Accessible, &share.Read, &share.Write} {
		if *permission == "" || *permission == Unknown {
			*permission = TimedOut
			changed = true
		}
	}
	if changed && share.Error == "" {
		share.Error = "share checks incomplete: timeout"
	}
	if changed && (share.status == statusUnset || share.status == statusOK) {
		share.status = statusCheckTimeout
	}
}

func connectionFailureMessage(err error, reachable bool) string {
	if !reachable {
		return fmt.Sprintf("connection failed: %v", err)
	}
	var status *smb.NTStatusError
	if errors.As(err, &status) {
		if reason := authenticationFailureReason(err); reason != "" {
			return fmt.Sprintf("authentication failed: %s (SMB status 0x%08x)", reason, status.Status)
		}
		switch status.Command {
		case 0:
			return fmt.Sprintf("SMB negotiation failed: %v", err)
		case smb.SessionSetupCommand:
			return fmt.Sprintf("SMB session setup failed: %v", err)
		}
	}
	return fmt.Sprintf("SMB connection: %v", err)
}

// Only a recognized session-setup rejection describes an authentication
// failure. The same status during negotiation must not blame the credentials.
func authenticationFailureReason(err error) string {
	var status *smb.NTStatusError
	if !errors.As(err, &status) || status.Command != smb.SessionSetupCommand {
		return ""
	}
	switch status.Status {
	case smb.StatusLogonFailure:
		return "username or password was rejected"
	case smb.StatusAccessDenied:
		return "server denied logon"
	case smb.StatusAccountRestriction:
		return "account restrictions prevent logon"
	case smb.StatusInvalidLogonHours:
		return "logon is not allowed at this time"
	case smb.StatusInvalidWorkstation:
		return "logon is not allowed from this workstation"
	case smb.StatusPasswordExpired:
		return "password has expired"
	case smb.StatusAccountDisabled:
		return "account is disabled"
	case smb.StatusAccountExpired:
		return "account has expired"
	case smb.StatusPasswordMustChange:
		return "password must be changed"
	case smb.StatusAccountLockedOut:
		return "account is locked out"
	}
	return ""
}

func hasSMBStatus(err error, codes ...uint32) bool {
	var status *smb.NTStatusError
	if !errors.As(err, &status) {
		return false
	}
	for _, code := range codes {
		if status.Status == code {
			return true
		}
	}
	return false
}

func accessDenied(err error) bool {
	return hasSMBStatus(err, smb.StatusAccessDenied) || errors.Is(err, smb.ErrRPCDenied)
}

func unprobedShare(share discoveredShare, reason string) ShareResult {
	result := ShareResult{Name: share.Name, Type: share.Type, Comment: share.Comment, Accessible: Unknown,
		Read: Unknown, Write: Unknown, WriteBasis: "unavailable", Error: reason, status: statusOK}
	if share.Type != "disk" {
		result.Accessible, result.Read, result.Write, result.WriteBasis = NotApplicable, NotApplicable, NotApplicable, "not_a_disk_share"
		result.Error = ""
		result.probeComplete = true
	}
	return result
}

func validShareName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 256 || strings.ContainsAny(name, "\\/:") {
		return false
	}
	// MS-FSCC 2.1.6 forbids only C0 controls. DEL and C1 controls are legal
	// share-name characters; text output escapes them separately.
	return strings.IndexFunc(name, func(r rune) bool { return r < 0x20 }) < 0
}

func inspectShare(conn *smb.Connection, wire *boundedDialer, share discoveredShare) (result ShareResult, cleanupErr error) {
	result = unprobedShare(share, "")
	if share.Type != "disk" {
		return
	}
	if !validShareName(share.Name) {
		result.Error = "server returned an invalid share name; not probed"
		result.probeComplete = true
		result.status = statusCheckFailed
		return
	}
	if err := conn.TreeConnect(share.Name); err != nil {
		result.Error = fmt.Sprintf("connect share: %v", err)
		result.probeComplete = !wire.timedOut()
		if accessDenied(err) {
			result.Accessible, result.Read, result.Write = Denied, Denied, Denied
			result.WriteBasis = "share_connection_denied"
		} else {
			result.status = operationStatus(err, wire.err(), statusCheckFailed, statusCheckTimeout)
		}
		return
	}
	defer func() {
		if err := conn.TreeDisconnect(share.Name); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("disconnect share: %w", err))
		}
		if cleanupErr != nil {
			if result.status == statusOK {
				result.status = operationStatus(cleanupErr, wire.err(), statusCleanupFailed, statusCleanupTimeout)
			}
			if result.Error == "" {
				result.Error = cleanupErr.Error()
			} else {
				result.Error += "\n" + cleanupErr.Error()
			}
		}
	}()
	result.Accessible = Allowed
	shareMask, shareKnown := conn.TreeMaximalAccess(share.Name)
	root, err := probeRoot(conn, share.Name, smb.FileListDirectory, true)
	if err == nil {
		result.Read = Allowed
	} else if accessDenied(err) {
		result.Read = Denied
		// A write-only root can reject LIST yet still expose metadata. This
		// fallback requests READ_ATTRIBUTES only, never write access.
		root, err = probeRoot(conn, share.Name, smb.FileReadAttributes, true)
	} else if metadataUnsupported(err) {
		// Some NAS servers reject unknown create contexts. One read-only retry
		// without MxAc can still determine LIST permission; WRITE stays unknown.
		root, err = probeRoot(conn, share.Name, smb.FileListDirectory, false)
		if err == nil {
			result.Read = Allowed
		} else if accessDenied(err) {
			result.Read = Denied
		}
	}
	cleanupErr = root.cleanupErr
	result.Write, result.WriteBasis = rootWritePermission(shareMask, shareKnown, root.mask, root.known)
	// A successful root-open response answered both requested questions even
	// if it omitted MxAc or its later CLOSE timed out. Missing metadata remains
	// UNKNOWN; a timeout waiting for the root-open response is unanswered.
	result.probeComplete = err == nil || !wire.timedOut()
	if err != nil {
		result.Error = fmt.Sprintf("root access query: %v", err)
		if !accessDenied(err) {
			result.status = operationStatus(err, wire.err(), statusCheckFailed, statusCheckTimeout)
		}
	} else if root.metadataErr != nil {
		result.Error = root.metadataErr.Error()
		result.status = statusCheckFailed
	} else if !root.known && result.Write == Unknown {
		result.Error = "server did not return root maximum-access metadata"
		result.status = statusCheckFailed
	}
	return
}

func metadataUnsupported(err error) bool {
	return hasSMBStatus(err, smb.StatusInvalidParameter, smb.StatusNotSupported)
}

type rootProbe struct {
	mask        uint32
	known       bool
	metadataErr error
	cleanupErr  error
}

// probeRoot opens ONLY the existing root directory. SMB calls opening a handle
// CREATE even with FILE_OPEN: it cannot create a new filesystem object. No child
// names/content are requested, and only LIST or READ_ATTRIBUTES can be requested.
func probeRoot(conn *smb.Connection, share string, desired uint32, maximal bool) (probe rootProbe, err error) {
	opened, err := conn.OpenRoot(share, desired, maximal)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := opened.Close(); closeErr != nil {
			// The successful open already answered LIST; cleanup failure does
			// not erase that result. Socket closure also releases the handle.
			probe.cleanupErr = fmt.Errorf("close root handle: %w", closeErr)
		}
	}()
	if opened.MetadataError != nil {
		probe.metadataErr = fmt.Errorf("invalid root access metadata: %w", opened.MetadataError)
		return
	}
	probe.mask, probe.known, probe.metadataErr = parseMaximalAccess(opened.Contexts)
	return
}
