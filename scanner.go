package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var silenceLogs sync.Once

func scanTarget(ctx context.Context, target Target, opts Options) (result Result) {
	if opts.HostTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
		defer cancel()
	}
	result = Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Shares: []ShareResult{}}
	// A literal target IP is known before dialing, even if the scan fails or
	// is canceled. Keep it as the result's identity throughout the scan.
	if _, err := netip.ParseAddr(target.Host); err == nil {
		result.ServerIP = target.Host
	}
	// Credentials and untrusted server fields must never reach library loggers.
	silenceLogs.Do(func() { golog.SetAll(golog.LevelNone, 0, golog.NoOutput, golog.NoOutput) })
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
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
			if result.Enumeration == "not_attempted" {
				result.Enumeration = "error"
			}
		}
		if conn != nil {
			if wire.arm() == nil {
				_ = conn.Logoff()
			}
			// All trees are normally disconnected by their scoped probes. Closing
			// the socket first bounds cleanup even if a server broke the protocol.
			wire.close()
			conn.Close()
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
	initiator := &spnego.NTLMInitiator{User: opts.Username, Password: opts.Password, Domain: opts.Domain}
	if opts.Guest {
		// Explicit guest is one distinct login attempt. Never send supplied or
		// environmental credentials, and never turn it into an anonymous retry.
		initiator = &spnego.NTLMInitiator{AuthMode: spnego.NTLMAuthGuest}
	}
	conn, err = smb.NewConnection(smb.Options{
		Host: target.Host, Port: target.Port, DialTimeout: opts.Timeout,
		ProxyDialer: wire, SMB2Only: true, RequireMessageSigning: true,
		Initiator: initiator,
		// Requests are strictly serial, and the library applies credit grants
		// before delivering each response. No other pending request could
		// replenish an empty balance. Fail immediately rather than entering
		// the dependency's context-insensitive default 60-second credit wait,
		// including on its receiver-panic cleanup path.
		CreditReserveTimeout: time.Nanosecond,
	})
	result.Reachable = wire.reachable()
	if err != nil {
		if result.Reachable {
			result.Authentication = "error"
			if authenticationFailure(err) {
				result.Authentication = "failed"
			}
		}
		result.Error = fmt.Sprintf("SMB connection: %v", err)
		result.authenticationComplete = !wire.timedOut() || result.Authentication == "failed"
		return
	}
	result.authenticationComplete = true
	if !conn.IsAuthenticated() {
		result.Authentication, result.Error = "failed", "server did not establish an authenticated session"
		return
	}
	switch conn.AuthResult() {
	case smb.AuthResultGuest:
		// This is the server's verdict on the original login, not a second
		// authentication attempt. Every reported permission belongs to Guest.
		result.Authentication = "guest"
		result.GuestFallback = !opts.Guest
	case smb.AuthResultAnonymous:
		result.Authentication, result.Error = "anonymous", "server established an anonymous session; not treated as user or guest authentication"
		return
	default:
		// The dependency's anonymous classification covers client-requested
		// null sessions only. A server-only IS_NULL flag can otherwise look
		// like a user session after it disabled signing and key derivation.
		if !conn.IsSigningRequired() || len(conn.GetSessionKey()) < 16 {
			result.Authentication = "unverified"
			result.Error = "server returned an unsigned or unkeyed session without identifying it as Guest"
			return
		}
		result.Authentication = "authenticated"
		if opts.Guest {
			result.Error = "server did not identify this as a guest session"
			return
		}
	}
	shares, err := enumerateShares(conn, wire, target.Host)
	result.Enumeration = "ok"
	result.enumerationComplete = err == nil || !wire.timedOut()
	if err != nil {
		result.Enumeration = "error"
		if accessDenied(err) {
			result.Enumeration = "denied"
		}
		result.Error = fmt.Sprintf("share enumeration: %v", err)
	}
	// Preserve any successfully enumerated page even if a later page failed.
	sort.SliceStable(shares, func(i, j int) bool { return strings.ToLower(shares[i].Name) < strings.ToLower(shares[j].Name) })
	for _, share := range shares {
		if err := wire.err(); err != nil {
			result.Error = "share checks incomplete: " + err.Error()
			result.Shares = append(result.Shares, unprobedShare(share, err.Error()))
			continue
		}
		result.Shares = append(result.Shares, inspectShare(conn, wire, share))
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
}

func authenticationFailure(err error) bool {
	for _, status := range []uint32{smb.StatusLogonFailure, smb.StatusAccessDenied, smb.StatusAccountRestriction,
		smb.StatusPasswordExpired, smb.StatusAccountDisabled, smb.StatusPasswordMustChange, smb.StatusAccountLockedOut} {
		if errors.Is(err, smb.StatusMap[status]) {
			return true
		}
	}
	return false
}

func accessDenied(err error) bool {
	return errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) || errors.Is(err, errRPCDenied)
}

func unprobedShare(share discoveredShare, reason string) ShareResult {
	result := ShareResult{Name: share.Name, Type: share.Type, Comment: share.Comment, Accessible: Unknown,
		Read: Unknown, Write: Unknown, WriteBasis: "unavailable", Error: reason}
	if !share.Disk {
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
	return strings.IndexFunc(name, unicode.IsControl) < 0
}

func inspectShare(conn *smb.Connection, wire *boundedDialer, share discoveredShare) (result ShareResult) {
	result = unprobedShare(share, "")
	if !share.Disk {
		return
	}
	if !validShareName(share.Name) {
		result.Error = "server returned an invalid share name; not probed"
		result.probeComplete = true
		return
	}
	if err := wire.arm(); err != nil {
		result.Error = err.Error()
		result.probeComplete = !wire.timedOut()
		return
	}
	if err := conn.TreeConnect(share.Name); err != nil {
		result.Error = fmt.Sprintf("connect share: %v", err)
		result.probeComplete = !wire.timedOut()
		if accessDenied(err) {
			result.Accessible, result.Read, result.Write = Denied, Denied, Denied
			result.WriteBasis = "share_connection_denied"
		}
		return
	}
	defer func() {
		if wire.arm() == nil {
			_ = conn.TreeDisconnect(share.Name)
		}
	}()
	result.Accessible = Allowed
	_, _, shareMask, shareKnown := conn.TreeConnectInfo(share.Name)
	rootMask, rootKnown, metadataErr, err := probeRoot(conn, wire, share.Name, smb.DAccMaskFileListDirectory, true)
	if err == nil {
		result.Read = Allowed
	} else if accessDenied(err) {
		result.Read = Denied
		// A write-only root can reject LIST yet still expose metadata. This
		// fallback requests READ_ATTRIBUTES only, never write access.
		rootMask, rootKnown, metadataErr, err = probeRoot(conn, wire, share.Name, smb.FAccMaskFileReadAttributes, true)
	} else if metadataUnsupported(err) {
		// Some NAS servers reject unknown create contexts. One read-only retry
		// without MxAc can still determine LIST permission; WRITE stays unknown.
		rootMask, rootKnown, metadataErr, err = probeRoot(conn, wire, share.Name, smb.DAccMaskFileListDirectory, false)
		if err == nil {
			result.Read = Allowed
		} else if accessDenied(err) {
			result.Read = Denied
		}
	}
	result.Write, result.WriteBasis = rootWritePermission(shareMask, shareKnown, rootMask, rootKnown)
	// A successful root-open response answered both requested questions even
	// if it omitted MxAc or its later CLOSE timed out. Missing metadata remains
	// UNKNOWN; a timeout waiting for the root-open response is unanswered.
	result.probeComplete = err == nil || !wire.timedOut()
	if err != nil {
		result.Error = fmt.Sprintf("root access query: %v", err)
	} else if metadataErr != nil {
		result.Error = metadataErr.Error()
	} else if !rootKnown && result.Write == Unknown {
		result.Error = "server did not return root maximum-access metadata"
	}
	return
}

func metadataUnsupported(err error) bool {
	var status *smb.NTStatusError
	return errors.As(err, &status) && (status.Status == smb.StatusInvalidParameter || status.Status == smb.StatusNotSupported)
}

// probeRoot opens ONLY the existing root directory. SMB calls opening a handle
// CREATE even with FILE_OPEN: it cannot create a new filesystem object. No child
// names/content are requested, and only LIST or READ_ATTRIBUTES can be requested.
func probeRoot(conn *smb.Connection, wire *boundedDialer, share string, desired uint32, maximal bool) (mask uint32, known bool, metadataErr error, err error) {
	if desired != smb.DAccMaskFileListDirectory && desired != smb.FAccMaskFileReadAttributes {
		return 0, false, nil, errors.New("refusing non-read-only root access")
	}
	req, err := conn.NewCreateReq(share, "", smb.OpLockLevelNone, smb.ImpersonationLevelImpersonation,
		desired, 0, smb.FileShareRead|smb.FileShareWrite|smb.FileShareDelete, smb.FileOpen, smb.FileDirectoryFile)
	if err != nil {
		return
	}
	if maximal {
		if err = addMaximalAccessContext(&req); err != nil {
			return
		}
	}
	pdu, err := req.MarshalBinary()
	if err != nil {
		return
	}
	if err = wire.arm(); err != nil {
		return
	}
	response, err := conn.SendRawPDU(pdu)
	if err != nil {
		return
	}
	var header smb.Header
	if err = header.UnmarshalBinary(response); err != nil {
		return
	}
	if header.Command != smb.CommandCreate {
		return 0, false, nil, errors.New("unexpected SMB response to root open")
	}
	if header.Status != smb.StatusOk {
		return 0, false, nil, &smb.NTStatusError{Op: "open existing root", Status: header.Status, Err: smb.StatusMap[header.Status]}
	}
	// Capture the fixed-width FileId before parsing variable server contexts.
	// Even a malformed MxAc response must not strand the opened handle.
	if len(response) < 152 {
		wire.close()
		return 0, false, nil, errors.New("truncated root-open response")
	}
	fileID := append([]byte(nil), response[128:144]...)
	defer func() {
		closeErr := closeRoot(conn, wire, share, fileID)
		if closeErr != nil {
			// A failed CLOSE is not a failed LIST permission check. Preserve
			// the granted access and surface cleanup separately; TreeDisconnect
			// and socket closure also release the handle.
			metadataErr = errors.Join(metadataErr, fmt.Errorf("close root handle: %w", closeErr))
		}
	}()
	var opened smb.CreateRes
	if decodeErr := opened.UnmarshalBinary(response); decodeErr != nil {
		return 0, false, fmt.Errorf("invalid root access metadata: %w", decodeErr), nil
	}
	if opened.StructureSize != 89 || opened.CreateAction != smb.FileOpened {
		return 0, false, nil, errors.New("server returned an unexpected result for existing-root open")
	}
	mask, known, metadataErr = parseMaximalAccess(opened.Buffer)
	return
}

func closeRoot(conn *smb.Connection, wire *boundedDialer, share string, fileID []byte) error {
	req, err := conn.NewCloseReq(share, fileID)
	if err != nil {
		return err
	}
	pdu, err := req.MarshalBinary()
	if err != nil {
		return err
	}
	if err := wire.arm(); err != nil {
		return err
	}
	response, err := conn.SendRawPDU(pdu)
	if err != nil {
		return err
	}
	var header smb.Header
	if err := header.UnmarshalBinary(response); err != nil {
		return err
	}
	if header.Status != smb.StatusOk {
		return &smb.NTStatusError{Op: "close root", Status: header.Status, Err: smb.StatusMap[header.Status]}
	}
	return nil
}
