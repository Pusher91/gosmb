package main

import (
	"context"
	"errors"
	"net"
	"syscall"

	smb "gosmb/internal/smbwire"
)

type scanStatus uint8

const (
	statusUnset scanStatus = iota
	statusOK
	statusAuthFailed
	statusAccountLocked
	statusAccountDisabled
	statusPasswordExpired
	statusPasswordChange
	statusAccountExpired
	statusAccountRestricted
	statusLogonHours
	statusWorkstationDenied
	statusConnectFailed
	statusConnectRefused
	statusConnectTimeout
	statusDNSFailed
	statusSMBFailed
	statusSMBTimeout
	statusNegotiateFailed
	statusEnumDenied
	statusEnumFailed
	statusEnumPartial
	statusEnumTimeout
	statusCheckFailed
	statusCheckTimeout
	statusCleanupFailed
	statusCleanupTimeout
	statusCanceled
	statusNoShares
	statusAuthUnverified
	statusGuestMismatch
	statusScanTimeout
	statusCount
)

// tableStatus never interprets free-form Error text. Recorded host failures
// affect every row; a failed share check affects only that share. In particular,
// access denied is an observed permission, not a failed check.
func tableStatus(result Result, share *ShareResult) string {
	status := result.status
	if status == statusUnset {
		status = inferredHostStatus(result)
	}
	if status != statusOK {
		return statusLabels[status]
	}
	if share != nil {
		status = share.status
		if status == statusUnset {
			status = inferredShareStatus(*share)
		}
		if status != statusOK {
			return statusLabels[status]
		}
	}
	if result.completionStatus != statusUnset {
		return statusLabels[result.completionStatus]
	}
	if share == nil && result.Enumeration == "ok" && len(result.Shares) == 0 {
		return statusLabels[statusNoShares]
	}
	return statusLabels[statusOK]
}

// These fallbacks also support scan hooks and results read without private
// metadata. More specific server errors require the scanner's typed outcome.
func inferredHostStatus(result Result) scanStatus {
	switch result.Authentication {
	case "failed":
		return statusAuthFailed
	case "anonymous", "unverified":
		return statusAuthUnverified
	case "authenticated":
		if result.explicitGuest {
			return statusGuestMismatch
		}
	case "error":
		return statusSMBFailed
	case TimedOut:
		if result.Reachable {
			return statusSMBTimeout
		}
		return statusConnectTimeout
	}
	switch result.Enumeration {
	case "error", "denied", TimedOut:
		if len(result.Shares) > 0 {
			return statusEnumPartial
		}
		if result.Enumeration == "denied" {
			return statusEnumDenied
		}
		if result.Enumeration == TimedOut {
			return statusEnumTimeout
		}
		return statusEnumFailed
	case "ok":
		return statusOK
	}
	if result.TimedOut {
		if !result.Reachable {
			return statusConnectTimeout
		}
		if result.Authentication == "authenticated" || result.Authentication == "guest" {
			return statusEnumTimeout
		}
		return statusSMBTimeout
	}
	if result.Error != "" {
		if !result.Reachable {
			return statusConnectFailed
		}
		return statusSMBFailed
	}
	return statusOK
}

func inferredShareStatus(share ShareResult) scanStatus {
	for _, permission := range []string{share.Accessible, share.Read, share.Write} {
		if permission == TimedOut {
			return statusCheckTimeout
		}
	}
	if share.Accessible == Denied || (share.Read == Denied && share.Write == Denied) {
		return statusOK
	}
	if share.Error != "" {
		return statusCheckFailed
	}
	return statusOK
}

// Socket closure is how a context interruption reaches an in-flight exchange.
// The retained transport cause distinguishes it from an ordinary protocol error.
func operationStatus(err, transportErr error, failed, timeout scanStatus) scanStatus {
	if errors.Is(err, context.Canceled) {
		return statusCanceled
	}
	if typedTimeout(err) {
		return timeout
	}
	// A server already answered this operation. Preserve that rejection when
	// cleanup or later bookkeeping observes a transport interruption. A joined
	// error containing its own timeout/cancellation still takes precedence above.
	if isSMBStatusError(err) {
		return failed
	}
	if errors.Is(transportErr, context.Canceled) {
		return statusCanceled
	}
	if typedTimeout(transportErr) {
		return timeout
	}
	return failed
}

// Authentication classification and its diagnostic text share one mapping so
// JSON, TSV diagnostics, and the interactive table cannot disagree. Only a
// session-setup rejection describes an authentication failure.
func authenticationFailure(err error) (scanStatus, string) {
	status, ok := errors.AsType[*smb.NTStatusError](err)
	if !ok || status.Command != smb.SessionSetupCommand {
		return statusUnset, ""
	}
	switch status.Status {
	case smb.StatusLogonFailure:
		return statusAuthFailed, "username or password was rejected"
	case smb.StatusAccessDenied:
		return statusAuthFailed, "server denied logon"
	case smb.StatusAccountRestriction:
		return statusAccountRestricted, "account restrictions prevent logon"
	case smb.StatusInvalidLogonHours:
		return statusLogonHours, "logon is not allowed at this time"
	case smb.StatusInvalidWorkstation:
		return statusWorkstationDenied, "logon is not allowed from this workstation"
	case smb.StatusPasswordExpired:
		return statusPasswordExpired, "password has expired"
	case smb.StatusAccountDisabled:
		return statusAccountDisabled, "account is disabled"
	case smb.StatusAccountExpired:
		return statusAccountExpired, "account has expired"
	case smb.StatusPasswordMustChange:
		return statusPasswordChange, "password must be changed"
	case smb.StatusAccountLockedOut:
		return statusAccountLocked, "account is locked out"
	}
	return statusUnset, ""
}

func connectionStatus(err, transportErr error, reachable bool) scanStatus {
	if reachable {
		if status, ok := errors.AsType[*smb.NTStatusError](err); ok {
			if status.Command == 0 {
				return statusNegotiateFailed
			}
			if failure, _ := authenticationFailure(err); failure != statusUnset {
				return failure
			}
			return statusSMBFailed
		}
		return operationStatus(err, transportErr, statusSMBFailed, statusSMBTimeout)
	}
	if errors.Is(err, context.Canceled) || errors.Is(transportErr, context.Canceled) {
		return statusCanceled
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return statusDNSFailed
	}
	// Windows sockets use WSAECONNREFUSED (10061), distinct from Go's
	// synthetic Windows syscall.ECONNREFUSED. Both remain typed errno checks.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10061)) {
		return statusConnectRefused
	}
	return operationStatus(err, transportErr, statusConnectFailed, statusConnectTimeout)
}

func enumerationStatus(enumerated smb.ShareEnumeration, err, transportErr error) scanStatus {
	if len(enumerated.Shares) > 0 {
		return statusEnumPartial
	}
	if enumerated.Failure != nil {
		// This failure was recorded before cleanup; a later cleanup timeout
		// must not turn an explicit enumeration denial into ENUM_TIMEOUT.
		err, transportErr = enumerated.Failure, nil
	}
	if accessDenied(err) {
		return statusEnumDenied
	}
	return operationStatus(err, transportErr, statusEnumFailed, statusEnumTimeout)
}
