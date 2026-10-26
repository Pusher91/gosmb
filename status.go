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
	statusCount
)

var statusLabels = [...]string{
	statusOK:                "OK",
	statusAuthFailed:        "AUTH_FAILED",
	statusAccountLocked:     "ACCOUNT_LOCKED",
	statusAccountDisabled:   "ACCOUNT_DISABLED",
	statusPasswordExpired:   "PASSWORD_EXPIRED",
	statusPasswordChange:    "PASSWORD_CHANGE",
	statusAccountExpired:    "ACCOUNT_EXPIRED",
	statusAccountRestricted: "ACCOUNT_RESTRICTED",
	statusLogonHours:        "LOGON_HOURS",
	statusWorkstationDenied: "WORKSTATION_DENIED",
	statusConnectFailed:     "CONNECT_FAILED",
	statusConnectRefused:    "CONNECT_REFUSED",
	statusConnectTimeout:    "CONNECT_TIMEOUT",
	statusDNSFailed:         "DNS_FAILED",
	statusSMBFailed:         "SMB_FAILED",
	statusSMBTimeout:        "SMB_TIMEOUT",
	statusNegotiateFailed:   "NEGOTIATE_FAILED",
	statusEnumDenied:        "ENUM_DENIED",
	statusEnumFailed:        "ENUM_FAILED",
	statusEnumPartial:       "ENUM_PARTIAL",
	statusEnumTimeout:       "ENUM_TIMEOUT",
	statusCheckFailed:       "CHECK_FAILED",
	statusCheckTimeout:      "CHECK_TIMEOUT",
	statusCleanupFailed:     "CLEANUP_FAILED",
	statusCleanupTimeout:    "CLEANUP_TIMEOUT",
	statusCanceled:          "CANCELED",
	statusNoShares:          "NO_SHARES",
	statusAuthUnverified:    "AUTH_UNVERIFIED",
	statusGuestMismatch:     "GUEST_MISMATCH",
}

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
	if result.cleanupStatus != statusUnset {
		return statusLabels[result.cleanupStatus]
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

func typedTimeout(err error) bool {
	var networkError net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout()
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
	if errors.Is(transportErr, context.Canceled) {
		return statusCanceled
	}
	if typedTimeout(transportErr) {
		return timeout
	}
	return failed
}

func connectionStatus(err, transportErr error, reachable bool) scanStatus {
	if reachable {
		var status *smb.NTStatusError
		if errors.As(err, &status) {
			if status.Command == 0 {
				return statusNegotiateFailed
			}
			if status.Command == smb.SessionSetupCommand {
				switch status.Status {
				case smb.StatusLogonFailure, smb.StatusAccessDenied:
					return statusAuthFailed
				case smb.StatusAccountLockedOut:
					return statusAccountLocked
				case smb.StatusAccountDisabled:
					return statusAccountDisabled
				case smb.StatusPasswordExpired:
					return statusPasswordExpired
				case smb.StatusPasswordMustChange:
					return statusPasswordChange
				case smb.StatusAccountExpired:
					return statusAccountExpired
				case smb.StatusAccountRestriction:
					return statusAccountRestricted
				case smb.StatusInvalidLogonHours:
					return statusLogonHours
				case smb.StatusInvalidWorkstation:
					return statusWorkstationDenied
				}
			}
			return statusSMBFailed
		}
		return operationStatus(err, transportErr, statusSMBFailed, statusSMBTimeout)
	}
	if errors.Is(err, context.Canceled) || errors.Is(transportErr, context.Canceled) {
		return statusCanceled
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
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
