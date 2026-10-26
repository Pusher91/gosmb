package main

import (
	"fmt"
	"strings"
)

type statusDefinition struct {
	status             scanStatus
	label, description string
}

// Keep table labels and help descriptions together, in their help order.
// The status identifiers remain independent of this presentation order.
var statusCatalog = [...]statusDefinition{
	{statusOK, "OK", "Check completed; READ/WRITE show the permissions"},
	{statusNoShares, "NO_SHARES", "Share enumeration completed but returned no shares"},
	{statusDNSFailed, "DNS_FAILED", "Hostname lookup failed"},
	{statusConnectFailed, "CONNECT_FAILED", "Could not establish a TCP connection"},
	{statusConnectRefused, "CONNECT_REFUSED", "TCP connection was refused"},
	{statusConnectTimeout, "CONNECT_TIMEOUT", "TCP connection timed out"},
	{statusNegotiateFailed, "NEGOTIATE_FAILED", "Server rejected SMB negotiation"},
	{statusSMBFailed, "SMB_FAILED", "SMB connection or protocol exchange failed"},
	{statusSMBTimeout, "SMB_TIMEOUT", "SMB negotiation or session setup timed out"},
	{statusAuthFailed, "AUTH_FAILED", "Server rejected the login"},
	{statusAccountLocked, "ACCOUNT_LOCKED", "Account is locked out"},
	{statusAccountDisabled, "ACCOUNT_DISABLED", "Account is disabled"},
	{statusAccountExpired, "ACCOUNT_EXPIRED", "Account has expired"},
	{statusAccountRestricted, "ACCOUNT_RESTRICTED", "Account restrictions prevented logon"},
	{statusPasswordExpired, "PASSWORD_EXPIRED", "Password has expired"},
	{statusPasswordChange, "PASSWORD_CHANGE", "Password must be changed before logon"},
	{statusLogonHours, "LOGON_HOURS", "Logon is not allowed at this time"},
	{statusWorkstationDenied, "WORKSTATION_DENIED", "Logon is not allowed from this workstation"},
	{statusAuthUnverified, "AUTH_UNVERIFIED", "Session was anonymous or its identity could not be verified"},
	{statusGuestMismatch, "GUEST_MISMATCH", "Server did not establish a Guest session for --guest"},
	{statusEnumDenied, "ENUM_DENIED", "Access to the share list was denied"},
	{statusEnumFailed, "ENUM_FAILED", "Could not retrieve the share list"},
	{statusEnumPartial, "ENUM_PARTIAL", "Share list is incomplete; discovered shares are shown"},
	{statusEnumTimeout, "ENUM_TIMEOUT", "Retrieving the share list timed out"},
	{statusCheckFailed, "CHECK_FAILED", "Permission check failed or required metadata was unavailable"},
	{statusCheckTimeout, "CHECK_TIMEOUT", "Share permission check timed out"},
	{statusCleanupFailed, "CLEANUP_FAILED", "Closing a handle, share connection, or session failed"},
	{statusCleanupTimeout, "CLEANUP_TIMEOUT", "Closing a handle, share connection, or session timed out"},
	{statusScanTimeout, "SCAN_TIMEOUT", "Host time limit expired after the recorded checks completed"},
	{statusCanceled, "CANCELED", "Scan was canceled"},
}

var statusLabels = func() [statusCount]string {
	var labels [statusCount]string
	for _, definition := range statusCatalog {
		labels[definition.status] = definition.label
	}
	return labels
}()

func statusHelp() string {
	var b strings.Builder
	for _, definition := range statusCatalog {
		fmt.Fprintf(&b, "  %-20s%s\n", definition.label, definition.description)
	}
	return b.String()
}
