package main

import (
	"net"
	"strconv"
	"time"
)

// Options contains only explicit credentials. No credential caches are consulted.
type Options struct {
	Username    string
	Password    string
	Domain      string
	Guest       bool
	Timeout     time.Duration
	HostTimeout time.Duration
}

type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

const (
	Allowed       = "allowed"
	Denied        = "denied"
	Unknown       = "unknown"
	TimedOut      = "timeout"
	NotApplicable = "n/a"
)

type Result struct {
	Target         string        `json:"target"`
	ServerIP       string        `json:"server_ip"`
	Reachable      bool          `json:"reachable"`
	Authentication string        `json:"authentication"`
	GuestFallback  bool          `json:"guest_fallback"`
	Enumeration    string        `json:"enumeration"`
	Shares         []ShareResult `json:"shares"`
	TimedOut       bool          `json:"timed_out,omitempty"`
	Error          string        `json:"error,omitempty"`

	// Explicit guest mode makes credential fallback inapplicable in text output,
	// including when the connection or authentication never completes.
	explicitGuest bool

	// A later timeout must not replace a result already obtained from the
	// server, including an error unrelated to the timeout.
	authenticationComplete bool
	enumerationComplete    bool

	// Interactive-table outcomes are recorded at the failing operation. They
	// deliberately stay separate from public diagnostics and serialized data.
	status scanStatus
	// Cleanup or a final time-budget outcome, below primary host/share failures.
	completionStatus scanStatus
}

type ShareResult struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Comment    string `json:"comment,omitempty"`
	Accessible string `json:"accessible"`
	Read       string `json:"read_root"`
	Write      string `json:"write_root"`
	WriteBasis string `json:"write_basis"`
	Error      string `json:"error,omitempty"`

	// A completed probe may legitimately have UNKNOWN metadata. Keep that
	// distinct from an unanswered probe when the host's deadline expires.
	probeComplete bool
	status        scanStatus
}
