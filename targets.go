package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Targets are materialized before scanning so progress has a fixed total and
// invalid input cannot start a partial scan. Bound both ranges and merged lists.
const maxTargets = 65536

// parseTargetSpec accepts one endpoint or an explicit CIDR range. Every address
// in a prefix is included, including IPv4 network and broadcast addresses.
func parseTargetSpec(raw string) ([]Target, error) {
	if !strings.ContainsRune(raw, '/') {
		target, err := parseTarget(raw)
		if err != nil {
			return nil, err
		}
		return []Target{target}, nil
	}
	bad := errors.New("invalid CIDR target: use IPv4/prefix[:port] or IPv6/prefix (bracket IPv6 CIDRs with a port)")
	prefixText, port := raw, 445
	bracketed := strings.HasPrefix(raw, "[")
	if bracketed {
		var portText string
		var err error
		prefixText, portText, err = net.SplitHostPort(raw)
		if err != nil {
			return nil, bad
		}
		port, err = parsePort(portText)
		if err != nil {
			return nil, bad
		}
	} else {
		address, suffix, _ := strings.Cut(raw, "/")
		if bits, portText, hasPort := strings.Cut(suffix, ":"); hasPort {
			if strings.ContainsRune(address, ':') {
				return nil, bad
			}
			var err error
			port, err = parsePort(portText)
			if err != nil {
				return nil, bad
			}
			prefixText = address + "/" + bits
		}
	}
	prefix, err := netip.ParsePrefix(prefixText)
	if err != nil || (bracketed && !prefix.Addr().Is6()) {
		return nil, bad
	}
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR range exceeds the limit of %d addresses", maxTargets)
	}
	count := 1 << hostBits
	targets := make([]Target, 0, count)
	address := prefix.Masked().Addr()
	for range count {
		targets = append(targets, Target{Host: address.String(), Port: port})
		address = address.Next()
	}
	return targets, nil
}

// appendUniqueTargets preserves input order across overlapping ranges and
// individual endpoints. Parsed targets already have canonical IP spellings;
// use their host and port directly instead of formatting another endpoint string.
func appendUniqueTargets(targets []Target, seen map[Target]struct{}, added []Target) ([]Target, error) {
	for _, target := range added {
		endpoint := target
		if addr, err := netip.ParseAddr(target.Host); err == nil {
			// IPv4 and its unscoped mapped spelling dial the same endpoint.
			// Normalize only the key so output retains the first supplied form.
			if addr.Is4In6() && addr.Zone() == "" {
				endpoint.Host = addr.Unmap().String()
			}
			// IPv6 zone identifiers name local interfaces and are case-sensitive.
			// Retain them exactly to keep distinct interfaces separate.
		} else {
			endpoint.Host = strings.ToLower(target.Host)
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		if len(targets) >= maxTargets {
			return nil, fmt.Errorf("target list exceeds the limit of %d unique endpoints", maxTargets)
		}
		seen[endpoint] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}
