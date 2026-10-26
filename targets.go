package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Targets are materialized before scanning so progress has a fixed total and
// invalid input cannot start a partial scan. Bound both ranges and merged lists.
const maxTargets = 65536

func parsePort(value string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("invalid port")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid port")
	}
	return n, nil
}

func parseTarget(raw string) (Target, error) {
	bad := errors.New("invalid target: use a hostname, IP address, or host:port (bracket IPv6 with a port)")
	if raw == "" || !utf8.ValidString(raw) || strings.ContainsAny(raw, `/\?#@`) || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return Target{}, bad
	}
	host, port := raw, 445
	if strings.HasPrefix(raw, "[") {
		if strings.HasSuffix(raw, "]") {
			host = raw[1 : len(raw)-1]
		} else {
			var portString string
			var err error
			host, portString, err = net.SplitHostPort(raw)
			if err != nil {
				return Target{}, bad
			}
			port, err = parsePort(portString)
			if err != nil {
				return Target{}, bad
			}
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return Target{}, bad
		}
		host = addr.String()
	} else if addr, err := netip.ParseAddr(raw); err == nil {
		host = addr.String()
	} else if strings.Contains(raw, ":") {
		var portString string
		var err error
		host, portString, err = net.SplitHostPort(raw)
		if err != nil {
			return Target{}, bad
		}
		port, err = parsePort(portString)
		if err != nil {
			return Target{}, bad
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if zone := addr.Zone(); zone != "" && strings.IndexFunc(zone, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-", r))
		}) >= 0 {
			return Target{}, bad
		}
		host = addr.String()
	} else {
		// A final dot is the DNS root label: retain it in the target so an
		// absolute name cannot become subject to resolver search suffixes.
		labels := strings.TrimSuffix(host, ".")
		if len(labels) == 0 || len(labels) > 253 || strings.Contains(labels, ":") {
			return Target{}, bad
		}
		if strings.Contains(labels, ".") && strings.IndexFunc(labels, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) == -1 {
			return Target{}, bad
		}
		for _, label := range strings.Split(labels, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Target{}, bad
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return Target{}, bad
				}
			}
		}
	}
	return Target{Host: host, Port: port}, nil
}

func readTargets(ctx context.Context, path string) ([]Target, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || strings.Contains(path, "://") {
		return nil, errors.New("host-list file must be a local path, not a URL or UNC path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("host-list path must be a readable regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open host-list file")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("host-list path must be a readable regular file")
	}
	return parseTargetList(ctx, f)
}

func parseTargetList(ctx context.Context, r io.Reader) ([]Target, error) {
	var targets []Target
	var seen map[Target]struct{}
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !scanner.Scan() {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("host-list line %d is not valid UTF-8", lineNumber)
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		expanded, err := parseTargetSpec(line)
		if err != nil {
			return nil, fmt.Errorf("invalid target at host-list line %d: %w", lineNumber, err)
		}
		if seen == nil {
			// Reuse the first expansion's storage. Deduplication only appends
			// at or before the element being read, so the input stays intact.
			seen = make(map[Target]struct{}, len(expanded))
			targets = expanded[:0]
		}
		targets, err = appendUniqueTargets(targets, seen, expanded)
		if err != nil {
			return nil, fmt.Errorf("host-list line %d: %w", lineNumber, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scanner.Err() != nil {
		return nil, errors.New("cannot read host-list file (read error or line too long)")
	}
	if len(targets) == 0 {
		return nil, errors.New("host-list file contains no targets")
	}
	return targets, nil
}

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
