package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// displayText escapes terminal controls before optional truncation. A negative
// limit preserves the full value. Truncation never splits runes or escapes.
func displayText(s string, limit int) string {
	// Ordinary output cells need no copy. Most share names and every fixed
	// permission cell take this path; escaping still handles all Unicode controls.
	if (limit < 0 || utf8.RuneCountInString(s) <= limit) && utf8.ValidString(s) && strings.IndexFunc(s, needsDisplayEscape) < 0 {
		return s
	}
	var b strings.Builder
	capacity := len(s)
	if limit >= 0 {
		capacity = min(capacity, limit)
	}
	b.Grow(capacity)
	var escape [10]byte // Longest escape: \U followed by eight hexadecimal digits.
	escape[0] = '\\'
	count := 0
	for _, r := range s {
		width := 1
		switch r {
		case '\n':
			escape[1], width = 'n', 2
		case '\r':
			escape[1], width = 'r', 2
		case '\t':
			escape[1], width = 't', 2
		default:
			if needsDisplayEscape(r) {
				if r <= 0xff {
					escape[1], width = 'x', 4
				} else if r <= 0xffff {
					escape[1], width = 'u', 6
				} else {
					escape[1], width = 'U', 10
				}
				value := uint32(r)
				for i := width - 1; i >= 2; i-- {
					escape[i] = "0123456789abcdef"[value&15]
					value >>= 4
				}
			}
		}
		if limit >= 0 && width > limit-count {
			b.WriteRune('…')
			break
		}
		if width == 1 {
			b.WriteRune(r)
		} else {
			b.Write(escape[:width])
		}
		count += width
	}
	return b.String()
}

func needsDisplayEscape(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

// A short successful write must not make a truncated report look complete.
func writeOutputString(out io.Writer, text string) (int, error) {
	n, err := io.WriteString(out, text)
	return n, outputWriteError(n, len(text), err)
}

func outputWriteError(written, expected int, err error) error {
	if err == nil && written != expected {
		return io.ErrShortWrite
	}
	return err
}

type checkedOutputWriter struct{ io.Writer }

func (w checkedOutputWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	return n, outputWriteError(n, len(data), err)
}

func redactResult(r Result, password string) Result {
	if password == "" {
		return r
	}
	redact := func(s string) string { return strings.ReplaceAll(s, password, "[REDACTED]") }
	r.Target, r.ServerIP, r.Error = redact(r.Target), redact(r.ServerIP), redact(r.Error)
	// Most results contain no credential text. Copy the share slice only when
	// redaction changes a field, preserving caller ownership in either case.
	copied := false
	for i, s := range r.Shares {
		s.Name, s.Type, s.Comment = redact(s.Name), redact(s.Type), redact(s.Comment)
		s.WriteBasis, s.Error = redact(s.WriteBasis), redact(s.Error)
		if s != r.Shares[i] {
			if !copied {
				r.Shares = append([]ShareResult(nil), r.Shares...)
				copied = true
			}
			r.Shares[i] = s
		}
	}
	return r
}

func writeTextHeader(out io.Writer) error {
	_, err := writeOutputString(out, "TARGET_IP\tSHARE\tREAD\tWRITE\tGUEST\tHOSTNAME\n")
	return err
}

// Each cell is one complete, untruncated field. Escape literal backslashes
// before control characters so a real tab differs from a literal backslash-t.
func tsvCell(value string) string {
	return displayText(strings.ReplaceAll(value, `\`, `\\`), -1)
}

func writeTextResult(out io.Writer, r Result) error {
	// Bound retained output independently of the host's share count. Reuse the
	// buffer, and flush only between rows so each write contains whole records.
	var b bytes.Buffer
	flush := func() error {
		n, err := out.Write(b.Bytes())
		if err := outputWriteError(n, b.Len(), err); err != nil {
			return err
		}
		b.Reset()
		return nil
	}
	for fields := range textResultRows(r) {
		for i, field := range fields {
			if i > 0 {
				b.WriteByte('\t')
			}
			b.WriteString(field)
		}
		b.WriteByte('\n')
		if b.Len() >= 16<<10 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return flush()
}

// Yield one row at a time so a host's entire escaped share list is not retained
// alongside its rendered output. The endpoint and hostname are shared by rows.
func textResultRows(r Result) iter.Seq[[6]string] {
	targetIP, hostname := r.ServerIP, "-"
	host, port, splitErr := net.SplitHostPort(r.Target)
	if splitErr != nil {
		host = r.Target
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err == nil {
			if targetIP == "" {
				targetIP = host
			}
		} else {
			hostname = host
		}
	}
	if targetIP == "" {
		targetIP = "UNKNOWN"
	}
	if splitErr == nil {
		targetIP = net.JoinHostPort(targetIP, port)
	}
	guestFallback := "FALSE"
	if r.GuestFallback {
		guestFallback = "TRUE"
	} else if r.TimedOut && !r.authenticationComplete {
		switch r.Authentication {
		case "", "not_attempted", "error", Unknown, TimedOut:
			guestFallback = "TIMEOUT"
		}
	}
	base := [6]string{tsvCell(targetIP), "", "", "", guestFallback, tsvCell(hostname)}
	return func(yield func([6]string) bool) {
		fields := base
		if len(r.Shares) == 0 {
			permission := Unknown
			// A timeout during cleanup does not erase a completed empty list
			// or enumeration denial. Only unanswered enumeration gets TIMEOUT.
			if r.TimedOut && !r.enumerationComplete && r.Enumeration != "ok" && r.Enumeration != "denied" {
				permission = TimedOut
			}
			fields[1], fields[2], fields[3] = "-", displayPermission(permission), displayPermission(permission)
			yield(fields)
			return
		}
		for _, share := range r.Shares {
			fields[1] = tsvCell(share.Name)
			fields[2] = tsvCell(displayPermission(share.Read))
			fields[3] = tsvCell(displayPermission(share.Write))
			if !yield(fields) {
				return
			}
		}
	}
}

// Minimum widths let every host print immediately. The unbounded hostname
// column comes last; no field is wrapped or truncated into extra result lines.
var alignedWidths = [6]int{47, 32, 7, 7, 7, 0}

func writeAlignedHeader(out io.Writer) error {
	return writeAlignedRow(out, [6]string{"TARGET_IP", "SHARE", "READ", "WRITE", "GUEST", "HOSTNAME"})
}

func writeAlignedResult(out io.Writer, result Result) error {
	for row := range textResultRows(result) {
		if err := writeAlignedRow(out, row); err != nil {
			return err
		}
	}
	return nil
}

func writeAlignedRow(out io.Writer, fields [6]string) error {
	var padding [6]int
	size := 1 // Final newline.
	for i, value := range fields {
		if i < len(fields)-1 {
			padding[i] = max(0, alignedWidths[i]-utf8.RuneCountInString(value)) + 2
		}
		size += len(value) + padding[i]
	}
	var b strings.Builder
	b.Grow(size)
	for i, value := range fields {
		b.WriteString(value)
		b.WriteString(strings.Repeat(" ", padding[i]))
	}
	b.WriteByte('\n')
	_, err := writeOutputString(out, b.String())
	return err
}

// Status explanations go to stderr, leaving stdout as a stable TSV stream.
func writeTextDiagnostics(out io.Writer, r Result) error {
	var b strings.Builder
	target := displayText(r.Target, 256)
	if r.Error != "" {
		fmt.Fprintf(&b, "gosmb: %s: %s\n", target, displayText(r.Error, 500))
	}
	for _, s := range r.Shares {
		if s.Error != "" {
			fmt.Fprintf(&b, "gosmb: %s: %s: %s\n", target, displayText(s.Name, 256), displayText(s.Error, 500))
		}
	}
	if len(r.Shares) == 0 && r.Enumeration == "ok" {
		fmt.Fprintf(&b, "gosmb: %s: no shares returned\n", target)
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := writeOutputString(out, b.String())
	return err
}

func displayPermission(value string) string {
	switch value {
	case Allowed:
		return "TRUE"
	case Denied:
		return "FALSE"
	case "", Unknown:
		return "UNKNOWN"
	case NotApplicable:
		return "N/A"
	case TimedOut:
		return "TIMEOUT"
	}
	return value
}

func writeJSONResults(out io.Writer, results []Result) error {
	if results == nil {
		results = []Result{}
	}
	copied := false
	for i := range results {
		if results[i].Shares == nil {
			// Normalize the JSON shape without mutating the caller's results.
			if !copied {
				results = append([]Result(nil), results...)
				copied = true
			}
			results[i].Shares = []ShareResult{}
		}
	}
	enc := json.NewEncoder(checkedOutputWriter{out})
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
