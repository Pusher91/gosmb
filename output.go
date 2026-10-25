package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// displayText escapes terminal controls before optional truncation. A negative
// limit preserves the full value. Truncation never splits runes or escapes.
func displayText(s string, limit int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		var part string
		switch r {
		case '\n':
			part = `\n`
		case '\r':
			part = `\r`
		case '\t':
			part = `\t`
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
				if r <= 0xff {
					part = fmt.Sprintf(`\x%02x`, r)
				} else if r <= 0xffff {
					part = fmt.Sprintf(`\u%04x`, r)
				} else {
					part = fmt.Sprintf(`\U%08x`, r)
				}
			} else {
				part = string(r)
			}
		}
		partLen := len([]rune(part))
		if limit >= 0 && count+partLen > limit {
			b.WriteRune('…')
			break
		}
		b.WriteString(part)
		count += partLen
	}
	return b.String()
}

func redactResult(r Result, password string) Result {
	if password == "" {
		return r
	}
	redact := func(s string) string { return strings.ReplaceAll(s, password, "[REDACTED]") }
	r.Target, r.ServerIP, r.Error = redact(r.Target), redact(r.ServerIP), redact(r.Error)
	// Copy the slice before modifying it so backends and callers retain their
	// own result without exposing its raw text through this output path.
	r.Shares = append([]ShareResult(nil), r.Shares...)
	for i := range r.Shares {
		s := &r.Shares[i]
		s.Name, s.Type, s.Comment = redact(s.Name), redact(s.Type), redact(s.Comment)
		s.WriteBasis, s.Error = redact(s.WriteBasis), redact(s.Error)
	}
	return r
}

func writeTextHeader(out io.Writer) error {
	_, err := io.WriteString(out, "SMB_SERVER_IP\tSHARE\tREAD\tWRITE\tGUEST_FALLBACK\n")
	return err
}

// Each cell is one complete, untruncated field. Escape literal backslashes
// before control characters so a real tab differs from a literal backslash-t.
func tsvCell(value string) string {
	return displayText(strings.ReplaceAll(value, `\`, `\\`), -1)
}

func writeTextResult(out io.Writer, r Result) error {
	var b strings.Builder
	for _, fields := range textResultRows(r) {
		b.WriteString(strings.Join(fields[:], "\t"))
		b.WriteByte('\n')
	}
	_, err := io.WriteString(out, b.String())
	return err
}

func textResultRows(r Result) [][5]string {
	var rows [][5]string
	serverIP := r.ServerIP
	if serverIP == "" {
		serverIP = "UNKNOWN"
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
	row := func(share, read, write string) {
		fields := [5]string{serverIP, share, displayPermission(read), displayPermission(write), guestFallback}
		for i := range fields {
			fields[i] = tsvCell(fields[i])
		}
		rows = append(rows, fields)
	}
	if len(r.Shares) == 0 {
		if r.TimedOut {
			row("-", TimedOut, TimedOut)
		} else {
			row("-", Unknown, Unknown)
		}
	}
	for _, s := range r.Shares {
		row(s.Name, s.Read, s.Write)
	}
	return rows
}

// Fixed widths let every host print immediately without waiting for later
// share names. Long values continue on the next line without being truncated.
var alignedWidths = [5]int{39, 32, 7, 7, 14}

func writeAlignedHeader(out io.Writer) error {
	return writeAlignedRow(out, [5]string{"SMB_SERVER_IP", "SHARE", "READ", "WRITE", "GUEST_FALLBACK"})
}

func writeAlignedResult(out io.Writer, result Result) error {
	for _, row := range textResultRows(result) {
		if err := writeAlignedRow(out, row); err != nil {
			return err
		}
	}
	return nil
}

func writeAlignedRow(out io.Writer, fields [5]string) error {
	var remaining [5][]rune
	for i, field := range fields {
		remaining[i] = []rune(field)
	}
	var b strings.Builder
	for {
		var line strings.Builder
		more := false
		for i, value := range remaining {
			n := min(len(value), alignedWidths[i])
			line.WriteString(string(value[:n]))
			remaining[i] = value[n:]
			more = more || len(remaining[i]) > 0
			if i < len(fields)-1 {
				line.WriteString(strings.Repeat(" ", alignedWidths[i]-n+2))
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteByte('\n')
		if !more {
			break
		}
	}
	_, err := io.WriteString(out, b.String())
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
	_, err := io.WriteString(out, b.String())
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
	for i := range results {
		if results[i].Shares == nil {
			results[i].Shares = []ShareResult{}
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
