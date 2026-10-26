package main

import (
	"bufio"
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

	"github.com/rivo/uniseg"
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

// lineOutputBuffer bounds retained output independently of the share count.
// Call endLine after each record: writes contain complete lines, even when one
// line exceeds the batch threshold. The buffer is reused between batches.
type lineOutputBuffer struct {
	bytes.Buffer
	out io.Writer
}

func (b *lineOutputBuffer) endLine() error {
	b.WriteByte('\n')
	if b.Len() >= 16<<10 {
		return b.flush()
	}
	return nil
}

func (b *lineOutputBuffer) flush() error {
	if b.Len() == 0 {
		return nil
	}
	n, err := b.out.Write(b.Bytes())
	if err := outputWriteError(n, b.Len(), err); err != nil {
		return err
	}
	b.Reset()
	return nil
}

func writeTextResult(out io.Writer, r Result) error {
	b := lineOutputBuffer{out: out}
	for fields := range textResultRows(r) {
		for i, field := range fields {
			if i > 0 {
				b.WriteByte('\t')
			}
			b.WriteString(field)
		}
		if err := b.endLine(); err != nil {
			return err
		}
	}
	return b.flush()
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
	if r.explicitGuest {
		guestFallback = "N/A"
	} else if r.GuestFallback {
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

// Fixed terminal-cell limits let each host print immediately without moving
// later columns. Zero leaves only the final hostname column unbounded.
var alignedWidths = [7]int{21, 20, 7, 7, 7, 18, 0}

func writeAlignedHeader(out io.Writer) error {
	return writeAlignedRow(out, [7]string{"TARGET_IP", "SHARE", "READ", "WRITE", "GUEST", "STATUS", "HOSTNAME"}, false)
}

func writeAlignedResult(out io.Writer, result Result, colored bool) error {
	i := 0
	for row := range textResultRows(result) {
		var share *ShareResult
		if i < len(result.Shares) {
			share = &result.Shares[i]
		}
		fields := [7]string{row[0], row[1], row[2], row[3], row[4], tableStatus(result, share), row[5]}
		if err := writeAlignedRow(out, fields, colored); err != nil {
			return err
		}
		i++
	}
	return nil
}

// alignedCell clips already escaped text by terminal width, reserving room for
// the ellipsis. Grapheme clusters and display escapes remain whole. TSV and
// JSON deliberately retain complete values for machine consumers.
func alignedCell(value string, limit int) (string, int) {
	value = displayText(value, -1)
	width := uniseg.StringWidth(value)
	if limit == 0 || width <= limit {
		return value, width
	}
	end, used, state := 0, 0, -1
	for remaining := value; remaining != ""; {
		var unit string
		var unitWidth int
		if n := displayEscapeLen(remaining); n > 0 {
			unit, remaining, unitWidth, state = remaining[:n], remaining[n:], n, -1
		} else {
			unit, remaining, unitWidth, state = uniseg.FirstGraphemeClusterInString(remaining, state)
		}
		if used+unitWidth > limit-1 {
			break
		}
		end += len(unit)
		used += unitWidth
	}
	return value[:end] + "…", used + 1
}

// The input was escaped by tsvCell/displayText. Recognizing those tokens keeps
// a clipped control character distinguishable from a partial escape sequence.
func displayEscapeLen(value string) int {
	if len(value) < 2 || value[0] != '\\' {
		return 0
	}
	n := 0
	switch value[1] {
	case '\\', 'n', 'r', 't':
		return 2
	case 'x':
		n = 4
	case 'u':
		n = 6
	case 'U':
		n = 10
	default:
		return 0
	}
	if len(value) < n {
		return 0
	}
	for _, digit := range []byte(value[2:n]) {
		if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f' || digit >= 'A' && digit <= 'F') {
			return 0
		}
	}
	return n
}

func writeAlignedRow(out io.Writer, fields [7]string, colored bool) error {
	const reset = "\x1b[0m"
	var padding [7]int
	var colors [7]string
	size := 1 // Final newline.
	for i, value := range fields {
		var width int
		value, width = alignedCell(value, alignedWidths[i])
		fields[i] = value
		if i < len(fields)-1 {
			padding[i] = alignedWidths[i] - width + 2
		}
		size += len(value) + padding[i]
		// Style only status columns, after measuring their visible widths.
		if colored && i >= 2 && i <= 4 {
			switch value {
			case "TRUE":
				colors[i] = "\x1b[32m"
			case "FALSE":
				colors[i] = "\x1b[31m"
			}
			if colors[i] != "" {
				size += len(colors[i]) + len(reset)
			}
		}
	}
	var b strings.Builder
	b.Grow(size)
	for i, value := range fields {
		b.WriteString(colors[i])
		b.WriteString(value)
		if colors[i] != "" {
			b.WriteString(reset)
		}
		b.WriteString(strings.Repeat(" ", padding[i]))
	}
	b.WriteByte('\n')
	_, err := writeOutputString(out, b.String())
	return err
}

// TSV status explanations go to stderr, leaving stdout as a stable data stream.
// The interactive table presents these outcomes in its STATUS column instead.
func writeTextDiagnostics(out io.Writer, r Result) error {
	b := lineOutputBuffer{out: out}
	target := displayText(r.Target, 256)
	if r.Error != "" {
		fmt.Fprintf(&b, "gosmb: %s: %s", target, displayText(r.Error, 500))
		if err := b.endLine(); err != nil {
			return err
		}
	}
	for _, s := range r.Shares {
		if s.Error != "" {
			fmt.Fprintf(&b, "gosmb: %s: %s: %s", target, displayText(s.Name, 256), displayText(s.Error, 500))
			if err := b.endLine(); err != nil {
				return err
			}
		}
	}
	if len(r.Shares) == 0 && r.Enumeration == "ok" {
		fmt.Fprintf(&b, "gosmb: %s: no shares returned", target)
		if err := b.endLine(); err != nil {
			return err
		}
	}
	return b.flush()
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
	if len(results) == 0 {
		_, err := writeOutputString(out, "[]\n")
		return err
	}
	// Encode one host at a time so a large scan does not need a second copy of
	// the full report. The caller still decides when the complete array is sent.
	buffered := bufio.NewWriterSize(checkedOutputWriter{out}, 16<<10)
	var host bytes.Buffer
	enc := json.NewEncoder(&host)
	enc.SetIndent("  ", "  ")
	var result Result
	for i := range results {
		result = results[i]
		if result.Shares == nil {
			// Normalize only the local copy, preserving caller-owned results.
			result.Shares = []ShareResult{}
		}
		host.Reset()
		if err := enc.Encode(&result); err != nil {
			return err
		}
		prefix := "[\n  "
		if i > 0 {
			prefix = ",\n  "
		}
		if _, err := buffered.WriteString(prefix); err != nil {
			return err
		}
		// Encode appends a newline. Array separators supply that newline after
		// its comma, retaining the same indentation as encoding the full slice.
		if _, err := buffered.Write(host.Bytes()[:host.Len()-1]); err != nil {
			return err
		}
	}
	if _, err := buffered.WriteString("\n]\n"); err != nil {
		return err
	}
	return buffered.Flush()
}
