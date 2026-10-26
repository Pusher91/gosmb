package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func BenchmarkTextOutput(b *testing.B) {
	result := Result{Target: "fileserver.example.test:445", ServerIP: "192.0.2.25", Authentication: "authenticated", Enumeration: "ok"}
	for range 1000 {
		result.Shares = append(result.Shares, ShareResult{Name: "documents and archives", Read: Allowed, Write: Denied})
	}
	for _, tc := range []struct {
		name  string
		write func(io.Writer, Result) error
	}{{"TSV", writeTextResult}, {"aligned", writeAlignedResult}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := tc.write(io.Discard, result); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRedactResult(b *testing.B) {
	result := Result{Target: "server:445", Shares: make([]ShareResult, 1000)}
	for i := range result.Shares {
		result.Shares[i] = ShareResult{Name: "documents", Type: "disk", Comment: "shared files", Read: Allowed, Write: Denied}
	}
	b.ReportAllocs()
	for b.Loop() {
		redactResult(result, "synthetic-password")
	}
}

func BenchmarkDisplayText(b *testing.B) {
	for _, tc := range []struct {
		name, input string
		limit       int
	}{
		{"plain", "documents and archives", -1},
		{"unicode", "共有ドキュメント", -1},
		{"controls", strings.Repeat("\x00\x1b\u202e\U000e0001", 64), -1},
		{"mixed", strings.Repeat("documents ", 25) + "\x00" + strings.Repeat("資料", 25), -1},
		{"diagnostic", strings.Repeat("server rejected operation: ", 40), 500},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				displayText(tc.input, tc.limit)
			}
		})
	}
}

func TestDisplayTextEscapingAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		input string
		limit int
		want  string
	}{
		{"\n\r\t\x00\x1b\x7f\u0080\u00ad\u200b\u202e\u2028\u2029\ufeff\U000e0001", -1, `\n\r\t\x00\x1b\x7f\x80\xad\u200b\u202e\u2028\u2029\ufeff\U000e0001`},
		{"a\nb", 3, "a\\n…"},
		{"a\nb", 2, "a…"},
		{"αβγ", 2, "αβ…"},
		{"a\x00", 4, "a…"},
		{"a\x00", 5, `a\x00`},
		{"\u202e", 6, `\u202e`},
		{"\U000e0001", 9, "…"},
		{"\U000e0001", 10, `\U000e0001`},
		{"", 0, ""},
		{"x", 0, "…"},
		{"\xffx", -1, "�x"},
		{"\xffx", 1, "�…"},
	} {
		if got := displayText(tc.input, tc.limit); got != tc.want {
			t.Errorf("displayText(%q, %d) = %q; want %q", tc.input, tc.limit, got, tc.want)
		}
	}
}

func BenchmarkLargeTSVOutput(b *testing.B) {
	result := Result{Target: "fileserver.example.test:445", ServerIP: "192.0.2.25", Shares: make([]ShareResult, 16384)}
	for i := range result.Shares {
		result.Shares[i] = ShareResult{Name: "documents and archives", Read: Allowed, Write: Denied}
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := writeTextResult(io.Discard, result); err != nil {
			b.Fatal(err)
		}
	}
}

func parseTestTSV(t *testing.T, output string) [][]string {
	t.Helper()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("TSV must end with a record newline: %q", output)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		cells := strings.Split(line, "\t")
		if len(cells) != 6 {
			t.Fatalf("expected exactly six tab-separated cells, without banners or blank lines: %q", line)
		}
		rows = append(rows, cells)
	}
	return rows
}

func TestTSVPreservesFullEscapedCells(t *testing.T) {
	longName := "長い share " + strings.Repeat("é", 512)
	cases := []struct{ name, escaped string }{
		{"a share with spaces", "a share with spaces"},
		{longName, longName},
		{`literal\n`, `literal\\n`},
		{"literal\n", `literal\n`},
		{"tab\tline\nreturn\rslash\\escape\x1b[2J\u202e", `tab\tline\nreturn\rslash\\escape\x1b[2J\u202e`},
	}
	result := Result{Target: "fileserver:445", ServerIP: "192.0.2.25", Reachable: true, Authentication: "authenticated", Enumeration: "ok"}
	for _, c := range cases {
		result.Shares = append(result.Shares, ShareResult{Name: c.name, Accessible: Allowed, Read: Allowed, Write: Denied, Comment: "do not put comments in TSV", WriteBasis: "metadata details"})
	}
	var out, diagnostics bytes.Buffer
	if err := writeTextResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if err := writeTextDiagnostics(&diagnostics, result); err != nil {
		t.Fatal(err)
	}
	rows := parseTestTSV(t, out.String())
	if len(rows) != len(cases) || diagnostics.Len() != 0 {
		t.Fatalf("successful output has extra records or diagnostics: %q %q", out.String(), diagnostics.String())
	}
	for i, row := range rows {
		if row[0] != "192.0.2.25:445" || row[1] != cases[i].escaped || strings.Join(row[2:], "|") != "TRUE|FALSE|FALSE|fileserver" {
			t.Errorf("row %d lost data or cell boundaries: %#v", i, row)
		}
	}
}

func TestOutputEscapesControlsInCellsAndDiagnostics(t *testing.T) {
	bad := "value\x1b[2J\t\n\u202e"
	result := Result{Target: bad, ServerIP: bad, Reachable: true, Authentication: bad, Enumeration: bad, Error: bad, Shares: []ShareResult{{Name: bad, Accessible: bad, Read: bad, Write: bad, Error: bad}}}
	var out, diagnostics bytes.Buffer
	if err := writeTextResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if err := writeTextDiagnostics(&diagnostics, result); err != nil {
		t.Fatal(err)
	}
	rows := parseTestTSV(t, out.String())
	if len(rows) != 1 || rows[0][0] != `value\x1b[2J\t\n\u202e` || rows[0][1] != `value\x1b[2J\t\n\u202e` || rows[0][5] != `value\x1b[2J\t\n\u202e` {
		t.Fatalf("untrusted cells were not escaped: %#v", rows)
	}
	if strings.ContainsAny(out.String()+diagnostics.String(), "\x1b\r\u202e") || strings.ContainsRune(diagnostics.String(), '\t') {
		t.Fatalf("terminal controls escaped into output: %q %q", out.String(), diagnostics.String())
	}
	if !strings.Contains(diagnostics.String(), `value\x1b[2J\t\n\u202e`) {
		t.Fatalf("error details missing from stderr diagnostics: %q", diagnostics.String())
	}
}

func TestRedactResultDoesNotModifyBackendResult(t *testing.T) {
	secret := "sensitive-password"
	original := Result{Target: "server", ServerIP: secret, Error: secret, Shares: []ShareResult{{Name: secret, Comment: "contains " + secret, Type: secret, Error: secret, WriteBasis: secret}}}
	got := redactResult(original, secret)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || original.Shares[0].Name != secret || original.Error != secret {
		t.Fatal("redaction leaked a secret or mutated original result")
	}
	if redactResult(original, "").Error != secret {
		t.Fatal("empty password should not modify output")
	}
}

func TestRedactResultPreservesSharesAroundLaterMatches(t *testing.T) {
	original := Result{Shares: []ShareResult{
		{Name: "unrelated", Read: Allowed},
		{Name: "contains-secret", Comment: "secret"},
		{Name: "another", Error: "secret failure"},
		{Name: "unchanged", Write: Denied},
	}}
	got := redactResult(original, "secret")
	if got.Shares[0] != original.Shares[0] || got.Shares[3] != original.Shares[3] ||
		got.Shares[1].Name != "contains-[REDACTED]" || got.Shares[1].Comment != "[REDACTED]" || got.Shares[2].Error != "[REDACTED] failure" {
		t.Fatalf("redaction lost or leaked share fields: %+v", got.Shares)
	}
	if original.Shares[1].Name != "contains-secret" || original.Shares[1].Comment != "secret" || original.Shares[2].Error != "secret failure" {
		t.Fatal("redaction modified the caller's shares")
	}
}

func TestJSONOutputIsArrayAndPreservesData(t *testing.T) {
	var out bytes.Buffer
	if err := writeJSONResults(&out, nil); err != nil || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("empty JSON array failed: %q %v", out.String(), err)
	}
	out.Reset()
	input := []Result{{Target: "first", ServerIP: "192.0.2.1", Authentication: "guest", GuestFallback: true, Enumeration: "ok", Shares: []ShareResult{{Name: "bad\x1b[2J\n\t", Read: Allowed, Write: Denied, Accessible: Unknown}}}, {Target: "second"}}
	if err := writeJSONResults(&out, input); err != nil {
		t.Fatal(err)
	}
	if input[1].Shares != nil {
		t.Fatal("JSON encoding mutated the caller's result")
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("raw escape control emitted in JSON")
	}
	var decoded []Result
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Target != "first" || decoded[1].Target != "second" || decoded[0].Shares[0].Name != input[0].Shares[0].Name || decoded[1].Shares == nil || decoded[0].ServerIP != "192.0.2.1" || !decoded[0].GuestFallback || decoded[1].GuestFallback {
		t.Fatalf("JSON lost data/order or returned null shares: %#v", decoded)
	}
	if share := decoded[0].Shares[0]; share.Read != Allowed || share.Write != Denied || share.Accessible != Unknown {
		t.Fatalf("TSV display values leaked into JSON: %#v", share)
	}
}

type shortOutputWriter struct{}

func (shortOutputWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestOutputRejectsShortWrites(t *testing.T) {
	result := Result{Target: "server:445", Error: "test diagnostic", Shares: []ShareResult{{Name: "data", Read: Allowed, Write: Denied}}}
	for _, tc := range []struct {
		name  string
		write func(io.Writer) error
	}{
		{"TSV header", writeTextHeader},
		{"aligned header", writeAlignedHeader},
		{"TSV result", func(out io.Writer) error { return writeTextResult(out, result) }},
		{"aligned result", func(out io.Writer) error { return writeAlignedResult(out, result) }},
		{"diagnostics", func(out io.Writer) error { return writeTextDiagnostics(out, result) }},
		{"JSON", func(out io.Writer) error { return writeJSONResults(out, []Result{result}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.write(shortOutputWriter{}); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("truncated output was reported as successful: %v", err)
			}
		})
	}
}

type outputWriteFunc func([]byte) (int, error)

func (f outputWriteFunc) Write(data []byte) (int, error) { return f(data) }

func TestTSVBatchesCompleteRowsWithoutTruncation(t *testing.T) {
	result := Result{Target: "server:445", ServerIP: "192.0.2.25", Shares: make([]ShareResult, 1000)}
	for i := range result.Shares {
		result.Shares[i] = ShareResult{Name: fmt.Sprintf("share-%04d", i), Read: Allowed, Write: Denied}
	}
	// A single row may exceed the batch threshold and must remain intact.
	result.Shares[500].Name = strings.Repeat("é", 20000) + "\tend"
	var combined bytes.Buffer
	writes := 0
	out := outputWriteFunc(func(data []byte) (int, error) {
		writes++
		parseTestTSV(t, string(data))
		if len(data) > 64<<10 {
			t.Fatalf("output accumulated beyond one batch plus its final row: %d bytes", len(data))
		}
		return combined.Write(data)
	})
	if err := writeTextResult(out, result); err != nil {
		t.Fatal(err)
	}
	if writes < 2 {
		t.Fatal("large host was retained in one output buffer")
	}
	rows := parseTestTSV(t, combined.String())
	if len(rows) != len(result.Shares) {
		t.Fatalf("lost or duplicated rows: got %d, want %d", len(rows), len(result.Shares))
	}
	for i, row := range rows {
		if row[1] != tsvCell(result.Shares[i].Name) || strings.Join(row[2:], "|") != "TRUE|FALSE|FALSE|server" {
			t.Fatalf("row %d lost its name, order, or permission cells", i)
		}
	}
}

func TestTSVStopsAfterFailedBatch(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "write_error"
		if short {
			name = "short_write"
		}
		t.Run(name, func(t *testing.T) {
			result := Result{Target: "server:445", Shares: make([]ShareResult, 2000)}
			for i := range result.Shares {
				result.Shares[i] = ShareResult{Name: "documents and archives", Read: Allowed, Write: Denied}
			}
			writes := 0
			var complete bytes.Buffer
			out := outputWriteFunc(func(data []byte) (int, error) {
				writes++
				if writes == 1 {
					return complete.Write(data)
				}
				if short {
					return len(data) / 2, nil
				}
				return 0, io.ErrClosedPipe
			})
			wantErr := io.ErrClosedPipe
			if short {
				wantErr = io.ErrShortWrite
			}
			if err := writeTextResult(out, result); !errors.Is(err, wantErr) {
				t.Fatalf("failed batch error = %v; want %v", err, wantErr)
			}
			if writes != 2 {
				t.Fatalf("writes = %d; expected one completed batch followed by the failure", writes)
			}
			if rows := parseTestTSV(t, complete.String()); len(rows) >= len(result.Shares) {
				t.Fatal("failed batch did not retain earlier partial results")
			}
		})
	}
}

func TestTSVRepeatsEndpointAndGuestFallbackForEveryShare(t *testing.T) {
	r := Result{Target: "fileserver:445", ServerIP: "192.0.2.25", Reachable: true, Authentication: "guest", GuestFallback: true, Enumeration: "ok", Shares: []ShareResult{
		{Name: "public", Accessible: Allowed, Read: Allowed, Write: Denied},
		{Name: "private", Accessible: Denied, Read: Denied, Write: Unknown},
		{Name: "IPC$", Accessible: Allowed, Read: NotApplicable, Write: NotApplicable},
	}}
	var out bytes.Buffer
	if err := writeTextResult(&out, r); err != nil {
		t.Fatal(err)
	}
	rows := parseTestTSV(t, out.String())
	if len(rows) != 3 || strings.Join(rows[0], "|") != "192.0.2.25:445|public|TRUE|FALSE|TRUE|fileserver" || strings.Join(rows[1], "|") != "192.0.2.25:445|private|FALSE|UNKNOWN|TRUE|fileserver" || strings.Join(rows[2], "|") != "192.0.2.25:445|IPC$|N/A|N/A|TRUE|fileserver" {
		t.Fatalf("TSV lost per-share permissions/fallback: %q", out.String())
	}
	r.GuestFallback = false
	out.Reset()
	if err := writeTextResult(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, row := range parseTestTSV(t, out.String()) {
		if row[4] != "FALSE" {
			t.Fatalf("explicit guest incorrectly labeled as fallback: %#v", row)
		}
	}
}

func TestTSVKeepsFailedAndEmptyServersVisible(t *testing.T) {
	for _, r := range []Result{
		{Target: "offline:445", Authentication: "not_attempted", Enumeration: "not_attempted", Error: "connection timed out"},
		{Target: "192.0.2.30:445", ServerIP: "192.0.2.30", Reachable: true, Authentication: "failed", Enumeration: "not_attempted", Error: "login failed"},
		{Target: "192.0.2.31:445", ServerIP: "192.0.2.31", Reachable: true, Authentication: "guest", GuestFallback: true, Enumeration: "denied", Error: "enumeration denied"},
		{Target: "192.0.2.32:445", ServerIP: "192.0.2.32", Reachable: true, Authentication: "authenticated", Enumeration: "ok"},
	} {
		var out, diagnostics bytes.Buffer
		if err := writeTextResult(&out, r); err != nil {
			t.Fatal(err)
		}
		if err := writeTextDiagnostics(&diagnostics, r); err != nil {
			t.Fatal(err)
		}
		endpoint, hostname := r.Target, "-"
		if r.ServerIP == "" {
			endpoint, hostname = "UNKNOWN:445", "offline"
		}
		fallback := "FALSE"
		if r.GuestFallback {
			fallback = "TRUE"
		}
		want := endpoint + "|-|UNKNOWN|UNKNOWN|" + fallback + "|" + hostname
		rows := parseTestTSV(t, out.String())
		if len(rows) != 1 || strings.Join(rows[0], "|") != want {
			t.Fatalf("server status disappeared from TSV: %q", out.String())
		}
		if r.Error != "" && strings.Count(diagnostics.String(), r.Error) != 1 {
			t.Fatalf("failure must be reported once on stderr: %q", diagnostics.String())
		}
		if r.Enumeration == "ok" && !strings.Contains(strings.ToLower(diagnostics.String()), "no shares returned") {
			t.Fatalf("missing empty-server diagnostic: %q", diagnostics.String())
		}
	}
}

func TestAlignedOutputKeepsLongCellsOnOneLine(t *testing.T) {
	ip := "2001:db8:1234:5678:90ab:cdef:1234:5678%interface"
	hostname := strings.Repeat("long-hostname-", 4) + "files.example.com"
	name := strings.Repeat("é", 90) + "\tend"
	result := Result{Target: hostname + ":1445", ServerIP: ip, GuestFallback: true, Shares: []ShareResult{{Name: name, Read: Allowed, Write: Denied}}}
	var out bytes.Buffer
	if err := writeAlignedHeader(&out); err != nil {
		t.Fatal(err)
	}
	if err := writeAlignedResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\t\r\x1b") {
		t.Fatalf("terminal output contains raw controls: %q", out.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want exactly one header and one data line: %q", out.String())
	}
	if got := strings.Fields(lines[0]); strings.Join(got, "|") != "TARGET_IP|SHARE|READ|WRITE|GUEST|HOSTNAME" {
		t.Fatalf("unexpected terminal header: %q", lines[0])
	}
	want := []string{"[" + ip + "]:1445", strings.Repeat("é", 90) + `\tend`, "TRUE", "FALSE", "TRUE", hostname}
	if got := strings.Fields(lines[1]); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("long fields were wrapped, truncated, or joined: %q", lines[1])
	}
	if !strings.HasSuffix(lines[1], hostname) {
		t.Fatalf("hostname must be the full final column: %q", lines[1])
	}
}

func TestTimeoutOutputPreservesKnownPermissionsAndAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name   string
		result Result
		want   string
	}{
		{"before authentication", Result{TimedOut: true, Authentication: TimedOut, Enumeration: TimedOut}, "UNKNOWN|-|TIMEOUT|TIMEOUT|TIMEOUT|-"},
		{"authenticated", Result{Target: "192.0.2.1:445", ServerIP: "192.0.2.1", TimedOut: true, Authentication: "authenticated", Enumeration: TimedOut}, "192.0.2.1:445|-|TIMEOUT|TIMEOUT|FALSE|-"},
		{"guest fallback", Result{Target: "192.0.2.1:445", ServerIP: "192.0.2.1", TimedOut: true, Authentication: "guest", GuestFallback: true, Enumeration: TimedOut}, "192.0.2.1:445|-|TIMEOUT|TIMEOUT|TRUE|-"},
		{"empty list before cleanup timeout", Result{Target: "192.0.2.1:445", TimedOut: true, Authentication: "authenticated", Enumeration: "ok", enumerationComplete: true}, "192.0.2.1:445|-|UNKNOWN|UNKNOWN|FALSE|-"},
		{"denial before cleanup timeout", Result{Target: "192.0.2.1:445", TimedOut: true, Authentication: "guest", GuestFallback: true, Enumeration: "denied", enumerationComplete: true}, "192.0.2.1:445|-|UNKNOWN|UNKNOWN|TRUE|-"},
		{"completed failure before cleanup timeout", Result{Target: "192.0.2.1:445", TimedOut: true, Authentication: "authenticated", Enumeration: "error", enumerationComplete: true}, "192.0.2.1:445|-|UNKNOWN|UNKNOWN|FALSE|-"},
		{"empty list from scan hook", Result{Target: "192.0.2.1:445", TimedOut: true, Authentication: "authenticated", Enumeration: "ok"}, "192.0.2.1:445|-|UNKNOWN|UNKNOWN|FALSE|-"},
		{"denial from scan hook", Result{Target: "192.0.2.1:445", TimedOut: true, Authentication: "guest", Enumeration: "denied"}, "192.0.2.1:445|-|UNKNOWN|UNKNOWN|FALSE|-"},
		{"partially checked share", Result{Target: "192.0.2.1:445", ServerIP: "192.0.2.1", TimedOut: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "files", Read: Allowed, Write: TimedOut}}}, "192.0.2.1:445|files|TRUE|TIMEOUT|FALSE|-"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeTextResult(&out, tt.result); err != nil {
				t.Fatal(err)
			}
			rows := parseTestTSV(t, out.String())
			if len(rows) != 1 || strings.Join(rows[0], "|") != tt.want {
				t.Fatalf("timeout output lost known state: %q want %q", out.String(), tt.want)
			}
			out.Reset()
			if err := writeJSONResults(&out, []Result{tt.result}); err != nil {
				t.Fatal(err)
			}
			var decoded []Result
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || len(decoded) != 1 {
				t.Fatalf("invalid timeout JSON: %v", err)
			}
			if !decoded[0].TimedOut || decoded[0].Authentication != tt.result.Authentication || decoded[0].Enumeration != tt.result.Enumeration || decoded[0].GuestFallback != tt.result.GuestFallback {
				t.Fatalf("JSON timeout/authentication markers changed: %#v", decoded)
			}
		})
	}
}
