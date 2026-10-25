package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func parseTestTSV(t *testing.T, output string) [][]string {
	t.Helper()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("TSV must end with a record newline: %q", output)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		cells := strings.Split(line, "\t")
		if len(cells) != 5 {
			t.Fatalf("expected exactly five tab-separated cells, without banners or blank lines: %q", line)
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
		if row[0] != result.ServerIP || row[1] != cases[i].escaped || strings.Join(row[2:], "|") != "TRUE|FALSE|FALSE" {
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
	if len(rows) != 1 || rows[0][0] != `value\x1b[2J\t\n\u202e` || rows[0][1] != `value\x1b[2J\t\n\u202e` {
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

func TestTSVRepeatsServerIPAndGuestFallbackForEveryShare(t *testing.T) {
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
	if len(rows) != 3 || strings.Join(rows[0], "|") != "192.0.2.25|public|TRUE|FALSE|TRUE" || strings.Join(rows[1], "|") != "192.0.2.25|private|FALSE|UNKNOWN|TRUE" || strings.Join(rows[2], "|") != "192.0.2.25|IPC$|N/A|N/A|TRUE" {
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
		ip := r.ServerIP
		if ip == "" {
			ip = "UNKNOWN"
		}
		fallback := "FALSE"
		if r.GuestFallback {
			fallback = "TRUE"
		}
		want := ip + "|-|UNKNOWN|UNKNOWN|" + fallback
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

func TestAlignedOutputWrapsLongCellsWithoutLosingValues(t *testing.T) {
	ip := "2001:db8:1234:5678:90ab:cdef:1234:5678%interface"
	name := strings.Repeat("é", 90) + "\tend"
	result := Result{Target: "server:445", ServerIP: ip, GuestFallback: true, Shares: []ShareResult{{Name: name, Read: Allowed, Write: Denied}}}
	var out bytes.Buffer
	if err := writeAlignedHeader(&out); err != nil {
		t.Fatal(err)
	}
	if err := writeAlignedResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\t\r\x1b") {
		t.Fatalf("wrapped terminal output contains raw controls: %q", out.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) <= 2 {
		t.Fatalf("long cells were not wrapped: %q", out.String())
	}
	var starts [5]int
	for column, heading := range []string{"SMB_SERVER_IP", "SHARE", "READ", "WRITE", "GUEST_FALLBACK"} {
		starts[column] = strings.Index(lines[0], heading)
		if starts[column] < 0 {
			t.Fatalf("missing terminal header %q: %q", heading, lines[0])
		}
	}
	var recovered [5]string
	for _, line := range lines[1:] {
		runes := []rune(line)
		for column, start := range starts {
			if start >= len(runes) {
				continue
			}
			end := len(runes)
			if column < len(starts)-1 {
				end = min(end, starts[column+1]-2)
			}
			recovered[column] += strings.TrimRight(string(runes[start:end]), " ")
		}
	}
	want := [5]string{ip, strings.Repeat("é", 90) + `\tend`, "TRUE", "FALSE", "TRUE"}
	if recovered != want {
		t.Fatalf("wrapping truncated cells or moved them into other columns:\ngot %#v\nwant %#v\noutput %q", recovered, want, out.String())
	}
}

func TestTimeoutOutputPreservesKnownPermissionsAndAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name   string
		result Result
		want   string
	}{
		{"before authentication", Result{TimedOut: true, Authentication: TimedOut, Enumeration: TimedOut}, "UNKNOWN|-|TIMEOUT|TIMEOUT|TIMEOUT"},
		{"authenticated", Result{ServerIP: "192.0.2.1", TimedOut: true, Authentication: "authenticated", Enumeration: TimedOut}, "192.0.2.1|-|TIMEOUT|TIMEOUT|FALSE"},
		{"guest fallback", Result{ServerIP: "192.0.2.1", TimedOut: true, Authentication: "guest", GuestFallback: true, Enumeration: TimedOut}, "192.0.2.1|-|TIMEOUT|TIMEOUT|TRUE"},
		{"partially checked share", Result{ServerIP: "192.0.2.1", TimedOut: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "files", Read: Allowed, Write: TimedOut}}}, "192.0.2.1|files|TRUE|TIMEOUT|FALSE"},
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
