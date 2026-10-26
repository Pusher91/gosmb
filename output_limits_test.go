package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInteractiveColumnCapsIncludeEllipsis(t *testing.T) {
	hostname := strings.Repeat("hostname-", 25) + "example.test"
	fields := [7]string{
		strings.Repeat("i", 80), strings.Repeat("s", 80), strings.Repeat("r", 20),
		strings.Repeat("w", 20), strings.Repeat("g", 20), strings.Repeat("z", 40), hostname,
	}
	var out bytes.Buffer
	if err := writeAlignedRow(&out, fields, false); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("i", 20) + "…  " + strings.Repeat("s", 19) + "…  " +
		strings.Repeat("r", 6) + "…  " + strings.Repeat("w", 6) + "…  " +
		strings.Repeat("g", 6) + "…  " + strings.Repeat("z", 17) + "…  " + hostname + "\n"
	if out.String() != want {
		t.Fatalf("column caps moved later cells or truncated hostname:\n%q\nwant %q", out.String(), want)
	}
}

func TestInteractiveUnicodeAndEscapeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		columns           int
	}{
		{"ASCII exact", strings.Repeat("a", 20), strings.Repeat("a", 20), 20},
		{"CJK exact", strings.Repeat("界", 10), strings.Repeat("界", 10), 20},
		{"CJK clipped", strings.Repeat("界", 11), strings.Repeat("界", 9) + "…", 19},
		{"combining exact", strings.Repeat("e\u0301", 20), strings.Repeat("e\u0301", 20), 20},
		{"combining clipped", strings.Repeat("e\u0301", 21), strings.Repeat("e\u0301", 19) + "…", 20},
		{"emoji modifier clipped", strings.Repeat("👍🏽", 11), strings.Repeat("👍🏽", 9) + "…", 19},
		{"flag clipped", strings.Repeat("🇺🇸", 11), strings.Repeat("🇺🇸", 9) + "…", 19},
		{"control escape exact", strings.Repeat("a", 16) + "\x1b", strings.Repeat("a", 16) + `\x1b`, 20},
		{"control escape clipped", strings.Repeat("a", 17) + "\x1btail", strings.Repeat("a", 17) + "…", 18},
		{"literal backslash clipped", strings.Repeat("a", 18) + `\tail`, strings.Repeat("a", 18) + "…", 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := Result{Target: "fileserver:445", ServerIP: "192.0.2.1", Reachable: true,
				Authentication: "authenticated", Enumeration: "ok",
				Shares: []ShareResult{{Name: tc.input, Accessible: Allowed, Read: Allowed, Write: Denied}}}
			for _, colored := range []bool{false, true} {
				var out bytes.Buffer
				if err := writeAlignedResult(&out, result, colored); err != nil {
					t.Fatal(err)
				}
				read, denied := "TRUE", "FALSE"
				if colored {
					read, denied = "\x1b[32mTRUE\x1b[0m", "\x1b[31mFALSE\x1b[0m"
				}
				// Widths here are known from the test data, independent of the
				// renderer's Unicode measurement and truncation implementation.
				want := "192.0.2.1:445" + strings.Repeat(" ", 10) + tc.want + strings.Repeat(" ", 22-tc.columns) +
					read + "     " + denied + "    " + denied + "    " + "OK" + strings.Repeat(" ", 18) + "fileserver\n"
				if out.String() != want {
					t.Errorf("colored=%t: clipped a grapheme/escape or moved a column:\n%q\nwant %q", colored, out.String(), want)
				}
			}
		})
	}
}

func TestInteractiveTruncationPreservesFullMachineOutput(t *testing.T) {
	hostname := strings.Repeat("long-hostname-", 6) + "example.test"
	ip := "2001:db8:1234:5678:90ab:cdef:1234:5678%interface-with-a-long-name"
	name := strings.Repeat("共有", 40) + "\tfull-name"
	result := Result{Target: hostname + ":1445", ServerIP: ip, Reachable: true,
		Authentication: "authenticated", Enumeration: "ok",
		Shares: []ShareResult{{Name: name, Accessible: Allowed, Read: Allowed, Write: Denied}}}
	var terminal, tsv, jsonOut bytes.Buffer
	if err := writeAlignedResult(&terminal, result, true); err != nil {
		t.Fatal(err)
	}
	if err := writeTextHeader(&tsv); err != nil {
		t.Fatal(err)
	}
	if err := writeTextResult(&tsv, result); err != nil {
		t.Fatal(err)
	}
	rows := parseTestTSV(t, tsv.String())
	wantHeader := "TARGET_IP|SHARE|READ|WRITE|GUEST|HOSTNAME"
	wantRow := "[" + ip + "]:1445|" + strings.Repeat("共有", 40) + `\tfull-name` + "|TRUE|FALSE|FALSE|" + hostname
	if len(rows) != 2 || strings.Join(rows[0], "|") != wantHeader || strings.Join(rows[1], "|") != wantRow {
		t.Fatalf("interactive truncation changed six-column TSV: %q", tsv.String())
	}
	if strings.ContainsRune(tsv.String(), '\x1b') {
		t.Fatal("interactive colors leaked into TSV")
	}
	if err := writeJSONResults(&jsonOut, []Result{result}); err != nil {
		t.Fatal(err)
	}
	var decoded []Result
	if err := json.Unmarshal(jsonOut.Bytes(), &decoded); err != nil || len(decoded) != 1 {
		t.Fatalf("invalid JSON after interactive rendering: %v", err)
	}
	if decoded[0].Target != result.Target || decoded[0].ServerIP != ip || len(decoded[0].Shares) != 1 || decoded[0].Shares[0].Name != name {
		t.Errorf("interactive rendering truncated machine fields: %#v", decoded)
	}
	if strings.Contains(jsonOut.String(), `"status":`) {
		t.Error("interactive STATUS added a JSON field")
	}
}
