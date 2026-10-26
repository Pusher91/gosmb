package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestShareNameAllowsDELAndC1WithEscapedOutput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		escaped string
	}{
		{"files\x7farchive", `files\x7farchive`},
		{"files\u0080archive", `files\x80archive`},
		{"files\u0085archive", `files\x85archive`},
		{"files\u009barchive", `files\x9barchive`},
		{"files\u009farchive", `files\x9farchive`},
	} {
		t.Run(tc.escaped, func(t *testing.T) {
			if !validShareName(tc.name) {
				t.Errorf("legal share name %q would be skipped", tc.name)
			}
			result := Result{Target: "192.0.2.1:445", Shares: []ShareResult{{Name: tc.name, Read: Allowed, Write: Denied}}}
			var output bytes.Buffer
			if err := writeTextResult(&output, result); err != nil {
				t.Fatal(err)
			}
			want := "192.0.2.1:445\t" + tc.escaped + "\tTRUE\tFALSE\tFALSE\t-\n"
			if output.String() != want {
				t.Errorf("text result = %q; want %q", output.String(), want)
			}
		})
	}
}

func TestShareNameRejectsC0BeforeProbing(t *testing.T) {
	for control := rune(0); control < 0x20; control++ {
		t.Run(fmt.Sprintf("U+%04X", control), func(t *testing.T) {
			name := "files" + string(control) + "archive"
			// Nil connection and dialer also enforce that an invalid name cannot
			// reach the network probe.
			result, cleanupErr := inspectShare(nil, nil, discoveredShare{Name: name, Type: "disk"})
			if cleanupErr != nil || !result.probeComplete || !strings.Contains(result.Error, "invalid share name") ||
				result.Accessible != Unknown || result.Read != Unknown || result.Write != Unknown {
				t.Errorf("invalid share result = %+v, cleanup error = %v", result, cleanupErr)
			}
		})
	}
}
