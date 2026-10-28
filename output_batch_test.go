package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAlignedOutputBatchesCompleteRows(t *testing.T) {
	for _, tc := range []struct {
		name, hostname string
		rows           int
	}{
		{"many rows", "files." + strings.Repeat("department.", 20) + "example.test", 1000},
		{"hostname exceeds batch", strings.Repeat("h", 20000), 3},
	} {
		for _, colored := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/colored=%t", tc.name, colored), func(t *testing.T) {
				result := Result{Target: tc.hostname + ":445", ServerIP: "192.0.2.25", Authentication: "authenticated", Enumeration: "ok"}
				read, denied, status := "TRUE", "FALSE", "OK"
				if colored {
					read, denied = "\x1b[32mTRUE\x1b[0m", "\x1b[31mFALSE\x1b[0m"
					status = "\x1b[32mOK\x1b[0m"
				}
				var expected bytes.Buffer
				for i := range tc.rows {
					result.Shares = append(result.Shares, ShareResult{Name: fmt.Sprintf("資料-\t%04d\x1b", i), Read: Allowed, Write: Denied})
					fmt.Fprintf(&expected, "192.0.2.25:445%s資料-\\t%04d\\x1b%s%s     %s    %s    %s%s%s\n",
						strings.Repeat(" ", 9), i, strings.Repeat(" ", 7), read, denied, denied, status, strings.Repeat(" ", 18), tc.hostname)
				}
				rowBytes := expected.Len() / tc.rows
				var combined bytes.Buffer
				writes := 0
				out := outputWriteFunc(func(data []byte) (int, error) {
					writes++
					if len(data) > (16<<10)+rowBytes || !bytes.HasSuffix(data, []byte{'\n'}) {
						t.Fatalf("batch exceeded its bound or split a row: %d bytes", len(data))
					}
					return combined.Write(data)
				})
				if err := writeAlignedResult(out, result, colored); err != nil {
					t.Fatal(err)
				}
				if writes < 2 || writes > tc.rows || tc.rows == 1000 && writes == tc.rows {
					t.Fatalf("rows were not emitted in bounded batches: %d writes for %d rows", writes, tc.rows)
				}
				if !bytes.Equal(combined.Bytes(), expected.Bytes()) {
					t.Fatal("batching changed row order, alignment, escaping, colors, or full hostnames")
				}
			})
		}
	}
}

func BenchmarkAlignedFileOutput(b *testing.B) {
	out, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer out.Close()
	for _, count := range []int{1, 1000} {
		for _, tc := range []struct{ name, share string }{
			{"ascii", "documents and archives"},
			{"short_unicode", "共有資料"},
			{"clipped_unicode", strings.Repeat("界", 80)},
			{"clipped_combining", strings.Repeat("e\u0301", 40)},
			{"clipped_escapes", strings.Repeat("x\u0085", 40)},
		} {
			b.Run(fmt.Sprintf("rows_%d/%s", count, tc.name), func(b *testing.B) {
				result := Result{Target: "server:445", ServerIP: "192.0.2.1", Authentication: "authenticated", Enumeration: "ok"}
				for range count {
					result.Shares = append(result.Shares, ShareResult{Name: tc.share, Read: Allowed, Write: Denied})
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := writeAlignedResult(out, result, false); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
