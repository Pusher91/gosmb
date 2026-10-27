package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestCLIProgressFailurePreservesBufferedJSON(t *testing.T) {
	path := schedulerHostFile(t, "first", "second", "third")
	for _, tc := range []struct {
		name                  string
		failClear, failUpdate int
		cancel, short         bool
		wantScans             int
	}{
		{"first result clear", 1, 0, false, false, 1},
		{"first result update", 0, 2, false, false, 1},
		{"partial progress update", 0, 2, false, true, 1},
		{"final clear", 4, 0, false, false, 3},
		{"cancellation diagnostic clear", 2, 0, true, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out bytes.Buffer
			clears, updates, scans := 0, 0, 0
			failed := false
			stderr := outputWriteFunc(func(data []byte) (int, error) {
				if string(data) == clearProgressLine {
					clears++
					failed = failed || clears == tc.failClear
				} else if bytes.Contains(data, []byte("Progress:")) && !bytes.HasSuffix(data, []byte{'\n'}) {
					updates++
					failed = failed || updates == tc.failUpdate
				}
				if failed {
					if tc.short {
						return len(data) / 2, nil
					}
					return 0, io.ErrClosedPipe
				}
				return len(data), nil
			})
			deps := testCLIDeps(&out, stderr)
			deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				scans++
				if out.Len() != 0 {
					t.Error("JSON was emitted before the run ended")
				}
				if tc.cancel {
					cancel()
				}
				return Result{Target: target.String(), Authentication: "authenticated", Enumeration: "ok",
					Shares: []ShareResult{{Name: target.Host + "-password-secret", Read: Allowed, Write: Denied}}}
			}
			code := runCLI(ctx, []string{path, "-u", "fixture", "-p", "password-secret", "--json", "--delay=0"}, deps)
			if !failed || code != 1 || scans != tc.wantScans {
				t.Fatalf("progress failure did not stop the run: failed=%t exit=%d scans=%d; want %d scans", failed, code, scans, tc.wantScans)
			}
			var results []Result
			if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != tc.wantScans {
				t.Fatalf("stderr failure discarded JSON: output=%q error=%v; want %d results", out.String(), err, tc.wantScans)
			}
			for i, host := range []string{"first", "second", "third"}[:tc.wantScans] {
				if result := results[i]; result.Target != host+":445" || len(result.Shares) != 1 || result.Shares[0].Name != host+"-[REDACTED]" {
					t.Errorf("retained result lost data or redaction: %+v", result)
				}
			}
			if strings.Contains(out.String(), "password-secret") || strings.ContainsAny(out.String(), "\r\x1b") {
				t.Fatalf("JSON exposed credentials or progress controls: %q", out.String())
			}
		})
	}
}

func TestCLIProgressFailureDrainsConcurrentJSONResults(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		clear, short, recovers, inFlight bool
	}{
		{"clear failure", true, false, false, false},
		{"update failure", false, false, false, false},
		{"partial update with recovered cleanup", false, true, true, false},
		{"active result during cancellation", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				path := schedulerHostFile(t, "first", "second", "queued")
				secondStarted, releaseSecond := make(chan struct{}), make(chan struct{})
				var completed, queued atomic.Int32
				var out bytes.Buffer
				failed, footerAttempted, footerWritten := false, false, false
				updates, clearsAfterFailure := 0, 0
				stderr := outputWriteFunc(func(data []byte) (int, error) {
					if bytes.Contains(data, []byte("gosmb: canceled")) {
						t.Error("progress failure was reported as user cancellation")
					}
					update := bytes.Contains(data, []byte("Progress:")) && !bytes.HasSuffix(data, []byte{'\n'})
					if update {
						updates++
						if failed {
							t.Error("draining results retried a failed progress update")
						}
					}
					if !failed && (tc.clear && string(data) == clearProgressLine || !tc.clear && updates == 2) {
						if !tc.inFlight {
							close(releaseSecond)
							// The second worker queues its completed result before
							// stderr fails, independently of real-time scheduling.
							synctest.Wait()
							if completed.Load() != 2 {
								t.Fatalf("expected two completed scans before output failure, got %d", completed.Load())
							}
						}
						failed = true
						if tc.short {
							return len(data) / 2, nil
						}
						return 0, io.ErrClosedPipe
					}
					if failed {
						if string(data) == clearProgressLine {
							clearsAfterFailure++
						}
						if bytes.Contains(data, []byte("Progress:")) && bytes.HasSuffix(data, []byte{'\n'}) {
							footerAttempted = true
							footerWritten = tc.recovers
						}
						if !tc.recovers {
							return 0, io.ErrClosedPipe
						}
					}
					return len(data), nil
				})
				stdout := outputWriteFunc(func(data []byte) (int, error) {
					if completed.Load() != 2 {
						t.Error("JSON was emitted before active scans finished")
					}
					return out.Write(data)
				})
				deps := testCLIDeps(stdout, stderr)
				deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
				deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
					switch target.Host {
					case "first":
						<-secondStarted
					case "second":
						close(secondStarted)
						if tc.inFlight {
							<-scanCtx.Done()
						} else {
							<-releaseSecond
						}
					default:
						queued.Add(1)
					}
					completed.Add(1)
					result := schedulerSuccess(target)
					result.Shares[0].Name = target.Host + "-password-secret"
					if tc.inFlight && target.Host == "second" {
						result.Error = scanCtx.Err().Error()
					}
					return result
				}
				code := runCLI(context.Background(), []string{path, "-u", "fixture", "-p", "password-secret",
					"--json", "--concurrency=2", "--delay=0"}, deps)
				if code != 1 || !failed || completed.Load() != 2 || queued.Load() != 0 {
					t.Fatalf("progress failure did not stop new work: exit=%d failed=%t completed=%d queued=%d", code, failed, completed.Load(), queued.Load())
				}
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 2 {
					t.Fatalf("completed results lost after stderr failure: output=%q error=%v", out.String(), err)
				}
				for i, host := range []string{"first", "second"} {
					result := results[i]
					wantError := ""
					if tc.inFlight && host == "second" {
						wantError = context.Canceled.Error()
					}
					if result.Target != host+":445" || result.Authentication != "authenticated" || result.Enumeration != "ok" ||
						len(result.Shares) != 1 || result.Shares[0].Name != host+"-[REDACTED]" ||
						result.Shares[0].Read != Allowed || result.Shares[0].Write != Denied || result.Error != wantError {
						t.Errorf("completed result changed during draining: %+v", result)
					}
				}
				if !footerAttempted || footerWritten != tc.recovers || tc.short && clearsAfterFailure == 0 {
					t.Errorf("terminal cleanup was skipped: footer attempted=%t written=%t clears=%d", footerAttempted, footerWritten, clearsAfterFailure)
				}
				if strings.Contains(out.String(), "password-secret") || strings.ContainsAny(out.String(), "\r\x1b") {
					t.Fatalf("JSON contains credentials or progress controls: %q", out.String())
				}
			})
		})
	}
}
