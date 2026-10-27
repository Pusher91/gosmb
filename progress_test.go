package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestProgressLinesThrottleOnlyIntermediateUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		p := newProgress(&out, true, 10)
		p.UseLines()
		update := func(completed int) {
			t.Helper()
			if err := p.Update(completed); err != nil {
				t.Fatal(err)
			}
		}
		update(0)
		initial := "Progress: 0% (0/10 hosts completed)\n"
		if out.String() != initial {
			t.Fatalf("initial progress was not printed immediately: %q", out.String())
		}
		update(1)
		time.Sleep(999 * time.Millisecond)
		update(2)
		if out.String() != initial {
			t.Fatalf("intermediate progress exceeded one line per second: %q", out.String())
		}
		time.Sleep(time.Millisecond)
		update(3)
		beforeIdle := out.String()
		if beforeIdle != initial+"Progress: 30% (3/10 hosts completed)\n" {
			t.Fatalf("one-second boundary did not emit the current count: %q", beforeIdle)
		}
		time.Sleep(5 * time.Second)
		if out.String() != beforeIdle {
			t.Fatalf("idle progress wrote without an Update call: %q", out.String())
		}
		update(4)
		time.Sleep(time.Second)
		update(10)
		if strings.Contains(out.String(), "100%") {
			t.Fatalf("Update duplicated the final summary: %q", out.String())
		}
		beforeClear := out.String()
		if err := p.Clear(); err != nil || out.String() != beforeClear {
			t.Fatalf("line-mode Clear touched shared output: %q, %v", out.String(), err)
		}
		if err := p.Finish(10, false); err != nil {
			t.Fatal(err)
		}
		want := initial + "Progress: 30% (3/10 hosts completed)\n" +
			"Progress: 40% (4/10 hosts completed)\nProgress: 100% (10/10 hosts completed)\n"
		if out.String() != want {
			t.Fatalf("line progress lost cadence, final count, or clean lines:\n%q\nwant %q", out.String(), want)
		}
	})
}

func TestProgressLinesPrintInitialEvenAtTotal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		total int
		want  string
	}{
		{"empty", 0, "Progress: 0% (0/0 hosts completed)\n"},
		{"already complete", 3, "Progress: 100% (3/3 hosts completed)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var out bytes.Buffer
				p := newProgress(&out, true, tc.total)
				p.UseLines()
				if err := p.Update(tc.total); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Second)
				if err := p.Update(tc.total); err != nil {
					t.Fatal(err)
				}
				if out.String() != tc.want {
					t.Fatalf("initial complete count was omitted or repeated: %q", out.String())
				}
			})
		})
	}
}

func TestProgressLinesFinalSummaryOmitsETA(t *testing.T) {
	for _, tc := range []struct {
		name        string
		completed   int
		interrupted bool
		want        string
	}{
		{"complete", 2, false, "Progress: 100% (2/2 hosts completed)\n"},
		{"interrupted", 1, true, "Progress: 50% (1/2 hosts completed) (interrupted)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			p := newProgress(&out, true, 2)
			p.UseLines()
			p.SetScanBudget(1, 10*time.Second, time.Second)
			if err := p.Update(0); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Max ETA:") {
				t.Fatalf("test did not exercise a configured live ETA: %q", out.String())
			}
			out.Reset()
			if err := p.Finish(tc.completed, tc.interrupted); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("final line contained ETA, cursor controls, or the wrong outcome: %q", out.String())
			}
		})
	}
}

func TestProgressLinesDisabledWritesNothing(t *testing.T) {
	writes := 0
	out := outputWriteFunc(func(data []byte) (int, error) {
		writes++
		return 0, io.ErrClosedPipe
	})
	p := newProgress(out, false, 2)
	p.UseLines()
	if err := p.Update(0); err != nil {
		t.Fatal(err)
	}
	if err := p.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := p.Finish(1, true); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("disabled progress attempted %d writes", writes)
	}
}

func TestProgressLinesPropagateWriteFailures(t *testing.T) {
	for _, phase := range []string{"initial", "intermediate", "final"} {
		for _, short := range []bool{false, true} {
			name := phase + "/error"
			if short {
				name = phase + "/short"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var writes []string
					fail := false
					out := outputWriteFunc(func(data []byte) (int, error) {
						writes = append(writes, string(data))
						if fail {
							if short {
								return len(data) / 2, nil
							}
							return 0, io.ErrClosedPipe
						}
						return len(data), nil
					})
					p := newProgress(out, true, 2)
					p.UseLines()
					if phase != "initial" {
						if err := p.Update(0); err != nil {
							t.Fatal(err)
						}
					}
					if phase == "intermediate" {
						time.Sleep(time.Second)
					}
					before := len(writes)
					fail = true
					var err error
					if phase == "final" {
						err = p.Finish(2, false)
					} else {
						err = p.Update(1)
					}
					wantErr := io.ErrClosedPipe
					if short {
						wantErr = io.ErrShortWrite
					}
					if !errors.Is(err, wantErr) || len(writes) != before+1 {
						t.Fatalf("write failure lost its cause or triggered extra writes: %v, %q", err, writes)
					}
					if err := p.Clear(); err != nil || len(writes) != before+1 {
						t.Fatalf("Clear retried or erased a partial line: %v, %q", err, writes)
					}
					if strings.ContainsAny(strings.Join(writes, ""), "\r\x1b") {
						t.Fatalf("line-mode failure emitted cursor controls: %q", writes)
					}
				})
			})
		}
	}
}

func TestProgressDirectTerminalKeepsCurrentLineBehavior(t *testing.T) {
	var out bytes.Buffer
	p := newProgress(&out, true, 2)
	if err := p.Update(0); err != nil {
		t.Fatal(err)
	}
	if err := p.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := p.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := p.Update(1); err != nil {
		t.Fatal(err)
	}
	if err := p.Finish(1, true); err != nil {
		t.Fatal(err)
	}
	want := clearProgressLine + "Progress: 0% (0/2 hosts completed)" + clearProgressLine +
		clearProgressLine + "Progress: 50% (1/2 hosts completed)" +
		clearProgressLine + "Progress: 50% (1/2 hosts completed) (interrupted)\n"
	if out.String() != want {
		t.Fatalf("direct terminal progress changed: %q", out.String())
	}
}
