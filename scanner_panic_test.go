package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const scanPanicValue = "sensitive-panic-payload"

type scanPanicContext struct {
	context.Context
	ready *atomic.Bool
}

func (c scanPanicContext) Deadline() (time.Time, bool) {
	if c.ready.Swap(false) {
		panic(scanPanicValue)
	}
	return c.Context.Deadline()
}

func TestScanTargetContainsBodyAndLogoffPanics(t *testing.T) {
	for _, stage := range []string{"before enumeration", "root open", "logoff after completed checks"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			// Keep the caller's Deadline callback visible to the wire. The
			// fixture's I/O timeout still bounds each network operation.
			fixture.options.HostTimeout = 0
			var ready atomic.Bool
			var logoffs atomic.Int32
			var diskDisconnects atomic.Int32
			target, _, closed := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) < 64 {
					return false
				}
				command := binary.LittleEndian.Uint16(raw[12:14])
				if command == 2 {
					logoffs.Add(1)
				}
				if command == 4 && binary.LittleEndian.Uint32(raw[36:40]) == 2 {
					diskDisconnects.Add(1)
				}
				// Arm the one-shot panic for the next operation's deadline: IPC$
				// connection, disk root OPEN, or LOGOFF after disk cleanup.
				if stage == "before enumeration" && command == 1 && bytes.Contains(raw[64:], []byte("NTLMSSP\x00\x03\x00\x00\x00")) ||
					stage == "root open" && command == 3 && len(raw) >= 72 && strings.HasSuffix(fxText(raw[72:]), "\\data$") ||
					stage == "logoff after completed checks" && command == 4 && binary.LittleEndian.Uint32(raw[36:40]) == 2 {
					ready.Store(true)
				}
				return false
			})
			ctx := scanPanicContext{context.Background(), &ready}
			result := scanTarget(ctx, target, fixture.options)
			if result.Error != "unexpected panic during SMB scan; scan aborted" ||
				tableStatus(result, nil) != "SMB_FAILED" || strings.Contains(result.Error, scanPanicValue) ||
				!result.Reachable || result.Authentication != "authenticated" || result.TimedOut {
				t.Fatalf("panic did not become a neutral per-host failure: %+v", result)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("panic left the socket open")
			}
			if logoffs.Load() != 0 {
				t.Fatal("body panic attempted protocol cleanup on the suspect connection")
			}
			if stage == "root open" && diskDisconnects.Load() != 0 {
				t.Fatal("nested share cleanup sent TREE_DISCONNECT after the root-open panic")
			}
			if stage == "before enumeration" {
				if result.Enumeration != "error" || len(result.Shares) != 0 {
					t.Fatalf("body panic misreported unfinished enumeration: %+v", result)
				}
				fixture.assertUnchanged(t, 0)
				return
			}
			wantShares := []discoveredShare{
				{"data$", "disk", "fixture disk"},
				{"IPC$", "ipc", "fixture RPC"},
				{"printer", "printer", "must not be probed"},
			}
			if result.Enumeration != "ok" || !result.enumerationComplete || len(result.Shares) != len(wantShares) {
				t.Fatalf("panic erased completed enumeration: %+v", result)
			}
			for i, share := range result.Shares {
				if want := wantShares[i]; share.Name != want.Name || share.Type != want.Type || share.Comment != want.Comment {
					t.Errorf("panic changed discovered share metadata: %+v; want %+v", share, want)
				}
				wantPermission, wantComplete := NotApplicable, true
				if share.Type == "disk" {
					wantPermission = Allowed
					if stage == "root open" {
						wantPermission, wantComplete = Unknown, false
					}
				}
				if share.probeComplete != wantComplete || share.Accessible != wantPermission || share.Read != wantPermission || share.Write != wantPermission {
					t.Errorf("panic changed permission results: %+v; want permission=%s, complete=%t", share, wantPermission, wantComplete)
				}
				if tableStatus(result, &share) != "SMB_FAILED" {
					t.Errorf("panic left a successful share status: %+v", share)
				}
			}
			opens := 0
			if stage == "logoff after completed checks" {
				opens = 1
			}
			fixture.assertUnchanged(t, opens)
		})
	}
}
