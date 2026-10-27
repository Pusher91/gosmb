package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func assertTargetIPOutput(t *testing.T, result Result, want string) {
	t.Helper()
	if result.ServerIP != want {
		t.Fatalf("server IP=%q, want supplied IP %q", result.ServerIP, want)
	}
	var text, encoded bytes.Buffer
	if err := writeTextResult(&text, result); err != nil {
		t.Fatal(err)
	}
	for _, row := range parseTestTSV(t, text.String()) {
		_, port, err := net.SplitHostPort(result.Target)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint := net.JoinHostPort(want, port); row[0] != endpoint || row[6] != "-" {
			t.Fatalf("TSV endpoint=%q hostname=%q, want %q and no hostname", row[0], row[6], endpoint)
		}
	}
	if err := writeJSONResults(&encoded, []Result{result}); err != nil {
		t.Fatal(err)
	}
	var decoded []Result
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].ServerIP != want {
		t.Fatalf("JSON lost supplied IP: %s", encoded.String())
	}
}

func TestScanTargetKeepsIPBeforeConnection(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "fe80::10%eth0"} {
		for _, timedOut := range []bool{false, true} {
			name := "canceled"
			if timedOut {
				name = "deadline"
			}
			t.Run(host+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				if timedOut {
					cancel()
					ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
				} else {
					cancel()
				}
				defer cancel()
				result := scanTarget(ctx, Target{Host: host, Port: 445}, Options{})
				if result.Reachable || result.Error == "" || result.TimedOut != timedOut {
					t.Fatalf("unexpected pre-connection result: %+v", result)
				}
				assertTargetIPOutput(t, result, host)
			})
		}
	}
}

func TestScanTargetKeepsSuppliedIPAfterConnection(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	target := fixture.target
	// The TCP peer reports IPv4, but the user supplied its IPv6-mapped form.
	target.Host = "::ffff:127.0.0.1"
	result := scanTarget(context.Background(), target, fixture.options)
	if !result.Reachable || result.Authentication != "authenticated" || result.Enumeration != "ok" {
		t.Fatalf("mapped loopback scan failed: %+v", result)
	}
	assertTargetIPOutput(t, result, target.Host)
	fixture.assertUnchanged(t, 1)
}
