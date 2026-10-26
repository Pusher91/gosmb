package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func BenchmarkParseTargetList(b *testing.B) {
	var hosts strings.Builder
	for i := range 1000 {
		hosts.WriteString("server-")
		hosts.WriteString(strconv.Itoa(i))
		hosts.WriteString(".example:1445\n")
	}
	var paddedHosts strings.Builder
	padding := strings.Repeat(" ", 60000)
	for i := range 64 {
		paddedHosts.WriteString("server-")
		paddedHosts.WriteString(strconv.Itoa(i))
		paddedHosts.WriteString(".example:1445")
		paddedHosts.WriteString(padding)
		paddedHosts.WriteByte('\n')
	}
	for _, tc := range []struct {
		name, input string
		count       int
	}{
		{"IPv4", "10.0.0.0/20\n", 4096},
		{"IPv6", "2001:db8::/116\n", 4096},
		{"MappedOverlap", "10.0.0.0/20\n::ffff:10.0.0.0/116\n10.0.1.0/24\n", 4096},
		{"Hostnames", hosts.String(), 1000},
		{"PaddedHostnames", paddedHosts.String(), 64},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				targets, err := parseTargetList(context.Background(), strings.NewReader(tc.input))
				if err != nil || len(targets) != tc.count {
					b.Fatalf("targets=%d error=%v; want %d", len(targets), err, tc.count)
				}
			}
		})
	}
}

func TestParseTargetSpecExpandsCIDR(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  []Target
	}{
		{"192.0.2.3/30", []Target{{"192.0.2.0", 445}, {"192.0.2.1", 445}, {"192.0.2.2", 445}, {"192.0.2.3", 445}}},
		{"192.0.2.3/31:1445", []Target{{"192.0.2.2", 1445}, {"192.0.2.3", 1445}}},
		{"192.0.2.7/32", []Target{{"192.0.2.7", 445}}},
		{"255.255.255.255/31", []Target{{"255.255.255.254", 445}, {"255.255.255.255", 445}}},
		{"2001:db8::3/126", []Target{{"2001:db8::", 445}, {"2001:db8::1", 445}, {"2001:db8::2", 445}, {"2001:db8::3", 445}}},
		{"[2001:db8::3/127]:1445", []Target{{"2001:db8::2", 1445}, {"2001:db8::3", 1445}}},
		{"2001:db8::7/128", []Target{{"2001:db8::7", 445}}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127", []Target{{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 445}, {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 445}}},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseTargetSpec(tt.input)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("expanded targets = %#v, %v; want %#v", got, err, tt.want)
			}
			cfg, err := parseCLI(context.Background(), []string{tt.input, "--guest"})
			if err != nil || !reflect.DeepEqual(cfg.targets, tt.want) {
				t.Fatalf("positional CIDR targets = %#v, %v; want %#v", cfg.targets, err, tt.want)
			}
		})
	}
}

func TestParseTargetSpecRejectsMalformedAndOversizedCIDR(t *testing.T) {
	for _, input := range []string{
		"192.0.2.1/33", "192.0.2.1/-1", "192.0.2.1/", "192.0.2.1/DO-NOT-ECHO-THIS",
		"192.0.2.0/30:0", "192.0.2.0/30:65536", "192.0.2.0/30:secret", "[192.0.2.0/30]:445",
		"server.example/30", "2001:db8::/129", "2001:db8::/126:1445",
		"[2001:db8::/126]:", "[2001:db8::/126]:-1", "[fe80::%eth0/126]:445",
		"10.0.0.0/15", "2001:db8::/111", "0.0.0.0/0", "::/0",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseTargetSpec(input); err == nil || strings.Contains(err.Error(), input) {
				t.Fatalf("invalid/oversized CIDR must fail without echoing input: %v", err)
			}
		})
	}
}

func TestCIDRMaximumRangeSize(t *testing.T) {
	for _, tt := range []struct{ input, first, last string }{
		{"10.0.1.2/16", "10.0.0.0", "10.0.255.255"},
		{"2001:db8::1234/112", "2001:db8::", "2001:db8::ffff"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			targets, err := parseTargetSpec(tt.input)
			if err != nil || len(targets) != 65536 {
				t.Fatalf("maximum-size range count = %d, err = %v", len(targets), err)
			}
			if targets[0] != (Target{tt.first, 445}) || targets[len(targets)-1] != (Target{tt.last, 445}) {
				t.Fatalf("wrong range boundaries: first=%v last=%v", targets[0], targets[len(targets)-1])
			}
		})
	}
}

func TestCIDRTargetListDeduplicatesOverlapsInInputOrder(t *testing.T) {
	input := "\ufeff# ranges and hosts\r\n\n192.0.2.1\n192.0.2.3/30\n192.0.2.0/31:1445\n192.0.2.1:1445\nSERVER\nserver\n2001:db8::1\n2001:db8::/127\n"
	want := []Target{
		{"192.0.2.1", 445}, {"192.0.2.0", 445}, {"192.0.2.2", 445}, {"192.0.2.3", 445},
		{"192.0.2.0", 1445}, {"192.0.2.1", 1445}, {"SERVER", 445},
		{"2001:db8::1", 445}, {"2001:db8::", 445},
	}
	got, err := parseTargetList(context.Background(), strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("merged targets = %#v, %v; want %#v", got, err, want)
	}
}

func TestCIDRTargetListLimitsUniqueEndpoints(t *testing.T) {
	const fullRange = "10.0.0.0/16\n"
	targets, err := parseTargetList(context.Background(), strings.NewReader(fullRange+"10.0.0.1\n"+fullRange))
	if err != nil || len(targets) != 65536 {
		t.Fatalf("overlapping targets should not consume additional capacity: count=%d err=%v", len(targets), err)
	}
	for _, extra := range []string{"192.0.2.1\n", "10.0.0.1:1445\n", "192.0.2.0/31\n"} {
		if _, err := parseTargetList(context.Background(), strings.NewReader(fullRange+extra)); err == nil {
			t.Errorf("accepted more than 65536 unique endpoints with extra %q", extra)
		}
	}
}

func TestTargetListPreservesDistinctIPv6Zones(t *testing.T) {
	input := "[fe80::a%Eth0]:445\n[FE80:0:0:0:0:0:0:A%Eth0]:445\n" +
		"[fe80::a%eth0]:445\n[fe80::a%Eth0]:1445\nSERVER\nserver\n"
	want := []Target{
		{"fe80::a%Eth0", 445}, {"fe80::a%eth0", 445},
		{"fe80::a%Eth0", 1445}, {"SERVER", 445},
	}
	got, err := parseTargetList(context.Background(), strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("scoped target deduplication = %#v, %v; want %#v", got, err, want)
	}
}

func TestTargetListDeduplicatesMappedIPv4WithoutChangingFirstSpelling(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        []Target
	}{
		{"IPv4 first", "192.0.2.1\n::ffff:192.0.2.1\n", []Target{{"192.0.2.1", 445}}},
		{"mapped first", "::ffff:192.0.2.1\n192.0.2.1\n", []Target{{"::ffff:192.0.2.1", 445}}},
		{"overlapping ranges and ports", "::ffff:192.0.2.0/127\n192.0.2.0/31\n192.0.2.1:1445\n[::ffff:192.0.2.1]:1445\n", []Target{
			{"::ffff:192.0.2.0", 445}, {"::ffff:192.0.2.1", 445}, {"192.0.2.1", 1445},
		}},
		{"mapped zones do not select an interface", "192.0.2.1\n::ffff:192.0.2.1%eth0\n::ffff:192.0.2.1%Eth0\n", []Target{
			{"192.0.2.1", 445},
		}},
		{"mapped zone spelling retained first", "::ffff:192.0.2.1%NONEXISTENT\n192.0.2.1\n::ffff:192.0.2.1\n::ffff:192.0.2.1%eth0\n", []Target{
			{"::ffff:192.0.2.1%NONEXISTENT", 445},
		}},
		{"mapped zones preserve separate ports", "[::ffff:192.0.2.1%eth0]:1445\n192.0.2.1\n[::ffff:192.0.2.1%Eth0]:1445\n", []Target{
			{"::ffff:192.0.2.1%eth0", 1445}, {"192.0.2.1", 445},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTargetList(context.Background(), strings.NewReader(tc.input))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mapped endpoint deduplication = %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
	got, err := parseTargetList(context.Background(), strings.NewReader("10.0.0.0/16\n::ffff:10.0.0.0/112\n::ffff:10.0.0.1%eth0\n"))
	if err != nil || len(got) != maxTargets {
		t.Fatalf("mapped duplicates consumed unique endpoint capacity: count=%d error=%v", len(got), err)
	}
}

func TestCLIMappedIPv4AliasesStartOnlyOneScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("[::ffff:192.0.2.1%Eth0]:1445\n192.0.2.1:1445\n[::ffff:192.0.2.1]:1445\n[::ffff:192.0.2.1%eth0]:1445\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	deps := testCLIDeps(&out, &diagnostics)
	calls := 0
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		calls++
		if target != (Target{"::ffff:192.0.2.1%Eth0", 1445}) {
			t.Errorf("scan lost the first target spelling: %+v", target)
		}
		return Result{Target: target.String(), ServerIP: target.Host, Authentication: "guest", Enumeration: "ok"}
	}
	code := runCLI(context.Background(), []string{path, "--guest", "--no-header", "--delay=0"}, deps)
	if code != 0 || calls != 1 {
		t.Fatalf("equivalent literal endpoints were scanned more than once: exit=%d scans=%d", code, calls)
	}
	if rows := parseTestTSV(t, out.String()); len(rows) != 1 || rows[0][0] != "[::ffff:192.0.2.1%Eth0]:1445" {
		t.Fatalf("output lost the first supplied literal endpoint: %q", out.String())
	}
}

func TestCLICIDRScansEachExpandedTargetAndReportsProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("192.0.2.0/30:1445\n192.0.2.1:1445\n192.0.2.0/31:1445\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"192.0.2.3/30:1445", path} {
		t.Run(input, func(t *testing.T) {
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			deps.stderrIsTerminal = true
			var attempted []Target
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				attempted = append(attempted, target)
				return Result{Target: target.String(), ServerIP: target.Host, Reachable: true,
					Authentication: "guest", Enumeration: "ok",
					Shares: []ShareResult{{Name: "data", Read: Allowed, Write: Denied}}}
			}
			code := runCLI(context.Background(), []string{input, "--guest", "--delay=0"}, deps)
			want := []Target{{"192.0.2.0", 1445}, {"192.0.2.1", 1445}, {"192.0.2.2", 1445}, {"192.0.2.3", 1445}}
			if code != 0 || !reflect.DeepEqual(attempted, want) {
				t.Fatalf("code=%d attempted=%#v; want %#v", code, attempted, want)
			}
			rows := parseTestTSV(t, out.String())
			if len(rows) != len(want)+1 {
				t.Fatalf("unexpected expanded result row count: %#v", rows)
			}
			for i, target := range want {
				if rows[i+1][0] != target.String() || rows[i+1][5] != "-" {
					t.Errorf("expanded result lost its literal endpoint: %#v", rows[i+1])
				}
			}
			if !strings.Contains(errOut.String(), "Progress: 100% (4/4 hosts completed)") || strings.Contains(out.String(), "Progress:") {
				t.Fatalf("incorrect progress for expanded unique endpoints: stdout=%q stderr=%q", out.String(), errOut.String())
			}
		})
	}
}

func TestCLIInvalidCIDRDoesNotPromptOrScan(t *testing.T) {
	const secret = "DO-NOT-ECHO-THIS"
	invalidList := filepath.Join(t.TempDir(), "invalid-hosts.txt")
	if err := os.WriteFile(invalidList, []byte("192.0.2.1\n192.0.2.0/"+secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oversizedList := filepath.Join(t.TempDir(), "oversized-hosts.txt")
	if err := os.WriteFile(oversizedList, []byte("10.0.0.0/16\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"192.0.2.0/" + secret, "10.0.0.0/15", "::/0", invalidList, oversizedList} {
		t.Run(input, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			prompts, scans := 0, 0
			deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
				prompts++
				return "", nil
			}
			deps.scan = func(context.Context, Target, Options) Result {
				scans++
				cancel()
				return Result{Error: "unexpected scan"}
			}
			code := runCLI(ctx, []string{input, "-u", "alice", "--delay=0"}, deps)
			if code != 2 || prompts != 0 || scans != 0 || out.Len() != 0 {
				t.Fatalf("invalid input must fail before credentials/network/output: code=%d prompts=%d scans=%d stdout=%q", code, prompts, scans, out.String())
			}
			if strings.Contains(errOut.String(), secret) || strings.Contains(errOut.String(), input) {
				t.Fatalf("diagnostic echoed an input value: %q", errOut.String())
			}
		})
	}
}
