package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseCLIFlagsAfterTarget(t *testing.T) {
	cfg, err := parseCLI(context.Background(), []string{"server.example:1445", "-u", `EXAMPLE\alice`, "-p", "", "--domain", "example", "--timeout", "7s", "--delay=0", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.options.Username != "alice" || cfg.options.Domain != "EXAMPLE" || !cfg.passwordSet || cfg.options.Password != "" {
		t.Fatalf("incorrect explicit credentials: %#v", cfg)
	}
	if !cfg.json || cfg.delay != 0 || cfg.options.Timeout != 7*time.Second || !reflect.DeepEqual(cfg.targets, []Target{{Host: "server.example", Port: 1445}}) {
		t.Fatalf("incorrect options: %#v", cfg)
	}
}

func TestCLIConcurrencyAndHostTimeoutOptions(t *testing.T) {
	cfg, err := parseCLI(context.Background(), []string{"server", "--guest"})
	if err != nil || cfg.delay != 0 || cfg.concurrency != 1 || cfg.options.HostTimeout != 30*time.Second || cfg.options.Timeout != 10*time.Second {
		t.Fatalf("unexpected scheduler defaults: %#v %v", cfg, err)
	}
	for _, args := range [][]string{
		{"--concurrency", "1024", "server", "--guest", "--host-timeout", "1", "--timeout", "2s"},
		{"server", "--concurrency=1024", "--host-timeout=1", "--timeout=2s", "--guest"},
	} {
		cfg, err = parseCLI(context.Background(), args)
		if err != nil || cfg.concurrency != 1024 || cfg.options.HostTimeout != time.Second || cfg.options.Timeout != 2*time.Second {
			t.Fatalf("scheduler options were not parsed independently: %#v %v", cfg, err)
		}
	}
	for _, value := range []string{"", "0", "-1", "1.5", "not-a-count", "999999999999999999999"} {
		if _, err := parseCLI(context.Background(), []string{"server", "--guest", "--concurrency", value}); err == nil {
			t.Errorf("accepted invalid concurrency %q", value)
		}
	}
	for _, value := range []string{"", "0", "-1", "1.5", "1s", "not-a-count", "9223372037", "999999999999999999999"} {
		if _, err := parseCLI(context.Background(), []string{"server", "--guest", "--host-timeout", value}); err == nil {
			t.Errorf("accepted invalid host timeout %q", value)
		}
	}
}

func TestParseIdentity(t *testing.T) {
	for _, tt := range []struct{ input, domain, user, wantDomain string }{
		{"alice", "", "alice", ""},
		{`EXAMPLE\alice`, "", "alice", "EXAMPLE"},
		{"alice@example.test", "EXAMPLE.TEST", "alice", "example.test"},
	} {
		user, domain, err := parseIdentity(tt.input, tt.domain)
		if err != nil || user != tt.user || domain != tt.wantDomain {
			t.Errorf("parseIdentity(%q): %q %q %v", tt.input, user, domain, err)
		}
	}
	for _, tt := range [][2]string{{"", ""}, {`\alice`, ""}, {"alice@", ""}, {"@example", ""}, {`EXAMPLE\alice`, "OTHER"}, {"alice@example", "other"}, {"a@b@c", ""}, {"a\nb", ""}, {" alice", ""}, {"ali\xffce", ""}, {"alice", "dom\xffain"}, {"alice@dom\xffain", ""}} {
		if _, _, err := parseIdentity(tt[0], tt[1]); err == nil {
			t.Errorf("accepted malformed/conflicting identity %q", tt)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  Target
	}{
		{"fileserver", Target{"fileserver", 445}},
		{"fileserver:1445", Target{"fileserver", 1445}},
		{"Server.Example.", Target{"Server.Example.", 445}},
		{"Fileserver.:1445", Target{"Fileserver.", 1445}},
		{"192.0.2.10", Target{"192.0.2.10", 445}},
		{"192.0.2.10:1445", Target{"192.0.2.10", 1445}},
		{"2001:db8::1", Target{"2001:db8::1", 445}},
		{"2001:0DB8::1:1445", Target{"2001:db8::1:1445", 445}},
		{"[2001:db8::1]:1445", Target{"2001:db8::1", 1445}},
		{"[::1]", Target{"::1", 445}},
		{"[FE80:0:0:0:0:0:0:1%Eth0]", Target{"fe80::1%Eth0", 445}},
		{"[fe80::1%eth0]:445", Target{"fe80::1%eth0", 445}},
	} {
		got, err := parseTarget(tt.input)
		if err != nil || got != tt.want {
			t.Errorf("parseTarget(%q) = %#v, %v; want %#v", tt.input, got, err, tt.want)
		}
		cfg, err := parseCLI(context.Background(), []string{tt.input, "--guest"})
		if err != nil || !reflect.DeepEqual(cfg.targets, []Target{tt.want}) {
			t.Errorf("CLI target %q = %#v, %v; want %#v", tt.input, cfg.targets, err, tt.want)
		}
	}
	for _, input := range []string{"", "https://server", "smb://server/share", `\\server\share`, "../hosts.txt", "server:0", "server:65536", "server:-1", "server:abc", "server:", ":445", "[server]:445", "[192.0.2.10]", "[192.0.2.10]:445", "server:part:445", "[::1]:", "[::1]:-1", "[::1]:445:1445", "server\t", "server\x1b[31m", "bad host", "-host", "host-", "host..name", "999.2.3.4", "192.168.001.1", "host/path", "user@host", "host#comment", "[fe80::1%bad!]:445", "fe80::1%eth0:445"} {
		if _, err := parseTarget(input); err == nil {
			t.Errorf("accepted malformed target %q", input)
		}
	}
}

func TestTargetListBOMCommentsDedupAndPorts(t *testing.T) {
	input := "\ufeff# hosts\r\n\n Server.Example \nserver.example:445\nserver.example:1445\n2001:db8::1\n[2001:0db8::1]:445\n"
	got, err := parseTargetList(context.Background(), strings.NewReader(input))
	want := []Target{{"Server.Example", 445}, {"server.example", 1445}, {"2001:db8::1", 445}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, %v; want %#v", got, err, want)
	}
	for _, input := range []string{"# nothing\n", "good\nbad:password-secret\n", "\xff\n", strings.Repeat("x", 70000)} {
		if _, err := parseTargetList(context.Background(), strings.NewReader(input)); err == nil || strings.Contains(err.Error(), "password-secret") {
			t.Errorf("malformed list must fail without including values: %v", err)
		}
	}
}

type targetListReaderFunc func([]byte) (int, error)

func (f targetListReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestTargetListCancellationDiscardsPartialTargets(t *testing.T) {
	for _, pending := range []string{"10.0.0.0/16\n", "# ignored\n", "0.0.0.0/0\n", ""} {
		t.Run(pending, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			reader := targetListReaderFunc(func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					return copy(p, "first-server\n"), nil
				}
				if reads != 2 {
					t.Fatal("continued reading after cancellation")
				}
				cancel()
				return copy(p, pending), io.EOF
			})
			targets, err := parseTargetList(ctx, reader)
			if !errors.Is(err, context.Canceled) || targets != nil || reads != 2 {
				t.Fatalf("cancellation returned partial targets or wrong error: targets=%v reads=%d error=%v", targets, reads, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := targetListReaderFunc(func([]byte) (int, error) {
		t.Fatal("already canceled parser read input")
		return 0, io.EOF
	})
	if targets, err := parseTargetList(ctx, reader); targets != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled parser: targets=%v error=%v", targets, err)
	}
}

func TestCLIParsingCancellationHasNoCredentialOrScanSideEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("0.0.0.0/0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
		}
		cancel()
		var out, diagnostics bytes.Buffer
		deps := testCLIDeps(&out, &diagnostics)
		deps.lookupEnv = func(string) (string, bool) {
			t.Fatal("canceled parsing accessed credentials")
			return "", false
		}
		deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
			t.Fatal("canceled parsing prompted for a password")
			return "", nil
		}
		deps.scan = func(context.Context, Target, Options) Result {
			t.Fatal("canceled parsing started a scan")
			return Result{}
		}
		if code := runCLI(ctx, []string{path, "-u", "alice"}, deps); code != 1 || out.Len() != 0 || diagnostics.String() != "gosmb: canceled\n" {
			t.Fatalf("canceled parsing: exit=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
		}
	}
}

func TestAbsoluteAndRelativeHostnamesRemainDistinctTargets(t *testing.T) {
	input := "Fileserver.\nfileserver\nFILESERVER.:445\nFILESERVER\n"
	want := []Target{{"Fileserver.", 445}, {"fileserver", 445}}
	got, err := parseTargetList(context.Background(), strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("absolute DNS name was altered or conflated with a relative name: %#v, %v", got, err)
	}
}

func TestCLIMaximumLengthHostnameWithPort(t *testing.T) {
	host := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	for _, spelling := range []string{host, host + "."} {
		for _, port := range []string{"445", "65535"} {
			cfg, err := parseCLI(context.Background(), []string{spelling + ":" + port, "--guest"})
			if err != nil || len(cfg.targets) != 1 || cfg.targets[0].String() != spelling+":"+port {
				t.Fatalf("valid long endpoint was rejected as a filename: targets=%#v error=%v", cfg.targets, err)
			}
		}
	}
	for _, invalid := range []string{host + "x:445", strings.Repeat("a", 64) + ".example:445"} {
		if _, err := parseCLI(context.Background(), []string{invalid, "--guest"}); err == nil {
			t.Fatal("overlong DNS name or label bypassed validation")
		}
	}
}

func TestCLIFileDetectionDoesNotHideCIDRBehindNonDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("192.0.2.0", []byte("irrelevant existing file"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseCLI(context.Background(), []string{"192.0.2.0/30", "--guest"})
	if err != nil || len(cfg.targets) != 4 || cfg.targets[0] != (Target{"192.0.2.0", 445}) {
		t.Fatalf("CIDR was rejected because its address names a local file: targets=%#v error=%v", cfg.targets, err)
	}
	// A regular file at the complete positional path still takes precedence.
	if err := os.WriteFile("192.0.2.1", []byte("fileserver\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = parseCLI(context.Background(), []string{"192.0.2.1", "--guest"})
	if err != nil || !reflect.DeepEqual(cfg.targets, []Target{{"fileserver", 445}}) {
		t.Fatalf("existing host-list file lost precedence: targets=%#v error=%v", cfg.targets, err)
	}
}

func TestCLIUnreadableHostFileDoesNotBecomeNetworkTarget(t *testing.T) {
	t.Chdir(t.TempDir())
	const candidate = "fileserver"
	if err := os.WriteFile(candidate, []byte("another-server\n"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(candidate, 0600)
	if file, err := os.Open(candidate); err == nil {
		file.Close()
		t.Skip("this environment permits reading a mode-000 file")
	}
	if _, err := parseCLI(context.Background(), []string{candidate, "--guest"}); err == nil {
		t.Fatal("unreadable existing host-list file was treated as a network target")
	}
}

func TestCLIAbsoluteHostnameReachesScanAndOutputUnchanged(t *testing.T) {
	const hostname = "Fileserver.Example."
	const endpoint = hostname + ":1445"
	for _, jsonOutput := range []bool{false, true} {
		var out, diagnostics bytes.Buffer
		deps := testCLIDeps(&out, &diagnostics)
		deps.scan = func(_ context.Context, target Target, _ Options) Result {
			if target.Host != hostname || target.String() != endpoint {
				t.Errorf("scan received a different DNS target: %q", target.String())
			}
			return Result{Target: target.String(), ServerIP: "192.0.2.1", Authentication: "guest", Enumeration: "ok"}
		}
		args := []string{endpoint, "--guest", "--no-header"}
		if jsonOutput {
			args = append(args, "--json")
		} else {
			args = append(args, "--tsv")
		}
		if code := runCLI(context.Background(), args, deps); code != 0 {
			t.Fatalf("absolute hostname scan failed: exit=%d diagnostics=%q", code, diagnostics.String())
		}
		if jsonOutput {
			var results []Result
			if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 || results[0].Target != endpoint {
				t.Fatalf("JSON lost the supplied absolute endpoint: %q (%v)", out.String(), err)
			}
		} else if rows := parseTestTSV(t, out.String()); len(rows) != 1 || rows[0][6] != hostname {
			t.Fatalf("text lost the supplied absolute hostname: %q", out.String())
		}
	}
}

func TestPositionalTargetFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("server\nSERVER\nother:1445\n192.0.2.10\n192.0.2.10:2445\n2001:db8::1\n[2001:db8::1]:3445\n"), 0600); err != nil {
		t.Fatal(err)
	}
	want := []Target{{"server", 445}, {"other", 1445}, {"192.0.2.10", 445}, {"192.0.2.10", 2445}, {"2001:db8::1", 445}, {"2001:db8::1", 3445}}
	for _, args := range [][]string{{path, "-u", "alice", "-p", "secret"}, {"-u", "alice", "-p", "secret", path}} {
		cfg, err := parseCLI(context.Background(), args)
		if err != nil || !reflect.DeepEqual(cfg.targets, want) {
			t.Fatalf("file parsing failed: %#v %v", cfg.targets, err)
		}
	}
	for _, args := range [][]string{
		{path + ".missing", "-u", "alice"},
		{filepath.Dir(path), "-u", "alice"},
		{path, "other", "-u", "alice"},
	} {
		if _, err := parseCLI(context.Background(), args); err == nil {
			t.Fatalf("accepted invalid file invocation: %#v", args)
		}
	}
}

func TestCLIRejectsRemovedOptions(t *testing.T) {
	for _, args := range [][]string{
		{"server", "--guest", "--port", "1445"},
		{"--port=1445", "server", "--guest"},
		{"--file", "servers.txt", "--guest"},
		{"--guest", "--file=servers.txt"},
	} {
		if _, err := parseCLI(context.Background(), args); err == nil || !strings.Contains(err.Error(), "unknown option") {
			t.Fatalf("removed option was not rejected: args=%q err=%v", args, err)
		}
	}
}

func TestCLIInvalidArgumentsDoNotEchoSecrets(t *testing.T) {
	secret := "DO-NOT-ECHO-THIS"
	for _, args := range [][]string{
		{"host", "-u", "alice", "-p", secret, "--unknown=" + secret},
		{"host:" + secret, "-u", "alice"},
		{"host", "-u", "alice", "--timeout", secret},
		{"host", "-u", "alice", "--port", secret},
		{"host", "-u", "alice", "--delay", secret},
		{"--file", secret, "-u", "alice"},
		{"host", "-u", "alice", "-p", secret, secret},
	} {
		_, err := parseCLI(context.Background(), args)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("diagnostic must fail without secret: %v", err)
		}
	}
}

func testCLIDeps(out, errOut io.Writer) cliDependencies {
	return cliDependencies{
		stdin: strings.NewReader(""), stdout: out, stderr: errOut,
		lookupEnv: func(string) (string, bool) { return "", false },
		prompt:    func(context.Context, io.Reader, io.Writer) (string, error) { return "prompt-secret", nil },
		scan: func(_ context.Context, target Target, _ Options) Result {
			return Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok"}
		},
	}
}

func TestCLIPasswordSourcesAndNoSecretOutput(t *testing.T) {
	for _, tt := range []struct {
		name   string
		args   []string
		env    string
		envSet bool
		want   string
		prompt bool
	}{
		{"explicit", []string{"-p", "explicit-secret"}, "env-secret", true, "explicit-secret", false},
		{"explicit empty", []string{"-p", ""}, "env-secret", true, "", false},
		{"literal unicode and whitespace", []string{"-p", "  p\täss🔑word\r\n  "}, "env-secret", true, "  p\täss🔑word\r\n  ", false},
		{"explicit overrides invalid environment", []string{"-p", "explicit-secret"}, "invalid-\xff", true, "explicit-secret", false},
		{"environment", nil, "env-secret", true, "env-secret", false},
		{"environment empty", nil, "", true, "", false},
		{"prompt", nil, "", false, "prompt-secret", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			deps.lookupEnv = func(key string) (string, bool) {
				if key != "GOSMB_PASSWORD" {
					t.Fatalf("unexpected environment access: %q", key)
				}
				return tt.env, tt.envSet
			}
			prompted := false
			deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
				prompted = true
				return "prompt-secret", nil
			}
			deps.scan = func(_ context.Context, target Target, opts Options) Result {
				if opts.Password != tt.want {
					t.Fatal("wrong password source selected")
				}
				return Result{Target: target.String(), Authentication: "failed", Enumeration: "not_attempted", Error: "server reflected " + opts.Password}
			}
			args := append([]string{"host", "-u", "alice", "--json"}, tt.args...)
			if code := runCLI(context.Background(), args, deps); code != 1 || prompted != tt.prompt {
				t.Fatalf("code=%d prompted=%v", code, prompted)
			}
			if tt.want != "" && strings.Contains(out.String()+errOut.String(), tt.want) {
				t.Fatal("secret appeared in output")
			}
			var results []Result
			if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 {
				t.Fatalf("invalid JSON results: %v", err)
			}
		})
	}
}

func TestCLIRejectsInvalidPasswordEncodingBeforeScanning(t *testing.T) {
	const invalidPassword = "secret-\xff-must-not-appear"
	for _, source := range []string{"argument", "environment", "prompt"} {
		t.Run(source, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stderrIsTerminal = true
			args := []string{"192.0.2.0/30", "-u", "alice", "--delay=0"}
			if source == "argument" {
				args = append(args, "-p", invalidPassword)
			}
			deps.lookupEnv = func(string) (string, bool) {
				if source == "argument" {
					t.Fatal("explicit password triggered an environment lookup")
				}
				return invalidPassword, source == "environment"
			}
			deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
				if source != "prompt" {
					t.Fatal("provided password triggered a prompt")
				}
				return invalidPassword, nil
			}
			scans := 0
			deps.scan = func(context.Context, Target, Options) Result {
				scans++
				return Result{Authentication: "authenticated", Enumeration: "ok"}
			}
			code := runCLI(context.Background(), args, deps)
			if code != 2 || scans != 0 || out.Len() != 0 || diagnostics.String() != "gosmb: password must be valid UTF-8\n" {
				t.Fatalf("invalid password was not rejected before scan/output: exit=%d scans=%d stdout=%q stderr=%q", code, scans, out.String(), diagnostics.String())
			}
		})
	}
}

func TestCLIPasswordCancellationPrecedesEncodingValidation(t *testing.T) {
	for _, source := range []string{"environment", "prompt"} {
		t.Run(source, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.lookupEnv = func(string) (string, bool) {
				if source == "environment" {
					cancel()
					return "invalid-\xff", true
				}
				return "", false
			}
			deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
				if source != "prompt" {
					t.Fatal("environment password triggered a prompt")
				}
				cancel()
				return "invalid-\xff", nil
			}
			deps.scan = func(context.Context, Target, Options) Result {
				t.Fatal("canceled password resolution started a scan")
				return Result{}
			}
			code := runCLI(ctx, []string{"host", "-u", "alice"}, deps)
			if code != 1 || out.Len() != 0 || diagnostics.String() != "gosmb: canceled\n" {
				t.Fatalf("password validation took precedence over cancellation: exit=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
			}
		})
	}
}

func TestCLISequentialOneAttemptAndExitCodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("first\nsecond\nFIRST\nthird\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	var attempted []string
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		attempted = append(attempted, target.Host)
		result := Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "denied", Accessible: Denied, Read: Denied, Write: Unknown}}}
		if target.Host == "second" {
			result.Enumeration = "denied"
		}
		return result
	}
	code := runCLI(context.Background(), []string{path, "-u", "alice", "-p", "secret", "--delay", "0"}, deps)
	if code != 1 || !reflect.DeepEqual(attempted, []string{"first", "second", "third"}) {
		t.Fatalf("code=%d attempted=%v", code, attempted)
	}
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		return Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "denied", Accessible: Denied}}}
	}
	if code = runCLI(context.Background(), []string{"host", "-u", "alice", "-p", ""}, deps); code != 0 {
		t.Fatalf("share denial should not fail successful enumeration: %d", code)
	}
}

func TestCLICancellationInterruptsDelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	calls := 0
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		calls++
		cancel()
		return Result{Target: target.String(), Authentication: "authenticated", Enumeration: "ok"}
	}
	if code := runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--delay", "1h", "--json"}, deps); code != 1 || calls != 1 {
		t.Fatalf("cancellation did not stop further targets: code=%d calls=%d", code, calls)
	}
	var results []Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 {
		t.Fatalf("partial JSON invalid: %v", err)
	}
}

func TestCLICancellationDuringFinalOutputReturnsFailure(t *testing.T) {
	for _, phase := range []string{"JSON", "progress footer"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				return Result{Target: target.String(), Authentication: "guest", Enumeration: "ok",
					Shares: []ShareResult{{Name: "data", Read: Allowed, Write: Denied}}}
			}
			args := []string{"host", "--guest"}
			if phase == "JSON" {
				args = append(args, "--json", "--no-progress")
				deps.stdout = outputWriteFunc(func(data []byte) (int, error) {
					cancel()
					return out.Write(data)
				})
			} else {
				deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
				args = append(args, "--tsv")
				deps.stderr = outputWriteFunc(func(data []byte) (int, error) {
					if bytes.Contains(data, []byte("Progress:")) && bytes.HasSuffix(data, []byte{'\n'}) {
						cancel()
					}
					return diagnostics.Write(data)
				})
			}
			if code := runCLI(ctx, args, deps); ctx.Err() == nil || code != 1 {
				t.Fatalf("cancellation during final output returned success: canceled=%v exit=%d", ctx.Err() != nil, code)
			}
			if phase == "JSON" {
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 || len(results[0].Shares) != 1 || results[0].Shares[0].Name != "data" {
					t.Fatalf("late cancellation lost completed JSON results: %q, error=%v", out.String(), err)
				}
			} else if rows := parseTestTSV(t, out.String()); len(rows) != 2 || rows[1][1] != "data" {
				t.Fatalf("late cancellation lost completed text results: %q", out.String())
			}
		})
	}
}

func TestHelpAndPromptErrorDoNotScan(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	deps.scan = func(context.Context, Target, Options) Result { t.Fatal("must not scan"); return Result{} }
	if code := runCLI(context.Background(), []string{"--help"}, deps); code != 0 || !strings.Contains(out.String(), "Columns:") {
		t.Fatalf("help failed: %d", code)
	}
	deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
		return "", errors.New("secret-in-provider-error")
	}
	if code := runCLI(context.Background(), []string{"host", "-u", "alice"}, deps); code != 2 || strings.Contains(errOut.String(), "secret-in-provider-error") {
		t.Fatalf("unsafe prompt error: %d", code)
	}
}

func TestCLIPasswordPromptCancellationDoesNotScan(t *testing.T) {
	for _, when := range []string{"before_prompt", "during_prompt", "ctrl_c", "deadline"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			deps.scan = func(context.Context, Target, Options) Result {
				t.Fatal("canceled password prompt must not scan")
				return Result{}
			}
			deps.prompt = func(promptCtx context.Context, _ io.Reader, _ io.Writer) (string, error) {
				if when == "before_prompt" {
					t.Fatal("already canceled command must not prompt")
				}
				if promptCtx != ctx {
					t.Fatal("prompt did not receive command context")
				}
				if when == "during_prompt" {
					cancel()
					return "secret", nil // Cancellation also wins over completed input.
				}
				if when == "deadline" {
					return "", context.DeadlineExceeded
				}
				return "", context.Canceled
			}
			if when == "before_prompt" {
				cancel()
			}
			if code := runCLI(ctx, []string{"host", "-u", "alice"}, deps); code != 1 {
				t.Fatalf("cancellation exit code=%d; want 1", code)
			}
			if out.Len() != 0 || errOut.String() != "gosmb: canceled\n" {
				t.Fatalf("unexpected cancellation output: stdout=%q stderr=%q", out.String(), errOut.String())
			}
		})
	}
}

func TestPasswordPromptAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	password, err := promptPassword(ctx, strings.NewReader("unused"), &out)
	if !errors.Is(err, context.Canceled) || password != "" || out.Len() != 0 {
		t.Fatalf("already canceled prompt: err=%v output=%q", err, out.String())
	}
}

func TestIncompleteScanReturnsFailureDespiteSuccessfulEnumeration(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		return Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok", Error: "scan canceled during access checks"}
	}
	if code := runCLI(context.Background(), []string{"host", "-u", "alice", "-p", ""}, deps); code != 1 {
		t.Fatalf("incomplete scan should fail: %d", code)
	}
}

func TestGuestFlagsBeforeAndAfterTarget(t *testing.T) {
	for _, args := range [][]string{
		{"server", "--guest"},
		{"--guest", "server", "--json"},
		{"server:1445", "--guest", "--delay", "0"},
	} {
		cfg, err := parseCLI(context.Background(), args)
		if err != nil || !cfg.options.Guest || len(cfg.targets) != 1 || cfg.options.Username != "" || cfg.options.Password != "" || cfg.options.Domain != "" || cfg.passwordSet {
			t.Fatalf("guest invocation failed: %#v %v", cfg, err)
		}
	}
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("server\nSERVER\nother\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{path, "--guest"}, {"--guest", path}} {
		cfg, err := parseCLI(context.Background(), args)
		if err != nil || !cfg.options.Guest || len(cfg.targets) != 2 {
			t.Fatalf("guest list invocation failed: %#v %v", cfg, err)
		}
	}
}

func TestGuestRejectsEveryExplicitCredentialOption(t *testing.T) {
	for _, option := range []string{"-u", "--user", "--username", "-p", "--pass", "--password", "-d", "--domain"} {
		for _, value := range []string{"", "credential-must-not-be-echoed"} {
			for _, args := range [][]string{
				{"host", "--guest", option, value},
				{option, value, "host", "--guest"},
				{"host", option + "=" + value, "--guest"},
			} {
				_, err := parseCLI(context.Background(), args)
				if err == nil || !strings.Contains(err.Error(), "cannot be combined") || strings.Contains(err.Error(), "credential-must-not-be-echoed") {
					t.Fatalf("guest credentials were accepted or echoed: %v", err)
				}
			}
		}
	}
	if _, err := parseCLI(context.Background(), []string{"host", "--guest=true"}); err == nil {
		t.Fatal("--guest must be an explicit flag without a value")
	}
	if _, err := parseCLI(context.Background(), []string{"host"}); err == nil {
		t.Fatal("user mode must still require a username")
	}
}

func TestGuestNeverLooksUpOrPromptsForCredentials(t *testing.T) {
	t.Setenv("GOSMB_PASSWORD", "environment-secret-must-be-ignored")
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	deps.lookupEnv = func(string) (string, bool) {
		t.Fatal("guest mode must not look up credentials")
		return "environment-secret-must-be-ignored", true
	}
	deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
		t.Fatal("guest mode must not prompt")
		return "", nil
	}
	calls := 0
	deps.scan = func(_ context.Context, target Target, opts Options) Result {
		calls++
		if !opts.Guest || opts.Username != "" || opts.Password != "" || opts.Domain != "" {
			t.Fatal("guest mode passed user credentials to scanner")
		}
		return Result{Target: target.String(), Reachable: true, Authentication: "guest", Enumeration: "ok"}
	}
	if code := runCLI(context.Background(), []string{"host", "--guest", "--json"}, deps); code != 0 || calls != 1 {
		t.Fatalf("guest scan failed or retried: code=%d calls=%d", code, calls)
	}
	var results []Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 || results[0].Authentication != "guest" {
		t.Fatalf("guest JSON label missing: %#v %v", results, err)
	}
	if strings.Contains(out.String()+errOut.String(), "environment-secret-must-be-ignored") {
		t.Fatal("guest mode exposed environment password")
	}
}

func TestGuestExitCodesRequireSuccessfulEnumeration(t *testing.T) {
	for _, tt := range []struct {
		name      string
		guest     bool
		auth      string
		enum      string
		err       string
		timedOut  bool
		want      int
		guestCell string
	}{
		{"explicit guest success", true, "guest", "ok", "", false, 0, "N/A"},
		{"guest enumeration denied", true, "guest", "denied", "", false, 1, "N/A"},
		{"guest incomplete scan", true, "guest", "ok", "canceled", false, 1, "N/A"},
		{"guest auth failed", true, "failed", "not_attempted", "", false, 1, "N/A"},
		{"guest timeout before authentication", true, TimedOut, TimedOut, "", true, 1, "N/A"},
		{"guest timeout after authentication", true, "guest", TimedOut, "", true, 1, "N/A"},
		{"anonymous is not guest", true, "anonymous", "ok", "", false, 1, "N/A"},
		{"user auth is not explicit guest", true, "authenticated", "ok", "", false, 1, "N/A"},
		{"server guest fallback accepted", false, "guest", "ok", "", false, 0, "TRUE"},
		{"server guest fallback enumeration denied", false, "guest", "denied", "", false, 1, "TRUE"},
		{"user anonymous fallback rejected", false, "anonymous", "ok", "", false, 1, "FALSE"},
		{"user auth unchanged", false, "authenticated", "ok", "", false, 0, "FALSE"},
	} {
		for _, format := range []struct {
			name     string
			terminal bool
		}{{"TSV", false}, {"aligned", true}} {
			t.Run(tt.name+"/"+format.name, func(t *testing.T) {
				var out, errOut bytes.Buffer
				deps := testCLIDeps(&out, &errOut)
				deps.stdoutIsTerminal = format.terminal
				calls := 0
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					calls++
					return Result{Target: target.String(), Reachable: true, Authentication: tt.auth, Enumeration: tt.enum, Error: tt.err, TimedOut: tt.timedOut, GuestFallback: tt.auth == "guest" && !tt.guest}
				}
				args := []string{"host", "--guest", "--no-header"}
				if !tt.guest {
					args = []string{"host", "-u", "alice", "-p", "", "--no-header"}
				}
				if format.name == "TSV" {
					args = append(args, "--tsv")
				}
				if code := runCLI(context.Background(), args, deps); code != tt.want || calls != 1 {
					t.Fatalf("code=%d calls=%d, want code=%d and one call", code, calls, tt.want)
				}
				if fields := strings.Fields(out.String()); len(fields) != 7 || fields[4] != tt.guestCell {
					t.Fatalf("guest column = %q; want %q", out.String(), tt.guestCell)
				}
			})
		}
	}
}

func TestHelpExplainsColumnsAndAccessStatuses(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	if code := runCLI(context.Background(), []string{"--help"}, deps); code != 0 {
		t.Fatalf("help failed: %d", code)
	}
	for _, expected := range []string{"--guest", "Columns:", "TARGET_IP", "Supplied or connected IP plus port", "UNKNOWN:port if unavailable", "[IPv6]:port", "SHARE", "Share name", "READ", "Root listing permission", "WRITE", "Permission to add files at root", "metadata only; no write test", "GUEST", "TRUE when supplied credentials are accepted as Guest", "N/A when --guest is used", "HOSTNAME", "Supplied hostname; - for literal IP targets (no reverse DNS)", "TRUE     Allowed", "FALSE    Denied", "UNKNOWN  Permission metadata missing/unsupported, or connection/login/access check failed", "TIMEOUT  Check timed out", "N/A      Not applicable"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("help missing output explanation %q", expected)
		}
	}
	for _, expected := range []string{"STATUS", "Scan outcome; codes below", "STATUS codes (table and TSV):"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("help missing text status explanation %q", expected)
		}
	}
	for _, label := range statusLabels[1:] {
		_, description, found := strings.Cut(out.String(), "\n  "+label+" ")
		if !found || strings.TrimSpace(strings.SplitN(description, "\n", 2)[0]) == "" {
			t.Errorf("help missing description for STATUS code %q", label)
		}
	}
	if strings.Contains(out.String(), "Interactive column limits") || strings.Contains(out.String(), "TARGET_IP 47;") {
		t.Error("help still includes the removed column-limits section")
	}
}

func TestServerGuestFallbackReportsActualSessionWithoutRetry(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := testCLIDeps(&out, &errOut)
	deps.stdoutIsTerminal = true
	calls := 0
	deps.scan = func(_ context.Context, target Target, opts Options) Result {
		calls++
		if opts.Guest || opts.Username != "alice" {
			t.Fatal("frontend changed the supplied-credential request into a guest request")
		}
		return Result{Target: target.String(), ServerIP: "192.0.2.10", Reachable: true, Authentication: "guest", GuestFallback: true, Enumeration: "ok", Shares: []ShareResult{{Name: "public", Accessible: Allowed, Read: Allowed, Write: Denied}}}
	}
	if code := runCLI(context.Background(), []string{"host", "-u", "alice", "-p", "secret", "--json", "--no-header"}, deps); code != 0 || calls != 1 {
		t.Fatalf("server guest fallback failed or caused retry: code=%d calls=%d", code, calls)
	}
	var results []Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 {
		t.Fatalf("invalid fallback JSON: %v", err)
	}
	got := results[0]
	if got.Authentication != "guest" || !got.GuestFallback || got.ServerIP != "192.0.2.10" || len(got.Shares) != 1 || got.Shares[0].Read != Allowed || got.Shares[0].Write != Denied {
		t.Fatalf("fallback JSON lost actual session permissions: %#v", got)
	}
}

func TestCLITerminalAlignsSevenColumnsAcrossServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	const longHost = "fileserver-with-a-hostname-longer-than-the-default-column.example.com"
	if err := os.WriteFile(path, []byte("first\n[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535\n"+longHost+":1445\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, noHeader := range []bool{false, true} {
		var out, errOut bytes.Buffer
		deps := testCLIDeps(&out, &errOut)
		deps.stdoutIsTerminal = true
		deps.scan = func(_ context.Context, target Target, _ Options) Result {
			if target.Host == "first" {
				return Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "a", Accessible: Allowed, Read: Allowed, Write: Denied}}}
			}
			if target.Host == longHost {
				return Result{Target: target.String(), ServerIP: "192.0.2.2", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "long-host-share", Accessible: Allowed, Read: Allowed, Write: Denied}}}
			}
			return Result{Target: target.String(), ServerIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reachable: true, Authentication: "guest", GuestFallback: true, Enumeration: "ok", Shares: []ShareResult{{Name: "a longer shared folder", Accessible: Denied, Read: Denied, Write: Denied}}}
		}
		args := []string{path, "-u", "alice", "-p", "", "--delay", "0"}
		wantRows := [][]string{
			{"192.0.2.1:445", "a", "TRUE", "FALSE", "FALSE", "OK", "first"},
			{"[ffff:ffff:ffff:ffff…", "a longer shared fol…", "FALSE", "FALSE", "TRUE", "OK", "-"},
			{"192.0.2.2:1445", "long-host-share", "TRUE", "FALSE", "FALSE", "OK", longHost},
		}
		if noHeader {
			args = append(args, "--no-header")
		} else {
			wantRows = append([][]string{{"TARGET_IP", "SHARE", "READ", "WRITE", "GUEST", "STATUS", "HOSTNAME"}}, wantRows...)
		}
		if code := runCLI(context.Background(), args, deps); code != 0 || errOut.Len() != 0 {
			t.Fatalf("terminal output failed: code=%d stderr=%q", code, errOut.String())
		}
		if strings.ContainsRune(out.String(), '\t') || !strings.HasSuffix(out.String(), "\n") {
			t.Fatalf("terminal output must use spaces, not raw tabs: %q", out.String())
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != len(wantRows) {
			t.Fatalf("terminal output has missing/extra rows: %q", out.String())
		}
		starts := make([]int, 7)
		for i, row := range wantRows {
			cursor := 0
			for column, value := range row {
				offset := strings.Index(lines[i][cursor:], value)
				if offset < 0 || strings.Trim(lines[i][cursor:cursor+offset], " ") != "" || (column > 0 && offset == 0) {
					t.Fatalf("terminal row does not preserve seven separated cells: %q", lines[i])
				}
				start := cursor + offset
				// This fixture uses ASCII plus the single-cell ellipsis. Count
				// visible runes so its UTF-8 bytes do not look like shifted columns.
				columnStart := utf8.RuneCountInString(lines[i][:start])
				if i == 0 {
					starts[column] = columnStart
				} else if starts[column] != columnStart {
					t.Fatalf("column %d starts at %d on first row but %d on row %d: %q", column, starts[column], columnStart, i, out.String())
				}
				cursor = start + len(value)
			}
			if strings.Trim(lines[i][cursor:], " ") != "" {
				t.Fatalf("extra terminal column or prose: %q", lines[i])
			}
		}
	}
}

func TestCLIProducesOneTSVHeaderWithStatusesAndNoScanDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("first:1445\nsecond\nthird\nmissing:3445\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const header = "TARGET_IP\tSHARE\tREAD\tWRITE\tGUEST\tSTATUS\tHOSTNAME\n"
	const data = "192.0.2.1:1445\tpublic data with a complete long share name\tTRUE\tUNKNOWN\tFALSE\tCHECK_FAILED\tfirst\n" +
		"192.0.2.1:1445\tprivate\tFALSE\tFALSE\tFALSE\tOK\tfirst\n" +
		"192.0.2.2:445\t-\tUNKNOWN\tUNKNOWN\tFALSE\tAUTH_FAILED\tsecond\n" +
		"192.0.2.3:445\t-\tUNKNOWN\tUNKNOWN\tFALSE\tNO_SHARES\tthird\n" +
		"UNKNOWN:3445\t-\tUNKNOWN\tUNKNOWN\tFALSE\tCONNECT_FAILED\tmissing\n"
	for _, mode := range []string{"header", "no-header-before", "no-header-after", "forced-tsv-terminal", "forced-tsv-terminal-no-header"} {
		t.Run(mode, func(t *testing.T) {
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				switch target.Host {
				case "first":
					return Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{
						{Name: "public data with a complete long share name", Accessible: Allowed, Read: Allowed, Write: Unknown, Comment: "comments stay out of TSV", Error: "root maximum-access metadata unavailable"},
						{Name: "private", Accessible: Denied, Read: Denied, Write: Denied, Error: "root listing denied"},
					}}
				case "second":
					return Result{Target: target.String(), ServerIP: "192.0.2.2", Reachable: true, Authentication: "failed", Enumeration: "not_attempted", Error: "login failed: do-not-leak-password"}
				case "missing":
					return Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Error: "name resolution failed"}
				default:
					return Result{Target: target.String(), ServerIP: "192.0.2.3", Reachable: true, Authentication: "authenticated", Enumeration: "ok"}
				}
			}
			args := []string{path, "-u", "alice", "-p", "do-not-leak-password", "--delay", "0", "--tsv"}
			want := data
			switch mode {
			case "header":
				want = header + data
			case "forced-tsv-terminal":
				deps.stdoutIsTerminal = true
				want = header + data
			case "forced-tsv-terminal-no-header":
				deps.stdoutIsTerminal = true
				args = append(args, "--no-header")
			case "no-header-before":
				args = append([]string{"--no-header"}, args...)
			case "no-header-after":
				args = append(args, "--no-header")
			}
			if code := runCLI(context.Background(), args, deps); code != 1 {
				t.Fatalf("expected host failure status: %d", code)
			}
			if out.String() != want {
				t.Fatalf("stdout has repeated headers, missing rows, or non-TSV content:\n%q\nwant:\n%q", out.String(), want)
			}
			parseTestTSV(t, out.String())
			if errOut.Len() != 0 {
				t.Errorf("TSV duplicated scan outcomes on stderr: %q", errOut.String())
			}
			if strings.Contains(out.String()+errOut.String(), "do-not-leak-password") || strings.Contains(errOut.String(), "comments stay out") {
				t.Fatal("secret or unused share comments appeared in output")
			}
		})
	}
}

func TestCLIStatusColorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, flag, noColor, terminal string
		tty, unsupported, wantColor   bool
	}{
		{name: "terminal", tty: true, wantColor: true},
		{name: "redirected"},
		{name: "forced TSV", flag: "--tsv", tty: true},
		{name: "JSON", flag: "--json", tty: true},
		{name: "NO_COLOR", tty: true, noColor: "1"},
		{name: "dumb terminal", tty: true, terminal: "dumb"},
		{name: "unsupported console", tty: true, unsupported: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stdoutIsTerminal = tc.tty
			deps.lookupEnv = func(key string) (string, bool) {
				switch key {
				case "NO_COLOR":
					return tc.noColor, tc.noColor != ""
				case "TERM":
					return tc.terminal, tc.terminal != ""
				default:
					t.Fatalf("unexpected environment lookup: %s", key)
					return "", false
				}
			}
			prepared, restored := false, false
			deps.enableColor = func() (func(), bool) {
				prepared = true
				return func() { restored = true }, !tc.unsupported
			}
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				return Result{Target: target.String(), Authentication: "authenticated", Enumeration: "ok",
					Shares: []ShareResult{{Name: "data", Read: Allowed, Write: Denied}}}
			}
			args := []string{"host", "-u", "alice", "-p", ""}
			if tc.flag != "" {
				args = append(args, tc.flag)
			}
			if code := runCLI(context.Background(), args, deps); code != 0 {
				t.Fatalf("scan failed: exit=%d stderr=%q", code, diagnostics.String())
			}
			if tc.wantColor {
				if !strings.Contains(out.String(), "\x1b[32mTRUE\x1b[0m") || strings.Count(out.String(), "\x1b[31mFALSE\x1b[0m") != 2 {
					t.Fatalf("terminal statuses were not colored: %q", out.String())
				}
			} else if strings.ContainsRune(out.String(), '\x1b') {
				t.Fatalf("color leaked into plain output: %q", out.String())
			}
			wantPrepare := tc.wantColor || tc.unsupported
			if prepared != wantPrepare || restored != prepared {
				t.Fatalf("unexpected terminal lifecycle: prepared=%t restored=%t", prepared, restored)
			}
		})
	}
}

func TestCLIStreamsTextBeforeNextHostAndKeepsProgressOffStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name, flag           string
		stdoutTTY, stderrTTY bool
		json, progress       bool
	}{
		{"terminal", "", true, true, false, true},
		{"piped-table", "", false, true, false, true},
		{"piped-tsv", "--tsv", false, true, false, true},
		{"piped-json", "--json", false, true, true, true},
		{"forced-tsv", "--tsv", true, true, false, true},
		{"json", "--json", true, true, true, true},
		{"redirected-stderr", "", true, false, false, false},
		{"no-progress", "--no-progress", true, true, false, false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			deps := testCLIDeps(&out, &errOut)
			deps.stdoutIsTerminal, deps.stderrIsTerminal = mode.stdoutTTY, mode.stderrTTY
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				if target.Host == "second" {
					if mode.json {
						if out.Len() != 0 {
							t.Fatalf("JSON must remain buffered until the run finishes: %q", out.String())
						}
					} else if !strings.Contains(out.String(), "first-share") {
						t.Fatalf("first host's rows were not emitted before starting the next host: %q", out.String())
					} else if !strings.HasSuffix(out.String(), "first\n") {
						t.Fatalf("streamed result did not retain the supplied hostname in the last column: %q", out.String())
					}
					wantProgress := "Progress: 50% (1/2 hosts completed)"
					if !mode.stdoutTTY {
						wantProgress = "Progress: 0% (0/2 hosts completed)" // Subsequent pipe updates are rate-limited.
					}
					if mode.progress && !strings.Contains(errOut.String(), wantProgress) {
						t.Fatalf("live progress was not emitted while scanning: %q", errOut.String())
					}
				}
				return Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: target.Host + "-share", Read: Allowed, Write: Denied}}}
			}
			args := []string{path, "-u", "alice", "-p", "", "--delay", "0"}
			if mode.flag != "" {
				args = append(args, mode.flag)
			}
			if code := runCLI(context.Background(), args, deps); code != 0 {
				t.Fatalf("scan failed: %d; %q", code, errOut.String())
			}
			if strings.Contains(out.String(), "Progress:") || strings.ContainsAny(out.String(), "\r\x1b") {
				t.Fatalf("progress corrupted stdout: %q", out.String())
			}
			if mode.progress {
				if !strings.Contains(errOut.String(), "Progress: 100% (2/2 hosts completed)") || mode.stdoutTTY && !strings.HasSuffix(errOut.String(), "\n") {
					t.Fatalf("missing final progress count/newline: %q", errOut.String())
				}
			} else if errOut.Len() != 0 {
				t.Fatalf("disabled progress emitted stderr content: %q", errOut.String())
			}
			if mode.json {
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 2 {
					t.Fatalf("progress corrupted JSON: %v %q", err, out.String())
				}
			} else if mode.flag == "--tsv" {
				if rows := parseTestTSV(t, out.String()); len(rows) != 3 {
					t.Fatalf("streaming TSV lost records: %#v", rows)
				}
			} else if strings.ContainsRune(out.String(), '\t') || strings.Count(out.String(), "\n") != 3 {
				t.Fatalf("streaming default table lost aligned records: %q", out.String())
			}
		})
	}
}

type observedOutputWriter struct {
	buffer *bytes.Buffer
	after  func()
}

func (w observedOutputWriter) Write(p []byte) (int, error) {
	n, err := w.buffer.Write(p)
	w.after()
	return n, err
}

func TestCLICancelKeepsCompletedRowsAndDoesNotCountInterruptedHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("first\nsecond\nthird\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, duringHost := range []bool{false, true} {
		var out, errOut bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		deps := testCLIDeps(&out, &errOut)
		deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
		calls := 0
		deps.scan = func(_ context.Context, target Target, _ Options) Result {
			calls++
			if target.Host == "second" {
				if !duringHost {
					t.Fatal("started another host after cancellation between hosts")
				}
				if !strings.Contains(out.String(), "completed-share") {
					t.Fatal("completed rows were buffered during the interrupted scan")
				}
				cancel()
				return Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Error: "context canceled"}
			}
			if target.Host != "first" {
				t.Fatal("started a host after an interrupted scan")
			}
			return Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: "completed-share", Read: Allowed, Write: Denied}}}
		}
		if !duringHost {
			// Cancellation after writing a finished result is between hosts, so
			// that first host must remain counted as completed.
			deps.stdout = observedOutputWriter{buffer: &out, after: func() {
				if strings.Contains(out.String(), "completed-share") {
					cancel()
				}
			}}
		}
		code := runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--delay", "0"}, deps)
		cancel()
		wantCalls := 1
		if duringHost {
			wantCalls = 2
		}
		if code != 1 || calls != wantCalls || !strings.Contains(out.String(), "completed-share") {
			t.Fatalf("cancel lost finished work or kept scanning: duringHost=%v code=%d calls=%d stdout=%q", duringHost, code, calls, out.String())
		}
		if !strings.Contains(errOut.String(), "Progress: 33% (1/3 hosts completed) (interrupted)") || strings.Contains(errOut.String(), "2/3 hosts completed") || strings.Contains(errOut.String(), "3/3 hosts completed") {
			t.Fatalf("cancellation counted incomplete work: %q", errOut.String())
		}
		if strings.ContainsAny(out.String(), "\r\x1b") {
			t.Fatalf("cancellation progress erased/corrupted existing rows: %q", out.String())
		}
	}
}
