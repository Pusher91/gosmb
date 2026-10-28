package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const usageIntro = `gosmb - Read-only SMB share permission checker

Usage:
  gosmb <server|CIDR|servers.txt> -u USER [-p PASSWORD] [options]
  gosmb <server|CIDR|servers.txt> --guest [options]

Each target: host[:port] or [IPv6]:port (default: 445).
CIDRs: IPv4/prefix[:port] or IPv6/prefix; [IPv6/prefix]:port for a custom port.
Ranges include every address; overlapping endpoints are scanned once.
Maximum: 65,536 unique endpoints per run; larger individual ranges are rejected.

Options (before or after the target):
  -u, --user USER       Account; DOMAIN\user or user@domain
  -p, --password PASS   Password; otherwise GOSMB_PASSWORD or hidden prompt
      --guest           Guest access; excludes -u, -p
      --concurrency N   Parallel hosts (default: 40)
      --host-timeout N  Per-host limit in seconds (default: 30)
      --timeout TIME    SMB I/O timeout (default: 10s)
      --delay TIME      Minimum time between starting host scans (default: 0; no delay)
      --json            JSON output
      --tsv             Tab-separated output with full values
      --shares-only     Show only hosts with discovered shares
      --no-header       Omit text header
      --no-progress     Hide progress and summary
  -h, --help            Show help

Columns:
  TARGET_IP  Supplied or connected IP plus port; UNKNOWN:port if unavailable
             IPv6 endpoints use [IPv6]:port
  SHARE      Share name
  READ       Root listing permission
  WRITE      Permission to add files at root (metadata only; no write test)
  GUEST      TRUE when supplied credentials are accepted as Guest
             N/A when --guest is used
  STATUS     Scan outcome; codes below
  HOSTNAME   Supplied hostname; - for literal IP targets (no reverse DNS)

READ/WRITE statuses (text output):
  TRUE     Allowed
  FALSE    Denied
  UNKNOWN  Permission metadata missing/unsupported, or connection/login/access check failed
  TIMEOUT  Check timed out
  N/A      Not applicable (non-disk share)

STATUS codes (table and TSV):
`

var usage = usageIntro + statusHelp()

type cliConfig struct {
	options     Options
	targets     []Target
	delay       time.Duration
	concurrency int
	json        bool
	tsv         bool
	sharesOnly  bool
	noHeader    bool
	noProgress  bool
	passwordSet bool
	help        bool
}

type cliDependencies struct {
	stdin            io.Reader
	stdout           io.Writer
	stderr           io.Writer
	stdoutIsTerminal bool
	stderrIsTerminal bool
	enableColor      func() (restore func(), enabled bool)
	enableProgress   func() (restore func(), enabled bool)
	lookupEnv        func(string) (string, bool)
	prompt           func(context.Context, io.Reader, io.Writer) (string, error)
	scan             func(context.Context, Target, Options) Result
}

// Normalize aliases once so help lookahead and argument parsing interpret the
// same option names and never mistake an alias's value for a help request.
func canonicalCLIOption(name string) (canonical string, takesValue bool) {
	switch name {
	case "-h", "--help":
		return "--help", false
	case "-u", "--user", "--username":
		return "--user", true
	case "-p", "--pass", "--password":
		return "--password", true
	case "--timeout", "--host-timeout", "--concurrency", "--delay":
		return name, true
	}
	return name, false
}

// Help takes precedence over validation, but an option value such as a password
// containing "--help", or an argument after "--", is not a help request.
func helpRequested(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		name, _, hasValue := strings.Cut(arg, "=")
		name, takesValue := canonicalCLIOption(name)
		if name == "--help" && !hasValue {
			return true
		}
		if takesValue && !hasValue {
			i++
		}
	}
	return false
}

// parseCLI deliberately excludes argument values from diagnostics: a misplaced
// credential must not be repeated in an error message.
func parseCLI(ctx context.Context, args []string) (cliConfig, error) {
	cfg := cliConfig{options: Options{Timeout: 10 * time.Second, HostTimeout: 30 * time.Second},
		delay: 0, concurrency: 40, help: helpRequested(args)}
	if cfg.help {
		return cfg, nil
	}
	if err := ctx.Err(); err != nil {
		return cfg, err
	}
	var positionals []string
	credentialsSet := false
	flagsDone := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if flagsDone || !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		if arg == "--" {
			flagsDone = true
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		name, takesValue := canonicalCLIOption(name)
		var toggle *bool
		switch name {
		case "--help":
			// Bare help flags returned above; only valued forms reach this case.
			return cfg, errors.New("help does not accept a value")
		case "--json":
			toggle = &cfg.json
		case "--tsv":
			toggle = &cfg.tsv
		case "--shares-only":
			toggle = &cfg.sharesOnly
		case "--no-header":
			toggle = &cfg.noHeader
		case "--no-progress":
			toggle = &cfg.noProgress
		case "--guest":
			toggle = &cfg.options.Guest
		default:
			if !takesValue {
				return cfg, errors.New("unknown option; use --help for supported options")
			}
		}
		if toggle != nil {
			if hasValue {
				return cfg, fmt.Errorf("%s does not accept a value", strings.TrimPrefix(name, "--"))
			}
			*toggle = true
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return cfg, errors.New("an option is missing its value")
			}
			i++
			value = args[i]
		}
		switch name {
		case "--user":
			credentialsSet = true
			cfg.options.Username = value
		case "--password":
			credentialsSet = true
			cfg.options.Password, cfg.passwordSet = value, true
		case "--timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return cfg, errors.New("timeout must be a positive duration such as 10s")
			}
			cfg.options.Timeout = d
		case "--host-timeout":
			seconds, err := strconv.ParseUint(value, 10, 64)
			if err != nil || seconds == 0 || seconds > uint64((1<<63-1)/int64(time.Second)) {
				return cfg, errors.New("host-timeout must be a positive whole number of seconds")
			}
			cfg.options.HostTimeout = time.Duration(seconds) * time.Second
		case "--concurrency":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return cfg, errors.New("concurrency must be a positive integer")
			}
			cfg.concurrency = n
		case "--delay":
			d, err := time.ParseDuration(value)
			if err != nil || d < 0 {
				return cfg, errors.New("delay must be a nonnegative duration such as 250ms")
			}
			cfg.delay = d
		}
	}
	if cfg.options.Guest && credentialsSet {
		return cfg, errors.New("--guest cannot be combined with username or password options")
	}
	if cfg.json && cfg.tsv {
		return cfg, errors.New("choose either --json or --tsv")
	}
	var err error
	if !cfg.options.Guest {
		cfg.options.Username, cfg.options.Domain, err = parseIdentity(cfg.options.Username)
		if err != nil {
			return cfg, err
		}
	}
	if len(positionals) != 1 {
		return cfg, errors.New("provide exactly one host, CIDR range, or host-list file")
	}
	if err := ctx.Err(); err != nil {
		return cfg, err
	}
	candidate := positionals[0]
	if strings.HasPrefix(candidate, `\\`) || strings.HasPrefix(candidate, "//") || strings.Contains(candidate, "://") {
		return cfg, errors.New("URLs and UNC paths are not valid targets or local host-list files")
	}
	if info, statErr := os.Stat(candidate); statErr == nil {
		if !info.Mode().IsRegular() {
			return cfg, errors.New("host-list path must be a regular file")
		}
		cfg.targets, err = readTargets(ctx, candidate)
	} else if !errors.Is(statErr, os.ErrNotExist) && !invalidListFilePath(statErr) {
		return cfg, errors.New("cannot inspect host-list path")
	} else {
		// A valid network endpoint need not be a valid local filename (for
		// example, a maximum-length hostname with a port, or Windows IPv6).
		if err := ctx.Err(); err != nil {
			return cfg, err
		}
		cfg.targets, err = parseTargetSpec(candidate)
	}
	if err == nil {
		err = ctx.Err()
	}
	return cfg, err
}

func parseIdentity(user string) (string, string, error) {
	if user == "" {
		return "", "", errors.New("username required: use -u USER or --guest")
	}
	if !utf8.ValidString(user) {
		return "", "", errors.New("username and domain must be valid UTF-8")
	}
	if strings.TrimSpace(user) != user {
		return "", "", errors.New("username and domain must not have surrounding whitespace")
	}
	if strings.ContainsFunc(user, unicode.IsControl) {
		return "", "", errors.New("username and domain must not contain control characters")
	}
	var domain string
	if strings.Contains(user, `\`) {
		if strings.Count(user, `\`) != 1 || strings.Contains(user, "@") {
			return "", "", errors.New("use a plain username, DOMAIN\\user, or user@domain")
		}
		domain, user, _ = strings.Cut(user, `\`)
	} else if strings.Contains(user, "@") {
		if strings.Count(user, "@") != 1 {
			return "", "", errors.New("use a plain username, DOMAIN\\user, or user@domain")
		}
		user, domain, _ = strings.Cut(user, "@")
	} else {
		return user, "", nil
	}
	if user == "" || domain == "" || strings.TrimSpace(user) != user || strings.TrimSpace(domain) != domain {
		return "", "", errors.New("qualified username must include a username and domain without surrounding whitespace")
	}
	return user, domain, nil
}

func runCLI(ctx context.Context, args []string, deps cliDependencies) (code int) {
	cfg, err := parseCLI(ctx, args)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(deps.stderr, "gosmb: canceled")
			return 1
		}
		fmt.Fprintf(deps.stderr, "gosmb: %s\n", err)
		return 2
	}
	if cfg.help {
		if _, err := writeOutputString(deps.stdout, usage); err != nil {
			fmt.Fprintln(deps.stderr, "gosmb: could not write output")
			return 1
		}
		return 0
	}
	if !cfg.options.Guest && !cfg.passwordSet && deps.lookupEnv != nil {
		cfg.options.Password, cfg.passwordSet = deps.lookupEnv("GOSMB_PASSWORD")
	}
	if !cfg.options.Guest && !cfg.passwordSet {
		if ctx.Err() != nil {
			fmt.Fprintln(deps.stderr, "gosmb: canceled")
			return 1
		}
		cfg.options.Password, err = deps.prompt(ctx, deps.stdin, deps.stderr)
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(deps.stderr, "gosmb: canceled")
			return 1
		}
		if err != nil {
			// Do not repeat errors from password providers: their messages could
			// contain a credential. The built-in prompt has no sensitive output.
			fmt.Fprintln(deps.stderr, "gosmb: could not obtain password; use a terminal prompt, -p, or GOSMB_PASSWORD")
			return 2
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(deps.stderr, "gosmb: canceled")
		return 1
	}
	if !utf8.ValidString(cfg.options.Password) {
		fmt.Fprintln(deps.stderr, "gosmb: password must be valid UTF-8")
		return 2
	}
	var results []Result
	if cfg.json {
		results = make([]Result, 0, len(cfg.targets))
	}
	aligned := !cfg.tsv && !cfg.json
	colored := aligned && deps.stdoutIsTerminal && deps.enableColor != nil
	showProgress := deps.stderrIsTerminal && !cfg.noProgress
	if (colored || showProgress) && deps.lookupEnv != nil {
		terminal, _ := deps.lookupEnv("TERM")
		if terminal == "dumb" {
			colored, showProgress = false, false
		} else if colored {
			noColor, _ := deps.lookupEnv("NO_COLOR")
			colored = noColor == ""
		}
	}
	if colored {
		var restore func()
		restore, colored = deps.enableColor()
		if restore != nil {
			defer restore()
		}
	}
	writeResult := writeTextResult
	if aligned {
		writeResult = func(out io.Writer, result Result) error {
			return writeAlignedResult(out, result, colored)
		}
	}
	if showProgress && deps.stdoutIsTerminal && deps.enableProgress != nil {
		var restore func()
		restore, showProgress = deps.enableProgress()
		if restore != nil {
			// Finish progress before restoring stderr, then restore stdout.
			// The handles may refer to the same Windows console buffer.
			defer restore()
		}
	}
	var summary scanSummary
	var elapsed time.Duration
	scanStarted := false
	progress := newProgress(deps.stderr, showProgress, len(cfg.targets))
	progress.SetScanBudget(cfg.concurrency, cfg.options.HostTimeout, cfg.delay)
	if !deps.stdoutIsTerminal {
		progress.UseLines()
	}
	defer func() {
		interrupted := ctx.Err() != nil
		if interrupted && aligned && !deps.stdoutIsTerminal && !cfg.noProgress {
			// Keep the interruption record after the rows in the same stream.
			// This is best effort: the reader may also have exited on Ctrl+C.
			_, _ = writeOutputString(deps.stdout, progress.label(summary.completed)+" (interrupted)\n")
			code = 1
		} else if err := progress.Finish(summary.completed, interrupted); err != nil {
			code = 1
		}
		if showProgress && scanStarted {
			if err := summary.Print(deps.stderr, len(cfg.targets), elapsed); err != nil {
				code = 1
			}
		}
		// Output writers can observe cancellation during final progress or
		// summary output, after the interruption check above.
		if ctx.Err() != nil {
			code = 1
		}
	}()
	if !cfg.json && !cfg.noHeader {
		writeHeader := writeTextHeader
		if aligned {
			writeHeader = writeAlignedHeader
		}
		if err := writeHeader(deps.stdout); err != nil {
			fmt.Fprintln(deps.stderr, "gosmb: could not write output")
			return 1
		}
	}
	if err := progress.Update(summary.completed); err != nil {
		return 1
	}
	scanCtx, stopScan := context.WithCancel(ctx)
	defer stopScan()
	outputFailed := false
	handleOutputError := func(err error) error {
		if err != nil {
			// Stop new work but drain active and buffered results for accurate
			// attempt totals and JSON. An emitter error would discard them.
			outputFailed, code = true, 1
			stopScan()
		}
		return nil
	}
	scanStarted = true
	started := time.Now()
	scanErr := scanTargets(scanCtx, cfg.targets, cfg.options, cfg.concurrency, cfg.delay, deps.scan, func(result Result, hostCompleted bool) error {
		result.explicitGuest = cfg.options.Guest
		summary.Add(result, hostCompleted)
		if !hostCompleted {
			code = 1
		}
		authenticationOK := result.Authentication == "authenticated" || result.Authentication == "guest"
		if cfg.options.Guest {
			authenticationOK = result.Authentication == "guest"
		}
		if !authenticationOK || result.Enumeration != "ok" || result.Error != "" || result.TimedOut {
			code = 1
		}
		result = redactResult(result, cfg.options.Password)
		showResult := !cfg.sharesOnly || len(result.Shares) > 0
		if cfg.json && showResult {
			// Keep completed work even if the separate progress stream fails.
			results = append(results, result)
		}
		if outputFailed {
			return nil
		}
		if err := progress.Clear(); err != nil {
			return handleOutputError(err)
		}
		if !cfg.json && showResult {
			if err := writeResult(deps.stdout, result); err != nil {
				fmt.Fprintln(deps.stderr, "gosmb: could not write output")
				return handleOutputError(err)
			}
		}
		return handleOutputError(progress.Update(summary.completed))
	})
	elapsed = time.Since(started)
	if scanErr != nil {
		code = 1
		if ctx.Err() != nil && !showProgress {
			fmt.Fprintln(deps.stderr, "gosmb: canceled")
		}
	}
	if cfg.json {
		if err := progress.Clear(); err != nil {
			code = 1
		}
		if err := writeJSONResults(deps.stdout, results); err != nil {
			fmt.Fprintln(deps.stderr, "gosmb: could not write output")
			return 1
		}
	}
	return code
}
