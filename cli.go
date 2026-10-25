package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const quickUsage = `gosmb - Read-only SMB share permission checker

Usage:
  gosmb <server|servers.txt> -u USER [-p PASSWORD] [options]
  gosmb <server|servers.txt> --guest [options]

Each target: host[:port] or [IPv6]:port (default: 445).

Examples:
  gosmb 192.0.2.10:1445 -u alice -p 'password'
  gosmb servers.txt -u 'DOMAIN\alice'
  gosmb 192.0.2.10 --guest

Omit -p for a hidden password prompt.
`

const usage = `gosmb - Read-only SMB share permission checker

Usage:
  gosmb <server|servers.txt> -u USER [-p PASSWORD] [options]
  gosmb <server|servers.txt> --guest [options]

Each target: host[:port] or [IPv6]:port (default: 445).

Options (before or after the target):
  -u, --user USER       Account; DOMAIN\user or user@domain
  -p, --password PASS   Password; otherwise GOSMB_PASSWORD or hidden prompt
  -d, --domain DOMAIN   Account domain
      --guest           Guest access; excludes -u, -p, -d
      --concurrency N   Parallel hosts (default: 1)
      --host-timeout N  Per-host limit in seconds (default: 30)
      --timeout TIME    SMB I/O timeout (default: 10s)
      --delay TIME      Minimum time between starting host scans (default: 250ms; 0 disables)
      --json            JSON output
      --tsv             Force TSV (automatic when piped)
      --no-header       Omit text header
      --no-progress     Hide progress
  -h, --help            Show help

Columns:
  SMB_SERVER_IP   Supplied target IP; connected IP for hostname targets
  SHARE           Share name
  READ            Root listing permission
  WRITE           Permission to add files at root (metadata only; no write test)
  GUEST_FALLBACK  TRUE when supplied credentials are accepted as Guest

READ/WRITE statuses (text output):
  TRUE     Allowed
  FALSE    Denied
  UNKNOWN  Permission metadata missing/unsupported, or connection/login/access check failed
  TIMEOUT  Check timed out
  N/A      Not applicable (non-disk share)
`

type cliConfig struct {
	options     Options
	targets     []Target
	delay       time.Duration
	concurrency int
	json        bool
	tsv         bool
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
	lookupEnv        func(string) (string, bool)
	prompt           func(context.Context, io.Reader, io.Writer) (string, error)
	scan             func(context.Context, Target, Options) Result
}

// parseCLI deliberately excludes argument values from diagnostics: a misplaced
// credential must not be repeated in an error message.
func parseCLI(args []string) (cliConfig, error) {
	cfg := cliConfig{options: Options{Timeout: 10 * time.Second, HostTimeout: 30 * time.Second},
		delay: 250 * time.Millisecond, concurrency: 1, help: len(args) == 0}
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
		switch name {
		case "-h", "--help":
			if hasValue {
				return cfg, errors.New("help does not accept a value")
			}
			cfg.help = true
			continue
		case "--json":
			if hasValue {
				return cfg, errors.New("json does not accept a value")
			}
			cfg.json = true
			continue
		case "--tsv":
			if hasValue {
				return cfg, errors.New("tsv does not accept a value")
			}
			cfg.tsv = true
			continue
		case "--no-header":
			if hasValue {
				return cfg, errors.New("no-header does not accept a value")
			}
			cfg.noHeader = true
			continue
		case "--no-progress":
			if hasValue {
				return cfg, errors.New("no-progress does not accept a value")
			}
			cfg.noProgress = true
			continue
		case "--guest":
			if hasValue {
				return cfg, errors.New("guest does not accept a value")
			}
			cfg.options.Guest = true
			continue
		case "-u", "--user", "--username", "-p", "--pass", "--password", "-d", "--domain", "--timeout", "--host-timeout", "--concurrency", "--delay":
		default:
			return cfg, errors.New("unknown option; use --help for supported options")
		}
		if !hasValue {
			if i+1 >= len(args) {
				return cfg, errors.New("an option is missing its value")
			}
			i++
			value = args[i]
		}
		switch name {
		case "-u", "--user", "--username":
			credentialsSet = true
			cfg.options.Username = value
		case "-p", "--pass", "--password":
			credentialsSet = true
			cfg.options.Password, cfg.passwordSet = value, true
		case "-d", "--domain":
			credentialsSet = true
			cfg.options.Domain = value
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
		return cfg, errors.New("--guest cannot be combined with username, password, or domain options")
	}
	if cfg.help {
		return cfg, nil
	}
	if cfg.json && cfg.tsv {
		return cfg, errors.New("choose either --json or --tsv")
	}
	var err error
	if !cfg.options.Guest {
		cfg.options.Username, cfg.options.Domain, err = parseIdentity(cfg.options.Username, cfg.options.Domain)
		if err != nil {
			return cfg, err
		}
	}
	if len(positionals) != 1 {
		return cfg, errors.New("provide exactly one host or host-list file")
	}
	candidate := positionals[0]
	if strings.HasPrefix(candidate, `\\`) || strings.HasPrefix(candidate, "//") || strings.Contains(candidate, "://") {
		return cfg, errors.New("URLs and UNC paths are not valid targets or local host-list files")
	}
	if info, statErr := os.Stat(candidate); statErr == nil {
		if !info.Mode().IsRegular() {
			return cfg, errors.New("host-list path must be a regular file")
		}
		cfg.targets, err = readTargets(candidate)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return cfg, errors.New("cannot inspect host-list path")
	} else {
		var target Target
		target, err = parseTarget(candidate)
		if err == nil {
			cfg.targets = []Target{target}
		}
	}
	return cfg, err
}

func parseIdentity(user, domain string) (string, string, error) {
	if user == "" {
		return "", "", errors.New("username required: use -u USER or --guest")
	}
	if strings.TrimSpace(user) != user || strings.TrimSpace(domain) != domain {
		return "", "", errors.New("username and domain must not have surrounding whitespace")
	}
	if strings.ContainsFunc(user+domain, unicode.IsControl) {
		return "", "", errors.New("username and domain must not contain control characters")
	}
	var embeddedDomain string
	qualified := strings.ContainsAny(user, `\@`)
	if strings.Contains(user, `\`) {
		if strings.Count(user, `\`) != 1 || strings.Contains(user, "@") {
			return "", "", errors.New("use a plain username, DOMAIN\\user, or user@domain")
		}
		embeddedDomain, user, _ = strings.Cut(user, `\`)
	} else if strings.Contains(user, "@") {
		if strings.Count(user, "@") != 1 {
			return "", "", errors.New("use a plain username, DOMAIN\\user, or user@domain")
		}
		user, embeddedDomain, _ = strings.Cut(user, "@")
	}
	if user == "" || strings.TrimSpace(user) != user || strings.TrimSpace(embeddedDomain) != embeddedDomain {
		return "", "", errors.New("username and embedded domain must be nonempty without surrounding whitespace")
	}
	// A separator without a domain is always a malformed qualified identity.
	if qualified && embeddedDomain == "" {
		return "", "", errors.New("qualified username must include a domain")
	}
	if embeddedDomain != "" {
		if domain != "" && !strings.EqualFold(domain, embeddedDomain) {
			return "", "", errors.New("explicit domain conflicts with the qualified username")
		}
		domain = embeddedDomain
	}
	return user, domain, nil
}

func parsePort(value string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("invalid port")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid port")
	}
	return n, nil
}

func parseTarget(raw string) (Target, error) {
	bad := errors.New("invalid target: use a hostname, IP address, or host:port (bracket IPv6 with a port)")
	if raw == "" || !utf8.ValidString(raw) || strings.ContainsAny(raw, `/\?#@`) || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return Target{}, bad
	}
	host, port := raw, 445
	if strings.HasPrefix(raw, "[") {
		if strings.HasSuffix(raw, "]") {
			host = raw[1 : len(raw)-1]
		} else {
			var portString string
			var err error
			host, portString, err = net.SplitHostPort(raw)
			if err != nil {
				return Target{}, bad
			}
			port, err = parsePort(portString)
			if err != nil {
				return Target{}, bad
			}
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return Target{}, bad
		}
		host = addr.String()
	} else if addr, err := netip.ParseAddr(raw); err == nil {
		host = addr.String()
	} else if strings.Contains(raw, ":") {
		var portString string
		var err error
		host, portString, err = net.SplitHostPort(raw)
		if err != nil {
			return Target{}, bad
		}
		port, err = parsePort(portString)
		if err != nil {
			return Target{}, bad
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if zone := addr.Zone(); zone != "" && strings.IndexFunc(zone, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-", r))
		}) >= 0 {
			return Target{}, bad
		}
		host = addr.String()
	} else {
		host = strings.TrimSuffix(host, ".")
		if len(host) == 0 || len(host) > 253 || strings.Contains(host, ":") {
			return Target{}, bad
		}
		if strings.Contains(host, ".") && strings.IndexFunc(host, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) == -1 {
			return Target{}, bad
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Target{}, bad
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return Target{}, bad
				}
			}
		}
	}
	return Target{Host: host, Port: port}, nil
}

func readTargets(path string) ([]Target, error) {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || strings.Contains(path, "://") {
		return nil, errors.New("host-list file must be a local path, not a URL or UNC path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("host-list path must be a readable regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open host-list file")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("host-list path must be a readable regular file")
	}
	return parseTargetList(f)
}

func parseTargetList(r io.Reader) ([]Target, error) {
	var targets []Target
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("host-list line %d is not valid UTF-8", lineNumber)
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target, err := parseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("invalid target at host-list line %d", lineNumber)
		}
		key := strings.ToLower(target.String())
		if !seen[key] {
			seen[key] = true
			targets = append(targets, target)
		}
	}
	if scanner.Err() != nil {
		return nil, errors.New("cannot read host-list file (read error or line too long)")
	}
	if len(targets) == 0 {
		return nil, errors.New("host-list file contains no targets")
	}
	return targets, nil
}

func runCLI(ctx context.Context, args []string, deps cliDependencies) (code int) {
	cfg, err := parseCLI(args)
	if err != nil {
		fmt.Fprintf(deps.stderr, "gosmb: %s\n", err)
		return 2
	}
	if cfg.help {
		helpText := usage
		if len(args) == 0 {
			helpText = quickUsage + "Run 'gosmb --help' for all options.\n"
		}
		if _, err := io.WriteString(deps.stdout, helpText); err != nil {
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
	results := make([]Result, 0, len(cfg.targets))
	aligned := deps.stdoutIsTerminal && !cfg.tsv && !cfg.json
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
	completed := 0
	progress := newProgress(deps.stderr, deps.stderrIsTerminal && !cfg.noProgress, len(cfg.targets))
	defer func() {
		if err := progress.Finish(completed, ctx.Err() != nil); err != nil {
			code = 1
		}
	}()
	if err := progress.Update(completed); err != nil {
		return 1
	}
	scanErr := scanTargets(ctx, cfg.targets, cfg.options, cfg.concurrency, cfg.delay, deps.scan, func(result Result, hostCompleted bool) error {
		if hostCompleted {
			completed++
		} else {
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
		if err := progress.Clear(); err != nil {
			return err
		}
		if cfg.json {
			results = append(results, result)
		} else {
			writeResult := writeTextResult
			if aligned {
				writeResult = writeAlignedResult
			}
			if err := writeResult(deps.stdout, result); err != nil {
				fmt.Fprintln(deps.stderr, "gosmb: could not write output")
				return err
			}
			if err := writeTextDiagnostics(deps.stderr, result); err != nil {
				return err
			}
		}
		return progress.Update(completed)
	})
	if scanErr != nil {
		code = 1
		if ctx.Err() != nil {
			if err := progress.Clear(); err != nil {
				return 1
			}
			fmt.Fprintln(deps.stderr, "gosmb: canceled")
		}
	}
	if cfg.json {
		if err := progress.Clear(); err != nil {
			return 1
		}
		if err := writeJSONResults(deps.stdout, results); err != nil {
			fmt.Fprintln(deps.stderr, "gosmb: could not write output")
			return 1
		}
	}
	return code
}
