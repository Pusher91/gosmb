# gosmb

A small, read-only SMB share permission checker. Supply one server, an IPv4/IPv6
CIDR range, or a local text file containing servers and ranges. It reports TCP
reachability, authentication, enumeration status, every share returned by the
server, and root read/write permissions for disk shares.

```sh
gosmb fileserver.example.com -u alice -p 'password'
gosmb servers.txt -u 'EXAMPLE\alice' -p 'password'
gosmb 192.0.2.0/30 -u alice
gosmb fileserver.example.com --guest
```

Run `gosmb`, `gosmb --help`, or `gosmb -h` for the same full help text.
An explicit help option takes precedence over other scan arguments, including
invalid options, without looking up credentials, prompting, or connecting.
Tokens used as option values or placed after `--` are not treated as help options.

Omit `-p` for a hidden password prompt. `GOSMB_PASSWORD` is also supported. An
explicit `-p ''` supplies an empty password. Command-line passwords can appear in
process arguments and shell history; the application never logs credentials.
Passwords must be valid UTF-8; malformed input is rejected before scanning.

If the server maps supplied credentials to Guest, the scan continues using that
same session and reports Guest's permissions with **GUEST = TRUE**.
There is no second login attempt. This reports the server's guest-session flag;
it does not claim the supplied account/password was validated.

Use `--guest` to request guest access explicitly, without `-u`, `-p`, or `-d`.
This ignores `GOSMB_PASSWORD` and never prompts. Explicit guest access is labeled
`authentication=guest` with `GUEST = FALSE`, because guest was requested
from the start. Anonymous/null sessions are a different mode and are not accepted.
The server must allow guest access. Guest sessions lack SMB signing/encryption;
ordinary authenticated user sessions continue to require signing.
Authentication requires the NTLM challenge/response exchange. Servers that
skip the challenge are reported as errors; the scanner does not make a second
authentication attempt.

## Strictly read-only

There is no write-test mode and no flag that enables one. The scanner does not
create test files or directories, upload/download content, modify attributes,
rename, delete, recursively list files, or acquire exclusive file locks.

For each server it uses one TCP connection and one NTLM authentication attempt,
queries the existing `srvsvc` RPC service for share names, and checks each
returned disk share in sequence. There is no guessed-share probing, automatic
guest retry, credential-cache use, or connection to DFS referrals. By default,
one host is scanned at a time. `--concurrency=N` permits up to N simultaneous
host scans, each with its own connection. The minimum interval between starting
hosts is 250 ms across all workers (`--delay=0` disables it). Authentication
failures are not retried.

Resolved addresses are tried serially until one TCP connection succeeds;
IPv4/IPv6 connections are not raced in parallel. DNS resolution and connection
attempts share the connection timeout, and SMB authentication starts only on
the connected socket.
A trailing DNS dot is preserved: `fileserver.` remains an absolute name and
is distinct from `fileserver`, which can use resolver search suffixes.

For each disk share it normally performs a tree connect, one read-only open of
the **existing root directory**, closes that handle, and disconnects the tree.
No directory entries or file contents are fetched. There can be one additional
read-only open if LIST access is denied or maximum-access queries are unsupported.
Server pagination is followed when necessary to obtain the share list.

Authenticated sessions below SMB 3.1.1 also send one signed negotiation-validation
request on the first tree connection, before enumeration. This checks connection
parameters and does not open or modify a filesystem object.

SMB names the open-handle request `CREATE`, but every disk request uses
`FILE_OPEN`, which cannot create a new filesystem object. Desired access is only
`FILE_LIST_DIRECTORY` or, for a metadata fallback, `FILE_READ_ATTRIBUTES`.
`FILE_SHARE_READ|WRITE|DELETE` allows other clients to coexist with the handle;
it does **not** request write or delete privileges. The existing `IPC$/srvsvc`
named pipe uses a duplex RPC exchange solely for enumeration.

The client creates no remote filesystem artifacts. Servers can still log normal
connections/access checks and maintain access timestamps under their own policy.
Read-only checks are not invisible or guaranteed to produce no server records.

## What the results mean

| Field | Meaning |
| --- | --- |
| `TARGET_IP` | The supplied literal IP or connected peer's IP plus the requested port, using `[IPv6]:port` for IPv6. If no IP is available, this is `UNKNOWN:port`. |
| `target` / `server_ip` (JSON) | `target` retains the requested hostname/IP and port. `server_ip` contains the supplied literal IP or connected peer's IP without the port, or an empty string when unavailable. |
| `SHARE` | The share whose permissions appear on this row. |
| `reachable` (JSON) | The TCP connection succeeded; this alone does not confirm a working SMB service. |
| `authentication` (JSON) | The server-reported session identity: authenticated user or guest. Anonymous/unverified sessions are labeled and rejected. |
| `enumeration` (JSON) | Whether the server returned its share list. An authenticated user may be denied enumeration. |
| `accessible` (JSON) | Whether the actual session identity could connect to this disk share. This is separate from its read/write permissions. |
| `READ` | Whether a read-only root open granting LIST_DIRECTORY succeeded. This does not prove access to each file inside. |
| `WRITE` | Permission to **add a file at the root**, reported by the share and root maximum-access masks. No write is attempted. |
| `GUEST` | `TRUE` when a supplied-credential login was accepted as Guest; the permissions on that row belong to Guest. `FALSE` means no fallback was observed, not necessarily that authentication succeeded. |
| `HOSTNAME` | The supplied hostname, preserved on both successful and failed connections. Literal IP targets, including addresses expanded from CIDR ranges, show `-`; no reverse DNS lookup is performed. This is the last text/TSV column so long hostnames do not shift the preceding columns. |

In a terminal, columns are padded with spaces to line up with their headers:

```text
TARGET_IP                                        SHARE                             READ     WRITE    GUEST    HOSTNAME
192.0.2.10:445                                   public                            TRUE     FALSE    TRUE     fileserver.example.com
192.0.2.10:1445                                  private                           FALSE    FALSE    TRUE     -
UNKNOWN:445                                      -                                 UNKNOWN  UNKNOWN  FALSE    unavailable.example.com
```

Text results print in completion order as soon as each host finishes, so already printed results
remain in the terminal if the process is interrupted or killed. Each row is
emitted on one line, without wrapping or truncating values. Terminal columns
are padded with spaces, with the full hostname in the last column. When piped
or redirected, output automatically uses
plain TSV (tab-separated values), with one full row per share. Use `--tsv` to
force TSV even in a terminal. Both formats have the same six columns. The
`TARGET_IP` column always includes the port, including the default `445`; for
example, `[2001:db8::10]:445` or `UNKNOWN:1445`. The original hostname stays
visible in `HOSTNAME` even when the connection fails or resolves to an IP.
JSON keeps the requested endpoint and server IP in separate fields.

A live footer beneath the output shows, for example,
`Progress: 50% (2/4 hosts completed)`. It starts at 0% and updates after each
host, including hosts that fail connection or authentication or time out.
A host interrupted by canceling the command mid-check is not counted as completed;
any partial results returned for that
host are still printed. Ctrl-C/SIGTERM leaves the current counts marked
`(interrupted)`. Progress only redraws its own line; previous results remain in
terminal scrollback. A second Ctrl-C/SIGTERM terminates immediately if orderly
shutdown stalls, including when output is blocked. A force kill cannot print a
final status but does not erase already printed rows.

The footer goes to stderr only when stderr is a terminal, keeping TSV and JSON
clean. Use `--no-progress` to hide it. Redirected stderr has diagnostics without
progress or cursor-control sequences. JSON remains a single array written on
completion or orderly cancellation; use the default text/TSV for immediate rows.

There is one header per run and one logical row per share. There are no borders,
horizontal lines, repeated headers, banners,
blank separator lines, or explanatory text on stdout. `--no-header` emits data
rows only. Failed/empty servers remain visible with a `-` share and `UNKNOWN`
permissions, or `TIMEOUT` when a timeout prevents the checks;
diagnostic details go to stderr. If guest enumeration is denied,
the row still records that fallback occurred; no share names are guessed.

For pipelines, use a tab field separator so share names containing spaces stay
in one field.
Fields are not truncated. Backslashes are escaped as `\\`, and control characters
such as embedded tabs/newlines are escaped rather than becoming delimiters or
extra rows. Comments and detailed authentication status remain available in JSON.

```sh
# Show readable shares; suppress the header before filtering.
gosmb servers.txt -u alice --no-header | awk -F '\t' '$3 == "TRUE"'

# Show server-side guest fallback results.
gosmb servers.txt -u alice --no-header | awk -F '\t' '$5 == "TRUE"'

# Sort rows and keep diagnostics separate.
gosmb servers.txt -u alice --no-header 2>errors.log | LC_ALL=C sort
```

Text output uses `TRUE` for allowed, `FALSE` for denied, `UNKNOWN` when a result
cannot be determined, `TIMEOUT` for unanswered checks stopped by a timeout,
and `N/A` where file permissions do not apply. Already determined permissions
are preserved when a later check times out. If authentication has not completed,
the guest-fallback cell is also `TIMEOUT`; an established Guest/user identity
keeps its known `TRUE`/`FALSE` value. JSON retains the descriptive `allowed`,
`denied`, `unknown`, `timeout`, and `n/a` permission values, adds `timed_out: true`
for timed-out hosts, and keeps native Boolean values for reachability and guest
fallback. Use authentication status to distinguish an unknown identity in JSON.
Missing, failed, or malformed
root permission metadata never becomes a positive write result. A share-level
grant alone cannot establish filesystem write permission; a known denial at
either layer is enough to report denied. Quotas, read-only volumes, and other
server policies can prevent an actual write even when ACL metadata allows it.
Modifying existing files, creating subdirectories, and accessing descendants are
different permissions and are not claimed by the WRITE column.

The tool requests SMB's `MxAc` maximum-access context for the root and combines
it with the tree-connect share access mask. It does not attempt to reconstruct
effective permissions by guessing group membership from ACL entries.

Hidden/admin shares such as `C$` are shown if the server returns them. Shares
hidden from this identity by server policy cannot be discovered by this query.
IPC, printer, and device shares are shown with `N/A` file permissions and are not
probed as disk shares.

## Targets and options

```text
# servers.txt: one hostname, IP address, or CIDR range per line
fileserver.example.com
192.0.2.10
192.0.2.11:1445
fileserver-two.example.com:1445
[2001:db8::10]:445
192.0.2.0/30
192.0.2.8/30:1445
2001:db8::/126
[2001:db8:1::/126]:1445
```

Each command-line target or list-file entry can specify its own port with
`host:port`, `[IPv6]:port`, `IPv4/prefix:port`, or `[IPv6/prefix]:port`.
If the port is omitted, **445** is used for every address.

Blank lines and lines starting with `#` are ignored. Duplicate endpoints are
removed, preserving their first occurrence, including overlaps between CIDR
ranges and individual IP targets. IPv4 and its unscoped mapped IPv6 spelling
(such as `192.0.2.1` and `::ffff:192.0.2.1`) count as one endpoint, retaining
the first spelling. The same address with different ports is treated as separate
endpoints. Pass the list-file path as the positional target;
existing regular files are detected automatically. URLs, UNC paths, and implicit
network discovery are not accepted.

CIDR ranges expand in ascending address order and include every address,
including IPv4 network and broadcast addresses. Host bits are masked to the
network prefix: `192.0.2.10/30` expands to `192.0.2.8` through `192.0.2.11`.
Each range must contain no more than **65,536 addresses**, and a run accepts at
most **65,536 unique endpoints** after deduplication. Larger ranges are rejected
before expansion.

The existing concurrency, delay, and timeout settings apply to each expanded
host. Progress counts expanded endpoints, and results identify each host by its
individual IP and port with `-` in the `HOSTNAME` column. These are the same
read-only checks used for individual targets.

```sh
gosmb servers.txt -u alice -d EXAMPLE
gosmb 192.0.2.10:1445 -u alice
gosmb 192.0.2.0/30 -u alice --concurrency=4
gosmb 192.0.2.0/30:1445 -u alice
gosmb '[2001:db8::/126]:1445' -u alice
gosmb fileserver -u alice --timeout 5s
gosmb servers.txt -u alice --concurrency=5 --host-timeout=30
gosmb servers.txt -u alice --delay 1s --json
gosmb servers.txt -u alice --no-header
gosmb servers.txt -u alice --tsv
gosmb servers.txt -u alice --no-progress
gosmb servers.txt --guest
gosmb --help
```

Options can appear before or after the target.
`--concurrency` accepts a positive integer and defaults to **1**. It limits active
host scans, not operating-system threads; Go manages those internally.

`--host-timeout` accepts a positive whole number of **seconds** and defaults to
**30**. Its timer starts when that host's scan begins, covering connection,
authentication, share enumeration, permission checks, and cleanup. Time spent
waiting for a worker is excluded. A timed-out host releases its slot, prints any
results obtained, and the scan moves on. `--host-timeout=60` allows a minute for
slower servers or larger share lists.

The existing `--timeout` defaults to **10 seconds per SMB exchange/RPC operation**
and accepts duration syntax such as `--timeout=5s`. Whichever limit expires first
stops the host scan. Neither timeout causes another authentication attempt.

Ctrl-C/SIGTERM stops host-list parsing between records and bounded CIDR expansions,
closes active sockets, and stops starting subsequent targets. It also cancels a
password prompt immediately and restores the terminal settings.
JSON output is an
array; `server_ip` and the Boolean `guest_fallback` apply to every share in that
server's result, while `read_root`, `write_root`, and `write_basis` retain explicit semantics.
Text output escapes server-supplied terminal control characters. Password prompts
and diagnostics are sent to stderr, leaving stdout suitable for pipelines.

Exit codes: `0` when every scanned server established an accepted user/guest
session and enumeration completed,
`1` for connection/authentication/enumeration failures, fatal protocol or cleanup
failures, timeouts, or cancellation, and `2`
for invalid input. Denied shares and unavailable write metadata are normal
results and do not alone cause a nonzero exit code. Results are printed to stdout;
the tool does not save a report or credentials automatically.

## Build and validate

Use Go 1.27.3 or a newer patched release. `go.mod` recommends 1.27.3 so Go's
automatic toolchain selection does not choose the original 1.27.0 release.

```sh
CGO_ENABLED=0 go build -trimpath -o gosmb .
go test -race ./...
go vet ./...
```

To install for your user:

```sh
mkdir -p "$HOME/.local/bin"
CGO_ENABLED=0 go build -trimpath -o "$HOME/.local/bin/gosmb" .
```

`make` also produces the standalone executable. The SMB transport, NTLMv2,
SPNEGO, DCE/RPC, and share-enumeration implementation lives in
`internal/smbwire`; neither production code nor tests use a third-party SMB
library. The remaining Go module dependencies provide terminal/OS support and
the MD4 primitive required by NTLM; they are compiled into the executable.
There is no Python, Samba, shared-library, or other runtime installation requirement.

The client supports SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1. It verifies user-session
response signatures and prefers encryption when negotiated. SMB2 uses
HMAC-SHA256; SMB3 uses AES-CMAC, with AES-128-CCM encryption for SMB 3.0/3.0.2
and AES-128-GCM for SMB 3.1.1. SMB 3.1.1 also verifies preauthentication integrity
through the derived session keys. Guest sessions have neither signing nor encryption.
Authentication rejects contradictory SPNEGO completion states. If the server
requests a mechanism-list MIC exchange, an authenticated user session requires
a valid final server MIC before share enumeration.
SMB1, Kerberos, interactive shells, relay mode, downloads, and
uploads are not exposed.

Automated tests use synthetic credentials and loopback-only SMB servers. They
inspect disk protocol requests, reject mutation attempts in the test filesystem,
and compare file contents/metadata before and after scans. Cases cover read-only,
write-allowed, write-only, unsupported/malformed metadata, denied credentials,
server-side guest fallback, explicit guest access, single-attempt authentication,
timeouts, cancellation, pagination, and CLI/output handling. The maximum-access
parser and protocol decoders also have fuzz targets. Cryptographic primitives
and NTLMv2 responses are checked against published known-answer vectors.
These checks do not replace testing against your
particular Windows/Samba/NAS implementation.

`make test-interop` runs an optional independent Samba matrix in disposable
Docker containers bound to localhost. It checks all five dialects, signing and
encryption, guest identities, root permissions, large fragmented share lists,
single-connection authentication, and unchanged share filesystem snapshots.
See [the interoperability test instructions](tests/interop/README.md) for
requirements, exact coverage, and JSON evidence output. Ordinary Go tests do
not require Docker or Samba. Samba 4.22.10 returns the large list in one page;
pagination is covered by local fixtures rather than this independent server.
Windows and NAS interoperability remain untested unless separately verified in
your environment.

Authenticated SMB 3.0/3.0.2 sessions require successful
`FSCTL_VALIDATE_NEGOTIATE_INFO` validation of the original client and server
negotiation fields. Unauthenticated, altered, malformed, or rejected validation replies
terminate the connection before enumeration. SMB 3.1.1 uses preauthentication
integrity instead.

SMB 2.0.2/2.1 sessions attempt the same check, but retain compatibility with
older servers that return a signed `STATUS_NOT_SUPPORTED`,
`STATUS_INVALID_DEVICE_REQUEST`, or `STATUS_FILE_CLOSED`. Those responses establish
the server's authenticated refusal; they do not validate the original negotiation
fields. Guest sessions cannot perform authenticated negotiation validation.

Protocol references: [SPNEGO negotiation and MICs](https://www.rfc-editor.org/rfc/rfc4178.html#section-5),
[secure negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b80eb31-7e0a-4f24-b570-15217d28f239),
[validation replies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6a5bc90d-3c08-4498-905b-e7dab30b2e0e),
[tree-connect maximum access](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96),
[maximum-access response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0fe6be15-3a76-4032-9a44-56f846ac6244).
