# gosmb

A small, read-only SMB share permission checker. Supply one server or a local
text file containing servers. It reports TCP reachability, authentication,
enumeration status, every share returned by the server, and root read/write
permissions for disk shares.

```sh
gosmb fileserver.example.com -u alice -p 'password'
gosmb servers.txt -u 'EXAMPLE\alice' -p 'password'
gosmb fileserver.example.com --guest
```

Run `gosmb` without arguments for usage and examples, or `gosmb --help` for all
options. Neither command connects to a server or prompts for credentials.

Omit `-p` for a hidden password prompt. `GOSMB_PASSWORD` is also supported. An
explicit `-p ''` supplies an empty password. Command-line passwords can appear in
process arguments and shell history; the application never logs credentials.

If the server maps supplied credentials to Guest, the scan continues using that
same session and reports Guest's permissions with **GUEST FALLBACK = TRUE**.
There is no second login attempt. This reports the server's guest-session flag;
it does not claim the supplied account/password was validated.

Use `--guest` to request guest access explicitly, without `-u`, `-p`, or `-d`.
This ignores `GOSMB_PASSWORD` and never prompts. Explicit guest access is labeled
`authentication=guest` with `GUEST FALLBACK = FALSE`, because guest was requested
from the start. Anonymous/null sessions are a different mode and are not accepted.
The server must allow guest access. Guest sessions lack SMB signing/encryption;
ordinary authenticated user sessions continue to require signing.
The pinned SMB library can reject servers that declare Guest in the first
authentication response while signing is required. Such handshakes are reported
as errors; the scanner does not make a second attempt with weaker settings.

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

For each disk share it normally performs a tree connect, one read-only open of
the **existing root directory**, closes that handle, and disconnects the tree.
No directory entries or file contents are fetched. There can be one additional
read-only open if LIST access is denied or maximum-access queries are unsupported.
Server pagination is followed when necessary to obtain the share list.

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
| `SMB_SERVER_IP` | The supplied target IP, retained even if the connection fails, times out, or is canceled. For hostname targets, the connected peer's IP is used when available; otherwise `UNKNOWN`. JSON `server_ip` follows the same rule. |
| `SHARE` | The share whose permissions appear on this row. |
| `reachable` (JSON) | The TCP connection succeeded; this alone does not confirm a working SMB service. |
| `authentication` (JSON) | The server-reported session identity: authenticated user or guest. Anonymous/unverified sessions are labeled and rejected. |
| `enumeration` (JSON) | Whether the server returned its share list. An authenticated user may be denied enumeration. |
| `accessible` (JSON) | Whether the actual session identity could connect to this disk share. This is separate from its read/write permissions. |
| `READ` | Whether a read-only root open granting LIST_DIRECTORY succeeded. This does not prove access to each file inside. |
| `WRITE` | Permission to **add a file at the root**, reported by the share and root maximum-access masks. No write is attempted. |
| `GUEST_FALLBACK` | `TRUE` when a supplied-credential login was accepted as Guest; the permissions on that row belong to Guest. `FALSE` means no fallback was observed, not necessarily that authentication succeeded. |

In a terminal, columns are padded with spaces to line up with their headers:

```text
SMB_SERVER_IP  SHARE    READ   WRITE  GUEST_FALLBACK
192.0.2.10     public   TRUE   FALSE  TRUE
192.0.2.10     private  FALSE  FALSE  TRUE
```

Text results print in completion order as soon as each host finishes, so already printed results
remain in the terminal if the process is interrupted or killed. Terminal columns
have fixed widths; long names continue on additional lines within their columns
without being truncated. When piped or redirected, output automatically uses
plain TSV (tab-separated values), with one full row per share. Use `--tsv` to
force TSV even in a terminal. Both formats have the same five columns.

A live footer beneath the output shows, for example,
`Progress: 50% (2/4 hosts completed)`. It starts at 0% and updates after each
host, including hosts that fail connection or authentication or time out.
A host interrupted by canceling the command mid-check is not counted as completed;
any partial results returned for that
host are still printed. Ctrl-C/SIGTERM leaves the current counts marked
`(interrupted)`. Progress only redraws its own line; previous results remain in
terminal scrollback. A force kill cannot print a final status but does not erase
already printed rows.

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
# servers.txt: one hostname or IP address per line
fileserver.example.com
192.0.2.10
192.0.2.11:1445
fileserver-two.example.com:1445
[2001:db8::10]:445
```

Each command-line target or list-file entry can specify its own port with
`host:port` or `[IPv6]:port`. If the port is omitted, **445** is used.

Blank lines and lines starting with `#` are ignored. Duplicate endpoints are
removed. Pass the list-file path as the positional target; existing regular
files are detected automatically. URLs, UNC paths, CIDR ranges, and implicit
network discovery are not accepted.

```sh
gosmb servers.txt -u alice -d EXAMPLE
gosmb 192.0.2.10:1445 -u alice
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

Ctrl-C closes active sockets and stops starting subsequent targets. Ctrl-C/SIGTERM
also cancels a password prompt immediately and restores the terminal settings.
JSON output is an
array; `server_ip` and the Boolean `guest_fallback` apply to every share in that
server's result, while `read_root`, `write_root`, and `write_basis` retain explicit semantics.
Text output escapes server-supplied terminal control characters. Password prompts
and diagnostics are sent to stderr, leaving stdout suitable for pipelines.

Exit codes: `0` when every scanned server established an accepted user/guest
session and enumeration completed,
`1` for connection/authentication/enumeration failures, timeouts, or cancellation, and `2`
for invalid input. Denied shares and unavailable write metadata are normal
results and do not alone cause a nonzero exit code. Results are printed to stdout;
the tool does not save a report or credentials automatically.

## Build and validate

Use Go 1.27.3 or a newer patched release. `go.mod` recommends 1.27.3 so Go's
automatic toolchain selection does not choose the original 1.27.0 release.

```sh
go build -trimpath -o gosmb .
go test -race ./...
go vet ./...
```

To install for your user:

```sh
mkdir -p "$HOME/.local/bin"
go build -trimpath -o "$HOME/.local/bin/gosmb" .
```

This is a separate application; it does not modify the original `go-shareenum`
clone. It pins `go-smb v0.12.0`, which fixes the response-signature state and
directory-offset issues found in the earlier v0.11.0 audit, and uses newer Go
crypto/network dependencies. SMB signing is required for user sessions and
encryption is preferred when supported; guest sessions have neither protection.
SMB1, Kerberos, interactive shells, relay mode, downloads, and
uploads are not exposed.

Automated tests use synthetic credentials and loopback-only SMB servers. They
inspect disk protocol requests, reject mutation attempts in the test filesystem,
and compare file contents/metadata before and after scans. Cases cover read-only,
write-allowed, write-only, unsupported/malformed metadata, denied credentials,
server-side guest fallback, explicit guest access, single-attempt authentication,
timeouts, cancellation, pagination, and CLI/output handling. The maximum-access
parser also has a fuzz target. These checks do not replace testing against your
particular Windows/Samba/NAS implementation.

Protocol references: [tree-connect maximum access](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96),
[maximum-access response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0fe6be15-3a76-4032-9a44-56f846ac6244).
