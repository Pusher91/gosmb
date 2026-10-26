# AI handoff: self-contained SMB implementation

Last updated: 2026-10-25. Workspace: `/opt/gosmb`.

## Status

The user requested an SMB implementation owned by this repository, **with no
third-party SMB code**, and a self-contained executable. The native replacement
is implemented, reviewed, and interoperates end to end
with independent Samba 4.22.10 across every advertised dialect. The complete
local test suite, race detector, and vet pass. The rebuilt `./gosmb` is statically
linked. The original Debian RPC startup blocker has been resolved by using the
Alpine fixture described below. No commit or push was requested or made.

**Validation remains bounded:** Windows/NAS coverage and pagination against a
real server that returns multiple pages are unverified. Samba returns the whole
large share list in one page; local tests cover pagination. Legacy negotiation
transcript protection remains a documented limitation, not a claimed feature.

## User requirements to preserve

- Strictly read-only disk checks. Never create/delete a test file or directory.
- Determine READ by opening the existing root for LIST_DIRECTORY. Determine
  WRITE (permission to add a file at the root) by intersecting the share maximum
  access mask and root `MxAc` metadata. Missing/malformed metadata stays unknown
  unless a known layer denies access. Descendant permissions are outside scope.
- One TCP connection and one NTLM authentication attempt per target. No credential
  retries, ambient credential caches, DFS referral connections, or guessed shares.
- Explicit guest authentication is distinct from anonymous/null access.
  `GUEST=TRUE` reports supplied credentials mapped to Guest; explicit `--guest`
  has `GUEST=FALSE`. Reject anonymous/unverified sessions before enumeration.
- Signed/verified user sessions; encryption when negotiated. Guest is explicitly
  identified and unsigned. Preserve operation deadlines, whole-host cancellation,
  partial results, and bounded cleanup.
- Existing CLI/output/CIDR work predates this migration and must be preserved.
  Columns are `TARGET_IP SHARE READ WRITE GUEST HOSTNAME`; hostname is last.
  Preserve supplied hostnames, one physical record per share, no application
  wrapping/truncation; terminals use padding and pipelines use TSV. JSON schema
  remains stable. No arguments, `-h`, and `--help` show identical full help.
  Explicit help overrides scan options while respecting values and `--`.
- CIDR supports IPv4/IPv6/custom ports, includes all addresses, deduplicates
  overlapping targets, and caps each range and total unique endpoints at 65,536.

## Implementation now in the working tree

`internal/smbwire` is new, written in-repository from protocol specifications.
It does not vendor or import a third-party SMB/NTLM/RPC implementation.

| File | Responsibility |
| --- | --- |
| `internal/smbwire/client.go` | SMB framing, bounded serial requests/credits/pending responses, negotiation, SPNEGO, session identity, signature verification, tree connections, existing-root and srvsvc opens, pipe I/O, handle cleanup. |
| `internal/smbwire/ntlm.go` | NTLMv2 challenge/proof, timestamp and target information, Type3 transcript MIC, exported session key, SPNEGO mechanism-list MIC and verification. |
| `internal/smbwire/crypto.go` | HMAC-SHA256/AES-CMAC signing, SP800-108 key derivation, SMB transform AES-CCM/AES-GCM encryption and authenticated decryption. |
| `internal/smbwire/rpc.go` | SRVS v3/NDR32, DCE/RPC bind and fragmentation over named-pipe WRITE/READ, bounded Level1 share decoding and pagination. |
| `scanner.go`, `enumeration.go`, `permissions.go` | Existing scanner behavior adapted to the native client; permission interpretation remains in the application. |
| `scanner_integration_test.go` | Independent scripted loopback SMB2.1 server, own NTLM proof/MIC verifier and packet/NDR encoders, read-only operation guards and filesystem snapshots. |
| `scanner_receiver_test.go`, `scanner_timeout_test.go` | Malformed/tampered replies, prompt shutdown, timeout and partial-result regressions without external SMB fixtures. |
| `Makefile` | `make` / `make build` produces a static executable; `make test` runs the race suite; `make vet` runs vet; `make test-interop` runs the optional independent Samba matrix. |
| `tests/interop/` | Disposable Alpine/Samba fixture, transparent traffic observer, filesystem snapshots, reproducible matrix and optional JSON evidence. |

Dialects offered: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1. SMB2 uses HMAC-SHA256;
SMB3 uses AES-CMAC. Encryption is AES-128-CCM for 3.0/3.0.2 and AES-128-GCM for
3.1.1. The 3.1.1 negotiation offers SHA-512 preauthentication, GCM, and CMAC.
Keys are derived using the preauthentication transcript through the final client
SESSION_SETUP request, before verifying the final successful server response.

The client exposes no disk write API. The private `rootRequest` encoder only accepts LIST_DIRECTORY
or READ_ATTRIBUTES and always uses FILE_OPEN with an empty root name. File
Read/Write methods are restricted to the existing `IPC$/srvsvc` pipe.

Important hardening already added during review:

- Signature/transport/protocol failures close the socket; normal authenticated
  NTSTATUS errors still permit documented read-only fallbacks.
- Invalid response-body structures also poison the connection, while malformed
  root context metadata still allows closing the already-opened handle.
- Reject contradictory/unknown session flags, encryption on SMB2, and zero
  asynchronous response identifiers.
- Honor negotiated SMB read/write limits when negotiating RPC fragment sizes.
- Cap RPC pages, fragments, shares, strings, individual responses, and total
  retained share-name/comment text (16 MiB).
- Parse SPNEGO fields with explicit boundaries; check completion for Guest as
  well as user sessions. Verify server mechanism-list MIC for user sessions.
- Report server-flagged null sessions as `anonymous` and reject them before
  enumeration, preserving their distinction from unverified user sessions.
- Reject malformed LOGOFF/TREE_DISCONNECT response bodies, invalid tree types,
  and reserved tree identifiers, closing the transport on protocol failure.
- Validate complete RPC fault fragments and the negotiated presentation context
  before classifying an access-denied status.
- Validate SMB error response bodies and context lengths before classifying
  permission denials or taking read-only fallbacks; reject reserved session IDs.

The follow-up cleanup removes the former dependency's compatibility interfaces:
one explicit `Dial` callback replaces the proxy-shaped dialer and redundant
destination/context handling; `AuthResult` owns identity verification without
exposing session keys; typed status errors replace the mutable status map.
Root request encoding and pagination are private protocol implementation details,
with their tests in `internal/smbwire` rather than application adapters. SMB,
NTLM, and RPC share one UTF-16 encoder, and pagination reuses its request buffer.

The transport now enforces one dial callback even for concurrent callers and
notifies the scanner when protocol failures close its socket. Cleanup and
deadline arming use the native exchange path, removing redundant calls. Existing
enumeration errors survive a later closed-transport result. RPC transfer limits
are explicit, and outgoing requests are capped by fragment count before sending.
Additional application fixes preserve case-sensitive IPv6 interface names during
deduplication, reject invalid UTF-8 account identities, and retain password read
errors returned alongside data. Regression tests cover these behaviors.

Additional review corrections and simplifications:

- SMB3.1.1 accepts the specified zero-cipher selection (encryption unavailable),
  rejects empty/malformed cipher lists, and ignores repeated unknown negotiate
  contexts while rejecting duplicate defined contexts. A fixed array replaces
  the context-tracking map. The srvsvc pipe opener is now private.
- NTLM ignores allocation sizes and fields disabled by negotiation flags,
  preserves payload bounds checks, and rejects misaligned Unicode target names.
  The bounded Type3 message is allocated once. Tests include a non-ASCII
  NTOWFv2 known-answer vector.
- DNS address fallback remains available, with IPv4/IPv6 connection attempts
  serialized to prevent parallel connected sockets. Resolution and connection
  attempts share the connection timeout; only one socket authenticates.
- Logoff errors become host errors, and disk disconnect errors become share
  diagnostics. Integrity/transport failures close the socket and fail the scan
  without discarding completed permission results. Signed-reply tampering
  regressions cover both cleanup paths.
- Enumeration pipe-close and IPC$ disconnect errors are reported while retaining
  a fully received share list and its completed enumeration status. The native
  result records completion before cleanup; the redundant application wrapper
  is removed. Primary enumeration failures retain precedence over cleanup errors.
  Independent loopback tests cover normal cleanup denials, signature corruption,
  and cleanup timeouts without erasing completed phases.
- Absolute DNS names retain their trailing dot through parsing, deduplication,
  dialing, and output. Relative and absolute spellings remain distinct targets.
  The Samba signed SMB3.1.1 user case now exercises `localhost.` end to end.
- NTLM channel binding comes from the client transport, never a hash supplied
  by the server. This transport sends one zero-valued binding because it has no
  TLS channel binding, as described by
  [MS-NLMP 3.1.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96).
  Regressions inspect the AV pairs inside the client proof and preserve the
  original challenge transcript.
- Text rows are generated on demand, invariant cells are escaped once per host,
  and ordinary cells avoid copies. Text mode no longer allocates a JSON result
  buffer. For 1,000 shares, the TSV benchmark fell from 12,033 to 28 allocations
  and aligned output from 15,013 to 1,007, with identical output bytes.
- Help, text, progress, and JSON output consistently detect short writes.
  Output failures stop queued scans. JSON normalization no longer mutates
  caller-owned result slices.
- IPv4 and unscoped mapped IPv6 aliases share one deduplication key, preventing
  duplicate scans and duplicate capacity accounting. Output keeps the first
  supplied spelling; ports and case-sensitive IPv6 zones remain distinct.
- Password prompting now checks both prompt and final newline writes. Output
  failures discard the password and retain terminal restoration. Linux PTY
  regressions cover a short prompt write and a failed final newline.
- Root WRITE checks only the three rights that grant FILE_ADD_FILE, separately
  for each ACL layer, removing unused generic-right expansion while preserving
  unknown/denied results and generic-mask behavior.
- Password redaction copies the share slice only when a field changes. For a
  normal 1,000-share result with no credential text, its benchmark fell from
  139,265 bytes/one allocation to zero bytes/zero allocations. Regressions retain
  caller-owned data and cover matches after unchanged shares.
- Native file handles now belong to a tree instance, so disconnecting a tree
  invalidates its handles even if a server reuses that numeric tree ID. Closed
  pipe operations report `net.ErrClosed` without sending requests. Connection
  close invalidates authorization and handles, closes the socket once, and can
  interrupt an exchange safely. Every logoff attempt terminates the connection;
  cancellation, protocol failures, and server errors remain observable.
  Regressions cover successful/failed disconnects, tree-ID reuse, logoff,
  cancellation, and stale READ/WRITE/CLOSE suppression.
- File autodetection no longer rejects valid network targets merely because
  their spelling is invalid as a local filename or exceeds a filename limit.
  Typed platform errors permit normal target parsing; existing files retain
  precedence, and permission/I/O errors still stop scanning. Linux regressions
  and Windows test-binary cross-compilation pass; Windows runtime is untested.
- Successful TREE_CONNECT replies must supply a synchronous header's TreeId;
  AsyncId bytes are never interpreted as a tree handle. Asynchronous status
  failures and opens on an existing tree retain their normal handling.
- NDR strings are validated and decoded directly into one UTF-8 allocation,
  eliminating temporary UTF-16/rune buffers without relaxing surrogate,
  terminator, offset, or size checks. For the 1,000-share ASCII benchmark,
  allocation fell from about 4.51 MB/6,002 allocations to 352 KB/2,002;
  the Unicode case fell from 2.47 MB/5,002 to 480 KB/2,002. Decoder fuzzing
  passed 768,068 executions after the change.
- Share preparation computes each lowercase sort key once and sorts indices,
  preserving original names, metadata, equal-key order, and protocol results.
  The 1,000-share benchmark fell from 18,140 allocations/493 KB to
  1,002 allocations/98 KB. A redundant disk-share Boolean was removed, and
  the scanner preallocates its result slice from the known share count.
- Password reads now preserve non-EOF errors even when the same read supplies
  the final newline or carriage return. Typed cancellation is retained, while
  EOF-terminated input and explicit empty passwords remain supported.
- An empty share result retains UNKNOWN placeholder permissions when a timeout
  occurs after enumeration has already completed, including a known denial or
  failure. TIMEOUT remains reserved for unanswered enumeration. Regressions
  cover both native completion markers and completed results from scan hooks.
- Target-list parsing now honors cancellation between records and bounded CIDR
  expansions, discards partial targets, and exits with code 1 before prompting
  or scanning. Help retains precedence. Deterministic regressions cover canceled
  reads, EOF, comments, and invalid ranges; an already-blocked filesystem call
  is not interrupted by this change.
- SMB3.1.1 encryption seals into the final transform buffer; decryption reuses
  its private ciphertext copy. For 64 KiB messages, allocated memory fell from
  about 149 KB to 75 KB for encryption and 141 KB to 75 KB for decryption.
  Caller inputs remain unchanged, and authentication failures return no
  plaintext. Benchmarks and buffer-ownership regressions cover encrypted dialects.
- Expired accounts, restricted logon hours, and restricted workstations now
  report authentication as failed instead of a generic error. Integration
  regressions preserve unrelated server errors and verify no share probes or
  additional connection/authentication attempts after these rejections.
- Target deduplication now keys directly on the normalized host/port pair and
  sizes its initial collections from the first bounded expansion. For a
  4,096-address IPv4 list, allocation fell from about 1.09 MB/16,449 allocations
  to 594 KB/4,120; IPv6 and overlapping mapped ranges also improved. Existing
  regressions preserve first spelling, ports, zones, DNS root dots, ordering,
  cancellation, and the unique-target cap.
- TSV output reuses a buffer and flushes complete rows after reaching 16 KiB,
  avoiding a retained rendering of the entire host. A row larger than the
  threshold remains intact. The 1,000-share benchmark fell from about
  383 KB/28 allocations to 66 KB/19; the 16,384-share case uses the same buffer
  allocation. Regression tests cover oversized Unicode rows and stopping
  immediately after a failed or short batch write.
- RPC fragment parsing no longer clones bytes already owned by its pending
  buffer. Capacity-limited views prevent appends from overwriting subsequent
  fragments. A 128 KiB fragmented response fell from about 870 KB/77 allocations
  to 721 KB/46; retained-fragment tests cover split and coalesced pipe reads.
- Terminal text escaping writes runes and fixed-width hexadecimal escapes
  directly into a sized builder, avoiding temporary formatted strings. The
  control-heavy benchmark fell from 394 allocations/about 17.5 microseconds
  to three allocations/about 3.4 microseconds; ordinary text still allocates
  nothing. Direct regressions and an independent 14,876,537-case comparison
  preserve Unicode, invalid UTF-8 replacement, escaping, and truncation output.
- Enumeration records a known primary failure before pipe/tree cleanup, so a
  later cleanup timeout cannot replace a server error or malformed NDR result
  with TIMEOUT. Cleanup uses one ordered defer and retains the original error.
  Signed loopback regressions cover server status, malformed NDR, and denial
  before each cleanup timeout; actual enumeration host/I/O timeouts still
  report TIMEOUT. Completed share lists and partial-page behavior are preserved.

Remaining module requirements are `golang.org/x/crypto` (MD4 primitive),
`golang.org/x/sys`, and `golang.org/x/term`. These are compiled into the binary;
there is no runtime Python, Samba, shared SMB library, or C runtime dependency.
This is **not** a standard-library-only or vendored/offline-build project.
`go mod tidy` removed all `jfjallid` modules and their SMB/Kerberos dependency tree.

## Validation completed

Commands run successfully on the final source state before this handoff:

```sh
go test -race ./...
go vet ./...
make build
file gosmb
git diff --check
python3 tests/interop/run.py --skip-build --report /tmp/gosmb-review10-interop-results.json
```

`file gosmb` reports a statically linked Linux amd64 ELF. CLI smoke checks
confirmed identical output from no arguments, `-h`, `--help`, and
`--invalid --help`. Source/go.mod/go.sum searches found no remaining `jfjallid`,
`go-smb`, `golog`, `gokrb5`, `mstypes`, or `gofork` references.

The replacement fixtures cover permissions, metadata fallbacks/malformed data,
credential rejection, guest/null identity (including contradictory flag cases),
single authentication, read-only wire operations, cleanup, tampered signatures,
timeouts/cancellation, pagination, and unchanged CLI behavior.

Crypto tests include Microsoft NTLMv2 and NTLM message-signature vectors,
RFC4493 CMAC, RFC3610 CCM, independent OpenSSL-backed CCM and mechanism-MIC
vectors, and encrypted-frame tampering. Short fuzz runs passed for NTLM
challenges, encrypted transforms, NDR share decoding, and RPC framing. The
completion review also ran dedicated fuzzing successfully:

- `FuzzSPNEGOResponse`: 30 seconds, 2,467,731 executions.
- `FuzzRPCResponse`: 30 seconds, approximately 799,000 executions.
- `FuzzDecodeSharePage`: 30 seconds, approximately 2.20 million executions.
- `FuzzParseMaximalAccess`: 20 seconds, 745,113 executions.
- NTLM challenge parser: 15 seconds, 1,047,605 executions.

## Independent Samba validation

The working environment is **Alpine 3.23.4 / Samba 4.22.10, linux/amd64**, using
only synthetic `LAB/audit-user` / `validation-password` credentials. Both the
independent `smbclient -L` and native client enumerate successfully. The old
Debian 4.17.12 RPC-startup issue is no longer a blocker. Samba is a separate test
server; no third-party SMB code was added to the executable or Go tests.

Reproduce from the repository root:

```sh
make test-interop
# Save detailed evidence, including observed traffic counts:
python3 tests/interop/run.py --report /tmp/gosmb-interop-results.json
```

See [tests/interop/README.md](tests/interop/README.md) for dependencies and exact
assertions. The harness builds its own temporary static executable, publishes
only on 127.0.0.1, creates no host filesystem mounts, and removes containers on
completion/failure. The reusable test image remains. No host Samba service is
installed. Ordinary Go tests require neither Docker nor Samba.

The matrix passed all ten server configurations and 35 scans again after the
latest review and cleanup. Detailed evidence from that run is at
`/tmp/gosmb-review10-interop-results.json`:

| Configuration | Cases |
| --- | --- |
| Each of SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 | User, wrong password, mapped guest, explicit guest. |
| Each SMB3 dialect with encryption disabled | Same four identities, exercising signed plaintext requests/responses. |
| SMB3.1.1 with required session encryption | User success and wrong-password rejection. |
| SMB2.1 with 1,000 additional long-comment shares | All 1,007 shares and fragmented RPC response reconstruction. |

Every successful scan checks writable, read-only, write-only, denied-root,
guest, and encryption-required shares, with an IPC share reported as N/A.
A denied root without maximum-access metadata remains WRITE=unknown; it does
not become a fabricated denial or grant. Encryption-required shares succeed
for encrypted SMB3 users and are denied for SMB2, signing-only, and guest cases.
Mapped guest reports GUEST=true; explicit guest reports GUEST=false.

The transparent observer checks the negotiated dialect and one TCP connection,
one NEGOTIATE, and two SESSION_SETUP messages representing a single NTLM login.
It inspects plaintext read-only disk opens and IPC-only content I/O, and records
security transforms without decrypting them. The client verifies signatures and
encryption integrity. Filesystem snapshots compare names, modes, owners, sizes,
mtime/ctime, and file hashes before and after each server scenario; atime is
excluded because normal reads can update it.

**Real-server pagination is not established by the large-list case.** Samba
4.22.10 returns all 1,007 shares in one successful enumeration response across
90 RPC response fragments, despite
the requested 65,536-byte preferred page length. The observer records page and
fragment counts rather than assuming more than one page. Pagination, resume
cursor progression, and partial-page failures remain covered by local tests.
The Samba behavior is consistent with its
[NetShareEnumAll implementation](https://github.com/samba-team/samba/blob/samba-4.22.10/source3/rpc_server/srvsvc/srv_srvsvc_nt.c).

Retain the proactive SPNEGO mechanism-list MIC: real Samba needs it in addition
to the NTLM Type3 transcript MIC. It enables authentication without another login
attempt. SMB3.1.1 final signature verification and encrypted IPC/root traffic
now work end to end; AES-CCM SMB3.0/3.0.2 and signing-only SMB3 are also exercised.

## Remaining coverage and limitations

- Obtain Windows/NAS coverage when an independent lab is available. Do not claim
  it from Samba, loopback fixtures, or cryptographic vectors.
- Exercise pagination against a real server that honors preferred page sizes;
  local tests already cover this behavior, but Samba 4.22.10 does not exercise it.
- SMB3.0/3.0.2 does not perform signed `FSCTL_VALIDATE_NEGOTIATE_INFO`. SMB3.1.1
  preauthentication protects its transcript; older negotiation lacks that
  protection. This is documented in README and predates the native migration.
- Kerberos, SMB1, DFS following, general filesystem operations, and interactive
  SMB features remain outside the scanner's scope.

The working tree contains earlier user-requested CLI/output/CIDR changes and
this migration, including the tracked rebuilt binary. Preserve them. Do not
reset the repository or replace the native implementation with a third-party
SMB library. No commit or push was requested or made.
