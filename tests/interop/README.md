# Independent Samba interoperability tests

Run from the repository root:

```sh
make test-interop
# Optionally retain detailed evidence outside the repository:
python3 tests/interop/run.py --report /tmp/gosmb-interop-results.json
```

Report validation tests need only Python and run without Docker or a Go binary:

```sh
python3 -m unittest discover -s tests/interop -p 'test_*.py'
```

Requirements: Go, Python 3, Docker with a running Linux daemon, and network access
for the initial Alpine image/package build. The fixture uses an explicitly amd64
Alpine 3.23.4 image; Docker may emulate amd64 on another architecture. Package
revisions come from Alpine's repositories, and the report records the Samba
version actually tested. Use `--skip-build` to reuse the local fixture image, or
`--image NAME` to choose its tag.

Validated on 2026-10-25 with Samba 4.22.10: all 35 scans across ten configurations
passed, with unchanged filesystem snapshots. The large-list case returned all
1,007 shares in one enumeration page spanning 90 RPC response fragments.

The script builds a temporary static gosmb binary and a disposable independent
Samba server. Each scenario publishes a random port on **127.0.0.1 only** and
uses synthetic `LAB/audit-user` / `validation-password` credentials. No host
directories are mounted, no host Samba service is installed, and no existing SMB
server is scanned. Containers are removed on completion, failure, or Ctrl-C;
the reusable Docker image remains. A force kill can leave a container named
`gosmb-interop-*`, which can be removed manually.

Before each scenario, Samba's own `smbclient -L` must successfully enumerate
shares. This separates fixture startup failures from native-client failures.
The matrix covers:

- SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1, with the server forced to each dialect.
- User authentication, wrong passwords, mapped guest, and explicit guest.
- Writable, read-only, write-only, inaccessible roots, and encryption-required
  shares. WRITE comes from metadata; the scanner never attempts a disk write.
- Cleanup failure reporting: if Samba refuses `TREE_DISCONNECT` on the fixture's
  inaccessible `denied` root, the scan must retain its permission results, report
  that specific cleanup error, and exit 1. Other cleanup or host errors fail the
  matrix; ordinary share denials alone still exit 0.
- SMB3 encryption, separate signing-only SMB3 cases, and required SMB3.1.1
  session encryption.
- Secure negotiation on authenticated sessions below SMB3.1.1. For visible
  traffic, the observer checks that the request and successful response exactly
  reproduce the original client and server negotiation fields. Signed unsupported
  responses are allowed only on SMB2.0.2/2.1.
- The signed SMB3.1.1 user case uses `localhost.` to exercise an absolute DNS
  name through authentication and enumeration, and preserve it in JSON output.
- A 1,000-share SMB2.1 case with long comments that must produce fragmented
  RPC responses and all 1,007 shares, including the standard fixture shares.
  Samba 4.22.10 returns the entire list in one page despite the preferred page
  length, so this does not establish independent-server pagination coverage.
  Pagination and cursor handling remain covered by the Go fixtures.

A transparent TCP observer checks the negotiated dialect and requires exactly
one connection, one NEGOTIATE, and two SESSION_SETUP messages (the two legs of
one NTLM login). It checks protection on every post-authentication packet in both
directions, allowing unsigned interim STATUS_PENDING replies where SMB permits
them. Encrypted RPC counts are recorded as unavailable. In
plaintext and signing-only scenarios, it rejects unexpected SMB/RPC commands,
disk content reads/writes, non-root disk opens, create dispositions other than
FILE_OPEN, and exclusive sharing/oplocks. The only allowed IOCTL is the bounded
`FSCTL_VALIDATE_NEGOTIATE_INFO` connection check on IPC$. It does not decrypt SMB3 transforms
or independently verify signatures; the native client verifies integrity, with
separate known-answer and tampering tests in the ordinary Go suite.

Before/after snapshots compare every fixture name, owner, mode, size, modification
and change times, and file digest, including the share roots. Access times are excluded
because normal server lookups and the snapshot itself can update them. The
ordinary loopback tests additionally enforce read-only requests and hostile
response behavior without Docker or Samba.

This matrix establishes interoperability with the Samba version in its report.
It does not establish Windows/NAS compatibility, exhaustive SMB conformance,
or interoperability with every server policy. SMB3.1.1 uses preauthentication
integrity. Older SMB2 servers can reject secure negotiation with an authenticated
unsupported response, leaving the original negotiation fields unvalidated.
Windows/NAS coverage requires a separately available lab.
