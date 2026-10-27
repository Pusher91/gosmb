# gosmb

Read-only SMB share permission checker for Windows, Samba, and NAS servers.
Lists shares and checks root permissions over SMB 2/3 using NTLM authentication.
No file contents are read, and no files are created or modified.

Binaries are in [builds/](builds/) for Linux, Windows, and macOS on AMD64 and ARM64.
Examples below use `gosmb` as the executable name.

## Usage

```sh
gosmb servers.txt --guest --concurrency 10 | tee gosmb_guest.out
gosmb fileserver.example.com -u 'EXAMPLE\alice'
gosmb 192.0.2.0/24 -u alice --json > results.json
gosmb --help
```

Omit `-p` for a hidden password prompt, or set `GOSMB_PASSWORD`.
`--guest` requires no credentials and cannot be combined with `-u`, `-p`, or `-d`.
Each host gets one authentication attempt; rejected credentials are not retried.

Targets can be hostnames, IP addresses, CIDRs, or a file containing one target per
line. Blank lines and `#` comments are ignored. Ports default to **445**;
use `host:port`, `[IPv6]:port`, or `[IPv6/prefix]:port` for a custom port.
CIDRs include every address. Duplicate endpoints are removed, with a maximum of
**65,536 unique endpoints** per run.

| Option | Purpose | Default |
| --- | --- | --- |
| `--concurrency N` | Parallel host scans | `1` |
| `--timeout TIME` | SMB I/O timeout | `10s` |
| `--host-timeout N` | Whole-host timeout in seconds | `30` |
| `--delay TIME` | Minimum interval between host starts | `0` |
| `--tsv` / `--json` | Select an output format | Aligned table |
| `--no-header` | Omit the text header | Header shown |
| `--no-progress` | Hide progress and summary | Shown on terminal stderr |

## Output

Example `--guest` output:

```text
TARGET_IP              SHARE                 READ     WRITE    GUEST    STATUS              HOSTNAME
192.0.2.10:445         public                TRUE     FALSE    N/A      OK                  -
192.0.2.10:445         IPC$                  N/A      N/A      N/A      OK                  -
192.0.2.11:445         -                     UNKNOWN  UNKNOWN  N/A      AUTH_FAILED         -
192.0.2.12:445         -                     TIMEOUT  TIMEOUT  N/A      CONNECT_TIMEOUT     -
```

- **READ**: permission to list the share root; individual files may differ.
- **WRITE**: permission to add files at the root, inferred from share and root
  metadata. No write is attempted; server policy or quotas can still prevent one.
- **GUEST**: `TRUE` when supplied credentials are accepted as Guest; `N/A` with `--guest`.
- **STATUS**: scan outcome. `OK` means the check completed, even when access is denied.
- **HOSTNAME**: supplied hostname, or `-` for literal IPs; no reverse DNS.

Permissions are `TRUE`, `FALSE`, `UNKNOWN`, `TIMEOUT`, or `N/A` for non-disk shares.
The table keeps the same format through pipes and clips long cells except
`HOSTNAME`. Use `--tsv` for full values or `--json` for detailed errors.
Text rows stream as hosts finish; JSON is written as one array at the end.

```sh
# Filter readable shares using explicit TSV output.
gosmb servers.txt --guest --tsv --no-header --no-progress | awk -F '\t' '$3 == "TRUE"'
```

Progress and totals use terminal stderr. Piped runs show only start/end counts;
`--no-progress` hides both. Ctrl+C keeps completed rows, but saving the final
interruption count through `tee` is best effort.

Exit codes: **0** for successful scans, **1** for scan/output failures or
interruption, **2** for invalid input. Denied share permissions and unavailable
permission metadata alone do not make a scan fail.

## Build and test

Use the Go toolchain specified in [go.mod](go.mod).

```sh
./build.sh             # Build all six binaries into builds/
go test -race ./...
go vet ./...
```

Optional Docker/Samba checks: [interoperability tests](tests/interop/README.md).
