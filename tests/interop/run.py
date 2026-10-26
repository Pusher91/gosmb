#!/usr/bin/env python3
"""Optional independent Samba matrix. Uses only Python's standard library."""

import argparse
import collections
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
DIALECTS = {"SMB2_02": 0x202, "SMB2_10": 0x210, "SMB3_00": 0x300,
            "SMB3_02": 0x302, "SMB3_11": 0x311}
USER = ["-u", "audit-user", "-d", "LAB", "-p", "validation-password"]


def run(*args, timeout=120, check=True, **kwargs):
    return subprocess.run(args, check=check, timeout=timeout, text=True,
                          capture_output=True, **kwargs)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


class Observer:
    """Observe framed traffic without terminating or changing SMB security.

    Plaintext SMB2/signing-only runs independently check read-only requests and
    RPC pagination. Encrypted runs count transforms; filesystem snapshots check
    their effects. Cryptographic verification remains the native client's job.
    """

    def __init__(self, upstream, identity, encrypted):
        self.upstream = upstream
        self.identity = identity
        self.expect_encryption = encrypted
        self.authenticated = False
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.errors = []
        self.connections = 0
        self.commands = collections.Counter()
        self.encrypted = collections.Counter()
        self.signed = collections.Counter()
        self.trees = {}
        self.tree_names = {}
        self.pending_tree_name = None
        self.dialect = None
        self.client_negotiate = None
        self.server_negotiate = None
        self.validation_status = None
        self.rpc_calls = set()
        self.rpc_requests = []
        self.rpc_pages = []
        self.rpc_request_stubs = {}
        self.rpc_response_stubs = {}
        self.rpc_fragments = 0
        self.rpc_more_data = 0
        self.rpc_pending = bytearray()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(5)
        try:
            require(not self.thread.is_alive(), "traffic observer did not stop")
            # A second connection may have queued while the first was active.
            # Count that completed TCP handshake even if it never sent SMB.
            self.listener.setblocking(False)
            while True:
                try:
                    client, _ = self.listener.accept()
                except BlockingIOError:
                    break
                self.connections += 1
                client.close()
        finally:
            self.listener.close()

    def serve(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.listener], [], [], 0.1)[0]:
                    continue
                client, _ = self.listener.accept()
                self.connections += 1
                with client, socket.create_connection(self.upstream, timeout=5) as server:
                    buffers = {client: bytearray(), server: bytearray()}
                    peers = {client: server, server: client}
                    active = set(peers)
                    while active and not self.stop.is_set():
                        for source in select.select(list(active), [], [], 0.1)[0]:
                            data = source.recv(65536)
                            if not data:
                                active.remove(source)
                                peers[source].shutdown(socket.SHUT_WR)
                                continue
                            buf = buffers[source]
                            buf.extend(data)
                            while len(buf) >= 4:
                                require(buf[0] == 0, "unexpected SMB transport frame")
                                length = int.from_bytes(buf[1:4], "big")
                                require(64 <= length <= 16 << 20, "invalid frame length")
                                if len(buf) < length + 4:
                                    break
                                packet = bytes(buf[4:4 + length])
                                del buf[:4 + length]
                                self.observe(packet, source is client)
                            peers[source].sendall(data)
        except Exception as exc:
            self.errors.append(str(exc))

    def observe(self, packet, request):
        if packet[:4] == b"\xfdSMB":
            require(self.authenticated and self.expect_encryption,
                    "unexpected encrypted traffic before user authentication")
            self.encrypted[request] += 1
            return
        require(packet[:4] == b"\xfeSMB", "unexpected protocol")
        command, flags, tree = u16(packet, 12), u32(packet, 16), u32(packet, 36)
        status = None if request else u32(packet, 8)
        if self.authenticated:
            require(not self.expect_encryption,
                    f"plaintext post-authentication SMB command {command}")
            if self.identity == "authenticated":
                # MS-SMB2 interim STATUS_PENDING replies can be unsigned.
                require(status == 0x103 or flags & 8,
                        f"unsigned post-authentication SMB command {command}")
            else:
                require(not flags & 8, "signed guest-session traffic")
        elif not request and command == 1 and status == 0:
            require(self.identity != "failed", "bad credentials established a session")
            require(bool(flags & 8) == (self.identity == "authenticated"),
                    "incorrect final session-setup signature flag")
            self.authenticated = True
        else:
            require(command in (0, 1), "SMB operation before authentication")
        if flags & 8:
            self.signed[request] += 1
        if not request:
            if command == 0 and status == 0:
                self.dialect = u16(packet, 68)
                self.server_negotiate = packet[88:92] + packet[72:88] + packet[66:70]
            if command == 3 and status == 0:
                self.trees[tree] = packet[66]
                self.tree_names[tree] = self.pending_tree_name
            if command == 11 and status != 0x103:
                require(self.commands[11] == 1 and self.validation_status is None,
                        "unexpected secure-negotiate response")
                self.validation_status = status
                if status == 0:
                    require(len(packet) >= 112 and u16(packet, 64) == 49
                            and u32(packet, 68) == 0x00140204
                            and packet[72:88] == b"\xff" * 16
                            and u32(packet, 92) == 0 and u32(packet, 100) == 24
                            and u32(packet, 104) == 0,
                            "invalid secure-negotiate response")
                    start = u32(packet, 96)
                    require(start >= 112 and start % 8 == 0
                            and packet[start:start + 24] == self.server_negotiate,
                            "secure negotiation changed the original server response")
                else:
                    require(self.dialect < 0x300
                            and status in (0xc00000bb, 0xc0000010, 0xc0000128),
                            "secure negotiation failed")
            if command == 8 and status in (0, 0x80000005):
                start, count = packet[66], u32(packet, 68)
                self.rpc_pending.extend(packet[start:start + count])
                while len(self.rpc_pending) >= 16:
                    size = u16(self.rpc_pending, 8)
                    require(size >= 16, "invalid RPC response length")
                    if len(self.rpc_pending) < size:
                        break
                    rpc = self.rpc_pending[:size]
                    if rpc[2] == 2:
                        require(size >= 24, "short RPC response")
                        call = u32(rpc, 12)
                        require(self.rpc_requests and call == self.rpc_requests[-1][0]
                                and len(self.rpc_pages) < len(self.rpc_requests),
                                "RPC response does not match an enumeration request")
                        require(bool(rpc[3] & 1) == (call not in self.rpc_response_stubs),
                                "invalid RPC response fragment sequence")
                        stub = self.rpc_response_stubs.setdefault(call, bytearray())
                        stub.extend(rpc[24:])
                        require(len(stub) <= 8 << 20, "RPC response exceeds safety limit")
                        self.rpc_fragments += 1
                        if rpc[3] & 2:
                            require(len(stub) >= 12, "short enumeration response")
                            page_status = u32(stub, len(stub) - 4)
                            resume = None
                            if page_status == 234:
                                require(len(stub) >= 16 and u32(stub, len(stub) - 12),
                                        "ERROR_MORE_DATA omitted its resume pointer")
                                resume = u32(stub, len(stub) - 8)
                                require(resume and resume not in [item[1] for item in self.rpc_requests],
                                        "ERROR_MORE_DATA returned a non-progressing cursor")
                                self.rpc_more_data += 1
                            self.rpc_pages.append((call, page_status, resume))
                            del self.rpc_response_stubs[call]
                    del self.rpc_pending[:size]
            return

        self.commands[command] += 1
        require(command in (0, 1, 2, 3, 4, 5, 6, 8, 9, 11),
                f"unexpected SMB command {command}")
        if command == 0:
            count = u16(packet, 66)
            require(len(packet) >= 100 + 2 * count, "incomplete negotiate dialects")
            self.client_negotiate = (packet[72:92] + packet[68:70]
                                     + packet[66:68] + packet[100:100 + 2 * count])
        if command == 3:
            start, count = u16(packet, 68), u16(packet, 70)
            path = packet[start:start + count].decode("utf-16-le")
            self.pending_tree_name = path.rsplit("\\", 1)[-1].casefold()
        if command == 11:
            require(self.identity == "authenticated" and self.dialect != 0x311
                    and self.commands[11] == 1 and self.trees.get(tree) == 2
                    and self.tree_names.get(tree) == "ipc$"
                    and len(packet) >= 120 and u16(packet, 64) == 57
                    and u32(packet, 68) == 0x00140204
                    and packet[72:88] == b"\xff" * 16
                    and u32(packet, 88) == 120 and u32(packet, 96) == 0
                    and u32(packet, 100) == 120 and u32(packet, 104) == 0
                    and u32(packet, 108) == 24 and u32(packet, 112) == 1,
                    "unexpected SMB IOCTL")
            count = u32(packet, 92)
            require(self.client_negotiate is not None
                    and count == len(self.client_negotiate) and len(packet) == 120 + count
                    and packet[120:120 + count] == self.client_negotiate,
                    "secure negotiation changed the original client offer")
        if command in (5, 8, 9) and self.identity == "authenticated" and self.dialect != 0x311:
            require(self.validation_status is not None,
                    "share probing began before secure negotiation finished")
        if command == 5:
            name_at, name_size = u16(packet, 108), u16(packet, 110)
            name = packet[name_at:name_at + name_size].decode("utf-16-le")
            require(u32(packet, 100) == 1, "open could create an object")
            require(packet[67] == 0 and u32(packet, 96) == 7,
                    "open requested an oplock or exclusive sharing")
            if self.trees.get(tree) == 2:
                require(name == "srvsvc" and u32(packet, 88) == 0x100003,
                        "unexpected pipe open")
            else:
                require(self.trees.get(tree) == 1, "open on unknown tree")
                require(name == "" and u32(packet, 88) in (1, 0x80)
                        and u32(packet, 104) == 1, "non-read-only root open")
        if command in (8, 9):
            require(self.trees.get(tree) == 2, "disk content read/write attempted")
        if command == 9:
            start, count = u16(packet, 66), u32(packet, 68)
            rpc = packet[start:start + count]
            require(len(rpc) >= 16 and rpc[2] in (0, 11), "unexpected pipe write")
            if rpc[2] == 0:
                require(len(rpc) >= 24 and u16(rpc, 8) == len(rpc), "invalid RPC request length")
                require(u16(rpc, 22) == 15, "unexpected RPC operation")
                call = u32(rpc, 12)
                require(bool(rpc[3] & 1) == (call not in self.rpc_request_stubs),
                        "invalid RPC request fragment sequence")
                if rpc[3] & 1:
                    require(call not in self.rpc_calls, "reused RPC enumeration call ID")
                    self.rpc_calls.add(call)
                stub = self.rpc_request_stubs.setdefault(call, bytearray())
                stub.extend(rpc[24:])
                require(len(stub) <= 8 << 20, "RPC request exceeds safety limit")
                if rpc[3] & 2:
                    require(len(stub) >= 8 and u32(stub, len(stub) - 8),
                            "enumeration request omitted its resume pointer")
                    resume = u32(stub, len(stub) - 4)
                    if self.rpc_requests:
                        require(len(self.rpc_pages) == len(self.rpc_requests)
                                and self.rpc_pages[-1][1] == 234
                                and resume == self.rpc_pages[-1][2],
                                "enumeration did not continue the returned cursor")
                    else:
                        require(resume == 0, "first enumeration did not start at zero")
                    self.rpc_requests.append((call, resume))
                    del self.rpc_request_stubs[call]


def check_result(result, identity, encrypted, bulk):
    require(result["authentication"] == identity, f"wrong identity: {result}")
    require(result["enumeration"] == "ok", f"enumeration failed: {result}")
    shares = {share["name"]: share for share in result["shares"]}
    require(len(shares) == bulk + 7, f"incomplete/duplicate shares: {len(shares)}")
    require(len(result["shares"]) == len(shares), "duplicate share records")
    require(shares["IPC$"]["read_root"] == "n/a", "IPC classified as a disk")

    def permissions(name, read, write):
        actual = shares[name]
        require((actual["read_root"], actual["write_root"]) == (read, write),
                f"incorrect {name} permissions: {actual}")

    permissions("guest", "allowed", "denied")
    if identity == "authenticated":
        permissions("readwrite", "allowed", "allowed")
        permissions("readonly", "allowed", "denied")
        permissions("writeonly", "denied", "allowed")
        permissions("denied", "denied", "unknown")
        permissions("encrypted", "allowed" if encrypted else "denied",
                    "allowed" if encrypted else "denied")
        for index in range(1, bulk + 1):
            permissions(f"bulk-{index:04d}", "allowed", "allowed")
    else:
        for name in ("readwrite", "readonly", "writeonly", "denied", "encrypted"):
            permissions(name, "denied", "denied")


def scan(binary, endpoint, dialect, mode, credentials, expected, bulk=0, target_host="127.0.0.1"):
    encrypted = DIALECTS[dialect] >= 0x300 and mode != "off" and expected == "authenticated"
    with Observer(endpoint, expected, encrypted) as observer:
        target = f"{target_host}:{observer.port}"
        completed = run(str(binary), target, "--json",
                        "--no-progress", "--timeout=10s", "--host-timeout=120",
                        *credentials, check=False, timeout=130)
    require(not observer.errors, f"traffic observer: {observer.errors}")
    require(observer.connections == 1, f"TCP attempts: {observer.connections}")
    require(observer.commands[0] == 1 and observer.commands[1] == 2,
            f"unexpected negotiate/authentication attempts: {observer.commands}")
    require(observer.dialect == DIALECTS[dialect], "wrong negotiated dialect")
    results = json.loads(completed.stdout)
    require(isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict),
            "expected exactly one JSON host result")
    result = results[0]
    require(result["target"] == target, "requested target spelling was changed")
    require(not result.get("timed_out", False), "unexpected scan timeout")
    if expected == "failed":
        require(completed.returncode == 1 and result["authentication"] == "failed"
                and result["enumeration"] == "not_attempted" and not result["shares"],
                f"bad password accepted: {result}")
    else:
        check_result(result, expected, encrypted, bulk)
        # Samba can reject TREE_DISCONNECT on the deliberately inaccessible
        # root. Keep that cleanup failure observable without accepting any
        # other host error or mistaking it for failed permission enumeration.
        cleanup_shares = [share for share in result["shares"]
                          if "close root handle:" in share.get("error", "")
                          or "disconnect share:" in share.get("error", "")]
        cleanup_error = None
        if cleanup_shares:
            require(expected == "authenticated" and len(cleanup_shares) == 1
                    and cleanup_shares[0]["name"] == "denied"
                    and cleanup_shares[0]["error"] == (
                        "root access query: request: SMB status 0xc0000022\n"
                        "disconnect share: request: SMB status 0xc0000022"),
                    f"unexpected cleanup failure: {cleanup_shares}")
            cleanup_error = "share denied cleanup: disconnect share: request: SMB status 0xc0000022"
        require(result.get("error") == cleanup_error,
                f"unexpected host error: {result.get('error')}")
        require(completed.returncode == int(cleanup_error is not None),
                completed.stderr or completed.stdout)
        fallback = expected == "guest" and credentials != ["--guest"]
        require(result["guest_fallback"] == fallback, "wrong guest fallback label")
        if encrypted:
            require(observer.encrypted[True] > 0 and observer.encrypted[False] > 0,
                    "SMB3 user traffic was not encrypted in both directions")
        else:
            require(not observer.encrypted, "unexpected encryption")
            validate = expected == "authenticated" and DIALECTS[dialect] != 0x311
            require(observer.commands[11] == int(validate),
                    "incorrect number of secure-negotiate requests")
            require((observer.validation_status is not None) == validate,
                    "secure negotiation did not finish")
            require(len(observer.rpc_pages) == len(observer.rpc_calls)
                    and observer.rpc_pages and observer.rpc_pages[-1][1] == 0
                    and not observer.rpc_request_stubs and not observer.rpc_response_stubs,
                    "enumeration did not finish its RPC responses")
            if expected == "authenticated":
                require(observer.signed[True] > 0 and observer.signed[False] > 0,
                        "unsigned user traffic")
            else:
                require(not observer.signed, "guest traffic unexpectedly signed")
        if bulk:
            require(observer.rpc_fragments > len(observer.rpc_calls),
                    "large list did not exercise RPC fragmentation")
    return {"identity": expected, "target": target, "connections": observer.connections,
            "session_setup_requests": observer.commands[1],
            "encrypted_requests": observer.encrypted[True],
            "negotiate_validation_status": None if encrypted else observer.validation_status,
            "cleanup_failure_reported": bool(result.get("error")) if expected != "failed" else False,
            "enumeration_pages": None if encrypted else len(observer.rpc_pages),
            "more_data_responses": None if encrypted else observer.rpc_more_data,
            "pagination_exercised": None if encrypted else observer.rpc_more_data > 0,
            "rpc_response_fragments": None if encrypted else observer.rpc_fragments}


def scenario(image, binary, dialect, mode, bulk):
    name = "gosmb-interop-" + uuid.uuid4().hex[:12]
    try:
        run("docker", "run", "--detach", "--platform", "linux/amd64", "--name", name,
            "--publish", "127.0.0.1::1445", "--env", "GOSMB_DIALECT=" + dialect,
            "--env", "GOSMB_ENCRYPTION=" + mode,
            "--env", f"GOSMB_BULK_SHARES={bulk}", image)
        port = json.loads(run("docker", "inspect", name).stdout)[0]["NetworkSettings"]["Ports"]["1445/tcp"][0]
        require(port["HostIp"] == "127.0.0.1", "fixture is not bound to loopback")
        endpoint = ("127.0.0.1", int(port["HostPort"]))
        # Prove independent server/RPC health before attributing faults to gosmb.
        deadline = time.monotonic() + 45
        while True:
            reference = run("docker", "exec", name, "smbclient", "-L", "127.0.0.1",
                            "-p", "1445", "-U", "LAB/audit-user%validation-password",
                            "--client-protection=encrypt" if mode == "required"
                            else "--client-protection=sign", check=False, timeout=20)
            if reference.returncode == 0 and "readwrite" in reference.stdout:
                break
            require(time.monotonic() < deadline,
                    "independent smbclient failed: " + reference.stdout + reference.stderr)
            time.sleep(0.25)
        before = run("docker", "exec", name, "/usr/local/bin/gosmb-interop-snapshot").stdout
        cases = [("user", USER, "authenticated")]
        if not bulk:
            cases.append(("wrong_password", ["-u", "audit-user", "-d", "LAB", "-p", "incorrect"], "failed"))
            if mode != "required":
                cases.extend([
                    ("mapped_guest", ["-u", "nonexistent-user", "-d", "LAB", "-p", "incorrect"], "guest"),
                    ("explicit_guest", ["--guest"], "guest"),
                ])
        evidence = []
        for label, credentials, identity in cases:
            # Exercise an absolute hostname through DNS, NTLM, tree connect,
            # and RPC while retaining the same loopback-only traffic observer.
            host = "localhost." if label == "user" and dialect == "SMB3_11" and mode == "off" else "127.0.0.1"
            result = scan(binary, endpoint, dialect, mode, credentials, identity, bulk, host)
            result["case"] = label
            evidence.append(result)
            print(f"PASS {dialect} encryption={mode} bulk={bulk} {label}", flush=True)
        after = run("docker", "exec", name, "/usr/local/bin/gosmb-interop-snapshot").stdout
        require(before == after, "share filesystem changed during scanning")
        version = run("docker", "exec", name, "smbd", "--version").stdout.strip()
        return {"dialect": dialect, "encryption": mode, "bulk_shares": bulk,
                "server": version, "filesystem_unchanged": True, "cases": evidence}
    except BaseException:
        logs = run("docker", "logs", name, check=False)
        print(logs.stdout + logs.stderr)
        raise
    finally:
        run("docker", "rm", "--force", name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="gosmb-interop:local")
    parser.add_argument("--skip-build", action="store_true", help="reuse the fixture image")
    parser.add_argument("--report", type=Path, help="write JSON validation evidence")
    args = parser.parse_args()
    if not args.skip_build:
        print("Building independent Samba fixture...", flush=True)
        build = run("docker", "build", "--platform", "linux/amd64", "-t", args.image,
                    str(ROOT / "tests" / "interop"), timeout=600, check=False)
        require(build.returncode == 0, build.stdout + build.stderr)
    with tempfile.TemporaryDirectory(prefix="gosmb-interop-") as work:
        binary = Path(work) / "gosmb"
        run("go", "build", "-trimpath", "-o", str(binary), ".", cwd=ROOT,
            env={**os.environ, "CGO_ENABLED": "0"})
        matrix = [(dialect, "if_required", 0) for dialect in DIALECTS]
        matrix += [(dialect, "off", 0) for dialect in DIALECTS if DIALECTS[dialect] >= 0x300]
        matrix += [("SMB3_11", "required", 0), ("SMB2_10", "if_required", 1000)]
        results = [scenario(args.image, binary, *item) for item in matrix]
    if args.report:
        args.report.write_text(json.dumps(results, indent=2) + "\n")
    print(f"PASS: {len(results)} independent-server scenarios; share snapshots unchanged.")


if __name__ == "__main__":
    main()
