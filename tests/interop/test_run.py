"""Report validation regressions; no Docker, SMB server, or Go binary needed."""

from collections import Counter
from contextlib import nullcontext
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run as interop


class ScanReportTests(unittest.TestCase):
    def setUp(self):
        self.observer = SimpleNamespace(
            port=12345, errors=[], connections=1, commands={0: 1, 1: 2, 11: 1},
            dialect=0x210, encrypted=Counter(), signed={True: 1, False: 1},
            validation_status=0xc00000bb, rpc_pages=[(1, 0, None)], rpc_calls={1},
            rpc_request_stubs={}, rpc_response_stubs={}, rpc_more_data=0, rpc_fragments=1,
        )
        permissions = {
            "IPC$": ("n/a", "n/a"), "guest": ("allowed", "denied"),
            "readwrite": ("allowed", "allowed"), "readonly": ("allowed", "denied"),
            "writeonly": ("denied", "allowed"), "denied": ("denied", "unknown"),
            "encrypted": ("denied", "denied"),
        }
        shares = [dict(name=name, read_root=read, write_root=write)
                  for name, (read, write) in permissions.items()]
        next(share for share in shares if share["name"] == "denied")["error"] = (
            "root access query: request: SMB status 0xc0000022\n"
            "disconnect share: request: SMB status 0xc0000022"
        )
        self.result = dict(
            target="127.0.0.1:12345", authentication="authenticated", enumeration="ok",
            guest_fallback=False, shares=shares,
            error="share denied cleanup: disconnect share: request: SMB status 0xc0000022",
        )

    def scan_report(self, results, identity="authenticated"):
        completed = subprocess.CompletedProcess([], 1, json.dumps(results), "")
        with patch.object(interop, "Observer", return_value=nullcontext(self.observer)), \
                patch.object(interop, "run", return_value=completed):
            return interop.scan("unused-binary", ("127.0.0.1", 1), "SMB2_10",
                                "if_required", interop.USER, identity)

    def test_expected_cleanup_denial_remains_accepted(self):
        report = self.scan_report([self.result])
        self.assertTrue(report["cleanup_failure_reported"])

    def test_timeout_cannot_hide_behind_preserved_cleanup_error(self):
        self.result["timed_out"] = True
        with self.assertRaisesRegex(AssertionError, "unexpected scan timeout"):
            self.scan_report([self.result])

    def test_wrong_password_result_must_not_time_out(self):
        self.result.update(authentication="failed", enumeration="not_attempted", shares=[])
        self.scan_report([self.result], "failed")
        self.result["timed_out"] = True
        with self.assertRaisesRegex(AssertionError, "unexpected scan timeout"):
            self.scan_report([self.result], "failed")

    def test_report_requires_exactly_one_host_object(self):
        for results in (None, self.result, [], [self.result, self.result], ["not a host"]):
            with self.subTest(results=results):
                with self.assertRaisesRegex(AssertionError, "exactly one JSON host result"):
                    self.scan_report(results)


if __name__ == "__main__":
    unittest.main()
