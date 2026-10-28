"""Pre-push integration checks using temporary local repositories and tiny builds."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / ".githooks" / "pre-push"
BINARIES = (
    "gosmb-linux-amd64", "gosmb-linux-arm64",
    "gosmb-macos-amd64", "gosmb-macos-arm64",
    "gosmb-windows-amd64.exe", "gosmb-windows-arm64.exe",
)
ZERO = "0" * 40


class PrePushTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="gosmb-hook-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "working repo"
        self.repo.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.build_log = self.root / "build.log"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        TMPDIR=str(self.scratch), GOSMB_TEST_BUILD_LOG=str(self.build_log))
        self.git("init", "-q", "--initial-branch=main")
        self.git("config", "user.name", "Hook test")
        self.git("config", "user.email", "hook@example.invalid")
        self.git("config", "core.hooksPath", ".githooks")
        (self.repo / ".githooks").mkdir()
        shutil.copy2(HOOK, self.repo / ".githooks" / "pre-push")
        (self.repo / "source.txt").write_text("original source\n")
        (self.repo / "build.sh").write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\n'
            'source_dir="$(dirname -- "${BASH_SOURCE[0]}")"\n'
            'printf "build\\n" >> "$GOSMB_TEST_BUILD_LOG"\n'
            '[[ ! -f "$source_dir/fail-build" ]] || exit 1\n'
            '[[ ! -f "$source_dir/empty-build" ]] || exit 0\n'
            'mkdir -p -- "$1"\n'
            'for name in ' + " ".join(BINARIES) + '; do\n'
            '  printf "%s\\n" "$name" > "$1/$name"\n'
            '  cat "$source_dir/source.txt" >> "$1/$name"\n'
            '  chmod +x "$1/$name"\n'
            'done\n'
        )
        self.command("bash", "build.sh", "builds")
        self.commit()
        self.initial = self.git("rev-parse", "HEAD").stdout.strip()
        self.build_log.write_text("")

    def tearDown(self):
        self.assertEqual(list(self.scratch.iterdir()), [], "hook left temporary builds behind")

    def command(self, *args, check=True, input=None):
        return subprocess.run(args, cwd=self.repo, env=self.env, input=input,
                              text=True, capture_output=True, check=check, timeout=20)

    def git(self, *args, **kwargs):
        return self.command("git", *args, **kwargs)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")

    def hook(self, *records):
        return self.command("bash", ".githooks/pre-push", "origin", "unused",
                            input="".join(records), check=False)

    def record(self, oid=None, ref="refs/heads/main"):
        oid = oid or self.git("rev-parse", "HEAD").stdout.strip()
        return f"{ref} {oid} {ref} {ZERO}\n"

    def test_local_push_accepts_current_builds_and_rejects_stale_builds(self):
        remote = self.root / "remote.git"
        self.git("init", "-q", "--bare", str(remote))
        self.git("remote", "add", "origin", str(remote))
        self.git("push", "origin", "main")
        self.assertEqual(self.git("--git-dir", str(remote), "rev-parse", "refs/heads/main").stdout.strip(),
                         self.initial)

        (self.repo / "source.txt").write_text("changed source\n")
        self.commit()
        result = self.git("push", "origin", "main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Push blocked:", result.stderr)
        for name in BINARIES:
            self.assertIn("Outdated or missing: builds/" + name, result.stderr)
        self.assertEqual(self.git("--git-dir", str(remote), "rev-parse", "refs/heads/main").stdout.strip(),
                         self.initial)
        self.assertEqual(self.build_log.read_text(), "build\nbuild\n")

        self.command("bash", "build.sh", "builds")
        self.commit()
        rebuilt = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("push", "origin", "main")
        self.assertEqual(self.git("--git-dir", str(remote), "rev-parse", "refs/heads/main").stdout.strip(),
                         rebuilt)
        self.assertEqual(self.build_log.read_text(), "build\n" * 4)

    def test_missing_committed_binary_blocks_push(self):
        (self.repo / "builds" / BINARIES[0]).unlink()
        self.commit()
        result = self.hook(self.record())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Outdated or missing: builds/" + BINARIES[0], result.stderr)

    def test_build_failure_and_empty_output_block_push(self):
        for marker, message in (("fail-build", "build failed"),
                                ("empty-build", "build produced no binaries")):
            with self.subTest(marker=marker):
                path = self.repo / marker
                path.touch()
                self.commit()
                result = self.hook(self.record())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                path.unlink()
                self.commit()

    def test_uncommitted_work_and_index_are_untouched(self):
        (self.repo / "source.txt").write_text("unstaged source\n")
        (self.repo / "untracked.go").write_text("invalid Go source\n")
        (self.repo / "builds" / BINARIES[0]).write_text("staged artifact\n")
        self.git("add", "builds/" + BINARIES[0])
        index = (self.repo / ".git" / "index").read_bytes()
        contents = {path: path.read_bytes() for path in self.repo.rglob("*")
                    if path.is_file() and ".git" not in path.relative_to(self.repo).parts}

        result = self.hook(self.record())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), index)
        self.assertEqual({path: path.read_bytes() for path in self.repo.rglob("*")
                          if path.is_file() and ".git" not in path.relative_to(self.repo).parts}, contents)

    def test_checks_outgoing_commit_instead_of_head(self):
        (self.repo / "source.txt").write_text("stale commit source\n")
        self.commit()
        stale = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("checkout", "-q", "--detach", self.initial)
        result = self.hook(self.record(stale, "refs/heads/other"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refs/heads/other", result.stderr)
        self.assertIn("Outdated or missing:", result.stderr)

    def test_deletion_and_empty_push_do_not_build(self):
        for records in ((), (f"(delete) {ZERO} refs/heads/old {self.initial}\n",)):
            with self.subTest(records=records):
                result = self.hook(*records)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
        self.assertEqual(self.build_log.read_text(), "")

    def test_duplicate_commit_refs_build_once(self):
        result = self.hook(self.record(), self.record(ref="refs/heads/other"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.build_log.read_text(), "build\n")


if __name__ == "__main__":
    unittest.main()
