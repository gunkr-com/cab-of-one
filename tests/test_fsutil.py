"""Invariant tests for cab_of_one.runtime.fsutil. Temporary files live under .local/test-tmp."""

from __future__ import annotations

import errno
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cab_of_one.runtime import fsutil

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_TMP = REPO_ROOT / ".local" / "test-tmp"


class _TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        TEST_TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="fsutil-", dir=TEST_TMP))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")


class AtomicWriteTests(_TmpCase):
    def test_creates_and_replaces_exact_bytes_without_leftovers(self) -> None:
        target = self.tmp / "settings.json"
        fsutil.atomic_write(target, b"first\n")
        self.assertEqual(target.read_bytes(), b"first\n")
        payload = bytes(range(256)) * 3
        fsutil.atomic_write(target, payload)
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(os.listdir(self.tmp), ["settings.json"])

    def test_preserves_existing_mode(self) -> None:
        target = self.tmp / "hook.py"
        target.write_bytes(b"old")
        os.chmod(target, 0o640)
        if stat.S_IMODE(os.stat(target).st_mode) != 0o640:
            self.skipTest("filesystem does not keep chmod bits")
        fsutil.atomic_write(target, b"new")
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o640)
        self.assertEqual(target.read_bytes(), b"new")

    def test_replace_failure_keeps_original_and_cleans_temp(self) -> None:
        target = self.tmp / "policy.toml"
        target.write_bytes(b"original")
        injected = OSError(errno.EIO, "injected replace failure")
        with mock.patch.object(fsutil.os, "replace", side_effect=injected):
            with self.assertRaises(OSError):
                fsutil.atomic_write(target, b"replacement")
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(os.listdir(self.tmp), ["policy.toml"])

    def test_fsync_failure_keeps_original_and_cleans_temp(self) -> None:
        target = self.tmp / "policy.toml"
        target.write_bytes(b"original")
        injected = OSError(errno.EIO, "injected fsync failure")
        with mock.patch.object(fsutil.os, "fsync", side_effect=injected):
            with self.assertRaises(OSError):
                fsutil.atomic_write(target, b"replacement")
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(os.listdir(self.tmp), ["policy.toml"])

    def test_refuses_symlink_target_and_leaves_link_target_untouched(self) -> None:
        outside = self.tmp / "outside.txt"
        outside.write_bytes(b"outside")
        link = self.tmp / "link.txt"
        self.symlink_or_skip(outside, link)
        with self.assertRaises(fsutil.SymlinkRefused):
            fsutil.atomic_write(link, b"attack")
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["link.txt", "outside.txt"])

    def test_refuses_dangling_symlink(self) -> None:
        link = self.tmp / "dangling"
        self.symlink_or_skip(self.tmp / "nowhere", link)
        with self.assertRaises(fsutil.SymlinkRefused):
            fsutil.atomic_write(link, b"x")
        self.assertFalse((self.tmp / "nowhere").exists())

    def test_refuses_directory_and_non_bytes(self) -> None:
        folder = self.tmp / "folder"
        folder.mkdir()
        with self.assertRaises(fsutil.FsError):
            fsutil.atomic_write(folder, b"x")
        self.assertTrue(folder.is_dir())
        with self.assertRaises(TypeError):
            fsutil.atomic_write(self.tmp / "text", "not bytes")  # type: ignore[arg-type]
        self.assertFalse((self.tmp / "text").exists())


class LockTests(_TmpCase):
    def test_only_one_holder_at_a_time_across_threads(self) -> None:
        lock_path = self.tmp / "ledger.lock"
        counter = self.tmp / "counter"
        counter.write_text("0")
        state = {"inside": 0, "max": 0}
        guard = threading.Lock()
        errors: list[BaseException] = []
        workers, rounds = 6, 5

        def work() -> None:
            try:
                for _ in range(rounds):
                    with fsutil.locked(lock_path, timeout=30):
                        with guard:
                            state["inside"] += 1
                            state["max"] = max(state["max"], state["inside"])
                        value = int(counter.read_text())
                        time.sleep(0.002)
                        counter.write_text(str(value + 1))
                        with guard:
                            state["inside"] -= 1
            except BaseException as exc:  # surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=work) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(state["max"], 1)
        self.assertEqual(int(counter.read_text()), workers * rounds)

    def test_timeout_raises_after_monotonic_deadline(self) -> None:
        lock_path = self.tmp / "x.lock"
        with fsutil.locked(lock_path, timeout=5):
            start = time.monotonic()
            with self.assertRaises(fsutil.LockTimeout):
                with fsutil.locked(lock_path, timeout=0.2):
                    self.fail("second holder entered the lock")
            elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 5)

    def test_zero_timeout_fails_fast_while_held(self) -> None:
        lock_path = self.tmp / "x.lock"
        with fsutil.locked(lock_path, timeout=1):
            with self.assertRaises(fsutil.LockTimeout):
                with fsutil.locked(lock_path, timeout=0):
                    pass

    def test_released_after_exception_and_after_normal_exit(self) -> None:
        lock_path = self.tmp / "x.lock"
        with self.assertRaises(RuntimeError):
            with fsutil.locked(lock_path, timeout=1):
                raise RuntimeError("boom")
        with fsutil.locked(lock_path, timeout=0):
            pass
        with fsutil.locked(lock_path, timeout=0):
            pass

    def test_refuses_symlink_lock_file(self) -> None:
        outside = self.tmp / "outside"
        outside.write_bytes(b"keep")
        link = self.tmp / "x.lock"
        self.symlink_or_skip(outside, link)
        with self.assertRaises(fsutil.SymlinkRefused):
            with fsutil.locked(link, timeout=0):
                self.fail("lock acquired through a symlink")
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_rejects_invalid_timeout(self) -> None:
        lock_path = self.tmp / "x.lock"
        for bad in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                with fsutil.locked(lock_path, timeout=bad):
                    pass
        with self.assertRaises(TypeError):
            with fsutil.locked(lock_path, timeout=True):
                pass


class ReservationTests(_TmpCase):
    def _race(self, count: int, action) -> tuple[list[int], list[BaseException]]:
        barrier = threading.Barrier(count, timeout=30)
        winners: list[int] = []
        failures: list[BaseException] = []
        guard = threading.Lock()

        def run(index: int) -> None:
            barrier.wait()
            try:
                action(index)
            except BaseException as exc:
                with guard:
                    failures.append(exc)
            else:
                with guard:
                    winners.append(index)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        return winners, failures

    def test_concurrent_reserve_exactly_one_wins(self) -> None:
        path = self.tmp / "write.reserved"
        winners, failures = self._race(16, lambda i: fsutil.reserve(path, f"toolu_{i:02d}"))
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(failures), 15)
        for exc in failures:
            self.assertIsInstance(exc, fsutil.ReservationHeld)
        self.assertEqual(path.read_text(), f"toolu_{winners[0]:02d}")

    def test_wrong_token_cannot_release(self) -> None:
        path = self.tmp / "write.reserved"
        fsutil.reserve(path, "toolu_A")
        with self.assertRaises(fsutil.ReservationMismatch):
            fsutil.release(path, "toolu_B")
        with self.assertRaises(fsutil.ReservationMismatch):
            fsutil.release(path, "toolu_A_suffix")
        self.assertEqual(path.read_text(), "toolu_A")
        fsutil.release(path, "toolu_A")
        self.assertFalse(path.exists())

    def test_release_twice_and_stale_release_are_refused(self) -> None:
        path = self.tmp / "write.reserved"
        fsutil.reserve(path, "toolu_A")
        fsutil.release(path, "toolu_A")
        with self.assertRaises(fsutil.ReservationMismatch):
            fsutil.release(path, "toolu_A")
        fsutil.reserve(path, "toolu_B")
        with self.assertRaises(fsutil.ReservationMismatch):
            fsutil.release(path, "toolu_A")
        self.assertEqual(path.read_text(), "toolu_B")

    def test_second_reserve_refused_until_release(self) -> None:
        path = self.tmp / "write.reserved"
        fsutil.reserve(path, "toolu_A")
        with self.assertRaises(fsutil.ReservationHeld):
            fsutil.reserve(path, "toolu_B")
        with self.assertRaises(fsutil.ReservationHeld):
            fsutil.reserve(path, "toolu_A")
        fsutil.release(path, "toolu_A")
        fsutil.reserve(path, "toolu_B")
        self.assertEqual(path.read_text(), "toolu_B")

    def test_concurrent_release_of_same_token_succeeds_once(self) -> None:
        path = self.tmp / "write.reserved"
        fsutil.reserve(path, "toolu_A")
        winners, failures = self._race(8, lambda i: fsutil.release(path, "toolu_A"))
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(failures), 7)
        for exc in failures:
            self.assertIsInstance(exc, fsutil.ReservationMismatch)
        self.assertFalse(path.exists())

    def test_symlink_reservation_path_refused(self) -> None:
        outside = self.tmp / "outside"
        outside.write_bytes(b"toolu_A")
        link = self.tmp / "write.reserved"
        self.symlink_or_skip(outside, link)
        with self.assertRaises(fsutil.SymlinkRefused):
            fsutil.reserve(link, "toolu_A")
        with self.assertRaises(fsutil.SymlinkRefused):
            fsutil.release(link, "toolu_A")
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_bytes(), b"toolu_A")

    def test_invalid_tokens_refused(self) -> None:
        path = self.tmp / "write.reserved"
        for bad in ("", "a\x00b", "a\nb", "x" * (fsutil.MAX_TOKEN_BYTES + 1)):
            with self.assertRaises(ValueError):
                fsutil.reserve(path, bad)
        with self.assertRaises(TypeError):
            fsutil.reserve(path, 7)  # type: ignore[arg-type]
        self.assertFalse(path.exists())


class SafeChildTests(_TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.tmp / "project"
        self.root.mkdir()
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.real_root = os.path.realpath(self.root)

    def test_plain_children_are_returned_under_real_root(self) -> None:
        got = fsutil.safe_child(self.root, "changes/CHG-0001/plan.md")
        self.assertEqual(str(got), os.path.join(self.real_root, "changes", "CHG-0001", "plan.md"))
        self.assertEqual(fsutil.safe_child(self.root, "./a//b"), Path(self.real_root, "a", "b"))

    def test_absolute_and_dotdot_and_empty_refused(self) -> None:
        for bad in (
            str(self.outside / "x"),
            "/etc/passwd",
            "../outside/x",
            "a/../../outside",
            "a/../b",
            "..",
            "",
            ".",
            "a\x00b",
        ):
            with self.subTest(relative=bad):
                with self.assertRaises(fsutil.PathEscape):
                    fsutil.safe_child(self.root, bad)

    def test_symlink_to_outside_refused(self) -> None:
        self.symlink_or_skip(self.outside, self.root / "escape")
        for bad in ("escape", "escape/file", "escape/new/deeper"):
            with self.subTest(relative=bad):
                with self.assertRaises(fsutil.PathEscape):
                    fsutil.safe_child(self.root, bad)

    def test_symlinked_file_to_outside_refused(self) -> None:
        secret = self.outside / "secret"
        secret.write_bytes(b"s")
        self.symlink_or_skip(secret, self.root / "innocent.txt")
        with self.assertRaises(fsutil.PathEscape):
            fsutil.safe_child(self.root, "innocent.txt")

    def test_symlink_inside_root_allowed(self) -> None:
        (self.root / "real").mkdir()
        self.symlink_or_skip(self.root / "real", self.root / "alias")
        got = fsutil.safe_child(self.root, "alias/file")
        self.assertEqual(got, Path(self.real_root, "alias", "file"))

    def test_symlink_back_to_root_is_not_a_child(self) -> None:
        self.symlink_or_skip(self.root, self.root / "self")
        with self.assertRaises(fsutil.PathEscape):
            fsutil.safe_child(self.root, "self")

    def test_root_must_be_existing_directory(self) -> None:
        with self.assertRaises(fsutil.FsError):
            fsutil.safe_child(self.tmp / "missing", "a")
        afile = self.tmp / "afile"
        afile.write_bytes(b"")
        with self.assertRaises(fsutil.FsError):
            fsutil.safe_child(afile, "a")


if __name__ == "__main__":
    unittest.main()
