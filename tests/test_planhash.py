"""Invariant tests for cab_of_one.runtime.planhash. Temporary files live under .local/test-tmp."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cab_of_one.runtime import planhash

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_TMP = REPO_ROOT / ".local" / "test-tmp"

FILES = {
    "change.toml": b'id = "CHG-0007"\ntier = "normal"\n',
    "plan.md": "# Remove forwarding\n\nContoso Sales — fictional\n".encode(),
    "targets.csv": b"id\nmbx-0001\nmbx-0002\nmbx-0003\n",
}


class PlanHashTests(unittest.TestCase):
    def setUp(self) -> None:
        TEST_TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="planhash-", dir=TEST_TMP))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make_change(self, name: str = "CHG-0007", files: dict[str, bytes] | None = None) -> Path:
        folder = self.tmp / name
        folder.mkdir()
        for filename, data in (FILES if files is None else files).items():
            (folder / filename).write_bytes(data)
        return folder

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")

    # ----------------------------------------------------------------- stability

    def test_same_bytes_same_hash_across_folders_and_calls(self) -> None:
        first = self.make_change("a")
        second = self.make_change("b")
        value = planhash.plan_hash(first)
        self.assertEqual(value, planhash.plan_hash(first))
        self.assertEqual(value, planhash.plan_hash(second))
        self.assertEqual(len(value), 64)
        self.assertEqual(value, value.lower())
        int(value, 16)

    def test_matches_documented_framing(self) -> None:
        folder = self.make_change()
        expected = hashlib.sha256()
        for name in ("change.toml", "plan.md", "targets.csv"):
            data = FILES[name]
            expected.update(name.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
        self.assertEqual(planhash.plan_hash(folder), expected.hexdigest())

    def test_metadata_and_extra_files_do_not_matter(self) -> None:
        folder = self.make_change()
        before = planhash.plan_hash(folder)
        for name in FILES:
            os.utime(folder / name, (1_000_000_000, 1_000_000_000))
        (folder / "intake.md").write_bytes(b"not part of the plan")
        (folder / "review.json").write_bytes(b"{}")
        self.assertEqual(planhash.plan_hash(folder), before)

    # ----------------------------------------------------------------- sensitivity

    def test_any_single_byte_change_in_any_file_changes_hash(self) -> None:
        baseline = planhash.plan_hash(self.make_change("base"))
        seen = {baseline}
        for name, data in FILES.items():
            variants = {
                "flip-first": bytes([data[0] ^ 0x01]) + data[1:],
                "flip-last": data[:-1] + bytes([data[-1] ^ 0x01]),
                "append": data + b"\n",
                "truncate": data[:-1],
            }
            for label, variant in variants.items():
                with self.subTest(file=name, change=label):
                    files = dict(FILES)
                    files[name] = variant
                    value = planhash.plan_hash(self.make_change(f"{name}-{label}", files))
                    self.assertNotEqual(value, baseline)
                    self.assertNotIn(value, seen - {baseline})
                    seen.add(value)

    def test_moving_bytes_between_files_changes_hash(self) -> None:
        left_files = {"change.toml": b"ab", "plan.md": b"c", "targets.csv": b"x"}
        right_files = {"change.toml": b"a", "plan.md": b"bc", "targets.csv": b"x"}
        left = self.make_change("left", left_files)
        right = self.make_change("right", right_files)
        self.assertNotEqual(planhash.plan_hash(left), planhash.plan_hash(right))

    def test_swapping_contents_between_files_changes_hash(self) -> None:
        swapped = dict(FILES)
        swapped["plan.md"], swapped["targets.csv"] = FILES["targets.csv"], FILES["plan.md"]
        self.assertNotEqual(
            planhash.plan_hash(self.make_change("orig")),
            planhash.plan_hash(self.make_change("swap", swapped)),
        )

    def test_empty_files_are_hashed_not_skipped(self) -> None:
        empty = self.make_change("empty", {name: b"" for name in FILES})
        one_files = {"change.toml": b"", "plan.md": b"", "targets.csv": b"\n"}
        one = self.make_change("one", one_files)
        self.assertNotEqual(planhash.plan_hash(empty), planhash.plan_hash(one))

    # ----------------------------------------------------------------- refusals

    def test_each_missing_file_is_refused(self) -> None:
        for name in FILES:
            with self.subTest(missing=name):
                files = {k: v for k, v in FILES.items() if k != name}
                with self.assertRaises(planhash.PlanHashError):
                    planhash.plan_hash(self.make_change(f"missing-{name}", files))

    def test_directory_in_place_of_file_is_refused(self) -> None:
        for name in FILES:
            with self.subTest(directory=name):
                files = {k: v for k, v in FILES.items() if k != name}
                folder = self.make_change(f"dir-{name}", files)
                (folder / name).mkdir()
                with self.assertRaises(planhash.PlanHashError):
                    planhash.plan_hash(folder)

    def test_symlinked_file_is_refused_even_inside_folder(self) -> None:
        folder = self.make_change("link", {k: v for k, v in FILES.items() if k != "plan.md"})
        (folder / "plan-real.md").write_bytes(FILES["plan.md"])
        self.symlink_or_skip(folder / "plan-real.md", folder / "plan.md")
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(folder)

    def test_dangling_symlink_is_refused(self) -> None:
        folder = self.make_change("dangle", {k: v for k, v in FILES.items() if k != "plan.md"})
        self.symlink_or_skip(folder / "nowhere.md", folder / "plan.md")
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(folder)

    def test_fifo_is_refused_without_hanging(self) -> None:
        folder = self.make_change("fifo", {k: v for k, v in FILES.items() if k != "targets.csv"})
        try:
            os.mkfifo(folder / "targets.csv")
        except (OSError, AttributeError) as exc:
            self.skipTest(f"mkfifo unsupported here: {exc.__class__.__name__}")
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(folder)

    def test_bad_change_folder_is_refused(self) -> None:
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(self.tmp / "absent")
        afile = self.tmp / "afile"
        afile.write_bytes(b"")
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(afile)
        real = self.make_change("real")
        alias = self.tmp / "alias"
        self.symlink_or_skip(real, alias)
        with self.assertRaises(planhash.PlanHashError):
            planhash.plan_hash(alias)


if __name__ == "__main__":
    unittest.main()
