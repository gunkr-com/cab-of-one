"""S10 setup-session marker: strict shape, one binding, no rebind. Temp files only."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.setup import session  # noqa: E402

SID = "sess-contoso-0001"
OTHER = "sess-contoso-0002"


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s10-sess-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = self.tmp / "ops"
        self.proj.mkdir()
        self.marker = self.proj / ".cab" / "setup" / "session.json"

    def test_begin_binds_and_is_idempotent_for_same_id(self) -> None:
        first = session.begin(str(self.proj), SID)
        self.assertTrue(first.created)
        data = self.marker.read_bytes()
        self.assertEqual(data, session.marker_bytes(SID))
        again = session.begin(str(self.proj), SID)
        self.assertFalse(again.created)
        self.assertEqual(self.marker.read_bytes(), data)
        self.assertEqual(session.load(str(self.proj)), session.Lookup("bound", SID))
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)

    def test_other_id_is_refused_and_marker_unchanged(self) -> None:
        session.begin(str(self.proj), SID)
        data = self.marker.read_bytes()
        with self.assertRaises(session.SessionError) as ctx:
            session.begin(str(self.proj), OTHER)
        self.assertEqual(ctx.exception.code, "session_conflict")
        self.assertEqual(self.marker.read_bytes(), data)

    def test_concurrent_begins_bind_one_id(self) -> None:
        results: dict[str, str] = {}

        def run(sid: str) -> None:
            try:
                session.begin(str(self.proj), sid)
                results[sid] = "ok"
            except session.SessionError as exc:
                results[sid] = exc.code

        threads = [threading.Thread(target=run, args=(s,)) for s in (SID, OTHER)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results.values()), ["ok", "session_conflict"])
        winner = next(s for s, r in results.items() if r == "ok")
        self.assertEqual(session.load(str(self.proj)).session_id, winner)

    def test_malformed_marker_is_never_replaced(self) -> None:
        self.marker.parent.mkdir(parents=True)
        bad = [
            b"{}",
            b'{"kind":"cab-of-one-setup","schema":1,"session_id":"a","x":1}',
            b'{"kind":"cab-of-one-setup","schema":2,"session_id":"a"}',
            b'{"kind":"cab-of-one-setup","schema":1,"session_id":"a b"}',
            b'{"kind":"cab-of-one-setup","schema":1,"session_id":"a","session_id":"b"}',
            b"not json",
        ]
        for data in bad:
            with self.subTest(data=data):
                self.marker.write_bytes(data)
                lookup = session.load(str(self.proj))
                self.assertEqual(lookup.status, "malformed")
                with self.assertRaises(session.SessionError) as ctx:
                    session.begin(str(self.proj), SID)
                self.assertEqual(ctx.exception.code, "marker_malformed")
                self.assertEqual(self.marker.read_bytes(), data)

    def test_symlinked_marker_or_folder_refused(self) -> None:
        outside = self.tmp / "outside.json"
        outside.write_bytes(session.marker_bytes(SID))
        self.marker.parent.mkdir(parents=True)
        os.symlink(outside, self.marker)
        self.assertEqual(session.load(str(self.proj)).status, "malformed")
        with self.assertRaises(session.SessionError):
            session.begin(str(self.proj), SID)
        self.marker.unlink()
        shutil.rmtree(self.proj / ".cab")
        (self.proj / ".cab").mkdir()
        os.symlink(self.tmp, self.proj / ".cab" / "setup")
        with self.assertRaises(session.SessionError) as ctx:
            session.begin(str(self.proj), SID)
        self.assertEqual(ctx.exception.code, "setup_dir_unsafe")
        self.assertEqual(session.load(str(self.proj)).status, "malformed")

    def test_hardlinked_marker_refused(self) -> None:
        session.begin(str(self.proj), SID)
        os.link(self.marker, self.tmp / "alias.json")
        self.assertEqual(session.load(str(self.proj)).status, "malformed")

    def test_invalid_ids_and_roots(self) -> None:
        for sid in ("", "a b", "x" * 200, None, 5):
            with self.subTest(sid=sid), self.assertRaises(session.SessionError) as ctx:
                session.begin(str(self.proj), sid)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "session_id_invalid")
        with self.assertRaises(session.SessionError):
            session.begin("relative", SID)
        self.assertFalse((self.proj / ".cab").exists())

    def test_end_only_for_same_id(self) -> None:
        session.begin(str(self.proj), SID)
        with self.assertRaises(session.SessionError) as ctx:
            session.end(str(self.proj), OTHER)
        self.assertEqual(ctx.exception.code, "session_conflict")
        self.assertTrue(self.marker.exists())
        session.end(str(self.proj), SID)
        self.assertFalse(self.marker.exists())
        self.assertEqual(session.load(str(self.proj)).status, "absent")
        with self.assertRaises(session.SessionError) as ctx:
            session.end(str(self.proj), SID)
        self.assertEqual(ctx.exception.code, "not_bound")

    def test_absent(self) -> None:
        self.assertEqual(session.load(str(self.proj)), session.Lookup("absent"))


if __name__ == "__main__":
    unittest.main()
