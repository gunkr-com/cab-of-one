"""S4 audit ledger: redaction, row framing, strict reading and fail-closed appends.

Files live under <repo>/.local/test-tmp (fixture projects from test_guard). No hash chain is
claimed: ``NoChain`` is a placeholder and rows carry no ``prev``.
"""

from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import fsutil, ledger  # noqa: E402
from cab_of_one.runtime.ledger import Ledger, LedgerError, LedgerFormatError  # noqa: E402
from test_guard import JWT, SECRET_CASES, T0, Project, S4Case, leaks  # noqa: E402

EXTRA = ("CONTOSO-SECRET-[0-9]{4}",)


class RedactionTests(unittest.TestCase):
    def test_every_known_secret_kind_is_redacted(self) -> None:
        for label, command, values in SECRET_CASES:
            with self.subTest(case=label):
                out = ledger.redact(command, EXTRA)
                self.assertIn(ledger.REDACTED, out)
                for value in values:
                    self.assertEqual(leaks(value, out), [])

    def test_redaction_is_stable_on_its_own_output(self) -> None:
        for label, command, _ in SECRET_CASES:
            with self.subTest(case=label):
                once = ledger.redact(command, EXTRA)
                self.assertEqual(ledger.redact(once, EXTRA), once)

    def test_plain_text_is_kept(self) -> None:
        text = "python3 simtenant/simtenant.py --state tenant/state.json get users u-1007"
        self.assertEqual(ledger.redact(text, EXTRA), text)

    def test_secret_named_keys_lose_their_whole_value(self) -> None:
        value = {
            "password": ["ListSENTINELpw01"],
            "client_secret": {"value": "MapSENTINELcs02"},
            "clientSecret": "CamelSENTINELcs03",
            "accessToken": "TokSENTINELat04",
            "api_key": 12345,
            "Authorization": "Bearer HdrSENTINELau05",
            "nested": [{"token": "NestSENTINELtk06"}, {"note": f"jwt {JWT}"}],
            "user": "u-1007",
        }
        out = ledger.redact_value(value, EXTRA)
        for key in ("password", "client_secret", "clientSecret", "accessToken", "api_key",
                    "Authorization"):  # fmt: skip
            self.assertEqual(out[key], ledger.REDACTED, key)
        self.assertEqual(out["nested"][0]["token"], ledger.REDACTED)
        self.assertEqual(out["user"], "u-1007")
        text = repr(out)
        for secret in ("ListSENTINELpw01", "MapSENTINELcs02", "CamelSENTINELcs03",
                       "TokSENTINELat04", "HdrSENTINELau05", "NestSENTINELtk06", JWT):  # fmt: skip
            self.assertEqual(leaks(secret, text), [], secret)
        self.assertNotIn("12345", text)

    def test_display_command_never_shows_file_contents(self) -> None:
        shown = ledger.display_command(
            "Write", {"file_path": "/tmp/contoso/notes.md", "content": "password=WrSENTINEL07"}
        )
        self.assertEqual(shown, "/tmp/contoso/notes.md")
        mcp = ledger.display_command("mcp__contosoadmin__x", {"password": "McpSENTINEL08"})
        self.assertNotIn("McpSENTINEL08", mcp)


class LedgerFileTests(S4Case):
    def book(self, **kw: object) -> Ledger:
        return Ledger(self.p.roots, extra_patterns=EXTRA, clock=self.p.clock, **kw)

    def month(self) -> Path:
        return Path(self.book().path_for(T0))

    def test_row_is_canonical_ascii_lf_framed_without_prev(self) -> None:
        book = self.book()
        command = "az x --password=RowSENTINELpw09"
        book.append("pre", command=command, decision="deny", reason_code="fixture")
        data = self.month().read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        data.decode("ascii")
        row = ledger.read_jsonl_strict(data)[0]
        self.assertEqual(
            (row["v"], row["event"], row["ts"]), (1, "pre", "2027-01-15T08:00:00.000Z")
        )
        self.assertNotIn("prev", row)
        redacted = ledger.redact(command, EXTRA)
        self.assertEqual(row["command_sha256"], hashlib.sha256(redacted.encode()).hexdigest())
        self.assertNotEqual(row["command_sha256"], hashlib.sha256(command.encode()).hexdigest())
        self.assertEqual(leaks("RowSENTINELpw09", data.decode()), [])

    def test_unknown_fields_and_types_are_refused(self) -> None:
        book = self.book()
        with self.assertRaises(LedgerError) as caught:
            book.append("pre", raw_command="x")
        self.assertEqual(caught.exception.code, "field_unknown")
        with self.assertRaises(LedgerError) as caught:
            book.append("pre", actor=["x"])
        self.assertEqual(caught.exception.code, "field_type")
        with self.assertRaises(LedgerError) as caught:
            book.append("pre", cls={"kind": "write", "canonical": "x"})
        self.assertEqual(caught.exception.code, "field_cls")
        self.assertFalse(self.month().exists())

    def test_s5_settlement_fields(self) -> None:
        book = self.book()
        digest = "a" * 64
        book.append("settle", source="post", exit=None, response_sha256=digest, outcome="ok")
        book.append("settle", source="failure", exit=7, response_sha256=None, outcome="failed")
        rows = ledger.read_jsonl_strict(self.month().read_bytes())
        self.assertEqual((rows[0]["source"], rows[0]["response_sha256"]), ("post", digest))
        self.assertEqual((rows[1]["source"], rows[1]["exit"]), ("failure", 7))
        bad = (
            ({"exit": 256}, "field_exit"),
            ({"exit": True}, "field_exit"),
            ({"exit": "7"}, "field_exit"),
            ({"response_sha256": "A" * 64}, "field_response"),
            ({"response_sha256": "secret text"}, "field_response"),
            ({"source": "Post Hook"}, "field_source"),
            ({"salt": "d" * 32}, "field_unknown"),
            ({"input_hmac": "f" * 64}, "field_unknown"),
            ({"input_sha256": "f" * 64}, "field_unknown"),
        )
        for fields, expected in bad:
            with self.subTest(fields=fields):
                with self.assertRaises(LedgerError) as caught:
                    book.append("settle", **fields)
                self.assertEqual(caught.exception.code, expected)
        self.assertEqual(len(ledger.read_jsonl_strict(self.month().read_bytes())), 2)

    def test_line_separators_never_break_framing(self) -> None:
        book = self.book()
        for i in range(3):
            book.append("state", actor=f"a b c-{i}", action="x\u0085y", seq=i + 1)
        data = self.month().read_bytes()
        self.assertEqual(data.count(b"\n"), 3)
        self.assertNotIn(" ".encode(), data)
        self.assertNotIn(" ".encode(), data)
        rows = ledger.read_jsonl_strict(data)
        self.assertEqual([r["seq"] for r in rows], [1, 2, 3])
        # a foreign line holding a raw U+2028 is still one line: framing is b"\n" only
        raw = '{"a":"x y"}\n{"a":"z"}\n'.encode()
        self.assertEqual(len(ledger.read_jsonl_strict(raw)), 2)

    def test_strict_reader_reports_the_first_broken_line(self) -> None:
        with self.assertRaises(LedgerFormatError) as caught:
            ledger.read_jsonl_strict(b'{"a":1}\nnot json\n{"a":2}\n')
        self.assertEqual((caught.exception.code, caught.exception.lineno), ("malformed", 2))
        with self.assertRaises(LedgerFormatError) as caught:
            ledger.read_jsonl_strict(b'{"a":1}\n{"a"')
        self.assertEqual((caught.exception.code, caught.exception.lineno), ("truncated", 2))
        statuses = [line.status for line in ledger.iter_jsonl_bytes(b'{"a":1}\n[]\n{"b"')]
        self.assertEqual(statuses, ["ok", "malformed", "truncated"])

    def test_truncated_tail_is_refused_and_left_byte_for_byte(self) -> None:
        book = self.book()
        book.append("state", action="first")
        month = self.month()
        with month.open("ab") as handle:
            handle.write(b'{"v":1,"event":"pre","deci')
        before = month.read_bytes()
        for _ in range(2):
            with self.assertRaises(LedgerError) as caught:
                book.append("state", action="second")
            self.assertEqual(caught.exception.code, "truncated_tail")
        self.assertEqual(month.read_bytes(), before)

    def test_partial_write_is_not_repaired_by_the_next_append(self) -> None:
        book = self.book()
        book.append("state", action="first")
        month = self.month()
        real_write = os.write

        def partial(fd: int, data: bytes) -> int:
            real_write(fd, bytes(data)[:10])
            raise OSError(5, "fixture: device error")

        with mock.patch("os.write", partial):
            with self.assertRaises(LedgerError) as caught:
                book.append("state", action="crashed")
        self.assertEqual(caught.exception.code, "append_failed")
        damaged = month.read_bytes()
        self.assertFalse(damaged.endswith(b"\n"))
        with self.assertRaises(LedgerError) as caught:
            book.append("state", action="after")
        self.assertEqual(caught.exception.code, "truncated_tail")
        self.assertEqual(month.read_bytes(), damaged)
        with self.assertRaises(LedgerFormatError):
            ledger.read_jsonl_strict(damaged)

    def test_symlinked_or_hardlinked_targets_are_refused(self) -> None:
        p = self.p
        book = self.book()
        book.append("state", action="first")
        month = self.month()
        outside = p.tmp / "outside.jsonl"
        outside.write_bytes(b"")
        month.unlink()
        p.symlink(outside, month)
        with self.assertRaises(LedgerError):
            book.append("state", action="through link")
        self.assertEqual(outside.read_bytes(), b"")
        month.unlink()
        month.write_bytes(b"")
        p.hardlink(month, p.tmp / "alias.jsonl")
        with self.assertRaises(LedgerError) as caught:
            book.append("state", action="hardlinked")
        self.assertEqual(caught.exception.code, "not_regular")
        self.assertEqual(month.read_bytes(), b"")

    def test_symlinked_audit_folder_or_lock_is_refused(self) -> None:
        p = self.p
        elsewhere = p.tmp / "audit-real"
        elsewhere.mkdir()
        p.symlink(elsewhere, p.path("audit"))
        with self.assertRaises(LedgerError):
            self.book().append("state", action="x")
        self.assertEqual(list(elsewhere.iterdir()), [])

        q = Project(self)
        folder = q.path("audit/ledger")
        folder.mkdir(parents=True)
        target = q.tmp / "lock-target"
        target.write_bytes(b"")
        q.symlink(target, folder / ".lock")
        book = Ledger(q.roots, clock=q.clock)
        with self.assertRaises(LedgerError):
            book.append("state", action="x")
        self.assertEqual(sorted(f.name for f in folder.iterdir()), [".lock"])

    def test_lock_timeout(self) -> None:
        book = self.book(lock_timeout=0.05)
        book.append("state", action="first")
        with fsutil.locked(self.p.roots.ledger_lock, 2.0):
            with self.assertRaises(LedgerError) as caught:
                book.append("state", action="blocked")
        self.assertEqual(caught.exception.code, "lock_timeout")
        self.assertEqual(len(ledger.read_jsonl_strict(self.month().read_bytes())), 1)

    def test_long_command_is_redacted_then_cut(self) -> None:
        book = self.book()
        command = "az x " + "w " * 250 + "--password=CutSENTINELpw10 " + "z " * 4000
        book.append("pre", command=command)
        data = self.month().read_bytes()
        self.assertLessEqual(len(data), ledger.MAX_ROW_BYTES)
        row = ledger.read_jsonl_strict(data)[0]
        self.assertLessEqual(len(row["command_redacted"]), ledger.MAX_COMMAND_CHARS)
        self.assertTrue(row["command_redacted"].endswith("...[cut]"))
        self.assertEqual(leaks("CutSENTINELpw10", data.decode()), [])

    def test_no_chain_is_not_a_hash_chain(self) -> None:
        book = self.book()
        self.assertIsInstance(book.chain, ledger.NoChain)
        self.assertIsNone(ledger.NoChain().link(b'{"v":1}\n'))
        book.append("state", action="one")
        book.append("state", action="two")
        rows = ledger.read_jsonl_strict(self.month().read_bytes())
        for row in rows:
            self.assertFalse({"prev", "hash", "chain"} & set(row))


if __name__ == "__main__":
    unittest.main()
