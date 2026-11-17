"""S6 transcript parser: LF-only framing, recognised records, de-duplication, association.

Fixture transcripts live under <repo>/.local/test-tmp only; the user's real transcript
folder is never read. Records are fictional Contoso data.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import transcripts  # noqa: E402
from cab_of_one.runtime.transcripts import (  # noqa: E402
    KIND_MAIN,
    KIND_SUBAGENT,
    discover,
    parse_bytes,
    parse_file,
)

SID = "0b6c1d2e-1111-4a4a-9b9b-000000000001"
CWD = "/fixture/contoso-ops"
TS = "2026-11-10T10:00:00.000Z"


def tool_use(tid: str | None, name: str, inp: object) -> dict:
    block: dict = {"type": "tool_use", "name": name, "input": inp}
    if tid is not None:
        block["id"] = tid
    return block


def assistant(*blocks: dict, sid: str = SID, cwd: str = CWD, ts: str = TS, **extra) -> dict:
    rec = {
        "type": "assistant",
        "sessionId": sid,
        "cwd": cwd,
        "timestamp": ts,
        "message": {"role": "assistant", "content": list(blocks)},
    }
    rec.update(extra)
    return rec


def user(text: str = "hello", sid: str = SID, cwd: str = CWD, ts: str = TS) -> dict:
    return {
        "type": "user",
        "sessionId": sid,
        "cwd": cwd,
        "timestamp": ts,
        "message": {"role": "user", "content": text},
    }


def jsonl(*records: dict, ascii_only: bool = True) -> bytes:
    return b"".join(json.dumps(r, ensure_ascii=ascii_only).encode("utf-8") + b"\n" for r in records)


class ParseBytesTests(unittest.TestCase):
    def test_extracts_tool_calls_with_session_cwd_and_time(self) -> None:
        data = jsonl(
            user(),
            assistant(
                {"type": "text", "text": "Checking the Sales mailboxes."},
                tool_use("toolu_01", "Bash", {"command": "ls"}),
            ),
        )
        t = parse_bytes(data, file_session_id=SID)
        self.assertEqual(t.status, "ok")
        self.assertEqual(len(t.calls), 1)
        call = t.calls[0]
        self.assertEqual((call.tool_use_id, call.name), ("toolu_01", "Bash"))
        self.assertEqual(call.input, {"command": "ls"})
        self.assertEqual((call.session_id, call.cwd), (SID, CWD))
        self.assertIsNone(call.agent_id)
        self.assertEqual(call.lineno, 2)
        self.assertIsNotNone(call.timestamp)
        self.assertEqual(t.session_ids, frozenset({SID}))
        self.assertEqual(t.cwds, (CWD,))
        self.assertEqual(t.records, 2)

    def test_splits_on_lf_only_not_unicode_line_separators(self) -> None:
        # U+2028, U+2029, U+0085, VT and FF are legal inside JSON strings (raw, not escaped);
        # str.splitlines would cut the record apart.
        odd = "Contoso Sales Team\x85end\x0bvt\x0cff"
        data = jsonl(
            assistant(tool_use("toolu_02", "Bash", {"command": f"echo '{odd}'"})),
            ascii_only=False,
        )
        self.assertIn(" ".encode(), data)
        t = parse_bytes(data)
        self.assertEqual(t.status, "ok", t.counts)
        self.assertEqual(t.lines, 1)
        self.assertEqual(len(t.calls), 1)
        self.assertIn(odd, t.calls[0].input["command"])

    def test_truncated_final_line_is_indeterminate(self) -> None:
        good = jsonl(assistant(tool_use("toolu_03", "Read", {"file_path": "/x"})))
        t = parse_bytes(good + b'{"type": "assistant", "message": {"content": [')
        self.assertEqual(t.status, "indeterminate")
        self.assertEqual(t.counts.get("truncated_line"), 1)
        self.assertEqual(len(t.calls), 1)  # what was readable is still reported

    def test_malformed_and_unrecognized_are_distinct_and_indeterminate(self) -> None:
        cases = {
            "malformed_line": b"{not json}\n",
            "unrecognized_record": jsonl({"type": "brand-new-record", "payload": 1}),
            "malformed_record": jsonl({"type": "assistant", "message": "text"}),
            "unrecognized_block": jsonl(assistant({"type": "server_tool_use", "name": "x"})),
            "malformed_tool_use": jsonl(assistant(tool_use("toolu_04", "Bash", "ls"))),
        }
        for code, data in cases.items():
            with self.subTest(code=code):
                t = parse_bytes(data)
                self.assertEqual(t.status, "indeterminate")
                self.assertEqual(t.counts.get(code), 1, t.counts)
                self.assertIn(code, t.reasons())
                others = set(t.reasons()) - {code}
                self.assertEqual(others, set())

    def test_duplicate_keys_nan_and_bom_are_malformed(self) -> None:
        for raw in (
            b'{"type": "user", "type": "assistant"}\n',
            b'{"type": "user", "n": NaN}\n',
            "﻿".encode() + jsonl(user()),
        ):
            with self.subTest(raw=raw[:20]):
                self.assertEqual(parse_bytes(raw).counts.get("malformed_line"), 1)

    def test_oversize_line_is_indeterminate(self) -> None:
        data = jsonl(assistant(tool_use("toolu_05", "Bash", {"command": "x" * 5000})))
        t = parse_bytes(data, max_line_bytes=1000)
        self.assertEqual(t.counts.get("oversize_line"), 1)
        self.assertEqual(t.calls, ())
        self.assertEqual(t.status, "indeterminate")

    def test_streamed_repeats_are_deduplicated(self) -> None:
        block = tool_use("toolu_06", "Bash", {"command": "ls"})
        data = jsonl(assistant(block), assistant(block), assistant(block))
        t = parse_bytes(data)
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(t.counts.get("duplicate_tool_id"), 2)
        self.assertEqual(t.status, "ok")

    def test_conflicting_tool_id_keeps_both_variants_and_is_indeterminate(self) -> None:
        data = jsonl(
            assistant(tool_use("toolu_07", "Bash", {"command": "ls"})),
            assistant(tool_use("toolu_07", "Bash", {"command": "simtenant purge users u-1"})),
        )
        t = parse_bytes(data)
        self.assertEqual(len(t.calls), 2)
        self.assertEqual(t.counts.get("tool_id_conflict"), 1)
        self.assertEqual(t.status, "indeterminate")

    def test_missing_tool_id_is_kept_and_counted(self) -> None:
        t = parse_bytes(jsonl(assistant(tool_use(None, "Bash", {"command": "ls"}))))
        self.assertEqual(len(t.calls), 1)
        self.assertIsNone(t.calls[0].tool_use_id)
        self.assertEqual(t.counts.get("tool_id_missing"), 1)

    def test_bad_tool_name_is_kept_as_empty_name(self) -> None:
        t = parse_bytes(jsonl(assistant(tool_use("toolu_08", "", {"command": "ls"}))))
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(t.calls[0].name, "")
        self.assertEqual(t.status, "indeterminate")

    def test_record_session_and_agent_override_file_names_and_are_counted(self) -> None:
        other = "0b6c1d2e-1111-4a4a-9b9b-000000000099"
        data = jsonl(
            assistant(
                tool_use("toolu_09", "Bash", {"command": "ls"}),
                sid=other,
                agentId="a77",
                isSidechain=True,
            )
        )
        t = parse_bytes(data, kind=KIND_SUBAGENT, file_session_id=SID, file_agent_id="a12")
        call = t.calls[0]
        self.assertEqual((call.session_id, call.agent_id, call.sidechain), (other, "a77", True))
        self.assertEqual(t.counts.get("session_id_mismatch"), 1)
        self.assertEqual(t.counts.get("agent_id_mismatch"), 1)
        self.assertEqual(t.status, "ok")  # association differences are not parse failures

    def test_file_identity_is_used_when_records_lack_it(self) -> None:
        rec = assistant(tool_use("toolu_10", "Bash", {"command": "ls"}))
        del rec["sessionId"]
        del rec["cwd"]
        t = parse_bytes(jsonl(rec), kind=KIND_SUBAGENT, file_session_id=SID, file_agent_id="a12")
        call = t.calls[0]
        self.assertEqual((call.session_id, call.agent_id, call.cwd), (SID, "a12", None))

    def test_invalid_cwd_session_and_timestamp_are_dropped_not_trusted(self) -> None:
        rec = assistant(
            tool_use("toolu_11", "Bash", {"command": "ls"}),
            sid="bad id with spaces",
            cwd="relative/path",
            ts="yesterday",
        )
        t = parse_bytes(jsonl(rec), file_session_id=SID)
        call = t.calls[0]
        self.assertEqual((call.session_id, call.cwd, call.timestamp), (SID, None, None))
        for code in ("session_id_invalid", "cwd_invalid", "timestamp_invalid"):
            self.assertEqual(t.counts.get(code), 1, code)

    def test_blank_lines_are_counted_but_harmless(self) -> None:
        t = parse_bytes(b"\n" + jsonl(user()) + b"  \n")
        self.assertEqual(t.counts.get("blank_line"), 2)
        self.assertEqual(t.status, "ok")

    def test_extra_record_types_can_be_recognised_by_the_caller(self) -> None:
        data = jsonl({"type": "brand-new-record"})
        self.assertEqual(parse_bytes(data).status, "indeterminate")
        types = transcripts.RECORD_TYPES | {"brand-new-record"}
        self.assertEqual(parse_bytes(data, record_types=types).status, "ok")


class _TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="transcripts-", dir=TMP_ROOT)).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "projects"
        self.root.mkdir()

    def write(self, rel: str, data: bytes) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")


class DiscoverTests(_TmpCase):
    def test_finds_main_and_subagent_files_only_at_documented_depth(self) -> None:
        body = jsonl(user())
        self.write(f"-fixture-contoso/{SID}.jsonl", body)
        self.write(f"-fixture-contoso/{SID}/subagents/agent-a12.jsonl", body)
        self.write(f"-fixture-contoso/{SID}/subagents/notes.txt", b"x")
        self.write(f"-fixture-contoso/{SID}/deeper/more/{SID}.jsonl", body)
        self.write("stray.jsonl", body)
        d = discover(str(self.root))
        self.assertIsNone(d.error)
        kinds = sorted((r.kind, r.session_id, r.agent_id) for r in d.refs)
        self.assertEqual(kinds, [(KIND_MAIN, SID, None), (KIND_SUBAGENT, SID, "a12")])
        self.assertTrue(all(r.project_dir == "-fixture-contoso" for r in d.refs))

    def test_symlinks_are_never_followed(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / f"{SID}.jsonl").write_bytes(jsonl(user()))
        self.symlink_or_skip(outside, self.root / "linked-project")
        proj = self.root / "-real"
        proj.mkdir()
        self.symlink_or_skip(outside / f"{SID}.jsonl", proj / f"{SID}.jsonl")
        d = discover(str(self.root))
        self.assertEqual(d.refs, ())
        self.assertEqual(d.counts.get("symlink_skipped"), 2)

    def test_root_must_be_a_real_absolute_directory(self) -> None:
        link = self.tmp / "root-link"
        self.symlink_or_skip(self.root, link)
        self.assertEqual(discover(str(link)).error, "root_symlink")
        self.assertEqual(discover(str(self.tmp / "nope")).error, "root_missing")
        self.assertEqual(discover("relative/projects").error, "root_not_absolute")
        file_root = self.tmp / "file"
        file_root.write_bytes(b"")
        self.assertEqual(discover(str(file_root)).error, "root_not_dir")

    def test_file_limit_is_counted(self) -> None:
        for i in range(3):
            self.write(f"-p/0b6c1d2e-1111-4a4a-9b9b-00000000000{i}.jsonl", jsonl(user()))
        d = discover(str(self.root), max_files=2)
        self.assertEqual(len(d.refs), 2)
        self.assertEqual(d.counts.get("file_limit"), 1)


class ParseFileTests(_TmpCase):
    def test_file_over_the_byte_bound_is_not_read(self) -> None:
        self.write(f"-p/{SID}.jsonl", jsonl(user("x" * 4000)))
        ref = discover(str(self.root)).refs[0]
        t = parse_file(ref, max_file_bytes=1000)
        self.assertEqual(t.counts, {"file_too_large": 1})
        self.assertEqual(t.status, "indeterminate")

    def test_file_replaced_by_symlink_after_discovery_is_refused(self) -> None:
        path = self.write(f"-p/{SID}.jsonl", jsonl(user()))
        ref = discover(str(self.root)).refs[0]
        target = self.tmp / "elsewhere.jsonl"
        target.write_bytes(jsonl(user()))
        path.unlink()
        self.symlink_or_skip(target, path)
        t = parse_file(ref)
        self.assertEqual(t.counts, {"symlink_skipped": 1})
        self.assertEqual(t.calls, ())

    def test_parse_file_reads_the_discovered_file(self) -> None:
        self.write(
            f"-p/{SID}.jsonl",
            jsonl(assistant(tool_use("toolu_12", "Bash", {"command": "ls"}))),
        )
        ref = discover(str(self.root)).refs[0]
        t = parse_file(ref)
        self.assertEqual(t.status, "ok")
        self.assertEqual([c.tool_use_id for c in t.calls], ["toolu_12"])


if __name__ == "__main__":
    unittest.main()
