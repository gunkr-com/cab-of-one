"""S4 process concurrency: one reservation among racing hooks, and lossless ledger appends.

Children run the installed package copy under <repo>/.local/test-tmp through a small driver
that passes the fixture registry home explicitly (HOME is not used). A file barrier starts
them together. Every join is bounded and only our own children are killed on cleanup.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import fsutil, ledger  # noqa: E402
from test_guard import S4Case, child_env, set_department  # noqa: E402

JOIN_SECONDS = 120


class ProcessCase(S4Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.install()
        self.procs: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap)

    def reap(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()

    def spawn(self, argv: list[str], stdin_data: bytes = b"") -> subprocess.Popen[bytes]:
        with tempfile.TemporaryFile(dir=self.p.tmp) as handle:
            handle.write(stdin_data)
            handle.seek(0)
            proc = subprocess.Popen(
                argv,
                stdin=handle,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env(str(self.p.project)),
                cwd=str(self.p.project),
            )
        self.procs.append(proc)
        return proc

    def finish(self, proc: subprocess.Popen[bytes]) -> tuple[int, bytes, bytes]:
        try:
            out, err = proc.communicate(timeout=JOIN_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=10)
            self.fail("child did not finish in time")
        return proc.returncode, out, err

    def barrier(self) -> Path:
        return self.p.tmp / "go"


class RacingPreTests(ProcessCase):
    def test_eight_concurrent_pre_calls_reserve_exactly_once(self) -> None:
        p = self.p
        p.prepare("standard")
        go = self.barrier()
        events = [p.bash(set_department("u-1007")) for _ in range(8)]
        procs = [
            self.spawn(p.guard_argv(barrier=str(go)), json.dumps(ev).encode()) for ev in events
        ]
        go.write_text("go\n")
        results = [self.finish(proc) for proc in procs]
        codes = [code for code, _, _ in results]
        self.assertEqual(Counter(codes), Counter({0: 1, 2: 7}), [r[2] for r in results])
        winner = events[codes.index(0)]["tool_use_id"]
        reasons = Counter()
        for code, out, err in results:
            if code == 0:
                self.assertEqual(json.loads(out), {})
                continue
            payload = json.loads(out)["hookSpecificOutput"]
            self.assertEqual(payload["permissionDecision"], "deny")
            text = err.decode()
            reason = "inflight" if "[inflight]" in text else "lock_timeout"
            self.assertTrue("[inflight]" in text or "[lock_timeout]" in text, text)
            reasons[reason] += 1
        doc = p.doc()
        self.assertEqual(len(doc["units"]), 1)
        self.assertEqual(doc["inflight"]["token"], winner)
        self.assertEqual(Path(p.roots.inflight_file).read_text(), winner)
        rows = p.ledger_rows()
        allows = [r for r in rows if r.get("event") == "pre" and r.get("decision") == "allow"]
        self.assertEqual([r["tool_use_id"] for r in allows], [winner])
        self.assertEqual(sum(reasons.values()), 7)


class LedgerProcessTests(ProcessCase):
    def test_eight_writers_times_fifty_rows_lose_nothing(self) -> None:
        p = self.p
        go = self.barrier()
        procs = [self.spawn(p.ledger_argv(worker, 50, barrier=str(go))) for worker in range(8)]
        go.write_text("go\n")
        for proc in procs:
            code, out, err = self.finish(proc)
            self.assertEqual((code, out), (0, b"ok\n"), err)
        data = p.ledger_bytes()
        self.assertEqual(data.count(b"\n"), 400)
        rows = ledger.read_jsonl_strict(data)
        keys = {(r["actor"], r["seq"]) for r in rows}
        self.assertEqual(len(keys), 400)
        per_worker = Counter(r["actor"] for r in rows)
        self.assertEqual(set(per_worker.values()), {50})

    def test_lock_held_by_another_process_times_out_cleanly(self) -> None:
        p = self.p
        folder = Path(p.roots.ledger_dir)
        folder.mkdir(parents=True)
        with fsutil.locked(p.roots.ledger_lock, 2.0):
            proc = self.spawn(p.ledger_argv(0, 1, timeout=0.2))
            code, out, _ = self.finish(proc)
        self.assertEqual((code, out), (4, b"lock_timeout\n"))
        self.assertEqual(p.ledger_bytes(), b"")

    def test_symlinked_month_file_is_refused_across_processes(self) -> None:
        p = self.p
        proc = self.spawn(p.ledger_argv(0, 1))
        self.assertEqual(self.finish(proc)[0], 0)
        month = p.ledger_files()[0]
        outside = p.tmp / "outside.jsonl"
        outside.write_bytes(b"")
        month.unlink()
        p.symlink(outside, month)
        proc = self.spawn(p.ledger_argv(1, 1))
        code, out, _ = self.finish(proc)
        self.assertEqual((code, out), (4, b"append_failed\n"))
        self.assertEqual(outside.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
