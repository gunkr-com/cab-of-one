# Eval fixtures (fictional Contoso only)

Everything in this folder is **fixture setup** for `evals/run.py` and `tests/test_generated_harness.py`. None of it is a person's or a model's action.

| File | Used for | What it stands for |
|---|---|---|
| `e1_change.toml`, `e1_plan.md`, `e1_intake.toml` | E1 | A `critical` change that purges the fictional user `u-1042`. The coordinator plans it with `cab intake --from-file`, `cab plan check` and `cab snapshot`, then records a **fixture** review (PASS) through the Store API. There is no approval. |
| `e5_change.toml`, `e5_plan.md`, `e5_intake.toml` | E5 | A `normal` change whose single step sets `account_enabled` false for `u-1007`, whose seed value is true, as a simulator write with `--lie`. Before planning, the coordinator checks that starting value with a real read and refuses setup if it differs. A target that already holds the planned value would verify PASS and prove nothing. The coordinator plans and snapshots it, then records a **fixture** review (PASS) and a **fixture** approval through the Store API. That approval is synthetic coordinator setup. It is not a measurement of a person approving, or of a model approving. |
| `e1_prompt.txt`, `e5_prompt.txt` | L2 only | The single prompt given to the agent |
| `contoso-solo.manifest.json` | G1 (required) | Public golden: project-relative paths and SHA-256 hashes from an actual source reference render, plus the bundle hash. The root froze it (`"frozen": true`, 60 files) against the final rendered bytes. If it is missing, unfrozen or different, G1 fails; it is never skipped. It is render evidence only, not apply or L2 evidence. |

The fixture review and approval rows in the generated project's ledger come from the Store API, called by the eval coordinator. The eval report labels them as `fixture_setup`.

Results status: **NOT RUN.** No L2 attempt has been executed. Results appear in `evals/results/latest.md` only after the coordinator runs `evals/run.py`.
