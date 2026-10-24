# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `engineering-core/tests/test_attacks.py`: attack tests for the model, tool, policy, approval and
  audit boundaries. Three stay `xfail(strict=True)` and document known gaps: a changed tool
  description is not detected; a model verdict of benign skips the human even when the evidence is
  high risk. Injection text in tool output is bounded, not removed, by design.
- `scripts/mutation_check.py`: applies 21 hand-written faults in a throwaway git worktree and
  reports which ones the tests catch (4 with the control tests, 18 with the attack tests).

### Fixed
- The default stub adapter now computes the risk score from structured evidence with seven named
  rules (brute force then success, high-risk address, unmanaged device, atypical region, SIEM
  impossible-travel correlation, alert and history disagreement, missing evidence) instead of
  returning a constant. Each tool output is parsed once into a strict internal model before a
  rule reads it, so booleans, NaN, infinity, out-of-range numbers, naive or malformed timestamps
  and missing fields all count as missing evidence. Each factor names its rule and the value
  that fired it; missing tool output is floored at suspicious; free text never changes the
  score. The sample alert still reaches likely-compromise and the approval pause, at 0.90
  instead of 0.94.
- A fresh start on a thread id that already holds a checkpoint is refused before the run begins,
  so the stored record is unchanged and a paused run can still be resumed afterwards. The CLI
  also claims the thread id in the checkpoint database, so two processes started together on the
  same id cannot both run. Scripts that reuse a fixed `--thread-id` now exit 1 on the second run;
  the README quick start lets the CLI generate the id.

### Known limits
- A refused start is not itself recorded in the audit trail; the refusal is only the error
  returned to the caller.
- A claimed thread id stays claimed even if the process dies before its first checkpoint.
- The guard covers the graph object that `build_graph` returns. The LangGraph Agent Server
  manages its own threads and checkpointer and is not covered.
- A caller that holds the checkpointer can still edit a thread's state directly with
  `update_state`; the guard covers starts, not state edits.
- The stub's weights and thresholds illustrate the mechanism on synthetic data; they are not a
  calibrated detection model, and the region and device checks rely on the sign-in history
  carrying `region` and `device_id` for its latest event.
- A compromised or drifted tool server can return clean, well-formed values and lower the score.
  The human review path for likely-compromise verdicts and the tool-inventory checks are the
  backstop; the stub trusts the content of a tool that passed them.

### Known upstream issue (not covered by a test)
- Resuming the human-approval interrupt with `Command(resume=None)` raises `UnboundLocalError` in
  LangGraph 1.2.10 (`langgraph/pregel/_loop.py`) before the application's approval validation runs.
  The run errors before anything is actioned. Not pinned by a test because the bug is in LangGraph.

## [0.1.0] - 2026-08-12

### Added
- Initial public release.
