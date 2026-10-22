# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `engineering-core/tests/test_attacks.py`: attack tests for the model, tool, policy, approval and
  audit boundaries. Eight are `xfail(strict=True)` and document known gaps: a completed thread id
  can be reused and its audit trail grows; the stub adapter returns a constant risk score; a changed
  tool description is not detected; a model verdict of benign skips the human even when the
  evidence is high risk. Injection text in tool output is bounded, not removed, by design.

### Known upstream issue (not covered by a test)
- Resuming the human-approval interrupt with `Command(resume=None)` raises `UnboundLocalError` in
  LangGraph 1.2.10 (`langgraph/pregel/_loop.py`) before the application's approval validation runs.
  The run errors before anything is actioned. Not pinned by a test because the bug is in LangGraph.

## [0.1.0] - 2026-08-12

### Added
- Initial public release.
