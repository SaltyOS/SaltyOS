# AGENTS.md

This file defines how **Codex** and other general agents operates in this repository.  
It is intentionally strict and executable as policy.

## Project Information
- Project name: `SaltyOS`
- Primary language: `Rust 2024` (kernel/userland), plus `C` and `Assembly` (boot/runtime)
- System type: microkernel OS + CLI-driven build/test workflow (Meson + QEMU)
- Main responsibilities:
  - Implement requested changes safely
  - Preserve kernel/boot correctness
  - Validate via repository test/build commands
  - Report exact commands, outcomes, and residual risks

## 1. Overview
### Purpose
The agent must deliver code changes end-to-end: analyze request, edit minimal files, run targeted validation, and produce auditable results.

### High-Level Architecture
Single-agent staged loop:

`Request Intake -> Discovery -> Edit -> Validate -> Report`

No hidden background agents are assumed. Every action is attributable to the agent.

## 2. Agent Role
| Name | Responsibility | Inputs | Outputs | Allowed tools | Forbidden actions |
|---|---|---|---|---|---|
| `The Agent` | End-to-end task execution for SaltyOS changes | User request, repository files, command outputs, existing git state | File diffs, validation results, final summary | `exec_command`, `write_stdin`, `apply_patch`, `list_mcp_resources`, `list_mcp_resource_templates`, `read_mcp_resource` | Destructive git/file actions without explicit user request; secret access; network-dependent actions not required by task |

## 3. Control Flow
### Main Loop
1. Parse request and constraints.
2. Discover impacted files using fast search (`rg`, `rg --files`) and focused reads (`sed -n`, `cat`).
3. Apply minimal patch(es) only to required files.
4. Run the smallest sufficient validation set.
5. If validation fails, iterate Edit -> Validate (max 3 loops).
6. Return final status with changed files and command results.

### Task State Model
- `NEW -> DISCOVERING -> EDITING -> VALIDATING -> DONE`
- `VALIDATING -> EDITING` on fixable failure
- `* -> BLOCKED` when permission or missing dependency prevents progress
- `BLOCKED -> DONE` only after user decision or approved escalation

### Task Queue
- One active task at a time per conversation turn.
- Follow-up user requests create a new task; do not silently merge unrelated work.

## 4. Tool Access Policy
### Allowed by Default
- Read/search: `rg`, `rg --files`, `ls`, `cat`, `sed`, `git status`, `git diff`
- Edit: `apply_patch` (preferred for manual source edits)
- Build/test: `just build`, `just test-integration`, `just test-smp`, `just test-all`, `just fmt`, `just fmt-check`

### Permission Boundaries
- Current sandbox mode is `workspace-write`.
- Writable roots: repository root and `/tmp`.
- If a necessary command is blocked by sandbox, rerun with explicit escalation request.
- Never bypass sandbox constraints using alternative side effects.

### Explicit Deny Rules
- No `git reset --hard`, `git checkout --`, or equivalent destructive rollback unless user explicitly asks.
- Do not revert unrelated working tree changes.
- Do not modify generated artifacts in `build/` except through normal build/test execution.

## 5. Context Management
### Context Inputs
- Required: user request, `AGENTS.md`, relevant source/docs, current git working tree status.
- Optional: `CLAUDE.md`, design/spec docs when architecture-sensitive changes are requested.

### Short-Term Context
- Keep only:
  - directly affected files,
  - latest command outputs,
  - current patch intent.

### Long-Term Context
- Treat repository files as source of truth.
- Do not rely on unstated memory across turns; re-read files if ambiguity exists.

### Trimming Rules
- Prefer targeted excerpts over full-file dumps.
- Default to reading only needed ranges (`sed -n start,endp`).
- Avoid loading large logs fully; extract relevant segments.

## 6. Failure Handling
### Tool/Command Failures
- Classify failure:
  - transient (timeout, resource contention),
  - deterministic (compile error, test failure, missing symbol),
  - permission/sandbox.

### Retry Policy
- Transient: retry up to 2 times.
- Deterministic: do not blind-retry; fix root cause first.
- Permission failure: request escalation and rerun only if task-critical.

### Escalation Rules
- Escalate to user when:
  - command requires out-of-sandbox privileges,
  - requirements are conflicting/underspecified,
  - unrelated repo changes appear unexpectedly during execution.

## 7. Security Boundaries
### Filesystem
- Read: repository files as needed.
- Write: only files needed for requested task.
- Never write outside allowed roots.

### Command Execution
- Allowed for local build/test/inspection required by task.
- Disallow arbitrary network-dependent workflows unless explicitly required and approved.

### Code Modification
- Must be minimal and scoped.
- Preserve existing license headers and project style conventions.
- Respect Rust 2024 rules (`unsafe_op_in_unsafe_fn`, no `static mut` references, etc.).

### Secrets
- Do not read or exfiltrate secrets (`~/.ssh`, tokens, key files, secret env vars).
- If secret access is required, stop and ask user.

## 8. Determinism & Reproducibility
- Prefer deterministic command ordering and explicit file paths.
- Report exact commands run and meaningful outputs.
- Keep diffs minimal and avoid unrelated formatting churn.
- For validation, run targeted checks first, then broader checks when required.
- In final response, include:
  - changed files,
  - validation commands executed,
  - pass/fail status,
  - remaining risks or unrun checks.

## 9. Extension Guidelines
When introducing an additional agent role in this file, include all required fields:

`AgentSpec { name, responsibility, inputs, outputs, allowed_tools, forbidden_actions, read_scope, write_scope, retry_policy, escalation_rules }`

Constraints:
1. New roles must map to real executable behavior in the current agent workflow.
2. Least privilege by default.
3. No overlap without explicit precedence rules.
4. Must define clear handoff/state transition points.
5. Must define failure and escalation policy.

## Repository Quick Reference
### Structure
- `boot/`: 3-stage bootloader
- `kernel/src/`: Rust microkernel
- `userland/`: servers/apps (`init`, `console`, `procmgr`, `vfs`, `nameserv`, tests)
- `lib/`: shared userspace libraries (`libsalty`, `libc`)
- `tools/`: build/image/test scripts
- `docs/`: architecture/design/spec
- `build/`: generated artifacts

### Common Commands
- `just setup`
- `just build`
- `just run`, `just run-smp`, `just run-uefi`
- `just reconfigure -Dkernel_log_level=debug`
- `just fmt`, `just fmt-check`
