# Review Task: {{TASK_ID}}

You are reviewing the implementation of {{TASK_ID}} for the pq-diary project. You are a separate reviewer with fresh eyes.

## Step 1: Read Context

1. `CLAUDE.md` — project conventions
2. `docs/tasks/{{SPRINT_NAME}}/{{TASK_ID}}.md` — task requirements and completion criteria
3. `docs/design/{{SPRINT_NAME}}/types.rs` — reference type definitions

## Step 2: Review Implementation

Read all source files that were created or modified for this task. Check:

### A. Requirements Compliance
- Does the implementation satisfy ALL items in "完了条件"?
- Does it match type signatures in `docs/design/{{SPRINT_NAME}}/types.rs`?
- Are all test cases from "テスト要件" implemented?

### B. CLAUDE.md Convention Compliance
- No `unwrap()` / `expect()` in production code
- Secret data protected by `zeroize` / `SecretString` / `SecretBytes`
- No raw `Vec<u8>` / `String` for secrets
- Errors use `thiserror` (core/) or `anyhow` (cli/ only)
- No `unsafe` in production code
- No platform-dependent UI code in core/

### C. Code Quality
- All public APIs have `///` doc comments (English)
- Error messages in English
- Test modules use `#[cfg(test)] mod tests`

### D. Security Invariants
- Drop implementations call `zeroize()`
- No secret data in error messages
- No plaintext written to disk

## Step 3: Fix Issues

If you find ANY issue:
1. Fix it directly by editing the file.
2. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
3. Ensure all checks pass.

If everything is correct, confirm the implementation is sound.
