# Implementation Task: {{TASK_ID}}

You are implementing {{TASK_ID}} for the pq-diary project (Rust post-quantum cryptography CLI journal).

## Step 1: Read Context

Read these files in order:
1. `CLAUDE.md` — project conventions and coding rules
2. `docs/tasks/s1-foundation/{{TASK_ID}}.md` — full task requirements and completion criteria
3. `docs/design/s1-foundation/types.rs` — reference type definitions
4. `docs/design/s1-foundation/architecture.md` — architectural context

## Step 2: Implement

This task is **{{TASK_TYPE}}** type.

**If DIRECT**: Create all required files and configurations as described in the task file.

**If TDD**: Follow the TDD cycle:
1. Write failing tests first based on the test cases in the task file.
2. Write the minimum implementation to make all tests pass.
3. Refactor while keeping tests green.

## Step 3: Rules (MUST follow)

- No `unwrap()` or `expect()` in production code. Test code only.
- Secret data must use `zeroize` / `SecretString` / `SecretBytes`. No raw `Vec<u8>` / `String`.
- Errors: `thiserror` in core/, `anyhow` in cli/ only.
- No `unsafe` in production code (test code allowed for zeroize verification).
- No platform-dependent UI code in core/.
- Tests in `#[cfg(test)] mod tests` blocks.
- All public APIs must have `/// doc comment` in English.
- Error messages in English.
- Match type signatures in `docs/design/s1-foundation/types.rs` exactly.

## Step 4: Verify

Run these commands and fix any issues:
```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Completion

Check every item in the "完了条件" section of the task file. All must be satisfied.
