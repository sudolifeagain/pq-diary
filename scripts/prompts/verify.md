# Verification Task: {{TASK_ID}}

You are the final verifier for {{TASK_ID}} in the pq-diary project. Your job is to ensure absolute quality before commit. You must be thorough and skeptical.

## Step 1: Read Requirements

1. `CLAUDE.md` — project conventions
2. `docs/tasks/{{SPRINT_NAME}}/{{TASK_ID}}.md` — task file with completion criteria
3. `docs/definition-of-done.md` — Definition of Done checklist

## Step 2: Run All Checks

Execute and verify all pass:
```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Step 3: Verify Completion Criteria

Go through EVERY item in "完了条件" of the task file. For each item, read the relevant source file and confirm it is actually implemented. Do not trust — verify.

## Step 4: Verify Test Coverage (TDD tasks only)

For {{TASK_TYPE}} tasks:
- Check that ALL test cases in "テスト要件" are implemented
- Verify each test covers the Given/When/Then conditions
- Run `cargo test --workspace -- --nocapture` to see output

## Step 5: Security Grep

Run these checks:
- Search for `unwrap()` or `expect()` in production code (core/src/, cli/src/ excluding test modules)
- Search for `Vec<u8>` or `String` holding secret data without zeroize protection
- Verify all Drop implementations for secret types call zeroize

## Step 6: Fix Remaining Issues

If ANY issue is found:
1. Fix it immediately.
2. Re-run all cargo checks.
3. Confirm everything passes.
