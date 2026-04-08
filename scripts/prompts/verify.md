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
cargo fmt --check
```

## Step 3: Verify Completion Criteria

Go through EVERY item in "完了条件" of the task file. For each item, read the relevant source file and confirm it is actually implemented. Do not trust — verify.

## Step 4: Verify Test Coverage (TDD tasks only)

For {{TASK_TYPE}} tasks:
- Check that ALL test cases in "テスト要件" are implemented
- Verify each test covers the Given/When/Then conditions
- Run `cargo test --workspace -- --nocapture` to see output

## Step 5: Automated Security Grep

Run each check below. If ANY violation is found in production code (exclude `#[cfg(test)]` modules), fix it immediately.

### 5-1: unwrap/expect in production code
```bash
# Search for unwrap() and expect() in production code
grep -rn 'unwrap()' core/src/ cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'
grep -rn 'expect(' core/src/ cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'
```
For each match: verify it is inside a `#[cfg(test)] mod tests` block. If not, it is a violation.
Note: `unwrap_or()`, `unwrap_or_else()`, `unwrap_or_default()` are safe and NOT violations.

### 5-2: Silenced security errors
```bash
grep -rn 'let _ =' cli/src/ core/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
grep -rn 'let _[a-z]' cli/src/ core/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
```
For each match: is the discarded result from a security-critical function
(secure_delete, zeroize, lock, set_permissions, remove_var)? If yes, fix it.

### 5-3: Resource cleanup after unlock
```bash
grep -rn 'core.unlock' cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
```
For each unlock call: trace forward to the matching `core.lock()`. Count every
`?` operator and `return Err` between them. If ANY error path skips `core.lock()`,
it is a violation. Fix by adding explicit lock calls or wrapping in a closure.

### 5-4: Raw secret data
```bash
# Look for variables likely holding secrets
grep -rn 'password.*String\|plaintext.*String\|secret.*String\|key.*Vec<u8>' core/src/ cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v '///'
```
For each match: is it wrapped in SecretString/SecretBox/Zeroizing? If it is a
raw String or Vec<u8> holding secret data, it is a violation.

### 5-5: Unsafe blocks
```bash
grep -rn 'unsafe' core/src/ cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
```
For each match in production code: is it for mlock/VirtualLock/PR_SET_DUMPABLE
or Win32 console API? If not, it is a violation.

### 5-6: Uncapped allocations from external input
```bash
grep -rn 'vec!\[0.*; .*len\|Vec::with_capacity.*len\|vec!\[0.*; .*size' core/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
```
For each match: is `len`/`size` from user input or file data? Is there an upper
bound check before the allocation? If not, it is a vulnerability (OOM attack).

### 5-7: Truncating casts
```bash
grep -rn 'as u32\|as u16\|as u8' core/src/ cli/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'
```
For each match: could the source value exceed the target type's range? If yes,
replace with `try_from()`.

## Step 6: Fix Remaining Issues

If ANY issue is found:
1. Fix it immediately.
2. Re-run all cargo checks.
3. Confirm everything passes.
