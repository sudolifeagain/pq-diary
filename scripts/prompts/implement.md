# Implementation Task: {{TASK_ID}}

You are implementing {{TASK_ID}} for the pq-diary project (Rust post-quantum cryptography CLI journal).

## Step 1: Read Context

Read these files in order:
1. `CLAUDE.md` — project conventions and coding rules
2. `docs/tasks/{{SPRINT_NAME}}/{{TASK_ID}}.md` — full task requirements and completion criteria
3. `docs/design/{{SPRINT_NAME}}/types.rs` — reference type definitions
4. `docs/design/{{SPRINT_NAME}}/architecture.md` — architectural context
5. `docs/design/{{SPRINT_NAME}}/dataflow.md` — data flow diagrams

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
- Match type signatures in `docs/design/{{SPRINT_NAME}}/types.rs` exactly.

## Step 4: Security Patterns (MUST follow)

These patterns are mandatory for all new code. Violations will be caught in review.

### 4-1: Guarantee resource cleanup after unlock
If your code calls `core.unlock()`, you MUST ensure `core.lock()` is called
on EVERY possible exit path — success, error, and early return. Preferred
patterns (in order of preference):

```rust
// Pattern A: Closure capture (best for complex logic with many ? operators)
let result = (|| -> anyhow::Result<T> {
    // ... all logic using core ...
    Ok(value)
})();
core.lock();
result?;

// Pattern B: Explicit match on each fallible call (for simple flows)
let data = match core.some_operation() {
    Ok(d) => d,
    Err(e) => {
        core.lock();
        return Err(anyhow::anyhow!("{e}"));
    }
};
```

NEVER use bare `?` after `core.unlock()` — it skips `core.lock()`.

### 4-2: Never silence security-critical errors
```rust
// BAD:
let _ = editor::secure_delete(&tmpfile);

// GOOD:
if let Err(e) = editor::secure_delete(&tmpfile) {
    eprintln!("Warning: failed to securely delete temp file: {e}");
}
```

### 4-3: Validate sizes before allocation
When reading variable-length data from files or external input:
```rust
// BAD:
let len = reader.read_u32::<LE>()? as usize;
let mut buf = vec![0u8; len];  // OOM if len = u32::MAX

// GOOD:
const MAX_FIELD_SIZE: usize = 16 * 1024 * 1024;  // 16 MiB
let len = reader.read_u32::<LE>()? as usize;
if len > MAX_FIELD_SIZE {
    return Err(DiaryError::Vault(format!("field size {len} exceeds maximum")));
}
let mut buf = vec![0u8; len];
```

### 4-4: Use try_from instead of truncating casts
```rust
// BAD:
writer.write_u32::<LE>(data.len() as u32)?;

// GOOD:
let len = u32::try_from(data.len())
    .map_err(|_| DiaryError::Vault("data exceeds u32 max".to_string()))?;
writer.write_u32::<LE>(len)?;
```

### 4-5: Check interaction with existing code
If you add new validation (uniqueness check, format restriction, etc.),
search for ALL existing callers of the modified function. Ensure no existing
code path is broken by the new constraint.

## Step 5: Verify

Run these commands and fix any issues:
```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Completion

Check every item in the "完了条件" section of the task file. All must be satisfied.
