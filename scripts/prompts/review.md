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

### D. Security Patterns (MUST check all)

**D-1: Resource cleanup guarantee**
- If the code calls `core.unlock()`, trace EVERY subsequent error path
  (every `?`, every `return Err`, every early return). Does each one call
  `core.lock()` before returning? If there are more than 3 `?` operators
  after unlock, require a closure/guard pattern instead of individual checks.
- If the code creates temp files, is `secure_delete` called on ALL paths
  (success AND failure)?

**D-2: Error silencing on security operations**
- Search for `let _ =` and `let _var =` patterns. If the ignored result
  is from a security-critical function (secure_delete, zeroize, lock,
  permission change), it MUST be replaced with `if let Err(e) = ... { eprintln!(...) }`.

**D-3: Secret data lifecycle**
- Trace any variable holding passwords, keys, or decrypted plaintext.
  Is it wrapped in `SecretString`/`SecretBox`/`Zeroizing`? Or is it a
  raw `String`/`Vec<u8>` that survives beyond its immediate use?
- Check for intermediate copies: `.to_vec()`, `.clone()`, `.to_string()`
  on secret data — these create unzeroized copies.
- If `std::env::var()` reads a secret, is the env var removed afterward
  with `std::env::remove_var()`?

**D-4: Input validation and bounds**
- Any `read` from a file/network that allocates based on a length field:
  is there a maximum size check BEFORE the allocation? (Prevents OOM.)
- Any `as u32`, `as u16`, `as u8` cast on a `usize`: could it silently
  truncate? Use `try_from()` instead.
- Are empty/zero-length inputs explicitly rejected where they are invalid?

**D-5: I/O safety**
- File writes: are they atomic (write to temp, then rename)? Or does a
  crash mid-write corrupt data?
- Temp files: are permissions restricted (0o600 on Unix)?
- Editor integration: does the vim/nvim command include `noswapfile`,
  `nobackup`, `noundofile`, `nowritebackup`, and `viminfo=NONE` / `shada=NONE`?

**D-6: Interaction with existing code**
- Does this task add new validation (e.g., uniqueness check, format
  restriction)? If so, trace ALL existing callers and code paths that
  might now fail. For example, a new "duplicate name" check could break
  an existing "overwrite" flow.

## Step 3: Fix Issues

If you find ANY issue:
1. Fix it directly by editing the file.
2. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
3. Ensure all checks pass.

If everything is correct, confirm the implementation is sound.
