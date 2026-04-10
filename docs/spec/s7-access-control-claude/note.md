# S7 Access Control + Claude - Context Note

## Tech Stack

- **Language**: Rust 2021 edition
- **Workspace**: `core/` (pq-diary-core) + `cli/` (binary)
- **Crypto**: aes-gcm, argon2, ml-kem/ml-dsa (RustCrypto fork), zeroize, secrecy
- **CLI**: clap (derive)
- **Config**: toml, serde

## Existing Infrastructure

### Policy Module (`core/src/policy.rs`)
- Pure stub: 4 lines, doc comment only
- `DiaryError::Policy(String)` variant already exists in `core/src/error.rs:62-64`

### Vault Config (`core/src/vault/config.rs`)
- `AccessSection { policy: String }` with default "none"
- VaultConfig already includes `access` field
- Serialization/deserialization via serde + toml
- vault.toml schema already includes `[access]` section

### CLI (`cli/src/main.rs`)
- `--claude` global flag exists (line 23-25)
- `VaultCommands` enum: Create, List, Policy, Delete (all stubbed)
- `not_implemented()` used for unfinished commands
- VaultGuard RAII pattern for lock/unlock

### --claude Current Behavior
- Skips confirmation in: cmd_delete, cmd_template_add, cmd_template_delete
- No policy enforcement yet

### Password Handling (`cli/src/password.rs`)
- 3-stage: --password flag > PQ_DIARY_PASSWORD env > TTY prompt
- All three remain available with --claude (no restriction)

### Vault Init (`core/src/vault/init.rs`)
- VaultManager::init_vault() creates vault dir + vault.pqd + vault.toml
- Policy defaults to "none" via VaultConfig::default()

## Development Rules

- `unsafe` only for mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console API
- Secrets must use zeroize / SecretString / SecretBytes
- No unwrap()/expect() in production code
- Errors via thiserror (core) / anyhow (cli only)
- Tests in `#[cfg(test)] mod tests` per module

## Related Files

- `requirements.md` section 4.4: Claude Code Integration spec
- `core/src/policy.rs`: Stub to implement
- `core/src/vault/config.rs`: AccessSection (needs enum migration)
- `core/src/error.rs`: DiaryError::Policy exists
- `cli/src/main.rs`: VaultCommands enum, --claude flag
- `cli/src/commands.rs`: Command implementations, VaultGuard pattern
- `docs/adr/`: ADR directory for new decisions

## Key Decisions from Interview

1. vault create/list/policy/delete all implemented in S7
2. AccessPolicy as Rust enum (None/WriteOnly/Full)
3. All commands supported via --claude (not just PRD's 4)
4. write_only: allows new/edit/delete/sync/today/template-add; denies list/show/search/stats/template-show
5. full policy warning at policy-set time only
6. Detailed error messages with policy name and required permission
7. No password restriction for --claude (existing 3-stage system)
8. vault create: PW required. list/policy/delete: PW not required (vault.toml only)
9. vault list: name + policy only (no entry count)
10. vault delete: --zeroize option for secure deletion (overwrites vault.pqd with random data)
11. Invalid policy values in vault.toml: DiaryError::Config error (no fallback to None)
12. Default vault deletion: additional confirmation message
13. vault.toml writes: atomic (temp + rename)
14. Vault name validation: reject empty, path traversal (/, \, ..)
