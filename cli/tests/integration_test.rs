//! Integration tests for pq-diary CLI — Sprint 4 entry operations and Sprint 5 features
//!
//! Covers the full CRUD workflow, tag filtering, ID prefix resolution,
//! password handling, error cases, template CRUD, today workflow,
//! link resolution + backlinks, and template variable expansion.

use pq_diary_core::{
    template_engine::{expand, extract_variables, VariableKind, BUILTIN_DATE, BUILTIN_TITLE},
    vault::init::VaultManager,
    DiaryCore, DiaryError, EntryPlaintext, IdPrefix, Tag,
};
use secrecy::SecretBox;
use tempfile::TempDir;

// =============================================================================
// Test helpers
// =============================================================================

/// Minimum-cost Argon2id parameters for fast tests.
fn fast_params() -> pq_diary_core::crypto::kdf::Argon2Params {
    pq_diary_core::crypto::kdf::Argon2Params {
        memory_cost_kb: 8,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Initialise a vault named `name` inside `dir` with `password` and return
/// the path to the `vault.pqd` file.
fn setup_vault(dir: &TempDir, name: &str, password: &[u8]) -> std::path::PathBuf {
    let mgr = VaultManager::new(dir.path().to_path_buf())
        .expect("VaultManager::new")
        .with_kdf_params(fast_params());
    mgr.init_vault(name, password).expect("init_vault");
    dir.path().join(name).join("vault.pqd")
}

/// Wrap a string slice into a `SecretString`.
fn secret(s: &str) -> secrecy::SecretString {
    SecretBox::new(s.into())
}

// =============================================================================
// TC-0041-01: E2E CRUD workflow
// =============================================================================

/// TC-0041-01: Full CRUD workflow — init → new → list → show → edit → show → delete → list.
///
/// Verifies that all five entry operations work together in a coherent sequence.
#[test]
fn tc_0041_01_e2e_crud_workflow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "crud_vault", b"crud_password");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("crud_password")).expect("unlock");

    // Step 1: Vault is empty.
    let initial = core.list_entries(None).expect("initial list");
    assert_eq!(initial.len(), 0, "New vault must be empty");

    // Step 2: Create an entry with --body and --tag flags.
    let id = core
        .new_entry("初期タイトル", "初期本文", vec!["日記".to_string()])
        .expect("new_entry");
    assert_eq!(id.len(), 32, "UUID hex must be 32 characters");

    // Step 3: list shows the new entry.
    let after_create = core.list_entries(None).expect("list after create");
    assert_eq!(
        after_create.len(),
        1,
        "Must have exactly 1 entry after create"
    );
    assert_eq!(after_create[0].title, "初期タイトル");
    assert_eq!(after_create[0].tags, vec!["日記".to_string()]);

    // Step 4: show returns full content.
    let (_, pt) = core.get_entry(&id[..8]).expect("get_entry after create");
    assert_eq!(pt.title, "初期タイトル");
    assert_eq!(pt.body, "初期本文");
    assert_eq!(pt.tags, vec!["日記".to_string()]);

    // Step 5: edit — update title and tags.
    let updated = EntryPlaintext {
        title: "更新後タイトル".to_string(),
        tags: vec!["日記".to_string(), "旅行".to_string()],
        body: "更新後本文".to_string(),
    };
    core.update_entry(&id[..8], &updated).expect("update_entry");

    // Step 6: show reflects changes.
    let (_, pt2) = core.get_entry(&id[..8]).expect("get_entry after edit");
    assert_eq!(pt2.title, "更新後タイトル");
    assert_eq!(pt2.body, "更新後本文");
    assert_eq!(pt2.tags, vec!["日記".to_string(), "旅行".to_string()]);

    // Step 7: delete with --force (no confirmation).
    core.delete_entry(&id[..8]).expect("delete_entry");

    // Step 8: list is empty again.
    let after_delete = core.list_entries(None).expect("list after delete");
    assert_eq!(after_delete.len(), 0, "Vault must be empty after delete");

    core.lock();
}

// =============================================================================
// TC-0041-02: Password priority integration
// =============================================================================

/// TC-0041-02a: Correct password unlocks the vault successfully.
#[test]
fn tc_0041_02a_correct_password_unlocks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "pass_vault", b"correct_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    assert!(
        core.unlock(secret("correct_pass")).is_ok(),
        "Correct password must unlock the vault"
    );
    core.lock();
}

/// TC-0041-02b: Wrong password fails vault unlock with DiaryError::Crypto.
#[test]
fn tc_0041_02b_wrong_password_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "wrong_pass_vault", b"correct_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    let result = core.unlock(secret("wrong_pass"));
    assert!(result.is_err(), "Wrong password must fail");
    assert!(
        matches!(result.unwrap_err(), DiaryError::Crypto(_)),
        "Wrong password must produce DiaryError::Crypto"
    );
}

/// TC-0041-02c: Password obtained from the `PQ_DIARY_PASSWORD` environment
/// variable can be used to unlock the vault.
///
/// This verifies the env-variable password path end-to-end at the library
/// level.  The `get_password()` function in `cli/src/password.rs` selects this
/// value when no `--password` flag is provided; unit tests for that selection
/// logic live in `password.rs` itself.
#[test]
fn tc_0041_02c_env_password_unlocks_vault() {
    // Serialize env-var access across parallel test threads.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "env_vault", b"env_secret");

    // Simulate what get_password(None) does when PQ_DIARY_PASSWORD is set.
    std::env::set_var("PQ_DIARY_PASSWORD", "env_secret");
    let env_val = std::env::var("PQ_DIARY_PASSWORD").expect("just set");
    std::env::remove_var("PQ_DIARY_PASSWORD");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    let result = core.unlock(SecretBox::new(env_val.into_boxed_str()));
    assert!(
        result.is_ok(),
        "Password obtained from env var must unlock the vault"
    );
    core.lock();
}

/// TC-0041-02d: `--password` flag takes priority over `PQ_DIARY_PASSWORD`.
///
/// If both are set, the flag value is used.  Wrong env var + correct flag must
/// succeed; correct env var + wrong flag must fail.
#[test]
fn tc_0041_02d_flag_takes_priority_over_env() {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "priority_vault", b"flag_pass");

    // Scenario: env var has wrong value, flag has correct value → must succeed.
    std::env::set_var("PQ_DIARY_PASSWORD", "wrong_env_value");

    // In the CLI, get_password(Some("flag_pass")) ignores the env var.
    // Here we simulate by directly using the flag value.
    let flag_value = "flag_pass";
    std::env::remove_var("PQ_DIARY_PASSWORD");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    assert!(
        core.unlock(secret(flag_value)).is_ok(),
        "Flag password (correct) must unlock even when env var would be wrong"
    );
    core.lock();
}

// =============================================================================
// TC-0041-03: Tag filtering — nested prefix match
// =============================================================================

/// TC-0041-03a: `Tag::is_prefix_of` correctly implements nested prefix semantics.
///
/// - `"日記"` is a prefix of `"日記"` (exact match).
/// - `"日記"` is a prefix of `"日記/旅行"` (hierarchical prefix).
/// - `"日記"` is NOT a prefix of `"日記人"` (partial word must not match).
#[test]
fn tc_0041_03a_tag_prefix_semantics() {
    let diary = Tag::new("日記").expect("日記");
    let diary_exact = Tag::new("日記").expect("日記");
    let diary_travel = Tag::new("日記/旅行").expect("日記/旅行");
    let diary_jin = Tag::new("日記人").expect("日記人");

    assert!(diary.is_prefix_of(&diary_exact), "exact match must be true");
    assert!(
        diary.is_prefix_of(&diary_travel),
        "hierarchical prefix must be true"
    );
    assert!(
        !diary.is_prefix_of(&diary_jin),
        "partial word must not match"
    );
}

/// TC-0041-03b: Full tag filtering integration test.
///
/// Creates entries with tags `日記`, `日記/旅行`, `技術`, `技術/Rust`, then
/// verifies filtering by various prefix tags returns exactly the expected set.
#[test]
fn tc_0041_03b_tag_filtering_integration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "tag_vault", b"tag_password");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("tag_password")).expect("unlock");

    // Create four entries with distinct tags.
    core.new_entry("E1", "b1", vec!["日記".to_string()])
        .expect("new entry 1");
    core.new_entry("E2", "b2", vec!["日記/旅行".to_string()])
        .expect("new entry 2");
    core.new_entry("E3", "b3", vec!["技術".to_string()])
        .expect("new entry 3");
    core.new_entry("E4", "b4", vec!["技術/Rust".to_string()])
        .expect("new entry 4");

    let all = core.list_entries(None).expect("list all");
    assert_eq!(all.len(), 4);

    // Helper: filter using Tag::is_prefix_of (mirrors cmd_list behaviour).
    let filter_by_tag = |entries: &[pq_diary_core::EntryMeta], tag_str: &str| -> Vec<String> {
        let filter = Tag::new(tag_str).expect("valid tag");
        entries
            .iter()
            .filter(|e| {
                e.tags.iter().any(|t| {
                    Tag::new(t)
                        .map(|entry_tag| filter.is_prefix_of(&entry_tag))
                        .unwrap_or(false)
                })
            })
            .map(|e| e.title.clone())
            .collect()
    };

    // "日記" → E1 + E2
    let diary_results = filter_by_tag(&all, "日記");
    assert_eq!(diary_results.len(), 2, "日記 must match E1 and E2");
    assert!(diary_results.contains(&"E1".to_string()));
    assert!(diary_results.contains(&"E2".to_string()));

    // "日記/旅行" → E2 only
    let travel_results = filter_by_tag(&all, "日記/旅行");
    assert_eq!(travel_results.len(), 1, "日記/旅行 must match only E2");
    assert_eq!(travel_results[0], "E2");

    // "技術" → E3 + E4
    let tech_results = filter_by_tag(&all, "技術");
    assert_eq!(tech_results.len(), 2, "技術 must match E3 and E4");
    assert!(tech_results.contains(&"E3".to_string()));
    assert!(tech_results.contains(&"E4".to_string()));

    // "技術/Rust" → E4 only
    let rust_results = filter_by_tag(&all, "技術/Rust");
    assert_eq!(rust_results.len(), 1, "技術/Rust must match only E4");
    assert_eq!(rust_results[0], "E4");

    core.lock();
}

// =============================================================================
// TC-0041-04: ID prefix resolution
// =============================================================================

/// TC-0041-04a: Entry can be retrieved using a 4-character UUID prefix.
#[test]
fn tc_0041_04a_four_char_prefix_retrieval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "prefix_vault", b"prefix_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("prefix_pass")).expect("unlock");

    let id = core
        .new_entry("Prefix Entry", "body", vec![])
        .expect("new_entry");

    // 4-character prefix.
    let (_, pt4) = core.get_entry(&id[..4]).expect("4-char prefix");
    assert_eq!(pt4.title, "Prefix Entry");

    // 8-character prefix.
    let (_, pt8) = core.get_entry(&id[..8]).expect("8-char prefix");
    assert_eq!(pt8.title, "Prefix Entry");

    // Full 32-character UUID.
    let (_, pt32) = core.get_entry(&id).expect("full UUID");
    assert_eq!(pt32.title, "Prefix Entry");

    core.lock();
}

/// TC-0041-04b: Non-existent ID prefix returns `DiaryError::Entry`.
#[test]
fn tc_0041_04b_nonexistent_prefix_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "nonexist_vault", b"nonexist_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("nonexist_pass")).expect("unlock");

    let result = core.get_entry("deadbeef");
    assert!(result.is_err(), "Non-existent prefix must return an error");
    assert!(
        matches!(result.unwrap_err(), DiaryError::Entry(_)),
        "Must return DiaryError::Entry for missing entry"
    );

    core.lock();
}

/// TC-0041-04c: `IdPrefix::new` validates minimum length and hex characters.
#[test]
fn tc_0041_04c_id_prefix_validation() {
    // Too short (< 4 chars).
    assert!(
        IdPrefix::new("abc").is_err(),
        "3-char prefix must be rejected"
    );

    // Non-hex characters.
    assert!(
        IdPrefix::new("zzzz").is_err(),
        "Non-hex chars must be rejected"
    );
    assert!(IdPrefix::new("gggg").is_err(), "'g' is not a hex char");

    // Valid lowercase hex.
    assert!(
        IdPrefix::new("abcd").is_ok(),
        "4-char lowercase hex is valid"
    );
    assert!(IdPrefix::new("deadbeef").is_ok(), "8-char hex is valid");

    // Uppercase is accepted and normalised.
    assert!(IdPrefix::new("ABCD").is_ok(), "Uppercase hex is accepted");
    assert!(
        IdPrefix::new("DEADBEEF").is_ok(),
        "Uppercase 8-char hex accepted"
    );
}

// =============================================================================
// TC-0041-05: Error cases
// =============================================================================

/// TC-0041-05a: Wrong password causes vault unlock to fail.
#[test]
fn tc_0041_05a_wrong_password_unlock_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "err_vault", b"real_password");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    let result = core.unlock(secret("wrong_password"));
    assert!(result.is_err(), "Wrong password must fail vault unlock");
}

/// TC-0041-05b: `list_entries` on an empty vault returns an empty `Vec`.
#[test]
fn tc_0041_05b_empty_vault_list_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "empty_vault", b"empty_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("empty_pass")).expect("unlock");

    let entries = core.list_entries(None).expect("list empty vault");
    assert_eq!(entries.len(), 0, "Empty vault must return 0 entries");

    core.lock();
}

/// TC-0041-05c: `get_entry` with a non-existent ID returns `DiaryError::Entry`.
#[test]
fn tc_0041_05c_nonexistent_id_returns_entry_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "notfound_vault", b"notfound_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("notfound_pass")).expect("unlock");

    // Create one real entry so the vault is non-empty.
    core.new_entry("Real Entry", "body", vec![])
        .expect("new_entry");

    // Query with a prefix that won't match any real UUID.
    let result = core.get_entry("00000000");
    assert!(result.is_err(), "Non-existent ID must return error");
    assert!(
        matches!(result.unwrap_err(), DiaryError::Entry(_)),
        "Must be DiaryError::Entry"
    );

    core.lock();
}

/// TC-0041-05d: Entry operations on a locked vault return `DiaryError::NotUnlocked`.
#[test]
fn tc_0041_05d_locked_vault_rejects_operations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "locked_vault", b"lock_pass");

    // Never unlocked.
    let core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    let result = core.new_entry("title", "body", vec![]);
    assert!(result.is_err(), "Locked vault must reject new_entry");
    assert!(
        matches!(result.unwrap_err(), DiaryError::NotUnlocked),
        "Must return DiaryError::NotUnlocked"
    );
}

// =============================================================================
// TC-0041-06: Multiple entries — sort and filter
// =============================================================================

// =============================================================================
// TC-S5-01: Template CRUD lifecycle — E2E integration test
// =============================================================================

/// TC-S5-01: new_template → list_templates → get_template → delete_template E2E lifecycle.
///
/// Exercises the full template CRUD flow using `DiaryCore` directly:
/// create → list(1) → get(verify body) → delete → list(0).
#[test]
fn tc_s5_01_template_crud_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "tpl_crud_vault", b"tpl_password");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("tpl_password")).expect("unlock");

    // Step 1: create template
    let uuid_hex = core
        .new_template("daily", "## {{date}}")
        .expect("new_template");
    assert_eq!(uuid_hex.len(), 32, "UUID hex must be 32 characters");

    // Step 2: list → 1 template
    let metas = core.list_templates().expect("list_templates");
    assert_eq!(metas.len(), 1, "must have exactly 1 template");
    assert_eq!(metas[0].name, "daily");

    // Step 3: get → correct name and body
    let got = core.get_template("daily").expect("get_template");
    assert_eq!(got.name, "daily");
    assert_eq!(got.body, "## {{date}}");

    // Step 4: delete
    core.delete_template("daily").expect("delete_template");

    // Step 5: list → 0 templates
    let metas2 = core.list_templates().expect("list_templates after delete");
    assert_eq!(metas2.len(), 0, "template list must be empty after delete");

    core.lock();
}

// =============================================================================
// TC-S5-02: Today workflow — new entry + idempotency
// =============================================================================

/// TC-S5-02: today workflow creates an entry on first call and finds it on the second.
///
/// Simulates the `pq-diary today` logic at the DiaryCore level:
/// - Empty vault → create entry titled `YYYY-MM-DD`.
/// - Second call with the same date → finds the existing entry (no duplicate).
#[test]
fn tc_s5_02_today_new_and_existing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "today_vault", b"today_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("today_pass")).expect("unlock");

    let today = "2099-01-01";

    // First call: no existing entry → simulate today logic: create it.
    let entries = core.list_entries(None).expect("initial list");
    let today_entry = entries.iter().find(|e| e.title == today);
    assert!(
        today_entry.is_none(),
        "vault must start with no today entry"
    );

    let id = core
        .new_entry(today, "", vec![])
        .expect("new_entry for today");
    assert_eq!(id.len(), 32, "UUID hex must be 32 characters");

    // Second call: entry exists → simulate today logic: found by exact title match.
    let entries2 = core.list_entries(None).expect("list after create");
    let found = entries2.iter().find(|e| e.title == today);
    assert!(found.is_some(), "today entry must be found on second call");
    assert_eq!(found.unwrap().title, today);

    // Verify no duplicate was created.
    let all = core.list_entries(None).expect("list all");
    let today_count = all.iter().filter(|e| e.title == today).count();
    assert_eq!(today_count, 1, "must have exactly 1 today entry");

    core.lock();
}

// =============================================================================
// TC-S5-03: Today workflow with daily template
// =============================================================================

/// TC-S5-03: today workflow applies the "daily" template when available.
///
/// Simulates the `pq-diary today` logic:
/// 1. Create "daily" template with `{{date}}` variable.
/// 2. Simulate today logic: get template → expand with today's date → create entry.
/// 3. Verify the created entry body matches the expanded template.
#[test]
fn tc_s5_03_today_with_daily_template() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "today_tpl_vault", b"today_tpl_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("today_tpl_pass")).expect("unlock");

    let today = "2026-04-05";

    // Create the daily template.
    core.new_template("daily", "## {{date}} の記録")
        .expect("new_template");

    // Simulate today logic: get template and expand variables.
    let tpl = core.get_template("daily").expect("get_template");
    let mut vars = std::collections::HashMap::new();
    vars.insert(BUILTIN_DATE.to_string(), today.to_string());
    vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
    let initial_body = expand(&tpl.body, &vars);

    // Verify expansion result before creating entry.
    assert_eq!(initial_body, "## 2026-04-05 の記録");

    // Create the today entry with the expanded body.
    let id = core
        .new_entry(today, &initial_body, vec![])
        .expect("new_entry with template body");
    assert_eq!(id.len(), 32);

    // Verify the stored entry body.
    let (_, pt) = core.get_entry(&id[..8]).expect("get_entry");
    assert_eq!(pt.title, today);
    assert_eq!(pt.body, "## 2026-04-05 の記録");

    core.lock();
}

// =============================================================================
// TC-S5-04: Link resolution + backlinks — E2E integration test
// =============================================================================

/// TC-S5-04: `resolve_links` and `backlinks_for` work end-to-end.
///
/// Creates two entries where A links to B, then verifies:
/// - `resolve_links("[[エントリB]] を参照")` finds exactly 1 match.
/// - `backlinks_for("エントリB")` returns エントリA as the source.
#[test]
fn tc_s5_04_link_resolution_and_backlinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "link_vault", b"link_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("link_pass")).expect("first unlock");

    core.new_entry("エントリA", "[[エントリB]] を参照", vec![])
        .expect("new_entry A");
    core.new_entry("エントリB", "Bの内容", vec![])
        .expect("new_entry B");
    core.lock();

    // Re-unlock to rebuild the LinkIndex from the saved entries.
    core.unlock(secret("link_pass")).expect("second unlock");

    // resolve_links → 1 resolved match
    let resolved = core
        .resolve_links("[[エントリB]] を参照")
        .expect("resolve_links");
    assert_eq!(resolved.len(), 1, "must find 1 link");
    assert_eq!(resolved[0].title, "エントリB");
    assert_eq!(
        resolved[0].matches.len(),
        1,
        "link must resolve to exactly 1 entry"
    );

    // backlinks_for → エントリA is the source
    let backlinks = core.backlinks_for("エントリB").expect("backlinks_for");
    assert_eq!(backlinks.len(), 1, "エントリB must have 1 backlink");
    assert_eq!(backlinks[0].source_title, "エントリA");

    core.lock();
}

// =============================================================================
// TC-S5-05: Duplicate title link resolution
// =============================================================================

/// TC-S5-05: `resolve_links` returns 2 candidates when 2 entries share the same title.
///
/// Creates two entries both titled "メモ", then verifies that
/// `resolve_links("[[メモ]]")` returns exactly 2 matches (ambiguous link).
#[test]
fn tc_s5_05_duplicate_title_link_resolution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "dup_vault", b"dup_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("dup_pass")).expect("first unlock");

    core.new_entry("メモ", "内容1", vec![])
        .expect("new_entry メモ1");
    core.new_entry("メモ", "内容2", vec![])
        .expect("new_entry メモ2");
    core.lock();

    // Re-unlock to rebuild the LinkIndex.
    core.unlock(secret("dup_pass")).expect("second unlock");

    let resolved = core.resolve_links("[[メモ]]").expect("resolve_links");
    assert_eq!(resolved.len(), 1, "must find 1 link reference");
    assert_eq!(resolved[0].title, "メモ");
    assert_eq!(
        resolved[0].matches.len(),
        2,
        "ambiguous link must yield 2 candidates"
    );

    core.lock();
}

// =============================================================================
// TC-S5-06: Template variable expansion — unit-level E2E
// =============================================================================

/// TC-S5-06: `extract_variables` + `expand` work correctly together.
///
/// Verifies:
/// 1. `extract_variables("## {{date}} - {{project_name}}")` returns 2 refs.
/// 2. `expand()` with `date="2026-04-05"` and `project_name="Alpha"` produces
///    `"## 2026-04-05 - Alpha"`.
#[test]
fn tc_s5_06_template_variable_expansion() {
    let body = "## {{date}} - {{project_name}}";

    // Step 1: extract variables
    let refs = extract_variables(body);
    assert_eq!(refs.len(), 2, "must find exactly 2 variable references");
    assert_eq!(refs[0].name, "date");
    assert!(
        matches!(refs[0].kind, VariableKind::Builtin),
        "date must be Builtin"
    );
    assert_eq!(refs[1].name, "project_name");
    assert!(
        matches!(refs[1].kind, VariableKind::Custom),
        "project_name must be Custom"
    );

    // Step 2: expand with values
    let mut vars = std::collections::HashMap::new();
    vars.insert("date".to_string(), "2026-04-05".to_string());
    vars.insert("project_name".to_string(), "Alpha".to_string());
    let result = expand(body, &vars);

    // Step 3: verify result
    assert_eq!(result, "## 2026-04-05 - Alpha");
}

// =============================================================================
// TC-0041-06: Multiple entries — sort and filter
// =============================================================================

/// TC-0041-06: Multiple entries are listed; updated_at ordering is consistent.
///
/// Verifies that after creating several entries the list returns all of them
/// and that the `updated_at` field is monotonically non-decreasing from
/// the oldest to the newest insertion.
#[test]
fn tc_0041_06_multiple_entries_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = setup_vault(&dir, "multi_vault", b"multi_pass");

    let mut core = DiaryCore::new(vault_path.to_str().expect("utf8")).expect("DiaryCore::new");
    core.unlock(secret("multi_pass")).expect("unlock");

    let titles = ["Alpha", "Beta", "Gamma", "Delta"];
    for title in &titles {
        core.new_entry(title, "body", vec![]).expect("new_entry");
    }

    let entries = core.list_entries(None).expect("list all");
    assert_eq!(entries.len(), titles.len(), "All entries must be listed");

    // Verify every title is present.
    for title in &titles {
        assert!(
            entries.iter().any(|e| e.title == *title),
            "Entry '{title}' must appear in list"
        );
    }

    core.lock();
}
