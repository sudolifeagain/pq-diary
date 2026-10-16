//! Shared synthetic vault fixtures for command and session unit tests only.

use pq_diary_core::DiaryCore;
use std::path::PathBuf;

pub(super) fn fast_params() -> pq_diary_core::crypto::kdf::Argon2Params {
    pq_diary_core::crypto::kdf::Argon2Params {
        memory_cost_kb: 8,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Initialise a test vault and return the vault **directory** path.
///
/// The vault is created with the password `"password"`.
pub(super) fn setup_vault(dir: &tempfile::TempDir) -> PathBuf {
    use pq_diary_core::vault::init::VaultManager;
    let mgr = VaultManager::new(dir.path().to_path_buf())
        .expect("VaultManager::new")
        .with_kdf_params(fast_params());
    mgr.init_vault("v", b"password").expect("init_vault");
    dir.path().join("v")
}

/// Create a vault with a specific access policy for policy-check tests.
pub(super) fn setup_vault_with_policy(
    dir: &tempfile::TempDir,
    policy: pq_diary_core::policy::AccessPolicy,
) -> PathBuf {
    use pq_diary_core::vault::init::VaultManager;
    let mgr = VaultManager::new(dir.path().to_path_buf())
        .expect("VaultManager::new")
        .with_kdf_params(fast_params());
    mgr.create_vault("v", b"password", policy)
        .expect("create_vault");
    dir.path().join("v")
}

/// Seed the vault with templates via DiaryCore directly.
pub(super) fn seed_templates(vault_dir: &std::path::Path, templates: &[(&str, &str)]) {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_str = vault_pqd.to_str().expect("utf8");
    let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
    let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
    core.unlock(pw).expect("unlock");
    for (name, body) in templates {
        core.new_template(name, body).expect("new_template");
    }
    core.lock();
}

/// A valid encrypted entry payload is not a valid template payload. Re-signing
/// the container isolates template deserialization from unlock integrity checks.
pub(super) fn seed_malformed_template(vault_dir: &std::path::Path) {
    use pq_diary_core::vault::{
        format::RECORD_TYPE_TEMPLATE, reader::read_vault, writer::write_vault_authenticated,
    };
    let path = vault_dir.join("vault.pqd");
    let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
    core.unlock(secrecy::SecretString::new("password".into()))
        .unwrap();
    core.new_entry("daily", "S47_PRIVATE_BODY", vec![]).unwrap();
    let key = core.vault_mac_key().unwrap();
    let (header, mut records) = read_vault(&path).unwrap();
    records[0].record_type = RECORD_TYPE_TEMPLATE;
    write_vault_authenticated(&path, header, &records, &key).unwrap();
}

pub(super) struct FailingMutationWriter {
    pub(super) fail_write: bool,
}

impl std::io::Write for FailingMutationWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail_write {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        } else {
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

/// Open the test vault and return all entry metadata.
pub(super) fn read_vault_entries(vault_dir: &std::path::Path) -> Vec<pq_diary_core::EntryMeta> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_str = vault_pqd.to_str().expect("utf8");
    let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
    let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
    core.unlock(pw).expect("unlock");
    let entries = core.list_entries(None).expect("list_entries");
    core.lock();
    entries
}
