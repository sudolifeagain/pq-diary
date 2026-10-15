//! vault.pqd write operations.
//!
//! Provides three public functions for serialising vault data to little-endian
//! binary format:
//!
//! - `write_header`: serialise a `VaultHeader` into any `Write` sink
//! - `write_entries`: serialise a slice of `EntryRecord`s into any `Write` sink
//! - `write_vault`: write a complete vault file to a `Path` with random tail padding

use std::io::Write;
use std::path::{Path, PathBuf};

use rand::Rng;

use crate::crypto::hmac_util;
use crate::error::DiaryError;
use crate::vault::format::{
    check_field_size, AttachmentRecord, EntryRecord, VaultHeader, FLAG_INTEGRITY, MAGIC,
    SCHEMA_VERSION,
};

// Fixed size of the on-disk verification-token ciphertext field (bytes 92-140).
const VERIFICATION_CT_LEN: usize = 48;

// Payload bytes excluding ciphertext, signature, legacy key block, and padding.
// The three u32 lengths and the u8 padding length are included.
const ENTRY_FIXED_LEN: usize = 1 + 16 + 8 + 8 + 12 + 4 + 4 + 32 + 1 + 4 + 2 + 8 + 1;
const ATTACHMENT_FIXED_LEN: usize = 1 + 16 + 12 + 4 + 4 + 32 + 1 + 4 + 1;

fn record_payload_len(
    fixed_len: usize,
    field_lengths: [usize; 3],
    padding_len: usize,
) -> Result<usize, DiaryError> {
    u8::try_from(padding_len)
        .map_err(|_| DiaryError::Vault("padding length exceeds 255-byte maximum".to_string()))?;
    let record_len =
        field_lengths
            .into_iter()
            .chain([padding_len])
            .try_fold(fixed_len, |len, field_len| {
                len.checked_add(field_len)
                    .ok_or_else(|| DiaryError::Vault("record length overflow".to_string()))
            })?;
    check_field_size(record_len)?;
    Ok(record_len)
}

fn entry_payload_len(entry: &EntryRecord) -> Result<usize, DiaryError> {
    record_payload_len(
        ENTRY_FIXED_LEN,
        [
            entry.ciphertext.len(),
            entry.signature.len(),
            entry.legacy_key_block.len(),
        ],
        entry.padding.len(),
    )
}

fn attachment_payload_len(attachment: &AttachmentRecord) -> Result<usize, DiaryError> {
    record_payload_len(
        ATTACHMENT_FIXED_LEN,
        [
            attachment.ciphertext.len(),
            attachment.signature.len(),
            attachment.legacy_key_block.len(),
        ],
        attachment.padding.len(),
    )
}

/// Serialise `header` into `writer` using little-endian byte order.
///
/// Writes the 204-byte fixed section followed by the variable-length
/// encrypted secret-key blocks:
///
/// ```text
/// [0..8]    magic b"PQDIARY\0"
/// [8]       schema_version
/// [9]       flags
/// [10..12]  reserved (0x00 0x00)
/// [12..16]  payload_size (LE u32)
/// [16..48]  kdf_salt (32 B)
/// [48..80]  legacy_salt (32 B)
/// [80..92]  verification_iv (12 B)
/// [92..140] verification_ct (48 B, zero-padded if field is shorter)
/// [140..172] kem_pk_offset (32 B)
/// [172..204] dsa_pk_hash (32 B)
/// [204..]   kem_encrypted_sk_len (LE u32) + kem_encrypted_sk bytes
///           dsa_encrypted_sk_len (LE u32) + dsa_encrypted_sk bytes
/// ```
pub fn write_header<W: Write>(writer: &mut W, header: &VaultHeader) -> Result<(), DiaryError> {
    // Validate both variable fields before touching even a caller-provided sink.
    check_field_size(header.kem_encrypted_sk.len())?;
    check_field_size(header.dsa_encrypted_sk.len())?;

    // --- Fixed 204-byte section ---
    writer.write_all(MAGIC)?;
    writer.write_all(&[header.schema_version])?;
    writer.write_all(&[header.flags])?;
    writer.write_all(&[0u8; 2])?; // reserved
    writer.write_all(&header.payload_size.to_le_bytes())?;
    writer.write_all(&header.kdf_salt)?;
    writer.write_all(&header.legacy_salt)?;
    writer.write_all(&header.verification_iv)?;

    // verification_ct is fixed 48 bytes on disk; zero-pad if the Vec is shorter.
    let ct = &header.verification_ct;
    if ct.len() >= VERIFICATION_CT_LEN {
        writer.write_all(&ct[..VERIFICATION_CT_LEN])?;
    } else {
        let mut padded = [0u8; VERIFICATION_CT_LEN];
        padded[..ct.len()].copy_from_slice(ct);
        writer.write_all(&padded)?;
    }

    writer.write_all(&header.kem_pk_offset)?;
    writer.write_all(&header.dsa_pk_hash)?;

    // --- Variable-length encrypted secret-key blocks ---
    let kem_len = u32::try_from(header.kem_encrypted_sk.len()).map_err(|_| {
        DiaryError::Vault("kem_encrypted_sk length exceeds u32 maximum".to_string())
    })?;
    writer.write_all(&kem_len.to_le_bytes())?;
    writer.write_all(&header.kem_encrypted_sk)?;

    let dsa_len = u32::try_from(header.dsa_encrypted_sk.len()).map_err(|_| {
        DiaryError::Vault("dsa_encrypted_sk length exceeds u32 maximum".to_string())
    })?;
    writer.write_all(&dsa_len.to_le_bytes())?;
    writer.write_all(&header.dsa_encrypted_sk)?;

    Ok(())
}

/// Serialise `entries` into `writer` using little-endian byte order.
///
/// Each entry record is written as a length-prefixed payload:
///
/// ```text
/// [record_len: LE u32]   -- byte count of the following payload
/// [record_type: 1 B]
/// [uuid: 16 B]
/// [created_at: LE u64]
/// [updated_at: LE u64]
/// [iv: 12 B]
/// [ciphertext_len: LE u32]
/// [ciphertext: variable]
/// [signature_len: LE u32]
/// [signature: variable]
/// [content_hmac: 32 B]
/// [legacy_flag: 1 B]
/// [legacy_key_block_len: LE u32]
/// [legacy_key_block: variable]
/// [attachment_count: LE u16]
/// [attachment_offset: LE u64]
/// [padding_len: 1 B]
/// [padding: variable]
/// ```
///
/// After all records a zero sentinel (`0u32` in LE) is appended so readers
/// can detect the end of the entry section without a separate count field.
pub fn write_entries<W: Write>(writer: &mut W, entries: &[EntryRecord]) -> Result<(), DiaryError> {
    write_entries_no_sentinel(writer, entries)?;
    writer.write_all(&0u32.to_le_bytes())?;
    Ok(())
}

/// Like [`write_entries`] but does NOT emit the zero sentinel — used by
/// [`write_vault_with_attachments`] so it can stitch entries + attachments
/// together and emit the sentinel exactly once at the end.
fn write_entries_no_sentinel<W: Write>(
    writer: &mut W,
    entries: &[EntryRecord],
) -> Result<(), DiaryError> {
    // Preflight the entire slice so a later invalid record cannot leave a
    // partially written sink. Include metadata and padding in the reader's cap.
    for entry in entries {
        entry_payload_len(entry)?;
    }
    for entry in entries {
        let mut payload = Vec::with_capacity(entry_payload_len(entry)?);

        // Record type is the first byte of every payload.
        payload.push(entry.record_type);
        payload.extend_from_slice(&entry.uuid);
        payload.extend_from_slice(&entry.created_at.to_le_bytes());
        payload.extend_from_slice(&entry.updated_at.to_le_bytes());
        payload.extend_from_slice(&entry.iv);

        let ct_len = u32::try_from(entry.ciphertext.len())
            .map_err(|_| DiaryError::Vault("ciphertext length exceeds u32 maximum".to_string()))?;
        payload.extend_from_slice(&ct_len.to_le_bytes());
        payload.extend_from_slice(&entry.ciphertext);

        let sig_len = u32::try_from(entry.signature.len())
            .map_err(|_| DiaryError::Vault("signature length exceeds u32 maximum".to_string()))?;
        payload.extend_from_slice(&sig_len.to_le_bytes());
        payload.extend_from_slice(&entry.signature);

        payload.extend_from_slice(&entry.content_hmac);
        payload.push(entry.legacy_flag);

        let lkb_len = u32::try_from(entry.legacy_key_block.len()).map_err(|_| {
            DiaryError::Vault("legacy_key_block length exceeds u32 maximum".to_string())
        })?;
        payload.extend_from_slice(&lkb_len.to_le_bytes());
        payload.extend_from_slice(&entry.legacy_key_block);

        payload.extend_from_slice(&entry.attachment_count.to_le_bytes());
        payload.extend_from_slice(&entry.attachment_offset.to_le_bytes());

        let pad_len = u8::try_from(entry.padding.len()).map_err(|_| {
            DiaryError::Vault("padding length exceeds 255-byte maximum".to_string())
        })?;
        payload.push(pad_len);
        payload.extend_from_slice(&entry.padding);

        // Write length prefix (LE u32) then the payload.
        let record_len = u32::try_from(payload.len())
            .map_err(|_| DiaryError::Vault("record length exceeds u32 maximum".to_string()))?;
        writer.write_all(&record_len.to_le_bytes())?;
        writer.write_all(&payload)?;
    }

    Ok(())
}

/// Serialise an [`AttachmentRecord`] slice into `writer` using the same
/// length-prefixed layout as [`write_entries`] but with the
/// attachment-specific payload schema. Does NOT emit a zero sentinel —
/// callers stitching entries + attachments together should write attachments
/// after entries and emit the sentinel once at the end.
pub fn write_attachments<W: Write>(
    writer: &mut W,
    attachments: &[AttachmentRecord],
) -> Result<(), DiaryError> {
    for attachment in attachments {
        attachment_payload_len(attachment)?;
    }
    for a in attachments {
        let mut payload = Vec::with_capacity(attachment_payload_len(a)?);

        payload.push(a.record_type);
        payload.extend_from_slice(&a.uuid);
        payload.extend_from_slice(&a.iv);

        let ct_len = u32::try_from(a.ciphertext.len()).map_err(|_| {
            DiaryError::Vault("attachment ciphertext length exceeds u32 maximum".to_string())
        })?;
        payload.extend_from_slice(&ct_len.to_le_bytes());
        payload.extend_from_slice(&a.ciphertext);

        let sig_len = u32::try_from(a.signature.len()).map_err(|_| {
            DiaryError::Vault("attachment signature length exceeds u32 maximum".to_string())
        })?;
        payload.extend_from_slice(&sig_len.to_le_bytes());
        payload.extend_from_slice(&a.signature);

        payload.extend_from_slice(&a.content_hmac);
        payload.push(a.legacy_flag);

        let lkb_len = u32::try_from(a.legacy_key_block.len()).map_err(|_| {
            DiaryError::Vault("attachment legacy_key_block length exceeds u32 maximum".to_string())
        })?;
        payload.extend_from_slice(&lkb_len.to_le_bytes());
        payload.extend_from_slice(&a.legacy_key_block);

        let pad_len = u8::try_from(a.padding.len()).map_err(|_| {
            DiaryError::Vault("attachment padding length exceeds 255-byte maximum".to_string())
        })?;
        payload.push(pad_len);
        payload.extend_from_slice(&a.padding);

        let record_len = u32::try_from(payload.len()).map_err(|_| {
            DiaryError::Vault("attachment record length exceeds u32 maximum".to_string())
        })?;
        writer.write_all(&record_len.to_le_bytes())?;
        writer.write_all(&payload)?;
    }
    Ok(())
}

/// Owns only a sibling successfully created with exclusive creation. The file
/// handle is closed before rename/removal, including on Windows. Cleanup is
/// best effort; this is not a physical-erasure or crash-durability guarantee.
struct VaultTemp {
    path: PathBuf,
    armed: bool,
}

impl VaultTemp {
    fn create(path: PathBuf) -> Result<(Self, std::fs::File), DiaryError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Apply permissions before any vault bytes reach the file. Windows
        // continues to rely on the vault directory's ACLs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok((Self { path, armed: true }, file))
    }
}

impl Drop for VaultTemp {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = std::fs::remove_file(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    // Drop must not panic if stderr is closed or broken,
                    // especially while unwinding another failure.
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "Warning: failed to remove temporary vault file: {error}"
                    );
                }
            }
        }
    }
}

fn write_atomic(
    path: &Path,
    write_and_sync: impl FnOnce(&mut std::fs::File) -> Result<(), DiaryError>,
) -> Result<(), DiaryError> {
    let mut name = path
        .file_name()
        .ok_or_else(|| DiaryError::Vault("vault path has no file name".to_string()))?
        .to_os_string();
    name.push(format!(".tmp.{}", uuid::Uuid::new_v4()));
    // A collision fails closed: no ownership guard exists until create_new
    // succeeds, so an existing file, directory or symlink cannot be cleaned up.
    let (mut temp, mut file) = VaultTemp::create(path.with_file_name(name))?;
    let result = write_and_sync(&mut file);
    drop(file);
    result?;
    // Keep the platform's existing atomic-replacement semantics. Do not delete
    // the destination first or fall back to copying over it.
    std::fs::rename(&temp.path, path)?;
    temp.armed = false;
    Ok(())
}

/// Write a complete vault to `path` *without* a vault-level integrity MAC.
///
/// Retained for test fixtures and the legacy v0x04/v0x05 layout. Production
/// code MUST use [`write_vault_authenticated`] so the resulting file is
/// tamper-evident; this entry point leaves the vault unauthenticated.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on any I/O failure.
pub fn write_vault(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
) -> Result<(), DiaryError> {
    write_vault_dispatch(path, header, entries, None, &[])
}

/// Write a complete vault to `path` with a trailing vault-level MAC.
///
/// `mac_key` is the vault integrity subkey (see
/// [`crate::crypto::derive_vault_mac_key`]). The file is stamped
/// [`SCHEMA_VERSION`] with [`FLAG_INTEGRITY`] set, and a
/// [`crate::vault::format::VAULT_MAC_LEN`]-byte HMAC-SHA256 over
/// `header || records || sentinel || padding` is appended so that any later
/// tampering (record edit, reorder, truncation, metadata flip) is detected by
/// [`crate::vault::reader::verify_vault_integrity`] on unlock.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on I/O failure or [`DiaryError::Crypto`] on MAC
/// computation failure.
pub fn write_vault_authenticated(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    mac_key: &[u8; 32],
) -> Result<(), DiaryError> {
    write_vault_dispatch(path, header, entries, Some(mac_key), &[])
}

/// Write an authenticated vault with caller-provided extra random padding.
///
/// The extra bytes are appended to the normal random tail padding before the
/// vault-level MAC is computed, so privacy padding remains tamper-evident.
pub fn write_vault_authenticated_with_extra_padding(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    mac_key: &[u8; 32],
    extra_padding: &[u8],
) -> Result<(), DiaryError> {
    write_vault_dispatch(path, header, entries, Some(mac_key), extra_padding)
}

/// Write records from a validated snapshot without reopening the destination
/// to recover attachment metadata. Padding and MAC semantics are unchanged.
pub(crate) fn write_vault_with_attachments_authenticated_with_extra_padding(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    attachments: &[AttachmentRecord],
    mac_key: &[u8; 32],
    extra_padding: &[u8],
) -> Result<(), DiaryError> {
    write_vault_inner(
        path,
        header,
        entries,
        attachments,
        Some(mac_key),
        extra_padding,
    )
}

/// Shared body for [`write_vault`] / [`write_vault_authenticated`]: preserves
/// any existing attachment records, then delegates to the with-attachments path.
fn write_vault_dispatch(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    mac_key: Option<&[u8; 32]>,
    extra_padding: &[u8],
) -> Result<(), DiaryError> {
    let attachments = match crate::vault::reader::read_vault_with_attachments(path) {
        Ok((_existing_header, _existing_entries, attachments)) => attachments,
        Err(DiaryError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    write_vault_inner(path, header, entries, &attachments, mac_key, extra_padding)
}

/// Write a complete vault containing entries + attachments (S13), *without* a
/// vault-level MAC. Retained for tests/legacy; production uses
/// [`write_vault_with_attachments_authenticated`].
pub fn write_vault_with_attachments(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    attachments: &[AttachmentRecord],
) -> Result<(), DiaryError> {
    write_vault_inner(path, header, entries, attachments, None, &[])
}

/// Write a complete vault containing entries + attachments with a trailing
/// vault-level MAC. See [`write_vault_authenticated`] for the integrity model.
pub fn write_vault_with_attachments_authenticated(
    path: &Path,
    header: VaultHeader,
    entries: &[EntryRecord],
    attachments: &[AttachmentRecord],
    mac_key: &[u8; 32],
) -> Result<(), DiaryError> {
    write_vault_inner(path, header, entries, attachments, Some(mac_key), &[])
}

/// Core vault writer. The attachment records are appended after the entry
/// records in the same length-prefixed payload section, and the zero sentinel
/// terminates both. When `mac_key` is `Some`, [`FLAG_INTEGRITY`] is set and an
/// HMAC-SHA256 trailer authenticating the whole serialised file is appended.
fn write_vault_inner(
    path: &Path,
    mut header: VaultHeader,
    entries: &[EntryRecord],
    attachments: &[AttachmentRecord],
    mac_key: Option<&[u8; 32]>,
    extra_padding: &[u8],
) -> Result<(), DiaryError> {
    // All writes migrate accepted older vaults to the current schema.
    header.schema_version = SCHEMA_VERSION;
    // The integrity flag must reflect whether a MAC trailer is actually written
    // so the reader knows whether to require one.
    if mac_key.is_some() {
        header.flags |= FLAG_INTEGRITY;
    } else {
        header.flags &= !FLAG_INTEGRITY;
    }

    // Serialise records first to measure the exact payload size.
    // Entries first, then attachments, then the single zero sentinel —
    // matches the partitioning logic in `reader::read_records`.
    let mut entry_buf: Vec<u8> = Vec::new();
    write_entries_no_sentinel(&mut entry_buf, entries)?;
    write_attachments(&mut entry_buf, attachments)?;
    entry_buf.extend_from_slice(&0u32.to_le_bytes()); // sentinel
    header.payload_size = u32::try_from(entry_buf.len())
        .map_err(|_| DiaryError::Vault("payload section length exceeds u32 maximum".to_string()))?;

    // Generate cryptographically random padding (512–4 096 bytes).
    let mut rng = rand::thread_rng();
    let pad_size: usize = rng.gen_range(512..=4096);
    let mut padding = vec![0u8; pad_size];
    rng.fill(padding.as_mut_slice());
    padding.extend_from_slice(extra_padding);

    // Assemble the authenticated region: header || records || padding. The
    // vault MAC (when present) is computed over exactly these bytes, so a flip
    // of any metadata byte, a dropped/reordered record, or a truncated tail is
    // detected on the next unlock.
    let mut body: Vec<u8> = Vec::with_capacity(entry_buf.len() + pad_size + 256);
    write_header(&mut body, &header)?;
    body.extend_from_slice(&entry_buf);
    body.extend_from_slice(&padding);

    let mac = match mac_key {
        Some(key) => Some(hmac_util::compute(key, &body)?),
        None => None,
    };

    write_atomic(path, |file| {
        file.write_all(&body)?;
        if let Some(mac) = mac.as_ref() {
            file.write_all(mac)?;
        }
        file.sync_all()?;
        Ok(())
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{
        AttachmentRecord, EntryRecord, VaultHeader, MAGIC, MAX_FIELD_SIZE, RECORD_TYPE_ATTACHMENT,
        RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE,
    };

    fn assert_no_owned_temps(path: &Path) {
        let prefix = format!("{}.tmp.", path.file_name().unwrap().to_string_lossy());
        for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
            assert!(!entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&prefix));
        }
    }

    #[test]
    fn predictable_existing_temp_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let old_temp = dir.path().join("vault.pqd.tmp");
        std::fs::write(&old_temp, b"unrelated file").unwrap();
        write_vault(&path, VaultHeader::new(), &[]).unwrap();
        assert_eq!(std::fs::read(&old_temp).unwrap(), b"unrelated file");
        crate::vault::reader::read_vault(&path).unwrap();
        assert_no_owned_temps(&path);
    }

    #[cfg(unix)]
    #[test]
    fn predictable_symlink_cannot_modify_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let target = dir.path().join("unrelated");
        let link = dir.path().join("vault.pqd.tmp");
        std::fs::write(&target, b"synthetic unrelated data").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_vault(&path, VaultHeader::new(), &[]).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"synthetic unrelated data");
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        crate::vault::reader::read_vault(&path).unwrap();
        assert_no_owned_temps(&path);
    }

    #[test]
    fn exclusive_collision_preserves_existing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd.tmp.collision");
        std::fs::write(&path, b"existing file").unwrap();
        assert!(VaultTemp::create(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing file");
        let directory = dir.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(VaultTemp::create(directory.clone()).is_err());
        assert!(directory.is_dir());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(VaultTemp::create(link.clone()).is_err());
            assert_eq!(std::fs::read_link(&link).unwrap(), path);
            assert_eq!(std::fs::read(&path).unwrap(), b"existing file");
            let dangling = dir.path().join("dangling");
            std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
            assert!(VaultTemp::create(dangling.clone()).is_err());
            assert!(std::fs::symlink_metadata(dangling).unwrap().is_symlink());
            assert!(!dir.path().join("absent").exists());
        }
    }

    #[test]
    fn partial_write_and_sync_errors_preserve_readable_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let key = [0x42; 32];
        let before = existing_vault(&path, &key);
        let old_temp = dir.path().join("vault.pqd.tmp");
        std::fs::write(&old_temp, b"unowned").unwrap();
        for stage in ["partial write", "sync"] {
            let result = write_atomic(&path, |file| {
                file.write_all(b"synthetic partial new vault")?;
                if stage == "sync" {
                    file.flush()?;
                }
                Err(std::io::Error::other(format!("injected {stage} failure")).into())
            });
            assert!(matches!(result, Err(DiaryError::Io(_))));
            assert_preserved_vault(&path, &before, &key);
            assert_eq!(std::fs::read(&old_temp).unwrap(), b"unowned");
        }
    }

    #[test]
    fn unwinding_closes_and_removes_owned_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let key = [0x42; 32];
        let before = existing_vault(&path, &key);
        let result = std::panic::catch_unwind(|| {
            let _ = write_atomic(&path, |file| {
                file.write_all(b"synthetic partial vault")?;
                panic!("injected unwinding failure");
            });
        });
        assert!(result.is_err());
        assert_preserved_vault(&path, &before, &key);
    }

    #[test]
    fn rename_failure_preserves_destination_and_removes_owned_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), b"original").unwrap();
        assert!(write_vault(&path, VaultHeader::new(), &[]).is_err());
        assert_eq!(std::fs::read(path.join("keep")).unwrap(), b"original");
        assert_no_owned_temps(&path);
    }

    #[cfg(unix)]
    #[test]
    fn temp_is_owner_only_before_writing_and_after_rename() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        write_atomic(&path, |file| {
            assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
            assert_eq!(file.metadata()?.len(), 0);
            file.write_all(b"synthetic")?;
            file.sync_all()?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_no_owned_temps(&path);
    }

    /// Build a minimal [`EntryRecord`] with known content for testing.
    fn make_test_entry() -> EntryRecord {
        EntryRecord {
            record_type: RECORD_TYPE_ENTRY,
            uuid: [0xABu8; 16],
            created_at: 1_000_000,
            updated_at: 2_000_000,
            iv: [0x01u8; 12],
            ciphertext: vec![0x10, 0x20, 0x30],
            signature: vec![0x40, 0x50],
            content_hmac: [0x7Fu8; 32],
            legacy_flag: 0x00,
            legacy_key_block: vec![],
            attachment_count: 0,
            attachment_offset: 0,
            padding: vec![],
        }
    }

    fn make_test_attachment() -> AttachmentRecord {
        AttachmentRecord {
            record_type: RECORD_TYPE_ATTACHMENT,
            uuid: [0xCDu8; 16],
            iv: [0x02u8; 12],
            ciphertext: vec![0xAA, 0xBB],
            signature: vec![0xCC],
            content_hmac: [0x7Eu8; 32],
            legacy_flag: 0x00,
            legacy_key_block: vec![],
            padding: vec![],
        }
    }

    fn assert_preserved_vault(path: &Path, before: &[u8], key: &[u8; 32]) {
        assert_eq!(std::fs::read(path).unwrap(), before);
        let (_, entries, attachments) =
            crate::vault::reader::read_vault_with_attachments(path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uuid, make_test_entry().uuid);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].uuid, make_test_attachment().uuid);
        crate::vault::reader::verify_vault_integrity(path, key).unwrap();
        assert_no_owned_temps(path);
    }

    fn existing_vault(path: &Path, key: &[u8; 32]) -> Vec<u8> {
        write_vault_with_attachments_authenticated(
            path,
            VaultHeader::new(),
            &[make_test_entry()],
            &[make_test_attachment()],
            key,
        )
        .unwrap();
        std::fs::read(path).unwrap()
    }

    #[test]
    fn oversized_entries_cannot_replace_readable_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let key = [0x42; 32];
        let before = existing_vault(&path, &key);

        for record_type in [RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE] {
            let mut oversized = make_test_entry();
            oversized.record_type = record_type;
            // The ciphertext alone fits; the complete record does not.
            oversized.ciphertext = vec![0xA5; MAX_FIELD_SIZE];
            let result = write_vault_authenticated(&path, VaultHeader::new(), &[oversized], &key);
            assert!(matches!(result, Err(DiaryError::Vault(_))), "{result:?}");
            assert_preserved_vault(&path, &before, &key);
        }
    }

    #[test]
    fn oversized_attachment_cannot_replace_readable_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let key = [0x42; 32];
        let before = existing_vault(&path, &key);
        let mut oversized = make_test_attachment();
        oversized.ciphertext = vec![0xA5; MAX_FIELD_SIZE];
        let result = write_vault_with_attachments_authenticated(
            &path,
            VaultHeader::new(),
            &[],
            &[oversized],
            &key,
        );
        assert!(matches!(result, Err(DiaryError::Vault(_))), "{result:?}");
        assert_preserved_vault(&path, &before, &key);
    }

    #[test]
    fn oversized_header_fields_cannot_mutate_sink_or_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let key = [0x42; 32];
        let before = existing_vault(&path, &key);
        for kem in [true, false] {
            let mut header = VaultHeader::new();
            let field = if kem {
                &mut header.kem_encrypted_sk
            } else {
                &mut header.dsa_encrypted_sk
            };
            *field = vec![0xA5; MAX_FIELD_SIZE + 1];
            let mut sink = b"unchanged".to_vec();
            let result = write_header(&mut sink, &header);
            assert!(matches!(result, Err(DiaryError::Vault(_))), "{result:?}");
            assert_eq!(sink, b"unchanged");
            let result = write_vault_authenticated(&path, header, &[], &key);
            assert!(matches!(result, Err(DiaryError::Vault(_))), "{result:?}");
            assert_preserved_vault(&path, &before, &key);
        }
    }

    #[test]
    fn invalid_later_record_cannot_mutate_sink() {
        let mut entry = make_test_entry();
        entry.padding = vec![0; 256];
        let mut sink = b"unchanged".to_vec();
        assert!(write_entries(&mut sink, &[make_test_entry(), entry]).is_err());
        assert_eq!(sink, b"unchanged");

        let mut attachment = make_test_attachment();
        attachment.padding = vec![0; 256];
        assert!(write_attachments(&mut sink, &[make_test_attachment(), attachment]).is_err());
        assert_eq!(sink, b"unchanged");
    }

    #[test]
    fn reader_size_boundaries_roundtrip() {
        use crate::vault::reader::{read_entries, read_header, read_records};

        for record_type in [RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE] {
            let mut entry = make_test_entry();
            entry.record_type = record_type;
            entry.legacy_key_block = vec![0x17; 13];
            entry.padding = vec![0x28; 255];
            let mut initial = Vec::new();
            write_entries(&mut initial, std::slice::from_ref(&entry)).unwrap();
            let overhead = initial.len() - 8 - entry.ciphertext.len();
            entry.ciphertext = vec![0xA5; MAX_FIELD_SIZE - overhead];
            let mut bytes = Vec::new();
            write_entries(&mut bytes, std::slice::from_ref(&entry)).unwrap();
            assert_eq!(bytes.len(), MAX_FIELD_SIZE + 8);
            let records = read_entries(&mut bytes.as_slice()).unwrap();
            assert_eq!(records[0].record_type, record_type);
            assert_eq!(records[0].ciphertext, entry.ciphertext);
            assert_eq!(records[0].signature, entry.signature);
            assert_eq!(records[0].legacy_key_block, entry.legacy_key_block);
            assert_eq!(records[0].padding, entry.padding);
            drop(records);
            drop(bytes);
            entry.ciphertext.push(0);
            let mut sink = Vec::new();
            assert!(write_entries(&mut sink, &[make_test_entry(), entry]).is_err());
            assert!(sink.is_empty());
        }

        let mut attachment = make_test_attachment();
        attachment.legacy_key_block = vec![0x17; 13];
        attachment.padding = vec![0x28; 255];
        let mut initial = Vec::new();
        write_attachments(&mut initial, std::slice::from_ref(&attachment)).unwrap();
        let overhead = initial.len() - 4 - attachment.ciphertext.len();
        attachment.ciphertext = vec![0xA5; MAX_FIELD_SIZE - overhead];
        let mut bytes = Vec::new();
        write_attachments(&mut bytes, std::slice::from_ref(&attachment)).unwrap();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(bytes.len(), MAX_FIELD_SIZE + 8);
        let (_, records) = read_records(&mut bytes.as_slice()).unwrap();
        assert_eq!(records[0].ciphertext, attachment.ciphertext);
        assert_eq!(records[0].signature, attachment.signature);
        assert_eq!(records[0].legacy_key_block, attachment.legacy_key_block);
        assert_eq!(records[0].padding, attachment.padding);
        drop(records);
        drop(bytes);
        attachment.ciphertext.push(0);
        let mut sink = Vec::new();
        assert!(write_attachments(&mut sink, &[make_test_attachment(), attachment]).is_err());
        assert!(sink.is_empty());

        for kem in [true, false] {
            let mut header = VaultHeader::new();
            let field = if kem {
                &mut header.kem_encrypted_sk
            } else {
                &mut header.dsa_encrypted_sk
            };
            *field = vec![0xA5; MAX_FIELD_SIZE];
            let mut bytes = Vec::new();
            write_header(&mut bytes, &header).unwrap();
            let restored = read_header(&mut bytes.as_slice()).unwrap();
            assert_eq!(restored.kem_encrypted_sk, header.kem_encrypted_sk);
            assert_eq!(restored.dsa_encrypted_sk, header.dsa_encrypted_sk);
        }
    }

    #[test]
    fn combined_vault_payload_may_exceed_single_record_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let mut entry = make_test_entry();
        entry.ciphertext = vec![0xA5; MAX_FIELD_SIZE / 2];
        let mut attachment = make_test_attachment();
        attachment.ciphertext = vec![0xB6; MAX_FIELD_SIZE / 2];
        write_vault_with_attachments(&path, VaultHeader::new(), &[entry], &[attachment]).unwrap();
        let (header, entries, attachments) =
            crate::vault::reader::read_vault_with_attachments(&path).unwrap();
        assert!(header.payload_size as usize > MAX_FIELD_SIZE);
        assert_eq!(entries[0].ciphertext.len(), MAX_FIELD_SIZE / 2);
        assert_eq!(attachments[0].ciphertext.len(), MAX_FIELD_SIZE / 2);
    }

    #[test]
    fn authenticated_snapshot_writer_preserves_records_and_extra_padding() {
        use crate::vault::format::VAULT_MAC_LEN;
        use crate::vault::reader::{read_vault_with_attachments, verify_vault_integrity};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        // The destination may differ from the snapshot already validated by
        // the caller. It must not supply any unverified attachment records.
        std::fs::write(&path, b"replaced after snapshot").unwrap();
        let entry = make_test_entry();
        let attachment = make_test_attachment();
        let extra = [0x5A; 127];
        let mac_key = [0x42; 32];
        write_vault_with_attachments_authenticated_with_extra_padding(
            &path,
            VaultHeader::new(),
            std::slice::from_ref(&entry),
            std::slice::from_ref(&attachment),
            &mac_key,
            &extra,
        )
        .unwrap();

        verify_vault_integrity(&path, &mac_key).unwrap();
        let (_, entries, attachments) = read_vault_with_attachments(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ciphertext, entry.ciphertext);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].ciphertext, attachment.ciphertext);
        let bytes = std::fs::read(path).unwrap();
        let body_len = bytes.len() - VAULT_MAC_LEN;
        assert_eq!(&bytes[body_len - extra.len()..body_len], &extra);
    }

    /// TC-021-01: write_header produces bytes whose first 8 bytes equal MAGIC.
    ///
    /// Given a default VaultHeader, when write_header writes it into a Vec<u8>,
    /// then the first 8 bytes of that buffer must equal b"PQDIARY\0".
    #[test]
    fn test_write_header_magic() {
        let header = VaultHeader::new();
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &header).expect("write_header must not fail");

        assert_eq!(&buf[..8], MAGIC.as_ref(), "first 8 bytes must equal MAGIC");
    }

    /// TC-021-02: payload_size field in the written bytes is accurate (LE u32).
    ///
    /// Given a VaultHeader and one entry, when write_vault writes to a temp file,
    /// then bytes [12..16] of the file must equal the actual entry-section size
    /// as a little-endian u32.
    #[test]
    fn test_write_vault_payload_size_accurate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");

        let entry = make_test_entry();
        write_vault(&path, VaultHeader::new(), &[entry]).expect("write_vault must not fail");

        let bytes = std::fs::read(&path).expect("read file");

        // payload_size is at header offset 12..16
        let payload_size = u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes"));

        // Independently compute the expected entry-section size.
        let mut expected_entry_buf: Vec<u8> = Vec::new();
        write_entries(&mut expected_entry_buf, &[make_test_entry()])
            .expect("write_entries must not fail");

        assert_eq!(
            payload_size,
            expected_entry_buf.len() as u32,
            "payload_size field must match actual entry-section byte count"
        );
    }

    /// TC-021-03: write_vault appends 512–4096 bytes of random padding.
    ///
    /// Given an empty vault (no entries, default header), when write_vault
    /// writes to a temp file, then (file_size - non_padding_size) must be
    /// in the range [512, 4096].
    #[test]
    fn test_write_vault_padding_size_in_range() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault_pad.pqd");

        write_vault(&path, VaultHeader::new(), &[]).expect("write_vault must not fail");

        let file_size = std::fs::metadata(&path).expect("metadata").len() as usize;

        // Compute the non-padding size by serialising header and entries independently.
        let mut entry_buf: Vec<u8> = Vec::new();
        write_entries(&mut entry_buf, &[]).expect("write_entries");
        let payload_size = entry_buf.len() as u32;

        let mut test_header = VaultHeader::new();
        test_header.payload_size = payload_size;
        let mut header_buf: Vec<u8> = Vec::new();
        write_header(&mut header_buf, &test_header).expect("write_header");

        let non_padding = header_buf.len() + entry_buf.len();
        let padding = file_size - non_padding;

        assert!(
            padding >= 512,
            "padding must be >= 512 bytes, got {}",
            padding
        );
        assert!(
            padding <= 4096,
            "padding must be <= 4096 bytes, got {}",
            padding
        );
    }

    // -----------------------------------------------------------------------
    // TASK-0053 test cases
    // -----------------------------------------------------------------------

    /// TC-A04-01: writing a normal EntryRecord via write_entries succeeds.
    ///
    /// Given a valid EntryRecord with all fields within acceptable limits,
    /// when write_entries is called, it must return Ok(()).
    #[test]
    fn test_tc_a04_01_normal_record_write_succeeds() {
        let entry = make_test_entry();
        let mut buf: Vec<u8> = Vec::new();
        let result = write_entries(&mut buf, &[entry]);
        assert!(
            result.is_ok(),
            "write_entries must succeed for normal record"
        );
    }

    /// TC-A04-02: padding field ≥ 256 bytes → DiaryError::Vault.
    ///
    /// Given an EntryRecord whose padding Vec has 256 elements (one beyond the
    /// u8 maximum of 255), when write_entries is called, then DiaryError::Vault
    /// must be returned.
    #[test]
    fn test_tc_a04_02_padding_too_large_returns_vault_error() {
        let mut entry = make_test_entry();
        entry.padding = vec![0u8; 256]; // exceeds u8::MAX (255)

        let mut buf: Vec<u8> = Vec::new();
        let result = write_entries(&mut buf, &[entry]);

        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for padding >= 256 bytes, got {:?}",
            result
        );
    }

    /// TC-A05-01: no temporary file exists after a successful write_vault call.
    ///
    /// Given a valid vault path, when write_vault succeeds, then the temporary
    /// file (`<name>.tmp.<uuid>`) must not exist in the same directory.
    #[test]
    fn test_tc_a05_01_no_temp_file_after_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");

        write_vault(&path, VaultHeader::new(), &[]).expect("write_vault must not fail");

        assert_no_owned_temps(&path);
        assert!(path.exists(), "vault.pqd must exist after write_vault");
    }

    /// TC-A05-02: vault written by write_vault is readable by read_vault.
    ///
    /// Given a VaultHeader and one EntryRecord, when write_vault writes them
    /// to a file and read_vault reads them back, the entry count must be 1.
    #[test]
    fn test_tc_a05_02_vault_readable_after_atomic_write() {
        use crate::vault::reader::read_vault;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");

        let entry = make_test_entry();
        write_vault(&path, VaultHeader::new(), &[entry]).expect("write_vault must not fail");

        let (_, entries) = read_vault(&path).expect("read_vault must not fail");
        assert_eq!(
            entries.len(),
            1,
            "must read back 1 entry after atomic write"
        );
        assert_eq!(entries[0].uuid, [0xABu8; 16]);
    }

    /// TC-S13-W01: any write migrates the header to the current schema version.
    #[test]
    fn tc_s13_w01_write_stamps_current_schema() {
        use crate::vault::reader::read_header;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");
        let mut header = VaultHeader::new();
        header.schema_version = 0x04;

        write_vault_with_attachments(&path, header, &[], &[make_test_attachment()])
            .expect("write_vault_with_attachments");

        let mut file = std::fs::File::open(&path).expect("open vault");
        let parsed = read_header(&mut file).expect("read_header");
        assert_eq!(parsed.schema_version, crate::vault::format::SCHEMA_VERSION);
    }
}
