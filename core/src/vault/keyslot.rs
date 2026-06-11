//! S16 keyslot envelope primitives.
//!
//! A keyslot is one independent way to recover the same Master Data Key (MDK).
//! The MDK is never stored in plaintext on disk; it is wrapped as
//! `AES-256-GCM(slot_key, MDK)`. Password, password+keyfile, recipient, and
//! recovery slots differ only in how `slot_key` is derived.

use std::io::{self, Read};

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        aead,
        kdf::{self, Argon2Params},
        kem,
        mdk::MasterDataKey,
        SecureBuffer,
    },
    error::DiaryError,
    vault::format::MAX_FIELD_SIZE,
};

const PASSWORD_KEYFILE_INFO: &[u8] = b"pq-diary/keyslot/keyfile/v1";
const RECIPIENT_INFO: &[u8] = b"pq-diary/keyslot/recipient/v1";

/// Keyfile magic bytes (`PQDKEYF\0`).
pub const KEYFILE_MAGIC: &[u8; 8] = b"PQDKEYF\0";
/// Current keyfile version.
pub const KEYFILE_VERSION: u8 = 0x01;
/// Serialized keyfile length.
pub const KEYFILE_SIZE: usize = 111;

/// Keyslot type byte in the v0x07 keyslot section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyslotType {
    Password,
    PasswordKeyfile,
    Recipient,
    Recovery,
}

impl KeyslotType {
    fn to_u8(self) -> u8 {
        match self {
            Self::Password => 0x01,
            Self::PasswordKeyfile => 0x02,
            Self::Recipient => 0x03,
            Self::Recovery => 0x04,
        }
    }
}

impl TryFrom<u8> for KeyslotType {
    type Error = DiaryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Password),
            0x02 => Ok(Self::PasswordKeyfile),
            0x03 => Ok(Self::Recipient),
            0x04 => Ok(Self::Recovery),
            other => Err(DiaryError::Vault(format!(
                "unknown keyslot type 0x{other:02x}"
            ))),
        }
    }
}

/// KDF algorithm tag stored in each keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    None,
    Argon2id,
}

impl KdfAlgorithm {
    fn to_u8(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Argon2id => 0x01,
        }
    }
}

impl TryFrom<u8> for KdfAlgorithm {
    type Error = DiaryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Argon2id),
            other => Err(DiaryError::Vault(format!(
                "unknown keyslot KDF algorithm 0x{other:02x}"
            ))),
        }
    }
}

/// KEM algorithm tag stored in each keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    None,
    MlKem768,
    MlKem768Hqc,
}

impl KemAlgorithm {
    fn to_u8(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::MlKem768 => 0x01,
            Self::MlKem768Hqc => 0x02,
        }
    }
}

impl TryFrom<u8> for KemAlgorithm {
    type Error = DiaryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::MlKem768),
            0x02 => Ok(Self::MlKem768Hqc),
            other => Err(DiaryError::Vault(format!(
                "unknown keyslot KEM algorithm 0x{other:02x}"
            ))),
        }
    }
}

/// One serialized v0x07 keyslot record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyslot {
    pub slot_type: KeyslotType,
    pub slot_id: [u8; 16],
    pub kdf_algorithm: KdfAlgorithm,
    pub kdf_params: Argon2Params,
    pub salt: [u8; 32],
    pub kem_algorithm: KemAlgorithm,
    pub kem_ct: Vec<u8>,
    pub wrap_iv: [u8; aead::NONCE_SIZE],
    pub wrapped_mdk: Vec<u8>,
    pub label: String,
}

/// Generated password+keyfile slot plus the keyfile material that must be saved
/// outside the vault.
pub struct GeneratedKeyfileSlot {
    pub slot: Keyslot,
    pub keyfile: KeyfileMaterial,
    pub public_key: Vec<u8>,
}

/// ML-KEM keyfile payload.
pub struct KeyfileMaterial {
    decapsulation_key: SecureBuffer,
    public_key_hash: [u8; 32],
}

impl KeyfileMaterial {
    pub fn new(decapsulation_key: SecureBuffer, public_key_hash: [u8; 32]) -> Self {
        Self {
            decapsulation_key,
            public_key_hash,
        }
    }

    pub fn decapsulation_key(&self) -> &SecureBuffer {
        &self.decapsulation_key
    }

    pub fn public_key_hash(&self) -> &[u8; 32] {
        &self.public_key_hash
    }

    /// Serialize this keyfile as magic + version + seed + public-key hash + CRC32.
    pub fn serialize(&self) -> Result<Zeroizing<Vec<u8>>, DiaryError> {
        if self.decapsulation_key.len() != 64 {
            return Err(DiaryError::Crypto(format!(
                "invalid keyfile decapsulation key length: expected 64 bytes, got {}",
                self.decapsulation_key.len()
            )));
        }

        let mut out = Zeroizing::new(Vec::with_capacity(KEYFILE_SIZE));
        out.extend_from_slice(KEYFILE_MAGIC);
        out.push(KEYFILE_VERSION);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(self.decapsulation_key.as_ref());
        out.extend_from_slice(&self.public_key_hash);
        let crc = crc32_ieee(out.as_slice());
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }
}

impl Keyslot {
    /// Create a password-only keyslot.
    pub fn password(
        mdk: &MasterDataKey,
        password: &[u8],
        params: Argon2Params,
        label: impl Into<String>,
    ) -> Result<Self, DiaryError> {
        let slot_id = Uuid::new_v4().into_bytes();
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let slot_key = derive_password_slot_key(password, &salt, &params)?;
        let (wrapped_mdk, wrap_iv) = wrap_mdk(mdk, &slot_key)?;

        Ok(Self {
            slot_type: KeyslotType::Password,
            slot_id,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            kdf_params: params,
            salt,
            kem_algorithm: KemAlgorithm::None,
            kem_ct: Vec::new(),
            wrap_iv,
            wrapped_mdk,
            label: label.into(),
        })
    }

    /// Create a password+ML-KEM keyfile slot.
    pub fn password_keyfile(
        mdk: &MasterDataKey,
        password: &[u8],
        params: Argon2Params,
        label: impl Into<String>,
    ) -> Result<GeneratedKeyfileSlot, DiaryError> {
        let kem_kp = kem::keygen()?;
        let public_key_hash = public_key_hash(&kem_kp.encapsulation_key);
        let (kem_ct, shared_secret) = kem::encapsulate(&kem_kp.encapsulation_key)?;

        let slot_id = Uuid::new_v4().into_bytes();
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let slot_key =
            derive_keyfile_slot_key(password, &salt, &params, shared_secret.as_ref(), &slot_id)?;
        let (wrapped_mdk, wrap_iv) = wrap_mdk(mdk, &slot_key)?;

        Ok(GeneratedKeyfileSlot {
            slot: Self {
                slot_type: KeyslotType::PasswordKeyfile,
                slot_id,
                kdf_algorithm: KdfAlgorithm::Argon2id,
                kdf_params: params,
                salt,
                kem_algorithm: KemAlgorithm::MlKem768,
                kem_ct,
                wrap_iv,
                wrapped_mdk,
                label: label.into(),
            },
            keyfile: KeyfileMaterial::new(kem_kp.decapsulation_key, public_key_hash),
            public_key: kem_kp.encapsulation_key,
        })
    }

    /// Create a recipient slot for an ML-KEM-768 public encapsulation key.
    pub fn recipient(
        mdk: &MasterDataKey,
        recipient_public_key: &[u8],
        label: impl Into<String>,
    ) -> Result<Self, DiaryError> {
        let slot_id = Uuid::new_v4().into_bytes();
        let (kem_ct, shared_secret) = kem::encapsulate(recipient_public_key)?;
        let slot_key = derive_recipient_slot_key(shared_secret.as_ref(), &slot_id)?;
        let (wrapped_mdk, wrap_iv) = wrap_mdk(mdk, &slot_key)?;

        Ok(Self {
            slot_type: KeyslotType::Recipient,
            slot_id,
            kdf_algorithm: KdfAlgorithm::None,
            kdf_params: no_kdf_params(),
            salt: [0u8; 32],
            kem_algorithm: KemAlgorithm::MlKem768,
            kem_ct,
            wrap_iv,
            wrapped_mdk,
            label: label.into(),
        })
    }

    /// Create a recovery-code keyslot.
    pub fn recovery(
        mdk: &MasterDataKey,
        recovery_code: &[u8],
        params: Argon2Params,
        label: impl Into<String>,
    ) -> Result<Self, DiaryError> {
        let slot_id = Uuid::new_v4().into_bytes();
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let slot_key = derive_password_slot_key(recovery_code, &salt, &params)?;
        let (wrapped_mdk, wrap_iv) = wrap_mdk(mdk, &slot_key)?;

        Ok(Self {
            slot_type: KeyslotType::Recovery,
            slot_id,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            kdf_params: params,
            salt,
            kem_algorithm: KemAlgorithm::None,
            kem_ct: Vec::new(),
            wrap_iv,
            wrapped_mdk,
            label: label.into(),
        })
    }

    /// Recover the MDK from a password or recovery-code slot.
    pub fn unwrap_with_password(&self, password: &[u8]) -> Result<MasterDataKey, DiaryError> {
        if !matches!(
            self.slot_type,
            KeyslotType::Password | KeyslotType::Recovery
        ) || self.kdf_algorithm != KdfAlgorithm::Argon2id
        {
            return Err(DiaryError::Crypto("invalid credentials".into()));
        }

        let slot_key = derive_password_slot_key(password, &self.salt, &self.kdf_params)?;
        unwrap_mdk(self, &slot_key)
    }

    /// Recover the MDK from a password+keyfile slot.
    pub fn unwrap_with_password_and_keyfile(
        &self,
        password: &[u8],
        keyfile: &KeyfileMaterial,
    ) -> Result<MasterDataKey, DiaryError> {
        if self.slot_type != KeyslotType::PasswordKeyfile
            || self.kdf_algorithm != KdfAlgorithm::Argon2id
            || self.kem_algorithm != KemAlgorithm::MlKem768
        {
            return Err(DiaryError::Crypto("invalid credentials".into()));
        }

        let shared_secret = kem::decapsulate(keyfile.decapsulation_key(), &self.kem_ct)?;
        let slot_key = derive_keyfile_slot_key(
            password,
            &self.salt,
            &self.kdf_params,
            shared_secret.as_ref(),
            &self.slot_id,
        )?;
        unwrap_mdk(self, &slot_key)
    }

    /// Recover the MDK from a recipient slot and ML-KEM decapsulation key.
    pub fn unwrap_with_recipient_key(
        &self,
        decapsulation_key: &SecureBuffer,
    ) -> Result<MasterDataKey, DiaryError> {
        if self.slot_type != KeyslotType::Recipient || self.kem_algorithm != KemAlgorithm::MlKem768
        {
            return Err(DiaryError::Crypto("invalid credentials".into()));
        }

        let shared_secret = kem::decapsulate(decapsulation_key, &self.kem_ct)?;
        let slot_key = derive_recipient_slot_key(shared_secret.as_ref(), &self.slot_id)?;
        unwrap_mdk(self, &slot_key)
    }
}

/// Serialize a complete keyslot section.
pub fn serialize_keyslots(slots: &[Keyslot]) -> Result<Vec<u8>, DiaryError> {
    let mut out = Vec::new();
    for slot in slots {
        let payload = serialize_slot_payload(slot)?;
        let len = len_to_u32("keyslot length", payload.len())?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&payload);
    }
    Ok(out)
}

/// Parse a complete keyslot section.
pub fn parse_keyslots(section: &[u8]) -> Result<Vec<Keyslot>, DiaryError> {
    let mut slots = Vec::new();
    let mut cursor = io::Cursor::new(section);

    while (cursor.position() as usize) < section.len() {
        let slot_len = read_u32(&mut cursor)? as usize;
        check_field_size("slot_len", slot_len)?;

        let start = cursor.position() as usize;
        let end = start.checked_add(slot_len).ok_or_else(|| {
            DiaryError::Vault("keyslot length overflows section bounds".to_string())
        })?;
        if end > section.len() {
            return Err(DiaryError::Vault(
                "keyslot length exceeds remaining section bytes".into(),
            ));
        }

        slots.push(parse_slot_payload(&section[start..end])?);
        cursor.set_position(end as u64);
    }

    Ok(slots)
}

/// Try password/recovery slots in order and return the first recovered MDK.
pub fn recover_mdk_with_password(
    slots: &[Keyslot],
    password: &[u8],
) -> Result<MasterDataKey, DiaryError> {
    for slot in slots.iter().filter(|slot| {
        matches!(
            slot.slot_type,
            KeyslotType::Password | KeyslotType::Recovery
        )
    }) {
        match slot.unwrap_with_password(password) {
            Ok(mdk) => return Ok(mdk),
            Err(DiaryError::Crypto(_)) => continue,
            Err(DiaryError::Password(_)) => {
                return Err(DiaryError::Crypto("invalid credentials".into()));
            }
            Err(e) => return Err(e),
        }
    }
    Err(DiaryError::Crypto("invalid credentials".into()))
}

/// Try password+keyfile slots in order and return the first recovered MDK.
pub fn recover_mdk_with_password_and_keyfile(
    slots: &[Keyslot],
    password: &[u8],
    keyfile: &KeyfileMaterial,
) -> Result<MasterDataKey, DiaryError> {
    for slot in slots
        .iter()
        .filter(|slot| slot.slot_type == KeyslotType::PasswordKeyfile)
    {
        match slot.unwrap_with_password_and_keyfile(password, keyfile) {
            Ok(mdk) => return Ok(mdk),
            Err(DiaryError::Crypto(_)) => continue,
            Err(DiaryError::Password(_)) => {
                return Err(DiaryError::Crypto("invalid credentials".into()));
            }
            Err(e) => return Err(e),
        }
    }
    Err(DiaryError::Crypto("invalid credentials".into()))
}

/// Try recipient slots in order and return the first recovered MDK.
pub fn recover_mdk_with_recipient_key(
    slots: &[Keyslot],
    decapsulation_key: &SecureBuffer,
) -> Result<MasterDataKey, DiaryError> {
    for slot in slots
        .iter()
        .filter(|slot| slot.slot_type == KeyslotType::Recipient)
    {
        match slot.unwrap_with_recipient_key(decapsulation_key) {
            Ok(mdk) => return Ok(mdk),
            Err(DiaryError::Crypto(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(DiaryError::Crypto("invalid credentials".into()))
}

/// Parse serialized keyfile material.
pub fn parse_keyfile(bytes: &[u8]) -> Result<KeyfileMaterial, DiaryError> {
    if bytes.len() != KEYFILE_SIZE {
        return Err(DiaryError::Vault(format!(
            "invalid keyfile length: expected {KEYFILE_SIZE}, got {}",
            bytes.len()
        )));
    }
    if &bytes[0..8] != KEYFILE_MAGIC {
        return Err(DiaryError::Vault("invalid keyfile magic".into()));
    }
    if bytes[8] != KEYFILE_VERSION {
        return Err(DiaryError::Vault(format!(
            "unsupported keyfile version 0x{:02x}",
            bytes[8]
        )));
    }
    if bytes[9] != 0 || bytes[10] != 0 {
        return Err(DiaryError::Vault(
            "keyfile reserved bytes must be zero".into(),
        ));
    }

    let expected_crc = u32::from_le_bytes(
        bytes[107..111]
            .try_into()
            .map_err(|_| DiaryError::Vault("malformed keyfile CRC".into()))?,
    );
    let actual_crc = crc32_ieee(&bytes[..107]);
    if expected_crc != actual_crc {
        return Err(DiaryError::Vault("keyfile CRC verification failed".into()));
    }

    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&bytes[11..75]);

    let mut pk_hash = [0u8; 32];
    pk_hash.copy_from_slice(&bytes[75..107]);

    Ok(KeyfileMaterial::new(
        SecureBuffer::new(seed.to_vec()),
        pk_hash,
    ))
}

/// Compute SHA-256 over an ML-KEM public encapsulation key for keyfile metadata.
pub fn public_key_hash(public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().into()
}

fn no_kdf_params() -> Argon2Params {
    Argon2Params {
        memory_cost_kb: 0,
        time_cost: 0,
        parallelism: 0,
    }
}

fn serialize_slot_payload(slot: &Keyslot) -> Result<Vec<u8>, DiaryError> {
    check_field_size("kem_ct", slot.kem_ct.len())?;
    check_field_size("wrapped_mdk", slot.wrapped_mdk.len())?;
    check_field_size("label", slot.label.len())?;

    let kem_ct_len = len_to_u32("kem_ct length", slot.kem_ct.len())?;
    let wrapped_mdk_len = len_to_u32("wrapped_mdk length", slot.wrapped_mdk.len())?;
    let label_len = len_to_u32("label length", slot.label.len())?;

    let mut payload = Vec::new();
    payload.push(slot.slot_type.to_u8());
    payload.extend_from_slice(&slot.slot_id);
    payload.push(slot.kdf_algorithm.to_u8());
    payload.extend_from_slice(&slot.kdf_params.memory_cost_kb.to_le_bytes());
    payload.extend_from_slice(&slot.kdf_params.time_cost.to_le_bytes());
    payload.extend_from_slice(&slot.kdf_params.parallelism.to_le_bytes());
    payload.extend_from_slice(&slot.salt);
    payload.push(slot.kem_algorithm.to_u8());
    payload.extend_from_slice(&kem_ct_len.to_le_bytes());
    payload.extend_from_slice(&slot.kem_ct);
    payload.extend_from_slice(&slot.wrap_iv);
    payload.extend_from_slice(&wrapped_mdk_len.to_le_bytes());
    payload.extend_from_slice(&slot.wrapped_mdk);
    payload.extend_from_slice(&label_len.to_le_bytes());
    payload.extend_from_slice(slot.label.as_bytes());
    Ok(payload)
}

fn parse_slot_payload(payload: &[u8]) -> Result<Keyslot, DiaryError> {
    let mut cursor = io::Cursor::new(payload);

    let slot_type = KeyslotType::try_from(read_u8(&mut cursor)?)?;
    let slot_id = read_array::<16>(&mut cursor)?;
    let kdf_algorithm = KdfAlgorithm::try_from(read_u8(&mut cursor)?)?;
    let kdf_params = Argon2Params {
        memory_cost_kb: read_u32(&mut cursor)?,
        time_cost: read_u32(&mut cursor)?,
        parallelism: read_u32(&mut cursor)?,
    };
    let salt = read_array::<32>(&mut cursor)?;
    let kem_algorithm = KemAlgorithm::try_from(read_u8(&mut cursor)?)?;

    let kem_ct_len = read_u32(&mut cursor)? as usize;
    check_field_size("kem_ct_len", kem_ct_len)?;
    let kem_ct = read_vec(&mut cursor, kem_ct_len)?;

    let wrap_iv = read_array::<{ aead::NONCE_SIZE }>(&mut cursor)?;

    let wrapped_mdk_len = read_u32(&mut cursor)? as usize;
    check_field_size("wrapped_mdk_len", wrapped_mdk_len)?;
    let wrapped_mdk = read_vec(&mut cursor, wrapped_mdk_len)?;

    let label_len = read_u32(&mut cursor)? as usize;
    check_field_size("label_len", label_len)?;
    let label_bytes = read_vec(&mut cursor, label_len)?;
    let label = String::from_utf8(label_bytes)
        .map_err(|e| DiaryError::Vault(format!("keyslot label is not valid UTF-8: {e}")))?;

    if cursor.position() as usize != payload.len() {
        return Err(DiaryError::Vault(
            "keyslot payload has trailing bytes".into(),
        ));
    }

    Ok(Keyslot {
        slot_type,
        slot_id,
        kdf_algorithm,
        kdf_params,
        salt,
        kem_algorithm,
        kem_ct,
        wrap_iv,
        wrapped_mdk,
        label,
    })
}

fn derive_password_slot_key(
    password: &[u8],
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
    let derived = kdf::derive_key(password, salt, params)?;
    Ok(Zeroizing::new(*derived.as_ref()))
}

fn derive_keyfile_slot_key(
    password: &[u8],
    salt: &[u8; 32],
    params: &Argon2Params,
    shared_secret: &[u8],
    slot_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
    if shared_secret.len() != 32 {
        return Err(DiaryError::Crypto(format!(
            "ML-KEM shared secret must be 32 bytes, got {}",
            shared_secret.len()
        )));
    }

    let password_key = kdf::derive_key(password, salt, params)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(password_key.as_ref());
    ikm[32..].copy_from_slice(shared_secret);
    derive_hkdf_slot_key(ikm.as_ref(), PASSWORD_KEYFILE_INFO, slot_id)
}

fn derive_recipient_slot_key(
    shared_secret: &[u8],
    slot_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
    if shared_secret.len() != 32 {
        return Err(DiaryError::Crypto(format!(
            "ML-KEM shared secret must be 32 bytes, got {}",
            shared_secret.len()
        )));
    }
    derive_hkdf_slot_key(shared_secret, RECIPIENT_INFO, slot_id)
}

fn derive_hkdf_slot_key(
    ikm: &[u8],
    label: &[u8],
    slot_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
    let mut info = Vec::with_capacity(label.len() + slot_id.len());
    info.extend_from_slice(label);
    info.extend_from_slice(slot_id);
    crate::crypto::hkdf::derive_32(ikm, &info)
}

fn wrap_mdk(
    mdk: &MasterDataKey,
    slot_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; aead::NONCE_SIZE]), DiaryError> {
    aead::encrypt(slot_key, mdk.as_ref())
}

fn unwrap_mdk(slot: &Keyslot, slot_key: &[u8; 32]) -> Result<MasterDataKey, DiaryError> {
    let plaintext = match aead::decrypt(slot_key, slot.wrap_iv, &slot.wrapped_mdk) {
        Ok(plaintext) => plaintext,
        Err(DiaryError::Crypto(_)) => {
            return Err(DiaryError::Crypto("invalid credentials".into()));
        }
        Err(e) => return Err(e),
    };

    if plaintext.len() != 32 {
        return Err(DiaryError::Crypto(format!(
            "wrapped MDK decrypted to {} bytes, expected 32",
            plaintext.len()
        )));
    }

    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(plaintext.as_ref());
    Ok(MasterDataKey::from_bytes(*bytes))
}

fn read_u8(cursor: &mut io::Cursor<&[u8]>) -> Result<u8, DiaryError> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32(cursor: &mut io::Cursor<&[u8]>) -> Result<u32, DiaryError> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_array<const N: usize>(cursor: &mut io::Cursor<&[u8]>) -> Result<[u8; N], DiaryError> {
    let mut out = [0u8; N];
    cursor.read_exact(&mut out)?;
    Ok(out)
}

fn read_vec(cursor: &mut io::Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, DiaryError> {
    let mut out = vec![0u8; len];
    if len > 0 {
        cursor.read_exact(&mut out)?;
    }
    Ok(out)
}

fn check_field_size(field: &str, len: usize) -> Result<(), DiaryError> {
    if len > MAX_FIELD_SIZE {
        return Err(DiaryError::Vault(format!(
            "{field} {len} exceeds 16MiB maximum"
        )));
    }
    Ok(())
}

fn len_to_u32(field: &str, len: usize) -> Result<u32, DiaryError> {
    check_field_size(field, len)?;
    u32::try_from(len).map_err(|_| DiaryError::Vault(format!("{field} exceeds u32 maximum")))
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320u32 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn test_mdk() -> MasterDataKey {
        MasterDataKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn tc_s16_slot_01_multiple_slot_types_recover_same_mdk() {
        let mdk = test_mdk();
        let password_slot =
            Keyslot::password(&mdk, b"owner password", fast_params(), "owner").expect("password");
        let keyfile_slot =
            Keyslot::password_keyfile(&mdk, b"keyfile password", fast_params(), "2fa")
                .expect("keyfile");
        let recipient_kp = kem::keygen().expect("recipient keygen");
        let recipient_slot =
            Keyslot::recipient(&mdk, &recipient_kp.encapsulation_key, "heir").expect("recipient");
        let recovery_slot =
            Keyslot::recovery(&mdk, b"RECOVERY", fast_params(), "paper").expect("recovery");

        let slots = vec![
            password_slot,
            keyfile_slot.slot.clone(),
            recipient_slot,
            recovery_slot,
        ];

        let via_password =
            recover_mdk_with_password(&slots, b"owner password").expect("password recover");
        let via_keyfile = recover_mdk_with_password_and_keyfile(
            &slots,
            b"keyfile password",
            &keyfile_slot.keyfile,
        )
        .expect("keyfile recover");
        let via_recipient = recover_mdk_with_recipient_key(&slots, &recipient_kp.decapsulation_key)
            .expect("recipient recover");
        let via_recovery = recover_mdk_with_password(&slots, b"RECOVERY").expect("recovery");

        assert_eq!(via_password.as_ref(), mdk.as_ref());
        assert_eq!(via_keyfile.as_ref(), mdk.as_ref());
        assert_eq!(via_recipient.as_ref(), mdk.as_ref());
        assert_eq!(via_recovery.as_ref(), mdk.as_ref());
    }

    #[test]
    fn tc_s16_slot_02_password_slot_wraps_32_byte_mdk() {
        let mdk = test_mdk();
        let slot =
            Keyslot::password(&mdk, b"correct password", fast_params(), "owner").expect("slot");

        assert_eq!(slot.wrapped_mdk.len(), 48);
        let recovered = slot
            .unwrap_with_password(b"correct password")
            .expect("unwrap");
        assert_eq!(recovered.as_ref(), mdk.as_ref());

        let err = match slot.unwrap_with_password(b"wrong password") {
            Ok(_) => panic!("wrong password must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, DiaryError::Crypto(_)));
    }

    #[test]
    fn tc_s16_slot_03_keyslot_serialization_roundtrip() {
        let mdk = test_mdk();
        let slot = Keyslot::password(&mdk, b"pw", fast_params(), "laptop").expect("slot");

        let encoded = serialize_keyslots(std::slice::from_ref(&slot)).expect("serialize");
        let decoded = parse_keyslots(&encoded).expect("parse");

        assert_eq!(decoded, vec![slot]);
    }

    #[test]
    fn tc_s16_slot_04_rewrap_generates_distinct_wrap_iv() {
        let mdk = test_mdk();
        let slot_key = [0x7Fu8; 32];

        let (ct1, iv1) = wrap_mdk(&mdk, &slot_key).expect("wrap1");
        let (ct2, iv2) = wrap_mdk(&mdk, &slot_key).expect("wrap2");

        assert_eq!(ct1.len(), 48);
        assert_eq!(ct2.len(), 48);
        assert_ne!(iv1, iv2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn tc_s16_slot_e01_rejects_oversized_slot_len() {
        let oversized = (MAX_FIELD_SIZE as u32) + 1;
        let bytes = oversized.to_le_bytes();

        let result = parse_keyslots(&bytes);
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    #[test]
    fn tc_s16_slot_e02_rejects_unknown_slot_type() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1u32.to_le_bytes());
        encoded.push(0xFF);

        let result = parse_keyslots(&encoded);
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    #[test]
    fn tc_s16_pw_01_password_slot_recovers_mdk() {
        let mdk = test_mdk();
        let slot = Keyslot::password(&mdk, b"passphrase", fast_params(), "").expect("slot");

        let recovered = slot
            .unwrap_with_password(b"passphrase")
            .expect("recover mdk");

        assert_eq!(recovered.as_ref(), mdk.as_ref());
    }

    #[test]
    fn tc_s16_pw_02_wrong_password_fails() {
        let mdk = test_mdk();
        let slot = Keyslot::password(&mdk, b"right", fast_params(), "").expect("slot");

        let result = slot.unwrap_with_password(b"wrong");

        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    #[test]
    fn tc_s16_pw_03_salts_differ_for_distinct_slots() {
        let mdk = test_mdk();
        let slot1 = Keyslot::password(&mdk, b"same-password", fast_params(), "").expect("slot1");
        let slot2 = Keyslot::password(&mdk, b"same-password", fast_params(), "").expect("slot2");

        assert_ne!(slot1.salt, slot2.salt);
        assert_ne!(slot1.wrapped_mdk, slot2.wrapped_mdk);
    }

    #[test]
    fn tc_s16_kf_02_password_and_keyfile_recover_mdk() {
        let mdk = test_mdk();
        let generated =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "owner key").expect("keyfile");

        let recovered = generated
            .slot
            .unwrap_with_password_and_keyfile(b"pw", &generated.keyfile)
            .expect("recover");

        assert_eq!(recovered.as_ref(), mdk.as_ref());
    }

    #[test]
    fn tc_s16_kf_e01_missing_or_wrong_keyfile_fails() {
        let mdk = test_mdk();
        let generated =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "owner key").expect("keyfile");
        let other =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "other key").expect("other");

        let result = generated
            .slot
            .unwrap_with_password_and_keyfile(b"pw", &other.keyfile);

        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    #[test]
    fn tc_s16_kf_e02_wrong_password_with_keyfile_fails() {
        let mdk = test_mdk();
        let generated =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "owner key").expect("keyfile");

        let result = generated
            .slot
            .unwrap_with_password_and_keyfile(b"wrong", &generated.keyfile);

        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    #[test]
    fn tc_s16_kf_e03_keyfile_crc_corruption_is_rejected() {
        let mdk = test_mdk();
        let generated =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "owner key").expect("keyfile");
        let mut bytes = generated.keyfile.serialize().expect("serialize keyfile");
        bytes[20] ^= 0x80;

        let result = parse_keyfile(bytes.as_slice());

        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    #[test]
    fn keyfile_serialization_roundtrip_preserves_seed_and_hash() {
        let mdk = test_mdk();
        let generated =
            Keyslot::password_keyfile(&mdk, b"pw", fast_params(), "owner key").expect("keyfile");
        let bytes = generated.keyfile.serialize().expect("serialize keyfile");
        let parsed = parse_keyfile(bytes.as_slice()).expect("parse keyfile");

        assert_eq!(
            parsed.decapsulation_key().as_ref(),
            generated.keyfile.decapsulation_key().as_ref()
        );
        assert_eq!(
            parsed.public_key_hash(),
            generated.keyfile.public_key_hash()
        );
    }

    #[test]
    fn tc_s16_rcp_01_recipient_slot_recovers_mdk() {
        let mdk = test_mdk();
        let recipient_kp = kem::keygen().expect("recipient keygen");
        let slot = Keyslot::recipient(&mdk, &recipient_kp.encapsulation_key, "heir")
            .expect("recipient slot");

        let recovered = slot
            .unwrap_with_recipient_key(&recipient_kp.decapsulation_key)
            .expect("recipient recover");

        assert_eq!(recovered.as_ref(), mdk.as_ref());
    }

    #[test]
    fn tc_s16_rcp_e01_invalid_public_key_is_rejected() {
        let mdk = test_mdk();
        let result = Keyslot::recipient(&mdk, b"not a valid public key", "bad");

        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    #[test]
    fn tc_s16_rec_02_recovery_slot_recovers_mdk() {
        let mdk = test_mdk();
        let slot = Keyslot::recovery(&mdk, b"RECOVERY-CODE", fast_params(), "paper")
            .expect("recovery slot");

        let recovered = slot
            .unwrap_with_password(b"RECOVERY-CODE")
            .expect("recovery");

        assert_eq!(recovered.as_ref(), mdk.as_ref());
    }

    #[test]
    fn tc_s16_hqc_01_hybrid_kem_tag_is_parseable() {
        let mdk = test_mdk();
        let slot = Keyslot::password(&mdk, b"pw", fast_params(), "future").expect("slot");
        let mut encoded = serialize_keyslots(&[slot]).expect("serialize");

        let kem_alg_offset = 4 + 1 + 16 + 1 + 4 + 4 + 4 + 32;
        encoded[kem_alg_offset] = KemAlgorithm::MlKem768Hqc.to_u8();

        let decoded = parse_keyslots(&encoded).expect("parse");

        assert_eq!(decoded[0].kem_algorithm, KemAlgorithm::MlKem768Hqc);
    }
}
