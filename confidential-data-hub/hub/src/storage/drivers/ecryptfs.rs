use std::path::Path;
use std::ffi::CString;
use anyhow::Context;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use sha2::{Sha512, Digest};
use tracing::{debug, info, error};
use zeroize::Zeroizing;
use kms::{Annotations, ProviderSettings};
use crate::secret;
use crate::storage::volume_type::blockdevice::error::BlockDeviceError;

const ECRYPTFS_FS_NAME: &str = "ecryptfs";
const ECRYPTFS_DEFAULT_SALT: [u8; 8] = [0x00; 8];
const ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS: u32 = 65536;
// Keyring constants - try session keyring first, as that's what ecryptfs searches
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;

mod defaults {
    pub const CIPHER: &str = "aes";
    pub const KEY_BYTES: usize = 32;
    pub const ENABLE_PASSTHROUGH: &str = "false";
    pub const ENABLE_FILENAME_CRYPTO: &str = "false";
    pub const UNLINK_SIGS: &str = "true";

    pub fn cipher() -> String { CIPHER.into() }
    pub fn key_bytes() -> String { KEY_BYTES.to_string() }
    pub fn enable_passthrough() -> String { ENABLE_PASSTHROUGH.into() }
    pub fn enable_filename_crypto() -> String { ENABLE_FILENAME_CRYPTO.into() }
    pub fn unlink_sigs() -> String { UNLINK_SIGS.into() }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EcryptfsMountParameters {
    /// Passphrase URI (e.g., "kbs://...") - required for key derivation
    passphrase: Option<String>,
    /// Optional separate passphrase for filename encryption key.
    /// If not provided and enable_filename_crypto is true, uses passphrase.
    fnek_passphrase: Option<String>,
    #[serde(default = "defaults::cipher")]
    cipher: String,
    #[serde(default = "defaults::key_bytes")]
    key_bytes: String,
    #[serde(default = "defaults::enable_passthrough")]
    enable_passthrough: String,
    #[serde(default = "defaults::enable_filename_crypto")]
    enable_filename_crypto: String,
    #[serde(default = "defaults::unlink_sigs")]
    unlink_sigs: String,
}

impl EcryptfsMountParameters {
    /// Do the mount operation for the LUKS2 device.
    /// Returns the header path if the source type is empty.
    pub async fn do_mount(
        self,
        source_path: &str,
        mount_point: &str,
    ) -> anyhow::Result<Option<String>> {
        self.validate()?;

        let parameters = self.build_parameters().await;

        // create directory for mount if it does not exist
        if !Path::new(&mount_point).exists() {
            tokio::fs::create_dir_all(&mount_point).await?;
            // #TODO: add umount mechanism
            // self.temp_paths.push(mount_point.to_string());
        }

        info!(
            "mounting ecryptfs to mount point: {}",
            mount_point
        );
        debug!(
            "ecryptfs options: {}",
            parameters
        );
        mount::<_, _, str, _>(
            Some(source_path),
            mount_point,
            Some(ECRYPTFS_FS_NAME),
            MsFlags::MS_NOATIME,
            Some(&parameters[..]),
        )
            .with_context(|| {
                format!(
                    "Failed to mount ecryptfs from {} to mount point {}",
                    source_path, mount_point
                )
            })?;
        Ok("".to_string().into())
    }

    async fn build_parameters(&self) -> String {
        let mut args = vec![];

        args.push(format!("ecryptfs_cipher={}", self.cipher));
        let key_bytes: usize = self.key_bytes.parse().unwrap_or(defaults::KEY_BYTES);
        args.push(format!("ecryptfs_key_bytes={}", key_bytes));
        if parse_string_boolean_to_bool(&self.enable_passthrough) {
            args.push("ecryptfs_passthrough".to_string());
        }
        // Note: filename encryption is enabled implicitly when ecryptfs_fnek_sig is provided
        if parse_string_boolean_to_bool(&self.unlink_sigs) {
            args.push("ecryptfs_unlink_sigs".to_string());
        }

        let filename_crypto_enabled = parse_string_boolean_to_bool(&self.enable_filename_crypto);

        // Derive key from passphrase and add to kernel keyring
        let computed_sig = if let Some(ref passphrase_uri) = self.passphrase {
            match get_plaintext_key(passphrase_uri).await {
                Ok(passphrase_bytes) => {
                    let passphrase = String::from_utf8(passphrase_bytes.to_vec())
                        .unwrap_or_default();
                    match add_key_to_keyring(passphrase.trim().as_bytes(), key_bytes) {
                        Ok(sig) => Some(sig),
                        Err(e) => {
                            error!("Failed to add key to keyring: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("Error getting passphrase: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Derive fnek key from fnek_passphrase (or passphrase if not provided)
        let computed_fnek_sig = if filename_crypto_enabled {
            // Use fnek_passphrase if provided, otherwise fall back to passphrase
            let fnek_uri = self.fnek_passphrase.as_ref().or(self.passphrase.as_ref());
            
            if let Some(uri) = fnek_uri {
                match get_plaintext_key(uri).await {
                    Ok(passphrase_bytes) => {
                        let passphrase = String::from_utf8(passphrase_bytes.to_vec())
                            .unwrap_or_default();
                        match add_key_to_keyring(passphrase.trim().as_bytes(), key_bytes) {
                            Ok(sig) => Some(sig),
                            Err(e) => {
                                error!("Failed to add fnek key to keyring: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error getting fnek passphrase: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Add ecryptfs_sig
        if let Some(ref sig) = computed_sig {
            args.push(format!("ecryptfs_sig={}", sig));
        }

        // Add ecryptfs_fnek_sig if filename crypto is enabled
        if let Some(ref fnek_sig) = computed_fnek_sig {
            args.push(format!("ecryptfs_fnek_sig={}", fnek_sig));
        }

        args.join(",").to_string()
    }

    /// Validate parameters before mounting.
    fn validate(&self) -> anyhow::Result<()> {
        if self.passphrase.is_none() {
            anyhow::bail!("passphrase must be provided");
        }
        Ok(())
    }
}

fn parse_string_boolean_to_bool(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "true" | "1" | "yes" | "y" | "on"
    )
}

async fn get_plaintext_key(key_uri: &str) -> crate::storage::volume_type::blockdevice::error::Result<Zeroizing<Vec<u8>>> {
    let key = if key_uri.starts_with("sealed.") {
        debug!("get key with sealed secret");
        secret::unseal_secret(key_uri.as_bytes())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("kbs://") {
        debug!("get key from kbs");
        kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
            .get_secret(key_uri, &Annotations::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("file://") {
        debug!("get key from local path");
        let path = key_uri.trim_start_matches("file://");
        tokio::fs::read(path).await?
    } else {
        return Err(BlockDeviceError::IllegalKeyScheme);
    };

    Ok(Zeroizing::new(key))
}

// eCryptfs auth_tok constants
const ECRYPTFS_VERSION: u16 = 0x0004;
const ECRYPTFS_PASSWORD: u16 = 0x0000;
const ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES: usize = 512;
const ECRYPTFS_MAX_KEY_BYTES: usize = 64;
const ECRYPTFS_SALT_SIZE: usize = 8;
const ECRYPTFS_PASSWORD_SIG_SIZE: usize = 17; // 16 hex chars + null terminator
const ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET: u32 = 0x02;
// session_key struct size: flags(4) + encrypted_key_size(4) + decrypted_key_size(4) + encrypted_key(512) + decrypted_key(64) = 588
const ECRYPTFS_SESSION_KEY_SIZE: usize = 4 + 4 + 4 + ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES + ECRYPTFS_MAX_KEY_BYTES;

// TODO: Verify if password_bytes (passphrase length) and hash_algo (10=SHA512)
// should be set in EcryptfsPassword. Currently works with 0s since kernel uses
// pre-derived session_key_encryption_key directly.

/// eCryptfs password structure - must match kernel layout exactly
#[repr(C)]
struct EcryptfsPassword {
    password_bytes: i32,
    hash_algo: i32,
    hash_iterations: i32,
    session_key_encryption_key_bytes: i32,
    flags: u32,
    session_key_encryption_key: [u8; ECRYPTFS_MAX_KEY_BYTES],
    signature: [u8; ECRYPTFS_PASSWORD_SIG_SIZE],
    salt: [u8; ECRYPTFS_SALT_SIZE],
}

/// eCryptfs auth_tok structure for password-based keys.
/// This must match the kernel's struct ecryptfs_auth_tok layout exactly.
#[repr(C, packed)]
struct EcryptfsAuthTok {
    version: u16,
    token_type: u16,
    flags: u32,
    // session_key struct - unused for passphrase auth, just padding for correct layout
    _session_key: [u8; ECRYPTFS_SESSION_KEY_SIZE],
    reserved: [u8; 32],
    password: EcryptfsPassword,
}

impl EcryptfsAuthTok {
    fn new(key: &[u8], sig: &str, salt: &[u8; 8]) -> Self {
        let mut auth_tok = EcryptfsAuthTok {
            version: ECRYPTFS_VERSION,
            token_type: ECRYPTFS_PASSWORD,
            flags: 0,
            _session_key: [0u8; ECRYPTFS_SESSION_KEY_SIZE],
            reserved: [0u8; 32],
            password: EcryptfsPassword {
                password_bytes: 0,
                hash_algo: 0,
                hash_iterations: ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS as i32,
                session_key_encryption_key_bytes: key.len() as i32,
                flags: ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET,
                session_key_encryption_key: [0u8; ECRYPTFS_MAX_KEY_BYTES],
                signature: [0u8; ECRYPTFS_PASSWORD_SIG_SIZE],
                salt: [0u8; ECRYPTFS_SALT_SIZE],
            },
        };

        // Copy signature (hex string) into password.signature
        let sig_bytes = sig.as_bytes();
        let copy_len = std::cmp::min(sig_bytes.len(), ECRYPTFS_PASSWORD_SIG_SIZE - 1);
        auth_tok.password.signature[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);

        // Copy salt
        auth_tok.password.salt.copy_from_slice(salt);

        // Copy derived key into session_key_encryption_key
        let key_copy_len = std::cmp::min(key.len(), ECRYPTFS_MAX_KEY_BYTES);
        auth_tok.password.session_key_encryption_key[..key_copy_len]
            .copy_from_slice(&key[..key_copy_len]);

        auth_tok
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

/// Derive ecryptfs key from passphrase using iterated SHA512 hash.
/// Returns the derived key and its signature (first 8 bytes hex-encoded).
fn derive_ecryptfs_key(passphrase: &[u8], key_bytes: usize) -> (Vec<u8>, String) {
    // Initial hash: passphrase + salt
    let mut data = Vec::with_capacity(passphrase.len() + ECRYPTFS_DEFAULT_SALT.len());
    data.extend_from_slice(passphrase);
    data.extend_from_slice(&ECRYPTFS_DEFAULT_SALT);

    // Iterate hash
    let mut hash = Sha512::digest(&data);
    for _ in 1..ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS {
        hash = Sha512::digest(&hash);
    }

    // Take first key_bytes as the key
    let key = hash[..key_bytes].to_vec();

    // Signature is first 8 bytes hex-encoded
    let sig = hex::encode(&key[..8]);

    (key, sig)
}

/// Add ecryptfs key to kernel keyring using add_key syscall.
/// Returns the signature of the added key.
fn add_key_to_keyring(passphrase: &[u8], key_bytes: usize) -> anyhow::Result<String> {
    let (key, sig) = derive_ecryptfs_key(passphrase, key_bytes);

    // Build the ecryptfs auth_tok structure
    let auth_tok = EcryptfsAuthTok::new(&key, &sig, &ECRYPTFS_DEFAULT_SALT);
    let payload = auth_tok.as_bytes();

    info!(
        "Adding ecryptfs key: sig={}, payload_size={}, key_bytes={}",
        sig, payload.len(), key_bytes
    );

    let key_type = CString::new("user").unwrap();
    // Description must be just the signature, no prefix
    let description = CString::new(sig.clone()).unwrap();

    // Try adding to session keyring first (what ecryptfs searches)
    let result = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr(),
            description.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            KEY_SPEC_SESSION_KEYRING,
        )
    };

    if result < 0 {
        let session_err = std::io::Error::last_os_error();
        info!("Session keyring failed: {}, trying user keyring", session_err);
        
        let result = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                key_type.as_ptr(),
                description.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                KEY_SPEC_USER_KEYRING,
            )
        };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("Failed to add key to keyring: {}", err);
        }
        info!("Added ecryptfs key to user keyring with sig: {}, key_id: {}", sig, result);
    } else {
        info!("Added ecryptfs key to session keyring with sig: {}, key_id: {}", sig, result);
    }

    Ok(sig)
}
