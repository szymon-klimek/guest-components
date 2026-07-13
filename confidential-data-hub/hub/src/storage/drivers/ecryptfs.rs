use std::path::Path;
use std::ffi::CString;
use anyhow::Context;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use sha2::{Sha512, Digest};
use tracing::{debug, info, error};
use zeroize::Zeroizing;
use crate::storage::drivers::get_plaintext_key;

const ECRYPTFS_FS_NAME: &str = "ecryptfs";
const ECRYPTFS_DEFAULT_SALT: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];


const ECRYPTFS_DEFAULT_SALT_FNEK: [u8; 8] = *b"99887766";
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
        let fek_uri = self.passphrase.as_deref();
        let fnek_uri = if filename_crypto_enabled {
            self.fnek_passphrase.as_deref().or(self.passphrase.as_deref())
        } else {
            None
        };

        let mut fek_passphrase: Option<Zeroizing<Vec<u8>>> = None;
        if let Some(passphrase_uri) = fek_uri {
            match get_plaintext_key(passphrase_uri).await {
                Ok(raw_passphrase_bytes) => {
                    let passphrase = normalize_passphrase_bytes(raw_passphrase_bytes.as_slice());
                    let utf8_valid = std::str::from_utf8(passphrase.as_slice()).is_ok();
                    debug!(
                        "ecryptfs FEK: fetched passphrase raw_len={} normalized_len={} utf8_valid={} source_uri={}",
                        raw_passphrase_bytes.len(),
                        passphrase.len(),
                        utf8_valid,
                        passphrase_uri
                    );
                    if utf8_valid {
                        debug!(
                            "ecryptfs FEK passphrase plaintext: {}",
                            String::from_utf8_lossy(passphrase.as_slice())
                        );
                    } else {
                        debug!(
                            "ecryptfs FEK passphrase plaintext: <non-utf8-bytes>"
                        );
                    }
                    fek_passphrase = Some(passphrase);
                }
                Err(e) => {
                    error!("Error getting passphrase: {}", e);
                }
            }
        }

        // Derive key from passphrase and add to kernel keyring
        let computed_sig = if let Some(passphrase) = fek_passphrase.as_ref() {
            debug!(
                "ecryptfs FEK: deriving signature with salt={} key_bytes={} passphrase_len={}",
                hex::encode(ECRYPTFS_DEFAULT_SALT),
                key_bytes,
                passphrase.len(),
            );
            match add_key_to_keyring(
                passphrase.as_slice(),
                key_bytes,
                &ECRYPTFS_DEFAULT_SALT,
            ) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    error!("Failed to add key to keyring: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Derive fnek key from fnek_passphrase (or passphrase if not provided)
        let computed_fnek_sig = if filename_crypto_enabled {
            if let Some(uri) = fnek_uri {
                let reuse_fek_for_fnek = fek_uri == Some(uri);
                let mut fnek_passphrase: Option<Zeroizing<Vec<u8>>> = None;

                if reuse_fek_for_fnek {
                    debug!(
                        "ecryptfs FNEK: reusing FEK passphrase fetched from source_uri={} (no second KBS fetch)",
                        uri
                    );
                } else {
                    match get_plaintext_key(uri).await {
                        Ok(raw_passphrase_bytes) => {
                            let passphrase = normalize_passphrase_bytes(raw_passphrase_bytes.as_slice());
                            let utf8_valid = std::str::from_utf8(passphrase.as_slice()).is_ok();
                            debug!(
                                "ecryptfs FNEK: fetched passphrase raw_len={} normalized_len={} utf8_valid={} source_uri={}",
                                raw_passphrase_bytes.len(),
                                passphrase.len(),
                                utf8_valid,
                                uri
                            );
                            debug!(
                                "ecryptfs FNEK passphrase plaintext='{}' hex={} source_uri={}",
                                String::from_utf8_lossy(passphrase.as_slice()),
                                hex::encode(passphrase.as_slice()),
                                uri
                            );
                            fnek_passphrase = Some(passphrase);
                        }
                        Err(e) => {
                            error!("Error getting fnek passphrase: {}", e);
                        }
                    }
                }

                let passphrase = if reuse_fek_for_fnek {
                    fek_passphrase.as_ref()
                } else {
                    fnek_passphrase.as_ref()
                };

                if let Some(passphrase) = passphrase {
                    if reuse_fek_for_fnek {
                        debug!(
                            "ecryptfs FNEK passphrase plaintext='{}' hex={} source_uri={} (reused from FEK)",
                            String::from_utf8_lossy(passphrase.as_slice()),
                            hex::encode(passphrase.as_slice()),
                            uri
                        );
                    }
                    debug!(
                        "ecryptfs FNEK: deriving signature with salt={} key_bytes={} passphrase_len={} source_uri={} reused_from_fek={}",
                        hex::encode(ECRYPTFS_DEFAULT_SALT_FNEK),
                        key_bytes,
                        passphrase.len(),
                        uri,
                        reuse_fek_for_fnek
                    );
                    match add_key_to_keyring(
                        passphrase.as_slice(),
                        key_bytes,
                        &ECRYPTFS_DEFAULT_SALT_FNEK,
                    ) {
                        Ok(sig) => Some(sig),
                        Err(e) => {
                            error!("Failed to add fnek key to keyring: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Add ecryptfs_sig
        if let Some(ref sig) = computed_sig {
            debug!("ecryptfs FEK signature: {}", sig);
            args.push(format!("ecryptfs_sig={}", sig));
        }

        // Add ecryptfs_fnek_sig if filename crypto is enabled
        if let Some(ref fnek_sig) = computed_fnek_sig {
            debug!("ecryptfs FNEK signature: {}", fnek_sig);
            args.push(format!("ecryptfs_fnek_sig={}", fnek_sig));
        }

        debug!(
            "ecryptfs mount signatures summary: sig={:?} fnek_sig={:?} filename_crypto_enabled={}",
            computed_sig,
            computed_fnek_sig,
            filename_crypto_enabled
        );

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

fn normalize_passphrase_bytes(input: &[u8]) -> Zeroizing<Vec<u8>> {
    // Keep secret bytes unchanged except common line endings from file-based secrets.
    let mut output = input.to_vec();
    while matches!(output.last(), Some(b'\n' | b'\r')) {
        output.pop();
    }
    Zeroizing::new(output)
}

// eCryptfs auth_tok constants
const ECRYPTFS_VERSION: u16 = 0x0004;
const ECRYPTFS_PASSWORD: u16 = 0x0000;
const ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES: usize = 512;
const ECRYPTFS_MAX_KEY_BYTES: usize = 64;
const ECRYPTFS_SALT_SIZE: usize = 8;
const ECRYPTFS_PASSWORD_SIG_SIZE: usize = 17; // 16 hex chars + null terminator
const ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET: u32 = 0x02;
const PGP_DIGEST_ALGO_SHA512: i32 = 10;
// session_key struct size: flags(4) + encrypted_key_size(4) + decrypted_key_size(4) + encrypted_key(512) + decrypted_key(64) = 588
const ECRYPTFS_SESSION_KEY_SIZE: usize = 4 + 4 + 4 + ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES + ECRYPTFS_MAX_KEY_BYTES;

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
                hash_algo: PGP_DIGEST_ALGO_SHA512,
                hash_iterations: ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS as i32,
                session_key_encryption_key_bytes: ECRYPTFS_MAX_KEY_BYTES as i32,
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
/// Returns the derived key and its signature.
/// 
/// The signature is computed as hex(SHA512(derived_key)[0..8]), matching
/// the ecryptfs-utils implementation in generate_passphrase_sig().
fn derive_ecryptfs_key(passphrase: &[u8], salt: &[u8; 8]) -> (Vec<u8>, String) {
    debug!(
        "derive_ecryptfs_key: salt={} passphrase_len={} iterations={} fekek_len={}",
        hex::encode(salt),
        passphrase.len(),
        ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS,
        ECRYPTFS_MAX_KEY_BYTES
    );

    // Initial hash: salt + passphrase (salt comes FIRST, per ecryptfs-utils)
    let mut data = Vec::with_capacity(salt.len() + passphrase.len());
    data.extend_from_slice(salt);
    data.extend_from_slice(passphrase);

    // Iterate hash (65536 times total)
    let mut hash = Sha512::digest(&data);
    for _ in 1..ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS {
        hash = Sha512::digest(&hash);
    }

    // ecryptfs-utils derives a full FEKEK (64 bytes) and computes the
    // 16-hex-char signature from SHA512(FEKEK)[0..8].
    let key = hash[..ECRYPTFS_MAX_KEY_BYTES].to_vec();

    // Signature is SHA512(derived_key)[0..8] hex-encoded
    // This matches ecryptfs-utils: after deriving fekek, it does one more
    // hash and takes first ECRYPTFS_SIG_SIZE (8) bytes for the signature
    let sig_hash = Sha512::digest(&key);
    let sig = hex::encode(&sig_hash[..8]);

    debug!(
        "derive_ecryptfs_key: derived signature={} key_material_len={}",
        sig,
        key.len()
    );

    (key, sig)
}

/// Add ecryptfs key to kernel keyring using add_key syscall.
/// Returns the signature of the added key.
fn add_key_to_keyring(passphrase: &[u8], key_bytes: usize, salt: &[u8; 8]) -> anyhow::Result<String> {
    let (key, sig) = derive_ecryptfs_key(passphrase, salt);

    // Build the ecryptfs auth_tok structure
    let auth_tok = EcryptfsAuthTok::new(&key, &sig, salt);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_passphrase_trims_trailing_newline_and_crlf_only() {
        let with_newline = normalize_passphrase_bytes(b"My secure password\n");
        assert_eq!(with_newline.as_slice(), b"My secure password");

        let with_crlf = normalize_passphrase_bytes(b"My secure password\r\n");
        assert_eq!(with_crlf.as_slice(), b"My secure password");

        let with_space = normalize_passphrase_bytes(b"My secure password ");
        assert_eq!(with_space.as_slice(), b"My secure password ");
    }

    #[test]
    fn derive_fek_signature_matches_ecryptfs_add_passphrase() {
        let passphrase = b"My secure password";
        let (_key, sig) = derive_ecryptfs_key(passphrase, &ECRYPTFS_DEFAULT_SALT);

        // Baseline from: echo "My secure password" | ecryptfs-add-passphrase
        assert_eq!(sig, "0ab955d75efe229c");
    }

    #[test]
    fn derive_fnek_signature_matches_ecryptfs_add_passphrase_fnek() {
        let passphrase = b"My secure password";
        let (_key, sig) = derive_ecryptfs_key(passphrase, &ECRYPTFS_DEFAULT_SALT_FNEK);

        // Baseline from: echo "My secure password" | ecryptfs-add-passphrase --fnek
        assert_eq!(sig, "39b3c3fa4d086d94");
    }

    #[test]
    fn auth_tok_uses_sha512_and_full_fekek_size() {
        let key = vec![0x11; ECRYPTFS_MAX_KEY_BYTES];
        let sig = "0ab955d75efe229c";
        let auth_tok = EcryptfsAuthTok::new(&key, sig, &ECRYPTFS_DEFAULT_SALT);

        let hash_algo = unsafe { std::ptr::addr_of!(auth_tok.password.hash_algo).read_unaligned() };
        let key_bytes = unsafe {
            std::ptr::addr_of!(auth_tok.password.session_key_encryption_key_bytes).read_unaligned()
        };
        let salt = unsafe { std::ptr::addr_of!(auth_tok.password.salt).read_unaligned() };

        assert_eq!(hash_algo, PGP_DIGEST_ALGO_SHA512);
        assert_eq!(key_bytes, ECRYPTFS_MAX_KEY_BYTES as i32);
        assert_eq!(salt, ECRYPTFS_DEFAULT_SALT);
    }
}
