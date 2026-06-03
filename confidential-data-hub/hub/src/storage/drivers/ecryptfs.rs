use std::path::Path;
use anyhow::Context;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, error};
use zeroize::Zeroizing;
use kms::{Annotations, ProviderSettings};
use crate::secret;
use crate::storage::volume_type::blockdevice::error::BlockDeviceError;

const ECRYPTFS_FS_NAME: &str = "ecryptfs";

mod defaults {
    pub const CIPHER: &str = "aes";
    pub const KEY_BYTES: &str = "32";
    pub const ENABLE_PASSTHROUGH: &str = "false";
    pub const ENABLE_FILENAME_CRYPTO: &str = "false";
    pub const UNLINK_SIGS: &str = "true";

    pub fn cipher() -> String { CIPHER.into() }
    pub fn key_bytes() -> String { KEY_BYTES.into() }
    pub fn enable_passthrough() -> String { ENABLE_PASSTHROUGH.into() }
    pub fn enable_filename_crypto() -> String { ENABLE_FILENAME_CRYPTO.into() }
    pub fn unlink_sigs() -> String { UNLINK_SIGS.into() }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EcryptfsMountParameters {
    passphrase: Option<String>,
    sig: Option<String>,
    fnek_sig: Option<String>,
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
        args.push(format!("ecryptfs_key_bytes={}", self.key_bytes));
        if parse_string_boolean_to_bool(&self.enable_passthrough) {
            args.push("ecryptfs_passthrough".to_string());
        }
        if parse_string_boolean_to_bool(&self.enable_filename_crypto) {
            args.push("ecryptfs_enable_filename_crypto".to_string());
        }
        if parse_string_boolean_to_bool(&self.unlink_sigs) {
            args.push("ecryptfs_unlink_sigs".to_string());
        }

        if let Some(ref sig) = self.sig {
            match get_plaintext_key(sig).await {
                Ok(vec) => {
                    args.push(format!(
                        "ecryptfs_sig={}",
                        String::from_utf8(vec.to_vec()).unwrap().trim()
                    ));
                }
                Err(e) => info!("Error while getting SIG: {}", e),
            }
        }

        if let Some(ref fnek_sig) = self.fnek_sig {
            match get_plaintext_key(fnek_sig).await {
                Ok(vec) => {
                    args.push(format!(
                        "ecryptfs_fnek_sig={}",
                        String::from_utf8(vec.to_vec()).unwrap().trim()
                    ));
                }
                Err(e) => error!("Error while getting FNEK_SIG: {}", e),
            }
        }

        // Note: passphrase is used to add key to kernel keyring (via add_key_to_keyring),
        // not passed directly to mount. The kernel only accepts ecryptfs_sig.

        args.join(",").to_string()
    }

    /// Validate parameters before mounting.
    /// Returns an error if:
    /// - neither passphrase nor sig is provided
    /// - enable_filename_crypto is true but fnek_sig is not provided
    fn validate(&self) -> anyhow::Result<()> {
        if self.passphrase.is_none() && self.sig.is_none() {
            anyhow::bail!("at least one of passphrase or sig must be provided");
        }

        let filename_crypto_enabled = parse_string_boolean_to_bool(&self.enable_filename_crypto);
        if filename_crypto_enabled && self.fnek_sig.is_none() {
            anyhow::bail!("fnek_sig is required when enable_filename_crypto is true");
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
