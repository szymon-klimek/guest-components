use std::path::Path;
use anyhow::Context;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, error};
use zeroize::Zeroizing;
use kms::{Annotations, ProviderSettings};
use crate::secret;
use crate::storage::volume_type::blockdevice::error::BlockDeviceError;

const ECRYPTFS: &str = "ecryptfs";
const DEFAULT_CIPHER: &str = "aes";
const DEFAULT_KEY_BYTES: &str = "32";
const DEFAULT_ENABLE_PASSTHROUGH: &str = "false";
const DEFAULT_ENABLE_FILENAME_CRYPTO: &str = "true";


#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EcryptfsMountParameters {
    sig: String,
    fnek_sig: String,
    passphrase: String,
    cipher: Option<String>,
    key_bytes: Option<String>,
    enable_passthrough: Option<String>,
    enable_filename_crypto: Option<String>
}

impl EcryptfsMountParameters {
    /// Do the mount operation for the LUKS2 device.
    /// Returns the header path if the source type is empty.
    pub async fn do_mount(
        self,
        source_path: &str,
        mount_point: &str,
    ) -> anyhow::Result<Option<String>> {

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
        mount::<_, _, str, _>(
            Some(source_path),
            mount_point,
            Some(ECRYPTFS),
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

        let cipher: String = self.cipher.clone().unwrap_or(DEFAULT_CIPHER.parse().unwrap());
        args.push(format!("ecryptfs_cipher={}", cipher));

        let key_bytes: String = self.key_bytes.clone().unwrap_or(DEFAULT_KEY_BYTES.parse().unwrap());
        args.push(format!("ecryptfs_key_bytes={}", key_bytes));

        let enable_passthrough: String =
            self.enable_passthrough.clone()
                .unwrap_or(DEFAULT_ENABLE_PASSTHROUGH.parse().unwrap());
        args.push(format!("ecryptfs_passthrough={}",
                          parse_string_boolean_value_to_mount_supported(enable_passthrough)));

        let enable_filename_crypto: String =
            self.enable_filename_crypto.clone()
                .unwrap_or(DEFAULT_ENABLE_FILENAME_CRYPTO.parse().unwrap());
        args.push(format!("ecryptfs_enable_filename_crypto={}",
                          parse_string_boolean_value_to_mount_supported(enable_filename_crypto)));

        let sig = get_plaintext_key(&self.sig[..]);
        match sig.await {
            Ok(vec) =>  {
                args.push(
                    format!("ecryptfs_sig={}", String::from_utf8(vec.to_vec()).unwrap()));
            },
            Err(e) => info!("Error while getting SIG: {}", e),
        }

        let fnek_sig = get_plaintext_key(&self.fnek_sig[..]);
        match fnek_sig.await {
            Ok(vec) =>  {
                args.push(
                    format!("ecryptfs_fnek_sig={}", String::from_utf8(vec.to_vec()).unwrap()));
            },
            Err(e) => error!("Error while getting FNEK_SIG: {}", e),
        }

        let passphrase = get_plaintext_key(&self.passphrase[..]);
        match passphrase.await {
            Ok(vec) =>  {
                args.push(
                    format!("key=passphrase:passphrase_passwd={}", String::from_utf8(vec.to_vec()).unwrap()));
            },
            Err(e) => error!("Error while getting passphrase: {}", e),
        }

        args.join(",").to_string()
    }
}

fn parse_string_boolean_value_to_mount_supported(string_boolean_value: String) -> String {
    let value_true = "y".parse().unwrap();
    let value_false = "n".parse().unwrap();
    match string_boolean_value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => value_true,
        "false" | "0" | "no" | "n" | "off" => value_false,
        _ => value_false,
    }
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
