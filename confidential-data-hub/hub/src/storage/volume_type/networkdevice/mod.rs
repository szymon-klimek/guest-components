// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # NetworkDevice SecureStorage

pub mod error;

use super::SecureMount;

use async_trait::async_trait;
use error::{NetworkDeviceError, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use serde::{Deserialize, Serialize};
use strum::Display;
use tracing::info;
use crate::storage::drivers::run_command;

const MOUNT_COMMAND: &str = "mount";

#[derive(Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum NetworkDeviceEncryptType {
    #[strum(serialize = "ecryptfs")]
    #[serde(rename = "ecryptfs")]
    Ecryptfs(crate::storage::drivers::ecryptfs::EcryptfsMountParameters),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct NetworkDeviceParameters {
    ip_addr: IpAddr,
    source_path: String,
    #[serde(default)]
    mount_options: String,
}

#[derive(Default)]
pub struct NetworkDevice {
    /// Paths to remove on umount (e.g. symlinks created for device target, LUKS header files).
    temp_paths: Vec<String>,

    /// The mount points created by the operation. This is used to
    /// clean up.
    mount_points: Vec<String>,
}

impl NetworkDevice {
    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct BlockDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let parameters: NetworkDeviceParameters = serde_json::from_str(&parameters)?;

        // 1. get the network source path
        let source_path = format!("{}:{}", parameters.ip_addr, parameters.source_path);

        // 2. # Create directory if it does not exist
        if !Path::new(&source_path).exists() {
            tokio::fs::create_dir_all(&source_path).await?;
            self.temp_paths.push(source_path.to_string());
        }

        // 3. do the workflow according to the source type and target type according to different encryption types
        info!(
            "mounting NFS from source point: {} to mount point: {}",
            &source_path, mount_point
        );

        // setup mount NFS parameters
        let mut args = vec!["-t", "nfs"];

        if !parameters.mount_options.is_empty() {
            args.extend(["-o", parameters.mount_options.as_str()]);
        }

        args.extend([source_path.as_str(), mount_point]);

        run_command(MOUNT_COMMAND, &args, None)
            .map_err(|source| NetworkDeviceError::MountError {
                ip_addr: source_path.clone(),
                mount_point: mount_point.parse().unwrap(),
                source,
            })?;

        info!("Target path {} mounted successfully", mount_point);
        Ok(())
    }

    pub async fn umount(&mut self) -> Result<()> {
        // 1. unmount the mount points
        for mount_point in &self.mount_points {
            nix::mount::umount(&mount_point[..]).map_err(|source| {
                NetworkDeviceError::UmountFailed {
                    mount_point: mount_point.to_string(),
                    source,
                }
            })?;
        }

        // 2. remove temporary paths (symlinks, LUKS header files, etc.)
        for path in &self.temp_paths {
            tokio::fs::remove_file(path).await?;
        }
        Ok(())
    }

}


#[async_trait]
impl SecureMount for NetworkDevice {
    /// Mount the block device to the given `mount_point``.
    ///
    /// This is a wrapper for inner function to convert error type.
    async fn mount(
        &mut self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> super::Result<()> {
        self.real_mount(options, flags, mount_point)
            .await
            .map_err(|e| e.into())
    }
}