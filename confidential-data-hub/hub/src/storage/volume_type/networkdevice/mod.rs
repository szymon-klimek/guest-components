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
    mount_options: Option<String>,
    transit_mount_point: Option<String>,
    #[serde(flatten)]
    encryption_type: Option<NetworkDeviceEncryptType>,
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
        // construct NetworkDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let parameters: NetworkDeviceParameters = serde_json::from_str(&parameters)?;

        // 1. get the network source path
        let source_path = format!("{}:{}", parameters.ip_addr, parameters.source_path);

        // 2. create transit mount point name if not given
        let transit_mount_point: String =
            parameters.transit_mount_point.unwrap_or(
                format!("{}_transit", mount_point).to_string());

        // 3. create directory for mount if it does not exist
        if !Path::new(&transit_mount_point).exists() {
            tokio::fs::create_dir_all(&transit_mount_point).await?;
            self.temp_paths.push(transit_mount_point.to_string());
        }

        // 4. setup mount NFS parameters
        let mut args = vec!["-t", "nfs"];

        if let Some(mount_options) = &parameters.mount_options {
            args.extend(["-o", mount_options.as_str()]);
        }

        args.extend([source_path.as_str(), transit_mount_point.as_str()]);

        // 5. mount not encrypted NFS as a transit step before encryption
        info!(
            "mounting NFS from source point: {} to mount point: {}",
            &source_path, transit_mount_point
        );

        // nix approach would need implementation of version+port negotiation first
        run_command(MOUNT_COMMAND, &args, None)
            .map_err(|source| NetworkDeviceError::MountError {
                ip_addr: source_path.clone(),
                mount_point: transit_mount_point.parse().unwrap(),
                source,
            })?;

        info!("Target path {} mounted successfully", transit_mount_point);

        // 6. do the workflow according to different encryption types
        match parameters.encryption_type {
            Some(NetworkDeviceEncryptType::Ecryptfs(ecryptfs_parameters)) => {
                ecryptfs_parameters
                    .do_mount(&transit_mount_point[..], mount_point)
                    .await
                    .map_err(|source| NetworkDeviceError::EcryptfsError { source })?;
            },
            None => {

            }
        }

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
