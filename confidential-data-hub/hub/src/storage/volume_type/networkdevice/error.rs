// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, NetworkDeviceError>;

#[derive(Error, Debug)]
pub enum NetworkDeviceError {

    #[error("Ecryptfs error: {source}")]
    EcryptfsError{
        #[source]
        source: anyhow::Error,
    },

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Failed to serialize or deserialize JSON: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to mount NFSv4 from {ip_addr} to mount point {mount_point}: {source}")]
    MountError {
        ip_addr: String,
        mount_point: String,
        #[source]
        source: nix::Error,
    },

    #[error("Failed to umount device {mount_point}: {source}")]
    UmountFailed {
        mount_point: String,
        #[source]
        source: nix::Error,
    },

    #[error("Network unreachable to {addr} after {attempts} attempts")]
    NetworkUnreachable {
        addr: String,
        attempts: u32,
    },
}
