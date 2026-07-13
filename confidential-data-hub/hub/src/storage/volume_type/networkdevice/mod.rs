// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # NetworkDevice SecureStorage
//!
//! This module implements NFS mounting using the nix crate's mount syscall directly.
//! 
//! **Important**: Only NFSv4 is supported. NFSv4 uses the well-known port 2049 and
//! doesn't require portmapper/rpcbind negotiation, making it compatible with direct
//! syscall-based mounting. NFSv3 requires mount helpers for port/version negotiation
//! and is not supported.

pub mod error;

use super::SecureMount;

use async_trait::async_trait;
use error::{NetworkDeviceError, Result};
use nix::mount::{mount, MsFlags};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Component, Path};
use serde::{Deserialize, Serialize};
use strum::Display;
use tracing::{info, error};
use uuid::Uuid;

/// NFSv4 filesystem type. We use "nfs4" to explicitly require NFSv4 protocol,
/// which uses the well-known port 2049 and doesn't need portmapper negotiation.
const NFS4_FS_NAME: &str = "nfs4";
const DEFAULT_NFS_VERSION: &str = "4.2";

/// Parse mount options string into a HashMap.
/// Format: "key1=value1,key2=value2,flag"
/// Splits on comma, then on equals for key=value pairs.
fn parse_mount_options(options_str: &str) -> HashMap<String, String> {
    options_str
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|opt| {
            if let Some((key, value)) = opt.split_once('=') {
                (key.trim().to_string(), value.trim().to_string())
            } else {
                // Flag-style option without value
                (opt.trim().to_string(), String::new())
            }
        })
        .collect()
}

/// Convert HashMap of mount options back to a comma-separated string.
fn mount_options_to_string(options: &HashMap<String, String>) -> String {
    options
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Ensure required NFS4 mount options are present.
/// Adds `vers=4.2` if not present, adds `addr=<ip>` if not present.
/// Returns the options as a comma-separated string ready for mount syscall.
fn ensure_nfs4_mount_options(server_addr: &IpAddr, user_options: Option<&str>) -> String {
    let mut options = user_options
        .map(parse_mount_options)
        .unwrap_or_default();
    
    // Add vers=4.2 if not present
    if !options.contains_key("vers") {
        options.insert("vers".to_string(), DEFAULT_NFS_VERSION.to_string());
    }
    
    // Add addr=<ip> if not present
    if !options.contains_key("addr") {
        options.insert("addr".to_string(), server_addr.to_string());
    }
    
    mount_options_to_string(&options)
}

/// Check if a path is already mounted by reading /proc/mounts
async fn is_mounted(mount_point: &str) -> Result<bool> {
    let mounts = tokio::fs::read_to_string("/proc/mounts").await?;
    let canonical_path = std::fs::canonicalize(mount_point)
        .unwrap_or_else(|_| std::path::PathBuf::from(mount_point));
    
    Ok(mounts.lines().any(|line| {
        // /proc/mounts format: device mount_point fstype options ...
        line.split_whitespace()
            .nth(1)
            .map(|mp| mp == canonical_path.to_string_lossy())
            .unwrap_or(false)
    }))
}

fn resolve_relative_mount_path(transit_mount_point: &str, relative_mount_path: Option<&str>) -> Result<String> {
    let Some(relative_mount_path) = relative_mount_path.map(str::trim) else {
        return Ok(transit_mount_point.to_string());
    };

    if relative_mount_path.is_empty() {
        return Ok(transit_mount_point.to_string());
    }

    let trimmed_relative = relative_mount_path.trim_matches('/');
    if trimmed_relative.is_empty() {
        return Ok(transit_mount_point.to_string());
    }

    let path = Path::new(trimmed_relative);
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(NetworkDeviceError::InvalidRelativeMountPath {
                    path: relative_mount_path.to_string(),
                    reason: "path must be relative and must not contain '.' or '..'".to_string(),
                });
            }
        }
    }

    Ok(format!(
        "{}/{}",
        transit_mount_point.trim_end_matches('/'),
        trimmed_relative
    ))
}

/// Wait for the system network to be ready.
/// Checks that a non-loopback network interface is up with routes configured.
async fn wait_for_system_network_ready() -> Result<()> {
    use std::time::Duration;
    
    const MAX_RETRIES: u32 = 60;
    const RETRY_DELAY_MS: u64 = 1000;
    
    for attempt in 1..=MAX_RETRIES {
        // Check /sys/class/net for interfaces and their operstate
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let iface = entry.file_name();
                let iface_str = iface.to_string_lossy();
                
                // Skip loopback
                if iface_str == "lo" {
                    continue;
                }
                
                // Check operstate is "up"
                let operstate_path = format!("/sys/class/net/{}/operstate", iface_str);
                if let Ok(state) = std::fs::read_to_string(&operstate_path) {
                    if state.trim() == "up" {
                        // Check if interface has routes in /proc/net/route
                        if let Ok(route) = std::fs::read_to_string("/proc/net/route") {
                            if route.lines().any(|line| line.starts_with(&*iface_str)) {
                                info!(
                                    "System network ready: interface {} is up with routes (attempt {})",
                                    iface_str, attempt
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        
        if attempt < MAX_RETRIES {
            info!(
                "Waiting for system network: attempt {}/{}, no ready interface yet...",
                attempt, MAX_RETRIES
            );
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }
    
    Err(NetworkDeviceError::NetworkUnreachable {
        addr: "system network".to_string(),
        attempts: MAX_RETRIES,
    })
}

#[derive(Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum NetworkDeviceEncryptType {
    #[strum(serialize = "ecryptfs")]
    #[serde(rename = "ecryptfs")]
    Ecryptfs(crate::storage::drivers::ecryptfs::EcryptfsMountParameters),
}

/// Kata guest hooks directory (writable location since rootfs is read-only)
const GUEST_HOOKS_DIR: &str = "/run/cdh-hooks";

/// Config file path for guest hooks (inside GUEST_HOOKS_DIR)
const HOOK_CONFIG_FILE: &str = "/run/cdh-hooks/conf";

/// Create Kata guest hooks dynamically.
/// Hooks wait for config file to appear (handles timing with NFS/ecryptfs mount).
async fn create_guest_hooks() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    
    let prestart_dir = format!("{}/prestart", GUEST_HOOKS_DIR);
    let poststop_dir = format!("{}/poststop", GUEST_HOOKS_DIR);
    
    tokio::fs::create_dir_all(&prestart_dir).await?;
    tokio::fs::create_dir_all(&poststop_dir).await?;
    
    // Prestart hook - waits for config, then mounts ecryptfs into container
    let prestart_script = r#"#!/bin/sh
# CDH ecryptfs prestart hook - mounts encrypted storage into container
CONFIG_FILE="/run/cdh-hooks/conf"

# Wait for config file (CDH may still be mounting NFS/ecryptfs)
WAIT_COUNT=0
while [ ! -f "$CONFIG_FILE" ] && [ $WAIT_COUNT -lt 60 ]; do
    sleep 0.5
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

[ ! -f "$CONFIG_FILE" ] && exit 0

. "$CONFIG_FILE"
[ -z "$SOURCE_MOUNT" ] || [ -z "$CONTAINER_PATH" ] && exit 0

STATE=$(cat)
CONTAINER_ID=$(echo "$STATE" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')

if [ -z "$CONTAINER_ID" ]; then
    BUNDLE=$(echo "$STATE" | grep -o '"bundle"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    [ -n "$BUNDLE" ] && CONTAINER_ID=$(basename "$BUNDLE")
fi

[ -z "$CONTAINER_ID" ] && exit 0

KATA_DIR="/run/kata-containers"
ROOTFS="$KATA_DIR/$CONTAINER_ID/rootfs"
TARGET="$ROOTFS$CONTAINER_PATH"

for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -d "$ROOTFS" ] && break
    sleep 0.1
done

[ ! -d "$ROOTFS" ] && exit 0

mkdir -p "$TARGET" 2>/dev/null
mountpoint -q "$TARGET" 2>/dev/null && exit 0

mount --bind "$SOURCE_MOUNT" "$TARGET" && mount --make-private "$TARGET"
echo "CDH prestart: Mounted $SOURCE_MOUNT to $TARGET" >&2
"#;

    // Poststop hook - unmounts to protect data
    let poststop_script = r#"#!/bin/sh
# CDH ecryptfs poststop hook - unmounts to protect data from cleanup
CONFIG_FILE="/run/cdh-hooks/conf"

[ ! -f "$CONFIG_FILE" ] && exit 0

. "$CONFIG_FILE"
[ -z "$CONTAINER_PATH" ] && exit 0

STATE=$(cat)
CONTAINER_ID=$(echo "$STATE" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')

if [ -z "$CONTAINER_ID" ]; then
    BUNDLE=$(echo "$STATE" | grep -o '"bundle"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    [ -n "$BUNDLE" ] && CONTAINER_ID=$(basename "$BUNDLE")
fi

[ -z "$CONTAINER_ID" ] && exit 0

TARGET="/run/kata-containers/$CONTAINER_ID/rootfs$CONTAINER_PATH"

sync
if mountpoint -q "$TARGET" 2>/dev/null; then
    umount "$TARGET" 2>/dev/null || umount -l "$TARGET" 2>/dev/null
    echo "CDH poststop: Unmounted $TARGET" >&2
fi
"#;

    let prestart_path = format!("{}/cdh-ecryptfs", prestart_dir);
    let poststop_path = format!("{}/cdh-ecryptfs", poststop_dir);
    
    tokio::fs::write(&prestart_path, prestart_script).await?;
    tokio::fs::set_permissions(&prestart_path, std::fs::Permissions::from_mode(0o755)).await?;
    
    tokio::fs::write(&poststop_path, poststop_script).await?;
    tokio::fs::set_permissions(&poststop_path, std::fs::Permissions::from_mode(0o755)).await?;
    
    info!("Created guest hooks at {}", GUEST_HOOKS_DIR);
    Ok(())
}

/// Write configuration for guest hooks.
async fn write_hook_config(
    source_mount: &str,
    container_path: &str,
) -> std::io::Result<()> {
    let config = format!(
        "# CDH ecryptfs hook configuration\n\
         SOURCE_MOUNT=\"{}\"\n\
         CONTAINER_PATH=\"{}\"\n",
        source_mount,
        container_path,
    );
    
    tokio::fs::write(HOOK_CONFIG_FILE, &config).await?;
    
    info!("Wrote hook config to {}", HOOK_CONFIG_FILE);
    info!("  SOURCE_MOUNT={}", source_mount);
    info!("  CONTAINER_PATH={}", container_path);
    
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct NetworkDeviceParameters {
    ip_addr: IpAddr,
    source_path: String,
    mount_options: Option<String>,
    transit_mount_point: Option<String>,
    relative_mount_path: Option<String>,
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

        // Create guest hooks early if ecryptfs is requested
        // Hooks will wait for config file, which is written after ecryptfs mount
        if parameters.encryption_type.is_some() {
            if let Err(e) = create_guest_hooks().await {
                error!("Failed to create guest hooks: {}", e);
            }
        }

        // 1. For display/logging purposes, format as server:path
        let display_source = format!("{}:{}", parameters.ip_addr, parameters.source_path);

        // 2. create transit mount point name if not given
        let transit_mount_point: String =
            parameters.transit_mount_point.unwrap_or_else(|| {
                format!("/tmp/{}/nfs", Uuid::new_v4())
            });

        // 3. create directory for mount if it does not exist
        if !Path::new(&transit_mount_point).exists() {
            tokio::fs::create_dir_all(&transit_mount_point).await?;
            self.temp_paths.push(transit_mount_point.to_string());
        }

        // 4. mount NFSv4 as a transit step before encryption
        // NFSv4 is required because it uses well-known port 2049 and doesn't need
        // portmapper/rpcbind negotiation that the mount helper would normally perform.
        
        // Check if already mounted (can happen if called multiple times)
        if is_mounted(&transit_mount_point).await? {
            info!(
                "Mount point {} is already mounted, skipping NFS mount",
                transit_mount_point
            );
        } else {
            // Wait for system network to be ready before attempting mount.
            // This handles the case where CDH starts via init_data before
            // the guest network is fully configured.
            wait_for_system_network_ready().await?;

            info!(
                "mounting NFSv4 from source point: {} to mount point: {}",
                &display_source, transit_mount_point
            );

            // Build mount options for kernel NFS client.
            // Ensures vers=4.2 and addr=<ip> are present.
            let mount_options = ensure_nfs4_mount_options(
                &parameters.ip_addr,
                parameters.mount_options.as_deref(),
            );

            mount::<str, str, str, str>(
                Some(&display_source),
                &transit_mount_point,
                Some(NFS4_FS_NAME),
                MsFlags::empty(),
                Some(&mount_options),
            )
            .map_err(|source| NetworkDeviceError::MountError {
                ip_addr: display_source.clone(),
                mount_point: transit_mount_point.clone(),
                source,
            })?;

            info!("Target path {} mounted successfully", transit_mount_point);
        }

        // 6. do the workflow according to different encryption types
        match parameters.encryption_type {
            Some(NetworkDeviceEncryptType::Ecryptfs(ecryptfs_parameters)) => {
                let ecryptfs_source_path = resolve_relative_mount_path(
                    &transit_mount_point,
                    parameters.relative_mount_path.as_deref(),
                )?;

                if !Path::new(&ecryptfs_source_path).exists() {
                    tokio::fs::create_dir_all(&ecryptfs_source_path).await?;
                }

                // ecryptfs mounts to a sibling directory of the NFS transit mount
                // e.g., /tmp/<uuid>/nfs -> /tmp/<uuid>/nfs_ecryptfs
                let ecryptfs_mount_point = format!(
                    "{}_ecryptfs",
                    transit_mount_point.trim_end_matches('/')
                );
                
                // Create the ecryptfs mount directory
                if !Path::new(&ecryptfs_mount_point).exists() {
                    tokio::fs::create_dir_all(&ecryptfs_mount_point).await?;
                    self.temp_paths.push(ecryptfs_mount_point.clone());
                }
                
                ecryptfs_parameters
                    .do_mount(&ecryptfs_source_path, &ecryptfs_mount_point)
                    .await
                    .map_err(|source| NetworkDeviceError::EcryptfsError { source })?;
                
                // Write config for dynamically created Kata guest hooks
                // Hooks read config from /run/cdh-hooks/conf
                if let Err(e) = write_hook_config(&ecryptfs_mount_point, mount_point).await {
                    error!("Failed to write hook config: {}", e);
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mount_options_handles_key_values_and_flags() {
        let parsed = parse_mount_options("vers=4.2,proto=tcp,soft");
        assert_eq!(parsed.get("vers"), Some(&"4.2".to_string()));
        assert_eq!(parsed.get("proto"), Some(&"tcp".to_string()));
        assert_eq!(parsed.get("soft"), Some(&"".to_string()));
    }

    #[test]
    fn mount_options_roundtrip_preserves_entries() {
        let original = "vers=4.2,addr=10.0.0.2,proto=tcp,soft";
        let parsed = parse_mount_options(original);
        let serialized = mount_options_to_string(&parsed);
        let reparsed = parse_mount_options(&serialized);

        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn ensure_nfs4_mount_options_adds_required_defaults() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let options = ensure_nfs4_mount_options(&addr, None);
        let parsed = parse_mount_options(&options);

        assert_eq!(parsed.get("vers"), Some(&DEFAULT_NFS_VERSION.to_string()));
        assert_eq!(parsed.get("addr"), Some(&addr.to_string()));
    }

    #[test]
    fn ensure_nfs4_mount_options_respects_user_values() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let options = ensure_nfs4_mount_options(&addr, Some("vers=4.1,addr=1.2.3.4,soft"));
        let parsed = parse_mount_options(&options);

        assert_eq!(parsed.get("vers"), Some(&"4.1".to_string()));
        assert_eq!(parsed.get("addr"), Some(&"1.2.3.4".to_string()));
        assert_eq!(parsed.get("soft"), Some(&"".to_string()));
    }

    #[test]
    fn deserialize_networkdevice_parameters_with_ecryptfs() {
        let json = r#"{
            "ip_addr": "127.0.0.1",
            "source_path": "/mnt/nfs/",
            "relative_mount_path": "tenant-a/models",
            "encryptionType": "ecryptfs",
            "passphrase": "kbs://127.0.0.1:31951/default/keys/passphrase",
            "enable_filename_crypto": "true"
        }"#;

        let params: NetworkDeviceParameters = serde_json::from_str(json).unwrap();
        assert_eq!(params.source_path, "/mnt/nfs/");
        assert_eq!(params.relative_mount_path, Some("tenant-a/models".to_string()));

        match params.encryption_type {
            Some(NetworkDeviceEncryptType::Ecryptfs(_)) => {}
            _ => panic!("expected ecryptfs encryption type"),
        }
    }

    #[test]
    fn resolve_relative_mount_path_joins_with_transit_mount_point() {
        let resolved = resolve_relative_mount_path("/tmp/abc/nfs", Some("tenant-a/models"))
            .expect("must resolve");
        assert_eq!(resolved, "/tmp/abc/nfs/tenant-a/models");
    }

    #[test]
    fn resolve_relative_mount_path_without_relative_path_uses_transit_mount_point() {
        let resolved = resolve_relative_mount_path("/tmp/abc/nfs", None)
            .expect("must resolve");
        assert_eq!(resolved, "/tmp/abc/nfs");
    }

    #[test]
    fn resolve_relative_mount_path_with_empty_relative_path_uses_transit_mount_point() {
        let resolved = resolve_relative_mount_path("/tmp/abc/nfs", Some("   "))
            .expect("must resolve");
        assert_eq!(resolved, "/tmp/abc/nfs");
    }

    #[test]
    fn resolve_relative_mount_path_rejects_parent_components() {
        let err = resolve_relative_mount_path("/tmp/abc/nfs", Some("../escape"))
            .expect_err("must reject parent component");

        match err {
            NetworkDeviceError::InvalidRelativeMountPath { .. } => {}
            _ => panic!("expected InvalidRelativeMountPath"),
        }
    }
}
