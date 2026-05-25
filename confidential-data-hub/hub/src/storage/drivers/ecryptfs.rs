use crate::storage::volume_type::blockdevice::SourceType;
use anyhow::Context;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

const NETWORK_FS_NFS: &str = "nfs";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EcryptfsMountParameters {
    ip_address: String,
    source_path: String,
    options: Vec<String>,
}

impl EcryptfsMountParameters {
    /// Do the mount operation for the LUKS2 device.
    /// Returns the header path if the source type is empty.
    pub async fn do_mount(
        self,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        source_type: SourceType,
    ) -> anyhow::Result<Option<String>> {
        info!(
            "mounting NFS from: {} to mount point: {}",
            &self.ip_address, mount_point
        );
        mount::<_, _, str, _>(
            Some(&self.get_mount_source()[..]),
            mount_point,
            Some(NETWORK_FS_NFS),
            MsFlags::MS_NOATIME,
            Some(&self.get_options()[..]),
        )
            .with_context(|| {
                format!(
                    "Failed to mount device {} to mount point {}",
                    &self.ip_address, mount_point
                )
            })?;
        Ok("".to_string().into())
    }
    fn get_mount_source(&self) -> String {
        format!("{}:{}", self.ip_address, self.source_path)
    }

    fn get_options(&self) -> String {
        self.options.join(",")
    }

}
