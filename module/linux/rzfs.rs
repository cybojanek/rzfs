// SPDX-License-Identifier: GPL-2.0 OR MIT
/*! ZFS Rust filesystem module.
 */
use kernel::prelude::*;
use zfs;

module! {
    type: RZFSModule,
    name: "rzfs",
    author: "Jan Kasiak",
    description: "Rust ZFS",
    license: "GPL",
}

struct RZFSModule {
    number: u32,
}

impl kernel::Module for RZFSModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("RZFS(init)\n");
        pr_info!("Sector: {}\n", zfs::phys::sector::SHIFT);
        Ok(RZFSModule { number: 1 })
    }
}

impl Drop for RZFSModule {
    fn drop(&mut self) {
        pr_info!("RZFS(exit) {}\n", self.number);
    }
}
