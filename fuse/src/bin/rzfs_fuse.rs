// SPDX-License-Identifier: GPL-2.0 OR MIT

use fuser::Filesystem;

use std::error::Error;
use zfs::phys;

struct RZFSFuse;

impl Filesystem for RZFSFuse {}

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", phys::SECTOR_SHIFT);

    Ok(())
}
