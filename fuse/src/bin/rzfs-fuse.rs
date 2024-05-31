// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::error::Error;

use fuser::Filesystem;

use rzfs::phys;

#[derive(Debug)]
struct RZFSFuse;

impl Filesystem for RZFSFuse {}

fn main() -> Result<(), Box<dyn Error>> {
    let rzfs = RZFSFuse {};
    println!("{:?}", rzfs);
    println!("{}", phys::SECTOR_SHIFT);

    Ok(())
}
