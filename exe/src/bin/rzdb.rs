// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::error::Error;
use zfs::phys;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", phys::SECTOR_SHIFT);

    Ok(())
}
