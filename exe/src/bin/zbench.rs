// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::error::Error;
use std::time::Instant;
use zfs::checksum::Checksum;
use zfs::checksum::{Fletcher4, Fletcher4Implementation};
use zfs::phys::{ENDIAN_ORDER_NATIVE, ENDIAN_ORDER_SWAP, SECTOR_SHIFT};

const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
const MICROSECONDS_IN_MILLISECOND: u64 = 1_000;

fn main() -> Result<(), Box<dyn Error>> {
    // 128 KiB.
    let size: usize = 1 << (SECTOR_SHIFT + 8);
    let iterations = 32;
    let display_units = 1024 * 1024;

    let mut data: Vec<u8> = vec![0; size];

    println!(
        "{:>16} {:>11} {:>11}",
        "implementation", "native", "byteswap"
    );

    // Fill data buffer.
    for i in 0..data.len() {
        data[i] = i as u8;
    }

    // Loop through each implementation.
    for implementation in Fletcher4Implementation::all() {
        let s = format!("{}", implementation);
        print!("{:>16}", s);

        // Loop through native and swap order.
        for endian in [ENDIAN_ORDER_NATIVE, ENDIAN_ORDER_SWAP] {
            // Skip if not supported.
            if !implementation.is_supported() {
                print!(" {:>11}", "n/a");
                continue;
            }

            // Warm up.
            let mut h = Fletcher4::new(endian, *implementation)?;
            h.update(&data)?;
            h.finalize()?;

            // Keep track of elapsed time and work.
            let mut microseconds = 0;
            let mut total_iterations = 0;

            let start = Instant::now();

            while microseconds < MICROSECONDS_IN_MILLISECOND {
                for _ in 0..iterations {
                    h.reset()?;
                    h.update(&data)?;
                    h.finalize()?;
                    total_iterations += 1;
                }

                microseconds = start.elapsed().as_micros() as u64;
            }

            // Total number of bytes hashed.
            let total_size = (size as u64) * total_iterations;

            // Bytes per second.
            let bytes_per_second = (MICROSECONDS_PER_SECOND * total_size) / microseconds;

            // Display units.
            print!(" {:11}", bytes_per_second / display_units)
        }
        println!("");
    }

    Ok(())
}
