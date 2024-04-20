// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::env;
use std::process::ExitCode;
use std::time::Instant;
use zfs::checksum::{Checksum, ChecksumError};
use zfs::checksum::{
    Fletcher2, Fletcher2Implementation, Fletcher4, Fletcher4Implementation, Sha256,
    Sha256Implementation,
};
use zfs::phys::{ENDIAN_ORDER_NATIVE, ENDIAN_ORDER_SWAP, SECTOR_SHIFT};

const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
const MICROSECONDS_IN_MILLISECOND: u64 = 1_000;

fn benchmark_checksum(
    checksum: &mut dyn Checksum,
    data: &[u8],
    iterations: usize,
    duration_us: u64,
) -> Result<u64, ChecksumError> {
    // Warm up.
    checksum.reset()?;
    checksum.update(data)?;
    checksum.finalize()?;

    // Keep track of elapsed time and work.
    let mut microseconds = 0;
    let mut total_iterations = 0;

    let start = Instant::now();

    while microseconds < duration_us {
        for _ in 0..iterations {
            checksum.reset()?;
            checksum.update(&data)?;
            checksum.finalize()?;
            total_iterations += 1;
        }

        microseconds = start.elapsed().as_micros() as u64;
    }

    // Total number of bytes hashed.
    let total_size = (data.len() as u64) * total_iterations;

    // Bytes per second.
    let bytes_per_second = (MICROSECONDS_PER_SECOND * total_size) / microseconds;

    Ok(bytes_per_second)
}

fn benchmark_fletcher2(
    data: &[u8],
    iterations: usize,
    duration_us: u64,
    display_units: u64,
) -> Result<(), ChecksumError> {
    println!(
        "{:>16} {:>11} {:>11}",
        "implementation", "native", "byteswap"
    );

    // Loop through each implementation.
    for implementation in Fletcher2Implementation::all() {
        let s = format!("{}", implementation);
        print!("{:>16}", s);

        // Loop through native and swap order.
        for endian in [ENDIAN_ORDER_NATIVE, ENDIAN_ORDER_SWAP] {
            // Skip if not supported.
            if !implementation.is_supported() {
                print!(" {:>11}", "n/a");
                continue;
            }

            let mut checksum = Fletcher2::new(endian, *implementation)?;
            let bytes_per_second =
                benchmark_checksum(&mut checksum, data, iterations, duration_us)?;

            // Display units.
            print!(" {:11}", bytes_per_second / display_units)
        }
        println!("");
    }

    Ok(())
}

fn benchmark_fletcher4(
    data: &[u8],
    iterations: usize,
    duration_us: u64,
    display_units: u64,
) -> Result<(), ChecksumError> {
    println!(
        "{:>16} {:>11} {:>11}",
        "implementation", "native", "byteswap"
    );

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

            let mut checksum = Fletcher4::new(endian, *implementation)?;
            let bytes_per_second =
                benchmark_checksum(&mut checksum, data, iterations, duration_us)?;

            // Display units.
            print!(" {:11}", bytes_per_second / display_units)
        }
        println!("");
    }

    Ok(())
}

fn benchmark_sha256(
    data: &[u8],
    iterations: usize,
    duration_us: u64,
    display_units: u64,
) -> Result<(), ChecksumError> {
    println!(
        "{:>16} {:>11} {:>11}",
        "implementation", "native", "byteswap"
    );

    // Loop through each implementation.
    for implementation in Sha256Implementation::all() {
        let s = format!("{}", implementation);
        print!("{:>16}", s);

        // Loop through native and swap order.
        for endian in [ENDIAN_ORDER_NATIVE] {
            // Skip if not supported.
            if !implementation.is_supported() {
                print!(" {:>11}", "n/a");
                continue;
            }

            let mut checksum = Sha256::new(endian, *implementation)?;
            let bytes_per_second =
                benchmark_checksum(&mut checksum, data, iterations, duration_us)?;

            // Display units.
            print!(" {:11}", bytes_per_second / display_units);
        }

        print!(" {:>11}", "n/a");

        println!("");
    }

    Ok(())
}

fn print_usage(arg0: &str) {
    eprintln!("usage: {} fletcher2|fletcher4", arg0);
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let duration_us = MICROSECONDS_IN_MILLISECOND;

    if args.len() != 2 {
        print_usage(&args[0]);
        return ExitCode::FAILURE;
    }

    // 128 KiB.
    let size: usize = 1 << (SECTOR_SHIFT + 8);
    let iterations = 32;
    let display_units = 1024 * 1024;

    // Allocate and align data.
    // TODO(cybojanek): Is there an API for this?
    let alignment = 4096;
    let mut data: Vec<u8> = vec![0; size + alignment];

    let mut offset = 0;
    let addr = data.as_ptr();
    let remainder = (addr as usize) % alignment;
    if remainder != 0 {
        offset = alignment - remainder;
    }
    let data = &mut data[offset..size + offset];

    // Fill data buffer.
    for i in 0..data.len() {
        data[i] = i as u8;
    }

    if args[1] == "fletcher2" {
        if let Err(e) = benchmark_fletcher2(data, iterations, duration_us, display_units) {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    } else if args[1] == "fletcher4" {
        if let Err(e) = benchmark_fletcher4(data, iterations, duration_us, display_units) {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    } else if args[1] == "sha256" {
        if let Err(e) = benchmark_sha256(data, iterations, duration_us, display_units) {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    } else {
        print_usage(&args[0]);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
