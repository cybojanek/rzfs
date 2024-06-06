// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::env;
use std::error::Error;

use std::process;

use rzfs::checksum::{Sha256, Sha256Implementation};
use rzfs::phys;
use rzfs::userspace;

fn is_array_empty(data: &[u8]) -> bool {
    for b in data {
        if *b != 0 {
            return false;
        }
    }

    true
}

fn dump_nv_list(decoder: &phys::NvDecoder, depth: usize) -> Result<(), Box<dyn Error>> {
    loop {
        let nv_pair_opt = decoder.next_pair()?;
        let nv_pair = match nv_pair_opt {
            Some(v) => v,
            None => break,
        };

        for _ in 0..depth {
            print!("  ");
        }

        print!("{}", nv_pair.name);

        match nv_pair.value {
            phys::NvDecodedDataValue::Boolean() => println!(""),
            phys::NvDecodedDataValue::Byte(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Int16(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Uint16(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Int32(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Uint32(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Int64(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Uint64(v) => println!(": {v}"),
            phys::NvDecodedDataValue::String(v) => println!(": {v}"),
            phys::NvDecodedDataValue::ByteArray(v) => {
                print!(": [");
                for (idx, b) in v.iter().enumerate() {
                    if idx != 0 {
                        print!(", {b:#02x}");
                    } else {
                        print!("{b:#02x}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int16Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint16Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int32Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint32Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int64Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint64Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::StringArray(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::HrTime(v) => println!(": {v} ns"),
            phys::NvDecodedDataValue::NvList(v) => {
                println!("");
                dump_nv_list(&v, depth + 1)?;
            }
            phys::NvDecodedDataValue::NvListArray(v) => {
                println!("");
                for _idx in 0..v.capacity() {
                    dump_nv_list(&v.get()?, depth + 1)?;
                }
            }
            phys::NvDecodedDataValue::BooleanValue(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Int8(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Uint8(v) => println!(": {v}"),
            phys::NvDecodedDataValue::BooleanArray(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int8Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint8Array(v) => {
                print!(": [");
                for idx in 0..v.capacity() {
                    let n = v.get()?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Double(v) => println!(": {v}"),
        };
    }

    Ok(())
}

fn dump() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} PATH", &args[0]);
        process::exit(1);
    }

    // Create SHA256 instance.
    let mut sha256 = Sha256::new(Sha256Implementation::Generic)?;

    // Open block device.
    let block_device = userspace::BlockDevice::open(&args[1])?;
    println!("Sectors: {}", block_device.sectors);

    ////////////////////////////////////
    // Read boot block.
    let boot_block_bytes = &mut vec![0; phys::BootBlock::LENGTH];
    block_device.read(
        boot_block_bytes,
        phys::BootBlock::VDEV_OFFSET >> phys::SECTOR_SHIFT,
    )?;

    // Causes stack overflow in debug release.
    // let boot_block = phys::BootBlock::from_bytes(
    //     boot_block_bytes[0..phys::BootBlock::LENGTH]
    //         .try_into()
    //         .unwrap(),
    // )?;
    // if !is_array_empty(&boot_block.payload) {
    //     println!("BootBlock is not empty");
    // }
    if !is_array_empty(&boot_block_bytes) {
        println!("BootBlock is not empty");
    }

    ////////////////////////////////////
    // Get label sectors.
    let label_sectors = phys::Label::sectors(block_device.sectors)?;

    ////////////////////////////////////
    // Parse each label.
    for (label_idx, sector) in label_sectors.into_iter().enumerate() {
        println!("");
        println!("Label {label_idx}");

        ////////////////////////////////
        // Read label.
        let label_bytes = &mut vec![0; phys::Label::LENGTH];
        block_device.read(label_bytes, sector)?;

        let label_byte_offset_into_vdev = sector << phys::SECTOR_SHIFT;

        ////////////////////////////////
        // Read blank.
        let blank = phys::Blank::from_bytes(
            label_bytes[phys::Blank::LABEL_OFFSET..phys::Blank::LABEL_OFFSET + phys::Blank::LENGTH]
                .try_into()
                .unwrap(),
        )?;
        if !is_array_empty(&blank.payload) {
            println!("Blank is not empty");
        }

        ////////////////////////////////
        // Read boot header.
        let boot_header = phys::BootHeader::from_bytes(
            label_bytes[phys::BootHeader::LABEL_OFFSET
                ..phys::BootHeader::LABEL_OFFSET + phys::BootHeader::LENGTH]
                .try_into()
                .unwrap(),
            label_byte_offset_into_vdev + (phys::BootHeader::LABEL_OFFSET as u64),
            &mut sha256,
        )?;

        if !is_array_empty(&boot_header.payload) {
            println!("BootHeader is not empty");
        }

        ////////////////////////////////
        // Read NV pairs.
        let nv_pairs = phys::NvPairs::from_bytes(
            label_bytes
                [phys::NvPairs::LABEL_OFFSET..phys::NvPairs::LABEL_OFFSET + phys::NvPairs::LENGTH]
                .try_into()
                .unwrap(),
            label_byte_offset_into_vdev + (phys::NvPairs::LABEL_OFFSET as u64),
            &mut sha256,
        )?;

        let nv_decoder = phys::NvDecoder::from_bytes(&nv_pairs.payload)?;
        dump_nv_list(&nv_decoder, 0)?;

        ////////////////////////////////
        // Get the ashift value for the vdev_tree.
        let vdev_tree = nv_decoder.get_nv_list("vdev_tree")?.unwrap();
        let version = nv_decoder.get_u64("version")?.unwrap();
        let ashift = vdev_tree.get_u64("ashift")?.unwrap();

        ////////////////////////////////
        // Read UberBlocks.
        let mut uberblock_size = 1 << ashift;
        if uberblock_size < 1024 {
            uberblock_size = 1024;
        }
        if version == 5000 && uberblock_size > 8192 {
            uberblock_size = 8192;
        }
        // for i in 0..phys::Label::UBER_COUNT {
        for i in 0..phys::UberBlock::TOTAL_LENGTH / uberblock_size {
            let uber_label_offset = phys::UberBlock::LABEL_OFFSET + i * uberblock_size;
            let uber_bytes = &label_bytes[uber_label_offset..uber_label_offset + uberblock_size];

            let uber_res = phys::UberBlock::from_bytes(
                uber_bytes.try_into().unwrap(),
                label_byte_offset_into_vdev + (uber_label_offset as u64),
                &mut sha256,
            );

            let uber_opt = match uber_res {
                Ok(v) => v,
                Err(_e @ phys::UberBlockDecodeError::LabelVerify { err: _ }) => {
                    println!("UberBlock {i} bad");
                    continue;
                }
                Err(e) => return Err(Box::new(e)),
            };

            if !uber_opt.is_none() {
                println!("UberBlock {i} Ok");
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = dump() {
        println!("{e}");
    }
}
