// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::env;
use std::error::Error;

use std::fs::File;
use std::io;
use std::io::Write;

use std::process;

use rzfs::checksum;
use rzfs::checksum::Checksum;
use rzfs::compression;
use rzfs::compression::{Compression, Decompression};
use rzfs::phys;
use rzfs::userspace;

////////////////////////////////////////////////////////////////////////////////

/// Is the array of bytes empty (all zeroes).
fn is_array_empty(data: &[u8]) -> bool {
    for b in data {
        if *b != 0 {
            return false;
        }
    }

    true
}

/// Writes the the bytes to a file.
fn _writes_bytes_to_file(path: &str, data: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    file.flush()?;

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

/// Reads `sectors` from a [`phys::Dva`].
fn read_dva(
    blk: &userspace::BlockDevice,
    dva: &phys::Dva,
    sectors: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if sectors > dva.allocated {
        todo!("error");
    }

    let size = usize::try_from(sectors)?;
    let size = match size.checked_shl(phys::SECTOR_SHIFT) {
        Some(v) => v,
        None => todo!("error"),
    };

    if dva.is_gang {
        todo!("implement");
    }

    if dva.vdev != 0 {
        todo!("implement");
    }

    let mut data = vec![0; size];
    blk.read(&mut data, dva.offset)?;

    Ok(data)
}

////////////////////////////////////////////////////////////////////////////////

/// Reads an embedded block pointer.
fn read_block_pointer_embedded(
    _ptr: &phys::BlockPointerEmbedded,
) -> Result<Vec<u8>, Box<dyn Error>> {
    todo!();
}

/// Reads a regular block pointer.
fn read_block_pointer_regular(
    blk: &userspace::BlockDevice,
    ptr: &phys::BlockPointerRegular,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut data: Option<Vec<u8>> = None;

    // Read all the dvas.
    for dva_opt in ptr.dvas.iter() {
        let dva = match dva_opt {
            Some(dva) => dva,
            None => continue,
        };

        // Read physical bytes.
        let phys_bytes = read_dva(blk, dva, ptr.physical_sectors)?;

        // Verify checksum.
        let computed_checksum = match ptr.checksum_type {
            phys::ChecksumType::Fletcher4 => {
                let mut h = checksum::Fletcher4::new(checksum::Fletcher4Implementation::Generic)?;
                h.hash(&phys_bytes, ptr.order)?
            }
            _ => todo!("Implement: {}", ptr.checksum_type),
        };

        match ptr.checksum_type {
            phys::ChecksumType::Off => (),
            _ => {
                if computed_checksum != ptr.checksum_value.words {
                    todo!(
                        "handle checksum error: {:?} {:?}",
                        computed_checksum,
                        ptr.checksum_value.words
                    );
                }
            }
        }

        // Decompress.
        let decompressed_size = usize::try_from(ptr.logical_sectors)?;
        let decompressed_size = match decompressed_size.checked_shl(phys::SECTOR_SHIFT) {
            Some(v) => v,
            None => todo!("error"),
        };
        let mut decompressed_data = vec![0; decompressed_size];

        match ptr.compression {
            phys::CompressionType::Off => {
                if ptr.logical_sectors != ptr.physical_sectors {
                    todo!("handle error");
                }
                data = Some(phys_bytes)
            }
            phys::CompressionType::Lzjb => {
                let mut lzjb = compression::LzjbDecoder {};
                lzjb.decompress(&mut decompressed_data, &phys_bytes, 0)?;

                let mut recompressed_data = vec![0; decompressed_size];
                let mut lzjb = compression::LzjbEncoder::new();
                let matches =
                    match lzjb.compress_pre_v21(&mut recompressed_data, &decompressed_data, 0) {
                        Ok(v) => {
                            if v <= phys_bytes.len() {
                                recompressed_data[0..phys_bytes.len()] == phys_bytes
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    };

                if !matches {
                    recompressed_data.fill(0);
                    let csize = lzjb.compress(&mut recompressed_data, &decompressed_data, 0)?;
                    assert!(csize <= phys_bytes.len());
                    assert_eq!(recompressed_data[0..phys_bytes.len()], phys_bytes);
                }

                // Save most recent DVA as response.
                data = Some(decompressed_data);
            }
            _ => todo!("Implement: {}", ptr.compression),
        }
    }

    match data {
        Some(bytes) => Ok(bytes),
        None => todo!("handle error"),
    }
}

/// Reads the [`phys::BlockPointer`].
fn read_block_pointer(
    blk: &userspace::BlockDevice,
    ptr: &phys::BlockPointer,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match ptr {
        phys::BlockPointer::Embedded(emb) => read_block_pointer_embedded(emb),
        phys::BlockPointer::Encrypted(_) => todo!("Implement encrypted"),
        phys::BlockPointer::Regular(reg) => read_block_pointer_regular(blk, reg),
    }
}

////////////////////////////////////////////////////////////////////////////////

type DnodeReadResult = Result<Option<(phys::EndianOrder, Vec<u8>)>, Box<dyn Error>>;

/// Reads the [`phys::Dnode`]. Returns [None] if empty.
fn read_dnode_block(
    blk: &userspace::BlockDevice,
    dnode: &phys::Dnode,
    block_id: u64,
) -> DnodeReadResult {
    // Return [None] if the block id is not allocated.
    if block_id > dnode.max_block_id {
        return Ok(None);
    }

    if dnode.levels == 1 {
        // If its just one level, and the block id is within the array of
        // pointers, then read the pointer.
        if let Ok(idx) = usize::try_from(block_id) {
            if let Some(Some(ptr)) = dnode.pointers().get(idx) {
                return Ok(Some((ptr.order(), read_block_pointer(blk, ptr)?)));
            }
        }
    } else {
        todo!("Implement");
    }

    Ok(None)
}

/// Reads the [`phys::Dnode`] object. Returns [None] if empty.
fn read_dnode_object(
    blk: &userspace::BlockDevice,
    dnode: &phys::Dnode,
    object_id: u64,
    object_size: usize,
) -> DnodeReadResult {
    // Compute the block size.
    let data_block_size = usize::from(dnode.data_block_size_sectors)
        .checked_shl(phys::SECTOR_SHIFT)
        .unwrap();

    // Check the block size is a multiple of the object size.
    assert!((data_block_size % object_size) == 0);

    // Compute the number of objects per block.
    let objects_per_block = data_block_size / object_size;

    // Compute the block id, and the object index in the block.
    let block_id = object_id / (objects_per_block as u64);
    let idx_in_block = (object_id as usize) % objects_per_block;

    // Read the block.
    if let Some((endian, block)) = read_dnode_block(blk, dnode, block_id)? {
        // Read the object in the block.
        let mut data = vec![0; object_size];

        let start = idx_in_block * object_size;
        let end = start + object_size;
        data.copy_from_slice(&block[start..end]);

        return Ok(Some((endian, data)));
    }

    Ok(None)
}

////////////////////////////////////////////////////////////////////////////////

fn dump_root(
    blk: &userspace::BlockDevice,
    nv: &phys::NvDecoder,
    uberblock: &phys::UberBlock,
) -> Result<(), Box<dyn Error>> {
    ////////////////////////////////////
    println!();
    println!("checkpoint_txg: {}", uberblock.checkpoint_txg);
    println!("guid_sum: {}", uberblock.guid_sum);
    println!("software_version: {:?}", uberblock.software_version);
    println!("timestamp: {}", uberblock.timestamp);
    println!("mmp: {:#?}", uberblock.mmp);
    println!("txg: {}", uberblock.txg);
    println!("version: {}", uberblock.version);

    ////////////////////////////////////
    // let vdev_tree = nv.get_nv_list("vdev_tree")?.unwrap();
    let version = nv.get_u64("version")?.unwrap();
    // let ashift = vdev_tree.get_u64("ashift")?.unwrap();
    let label_txg = nv.get_u64("txg")?.unwrap();

    assert!(uberblock.txg >= label_txg);
    assert_eq!(u64::from(uberblock.version), version);

    ////////////////////////////////////
    // Read Meta ObjectSet.
    let meta_object_set_bytes = read_block_pointer(blk, &uberblock.ptr)?;
    let decoder = phys::EndianDecoder::from_bytes(&meta_object_set_bytes, uberblock.ptr.order());
    let meta_object_set = phys::ObjectSet::from_decoder(&decoder)?;

    ////////////////////////////////////
    // Read ObjectDirectory at fixed object id 1.
    let (endian, obj_dir_bytes) =
        read_dnode_object(blk, &meta_object_set.dnode, 1, phys::Dnode::SIZE)?.unwrap();
    let decoder = phys::EndianDecoder::from_bytes(&obj_dir_bytes, endian);
    let root_obj_dir_dnode = phys::Dnode::from_decoder(&decoder)?.unwrap();

    println!("root_object_dir_node: {:?}", root_obj_dir_dnode);

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

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
            phys::NvDecodedDataValue::Boolean() => println!(),
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
                println!();
                dump_nv_list(&v, depth + 1)?;
            }
            phys::NvDecodedDataValue::NvListArray(v) => {
                println!();
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
    let mut sha256 = checksum::Sha256::new(checksum::Sha256Implementation::Generic)?;

    // Open block device.
    let block_device = userspace::BlockDevice::open(&args[1])?;
    println!("Sectors: {}", block_device.sectors);

    ////////////////////////////////////
    // Read boot block.
    let boot_block_bytes = &mut vec![0; phys::BootBlock::SIZE];
    block_device.read(
        boot_block_bytes,
        phys::BootBlock::VDEV_OFFSET >> phys::SECTOR_SHIFT,
    )?;

    // Causes stack overflow in debug release.
    // let boot_block = phys::BootBlock::from_bytes(
    //     boot_block_bytes[0..phys::BootBlock::SIZE]
    //         .try_into()
    //         .unwrap(),
    // )?;
    // if !is_array_empty(boot_block.payload) {
    //     println!("BootBlock is not empty");
    // }
    if !is_array_empty(boot_block_bytes) {
        println!("BootBlock is not empty");
    }

    ////////////////////////////////////
    // Get label sectors.
    let label_sectors = phys::Label::sectors(block_device.sectors)?;

    ////////////////////////////////////
    // Parse each label.
    for (label_idx, sector) in label_sectors.into_iter().enumerate() {
        println!();
        println!("Label {label_idx}");
        println!();

        ////////////////////////////////
        // Read label.
        let label_bytes = &mut vec![0; phys::Label::SIZE];
        block_device.read(label_bytes, sector)?;

        let label_byte_offset_into_vdev = sector << phys::SECTOR_SHIFT;

        ////////////////////////////////
        // Read blank.
        let blank = phys::Blank::from_bytes(
            label_bytes[phys::Blank::LABEL_OFFSET..phys::Blank::LABEL_OFFSET + phys::Blank::SIZE]
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
                ..phys::BootHeader::LABEL_OFFSET + phys::BootHeader::SIZE]
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
                [phys::NvPairs::LABEL_OFFSET..phys::NvPairs::LABEL_OFFSET + phys::NvPairs::SIZE]
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
        let version = phys::Version::try_from(nv_decoder.get_u64("version")?.unwrap())?;
        let ashift = vdev_tree.get_u64("ashift")?.unwrap();
        let label_txg = nv_decoder.get_u64("txg")?.unwrap();

        let mut max_uberblock: Option<phys::UberBlock> = None;

        ////////////////////////////////
        // Read UberBlocks.
        let uberblock_size = 1 << phys::UberBlock::get_shift_from_version_ashift(version, ashift);
        for i in 0..phys::UberBlock::TOTAL_SIZE / uberblock_size {
            let uber_label_offset = phys::UberBlock::LABEL_OFFSET + i * uberblock_size;
            let uber_bytes = &label_bytes[uber_label_offset..uber_label_offset + uberblock_size];

            let uber_res = phys::UberBlock::from_bytes(
                uber_bytes,
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

            if let Some(uberblock) = uber_opt {
                println!("UberBlock {i} Ok");

                max_uberblock = match max_uberblock {
                    None => {
                        if uberblock.txg >= label_txg {
                            Some(uberblock)
                        } else {
                            None
                        }
                    }
                    Some(current) => {
                        if uberblock.txg > current.txg {
                            Some(uberblock)
                        } else {
                            Some(current)
                        }
                    }
                }
            }
        }

        if let Some(uberblock) = max_uberblock {
            dump_root(&block_device, &nv_decoder, &uberblock)?;
            break;
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = dump() {
        println!("{e}");
    }
}
