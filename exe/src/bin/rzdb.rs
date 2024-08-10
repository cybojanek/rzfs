// SPDX-License-Identifier: GPL-2.0 OR MIT

use std::collections::HashSet;
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex_string = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        hex_string.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex_string.push(HEX_CHARS[(byte & 0xf) as usize] as char);
    }

    hex_string
}

////////////////////////////////////////////////////////////////////////////////

/// Reads `sectors` from a [`phys::Dva`].
fn dva_read(
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
        todo!("implement gang");
    }

    let mut data = vec![0; size];
    blk.read(
        &mut data,
        dva.offset + phys::BootBlock::BLOCK_DEVICE_OFFSET + phys::BootBlock::SECTORS,
    )?;

    Ok(data)
}

////////////////////////////////////////////////////////////////////////////////

/// Reads an embedded block pointer.
fn block_pointer_embedded_read(
    _ptr: &phys::BlockPointerEmbedded,
) -> Result<Vec<u8>, Box<dyn Error>> {
    todo!();
}

/// Reads a regular block pointer.
fn block_pointer_regular_read(
    blk_devs: &[userspace::BlockDevice],
    ptr: &phys::BlockPointerRegular,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut data: Option<Vec<u8>> = None;

    // Read all the dvas.
    for dva in ptr.dvas.iter().flatten() {
        let vdev: usize = dva.vdev.try_into().unwrap();
        if vdev >= blk_devs.len() {
            todo!("implement error handling");
        }

        let blk = &blk_devs[vdev];

        // Read physical bytes.
        let phys_bytes = dva_read(blk, dva, ptr.physical_sectors)?;

        // Verify checksum.
        let computed_checksum = match ptr.checksum_type {
            phys::ChecksumType::Fletcher2 => {
                let mut h = checksum::Fletcher2::new(checksum::Fletcher2Implementation::Generic)?;
                h.hash(&phys_bytes, ptr.order)?
            }
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
fn block_pointer_read(
    blk_devs: &[userspace::BlockDevice],
    ptr: &phys::BlockPointer,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match ptr {
        phys::BlockPointer::Embedded(emb) => block_pointer_embedded_read(emb),
        phys::BlockPointer::Encrypted(_) => todo!("Implement encrypted"),
        phys::BlockPointer::Regular(reg) => block_pointer_regular_read(blk_devs, reg),
    }
}

////////////////////////////////////////////////////////////////////////////////

type DnodeReadResult = Result<Option<(phys::EndianOrder, Vec<u8>)>, Box<dyn Error>>;

/// Reads the [`phys::Dnode`]. Returns [None] if empty.
fn dnode_read_block(
    blk_devs: &[userspace::BlockDevice],
    dnode: &phys::Dnode,
    block_id: u64,
) -> DnodeReadResult {
    // Return [None] if the block id is not allocated.
    if block_id > dnode.max_block_id {
        return Ok(None);
    }

    // Number of block pointers per indirect block.
    let block_pointers_per_block = 1u64.checked_shl(dnode.indirect_block_shift.into()).unwrap()
        / (phys::BlockPointer::SIZE as u64);

    let levels = usize::from(dnode.levels);
    let mut block_ids: [u64; 8] = [0; 8];
    let mut block_pointer_idxs: [usize; 8] = [0; 8];

    if levels > block_ids.len() {
        todo!("Error too many levels");
    }

    // Level 0 block is the requested block id.
    block_ids[0] = block_id;

    // Compute the block ids and block pointers for the intermediate levels.
    for level in 1..levels {
        let block_id = block_ids[level - 1];
        block_ids[level] = block_id / block_pointers_per_block;
        block_pointer_idxs[level] =
            ((block_id % block_pointers_per_block) as usize) * phys::BlockPointer::SIZE;
    }

    // Read the top most block pointer.
    let ptr = match usize::try_from(block_ids[levels - 1]) {
        Ok(idx) => {
            if let Some(Some(ptr)) = dnode.pointers().get(idx) {
                ptr
            } else {
                // Block id is too large for dnode.pointers(), or empty.
                // That means the block is not allocated, so return None.
                return Ok(None);
            }
        }
        Err(_) => {
            // Block id is too large for usize - return None, because this
            // block is not allocated.
            return Ok(None);
        }
    };

    // Block order and bytes.
    let mut order = ptr.order();
    let mut block_bytes = block_pointer_read(blk_devs, ptr)?;

    // Read intermediate block pointers.
    let mut level = levels - 1;

    while level > 0 {
        // Decode the block as an intermediate block.
        let decoder = phys::EndianDecoder::from_bytes(&block_bytes, order);

        // Seek to index of block pointer.
        decoder.seek(block_pointer_idxs[level])?;

        // Decode block pointer.
        let ptr = match phys::BlockPointer::from_decoder(&decoder)? {
            Some(ptr) => ptr,
            None => return Ok(None),
        };

        // Read data for next block.
        order = ptr.order();
        block_bytes = block_pointer_read(blk_devs, &ptr)?;

        // Decrement level.
        level -= 1;
    }

    Ok(Some((order, block_bytes)))
}

/// Reads the [`phys::Dnode`] object. Returns [None] if empty.
fn dnode_read_object(
    blk_devs: &[userspace::BlockDevice],
    dnode: &phys::Dnode,
    object_id: u64,
    object_size: usize,
) -> DnodeReadResult {
    // Compute the block size.
    let data_block_size = usize::from(dnode.data_block_size_sectors)
        .checked_shl(phys::SECTOR_SHIFT)
        .unwrap();

    // Check the block size is a multiple of the object size.
    assert!(
        (data_block_size % object_size) == 0,
        "{data_block_size} % {object_size}"
    );

    // Compute the number of objects per block.
    let objects_per_block = data_block_size / object_size;

    // Compute the block id, and the object index in the block.
    let block_id = object_id / (objects_per_block as u64);
    let idx_in_block = (object_id as usize) % objects_per_block;

    // Read the block.
    if let Some((endian, block)) = dnode_read_block(blk_devs, dnode, block_id)? {
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

/// Reads the [`phys::Dnode`] object for a [`phys::DmuType::Dnode`]. Returns [None] if empty.
fn _dnode_read_dnode(
    blk_devs: &[userspace::BlockDevice],
    dnode: &phys::Dnode,
    object_id: u64,
) -> Result<Option<(phys::EndianOrder, phys::Dnode)>, Box<dyn Error>> {
    match dnode.dmu {
        phys::DmuType::Dnode => (),
        // phys::DmuType::DslDataSet => (),
        _ => todo!("todo error {}", dnode.dmu),
    };
    match dnode_read_object(blk_devs, dnode, object_id, phys::Dnode::SIZE)? {
        Some((endian, dnode_bytes)) => {
            let decoder = phys::EndianDecoder::from_bytes(&dnode_bytes, endian);
            match phys::Dnode::from_decoder(&decoder)? {
                Some(dnode) => Ok(Some((endian, dnode))),
                None => Ok(None),
            }
        }
        None => Ok(None),
    }
}

fn dnode_dump_zap(
    blk_devs: &[userspace::BlockDevice],
    dnode: &phys::Dnode,
    depth: usize,
) -> Result<(), Box<dyn Error>> {
    let (endian, zap_header_block) = dnode_read_block(blk_devs, dnode, 0)?.unwrap();
    let decoder = phys::EndianDecoder::from_bytes(&zap_header_block, endian);

    let zap_header = phys::ZapHeader::from_decoder(&decoder)?;

    match zap_header {
        phys::ZapHeader::Micro(_) => {
            decoder.reset();
            let zap_micro_iter = phys::ZapMicroIterator::from_decoder(&decoder)?;

            for entry_res in &zap_micro_iter {
                let entry = entry_res?;
                println!(
                    "{:width$}{} -> {}",
                    "",
                    entry.name,
                    entry.value,
                    width = depth,
                );
            }

            Ok(())
        }
        phys::ZapHeader::Mega(zap_mega_header) => {
            let (padding, leaves_count) =
                phys::ZapMegaHeader::get_padding_size_and_embedded_leaf_pointer_count(
                    zap_header_block.len(),
                )?;

            if zap_mega_header.table.blocks == 0 {
                decoder.skip_zero_padding(padding)?;

                let leaf_pointers = &mut vec![0; leaves_count];
                for i in &mut *leaf_pointers {
                    *i = decoder.get_u64()?;
                }
                assert!(decoder.is_empty());

                // TODO: Avoid hashset?
                #[allow(clippy::mutable_key_type)]
                let mut leaf_hashset = HashSet::new();
                for leaf_pointer in leaf_pointers {
                    leaf_hashset.insert(leaf_pointer);
                }

                for leaf_pointer in leaf_hashset {
                    let (endian, zap_leaf_block_bytes) =
                        dnode_read_block(blk_devs, dnode, *leaf_pointer)?.unwrap();
                    let decoder = phys::EndianDecoder::from_bytes(&zap_leaf_block_bytes, endian);

                    let _zap_leaf_header = phys::ZapLeafHeader::from_decoder(&decoder)?;

                    let (entries_count, _chunks_count) =
                        phys::ZapLeafHeader::get_entries_and_chunks_counts(
                            zap_leaf_block_bytes.len(),
                        )?;

                    let hash_table = &mut vec![0; entries_count];
                    for i in &mut *hash_table {
                        *i = decoder.get_u16()?;
                    }

                    // TODO: Avoid hashset?
                    let mut entry_hashset = HashSet::new();
                    for entry_hash in hash_table {
                        // ZAP_LEAF_EOL
                        if *entry_hash != 0xffff {
                            entry_hashset.insert(*entry_hash);
                        }
                    }
                    let mut sorted_entry_hashset = entry_hashset.into_iter().collect::<Vec<_>>();
                    sorted_entry_hashset.sort();

                    let offset = decoder.offset();
                    for entry_hash in sorted_entry_hashset {
                        let entry_hash = usize::from(entry_hash);

                        decoder.seek(offset + entry_hash * phys::ZapLeafChunk::SIZE)?;
                        let zap_leaf_chunk_entry = phys::ZapLeafChunkEntry::from_decoder(&decoder)?;

                        let mut value_u64 = None;
                        let mut value_str = None;

                        let mut todo = usize::from(zap_leaf_chunk_entry.name_length);
                        let mut name_chunk = usize::from(zap_leaf_chunk_entry.name_chunk);
                        let mut name = String::new();
                        while todo > 0 {
                            decoder.seek(offset + name_chunk * phys::ZapLeafChunk::SIZE)?;
                            let zap_leaf_chunk_data =
                                phys::ZapLeafChunkData::from_decoder(&decoder)?;

                            let can_do = core::cmp::min(todo, zap_leaf_chunk_data.data.len());
                            let s = core::str::from_utf8(&zap_leaf_chunk_data.data[0..can_do])?;

                            name += s;
                            todo -= can_do;

                            if todo > 0 {
                                name_chunk = usize::from(zap_leaf_chunk_data.next.unwrap());
                            }
                        }
                        // Remove NULL?
                        name = name[0..name.len() - 1].to_string();

                        let mut todo = usize::from(zap_leaf_chunk_entry.value_length)
                            * usize::from(zap_leaf_chunk_entry.value_int_size);
                        let mut value_chunk = usize::from(zap_leaf_chunk_entry.value_chunk);

                        if zap_leaf_chunk_entry.value_int_size == 8 {
                            if zap_leaf_chunk_entry.value_length != 1 {
                                todo!("implement");
                            }

                            decoder.seek(offset + value_chunk * phys::ZapLeafChunk::SIZE)?;
                            let zap_leaf_chunk_data =
                                phys::ZapLeafChunkData::from_decoder(&decoder)?;

                            // Always big endian.
                            let dec = phys::EndianDecoder::from_bytes(
                                &zap_leaf_chunk_data.data,
                                phys::EndianOrder::Big,
                            );
                            value_u64 = Some(dec.get_u64()?);
                        } else if zap_leaf_chunk_entry.value_int_size == 1 {
                            let mut value_bytes = vec![0; todo];
                            let mut done = 0;

                            while todo > 0 {
                                decoder.seek(offset + value_chunk * phys::ZapLeafChunk::SIZE)?;
                                let zap_leaf_chunk_data =
                                    phys::ZapLeafChunkData::from_decoder(&decoder)?;

                                let can_do = core::cmp::min(todo, zap_leaf_chunk_data.data.len());
                                value_bytes[done..done + can_do]
                                    .copy_from_slice(&zap_leaf_chunk_data.data[0..can_do]);

                                todo -= can_do;
                                done += can_do;

                                if todo > 0 {
                                    value_chunk = usize::from(zap_leaf_chunk_data.next.unwrap());
                                }
                            }

                            let value = match core::str::from_utf8(&value_bytes) {
                                Ok(v) => v.to_string(),
                                Err(_) => bytes_to_hex(&value_bytes).to_string(),
                            };

                            value_str = Some(value);
                        } else {
                            // todo!("Implement: {name} {:?}", zap_leaf_chunk_entry);
                        }

                        if let Some(v) = value_u64 {
                            println!("{:width$}{} -> {}", "", name, v, width = depth,);
                        } else if let Some(v) = value_str {
                            println!("{:width$}{} -> {}", "", name, v, width = depth,);
                        } else {
                            println!("{:width$}{} -> ???", "", name, width = depth,);
                        }

                        if zap_leaf_chunk_entry.next.is_some() {
                            todo!("Implement");
                        }
                    }
                }
            } else {
                todo!("Implement ZapMegaHeader with non embedded table");
            }

            Ok(())
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

fn dump_dsl_dataset(
    blk_devs: &[userspace::BlockDevice],
    object_set: &phys::ObjectSet,
    depth: usize,
) -> Result<(), Box<dyn Error>> {
    println!(
        "{:width$}=================== {} ===================",
        "",
        object_set.os_type,
        width = depth
    );

    for block_id in 0..object_set.dnode.max_block_id + 1 {
        let block_opt = dnode_read_block(blk_devs, &object_set.dnode, block_id)?;

        if let Some((order, block_bytes)) = block_opt {
            let mut object_id = (block_bytes.len() / phys::Dnode::SIZE) * (block_id as usize);
            let decoder = phys::EndianDecoder::from_bytes(&block_bytes, order);
            while !decoder.is_empty() {
                if let Some(dnode) = phys::Dnode::from_decoder(&decoder)? {
                    let dmu_str = format!("{}", dnode.dmu);
                    println!(
                        "{:width$}{object_id:03}: {dmu_str:<24} {}",
                        "",
                        dnode.bonus_type,
                        width = depth
                    );

                    let is_zap = matches!(
                        dnode.dmu,
                        phys::DmuType::ObjectDirectory
                            | phys::DmuType::DslDirectoryChildMap
                            | phys::DmuType::DslDsSnapshotMap
                            | phys::DmuType::DslProperties
                            | phys::DmuType::DirectoryContents
                            | phys::DmuType::MasterNode
                            | phys::DmuType::UnlinkedSet
                            | phys::DmuType::ZvolProperty
                            | phys::DmuType::ZapOther
                            | phys::DmuType::ErrorLog
                            | phys::DmuType::PoolProperties
                            | phys::DmuType::DslPermissions
                            | phys::DmuType::NextClones
                            | phys::DmuType::ScanQueue
                            | phys::DmuType::UserGroupUsed
                            | phys::DmuType::UserGroupQuota
                            | phys::DmuType::UserRefs
                            | phys::DmuType::DdtZap
                            | phys::DmuType::DdtStats
                            | phys::DmuType::SystemAttributeMasterNode
                            | phys::DmuType::SystemAttributeRegistration
                            | phys::DmuType::SystemAttributeLayouts
                            | phys::DmuType::ScanXlate
                            | phys::DmuType::DeadList
                            | phys::DmuType::DslClones
                    );

                    let decoder = phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);

                    match dnode.bonus_type {
                        phys::DmuType::None => (),
                        phys::DmuType::DslDirectory => {
                            let dsl_dir = phys::DslDirectory::from_decoder(&decoder)?;
                            println!(
                                    "{:width$}dsl_dir: head_dataset_obj: {:?}, parent_directory_obj: {:?}, origin_dataset_obj: {:?}, child_directory_zap_obj: {:?}, properties_zap_obj: {:?}, delegation_zap_obj: {:?}",
                                    "",
                                    dsl_dir.head_dataset_obj,
                                    dsl_dir.parent_directory_obj,
                                    dsl_dir.origin_dataset_obj,
                                    dsl_dir.child_directory_zap_obj,
                                    dsl_dir.properties_zap_obj,
                                    dsl_dir.delegation_zap_obj,
                                    width = depth + 4
                                );
                        }
                        phys::DmuType::DslDataSet => {
                            let dsl_data_set = phys::DslDataSet::from_decoder(&decoder)?;
                            println!(
                                "{:width$}dsl_data_set: {:?}",
                                "",
                                dsl_data_set,
                                width = depth + 4
                            );

                            if let Some(ptr) = dsl_data_set.block_pointer {
                                let object_set_bytes = block_pointer_read(blk_devs, &ptr)?;
                                let decoder =
                                    phys::EndianDecoder::from_bytes(&object_set_bytes, ptr.order());
                                let object_set = phys::ObjectSet::from_decoder(&decoder)?;

                                dump_dsl_dataset(blk_devs, &object_set, depth + 4)?;
                            }
                        }
                        phys::DmuType::BpObjectHeader => {}
                        phys::DmuType::PackedNvListSize => {}
                        phys::DmuType::SpaHistoryOffsets => {
                            let decoder =
                                phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                            print!("{:width$}", "", width = depth + 4);
                            print!("pool_create_len: {}", decoder.get_u64()?);
                            print!(", phys_max_off: {}", decoder.get_u64()?);
                            print!(", bof: {}", decoder.get_u64()?);
                            print!(", eof: {}", decoder.get_u64()?);
                            println!(", records_lost: {}", decoder.get_u64()?);
                        }
                        phys::DmuType::SpaceMapHeader => (),
                        phys::DmuType::Znode => {
                            let decoder =
                                phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                            let znode = phys::Znode::from_decoder(&decoder)?;
                            println!("{:width$}Znode: {:?}", "", znode, width = depth + 4);
                            match znode.acl {
                                phys::Acl::V0(acl) => {
                                    for i in 0..acl.count as usize {
                                        println!(
                                            "{:width$}  AceV0: {:?}",
                                            "",
                                            acl.aces[i],
                                            width = depth + 4
                                        );
                                    }
                                }
                                phys::Acl::V1(acl) => {
                                    let decoder = phys::EndianDecoder::from_bytes(
                                        &acl.aces[0..(acl.size) as usize],
                                        order,
                                    );
                                    let iterator = phys::AceV1Iterator::from_decoder(&decoder)?;
                                    for (index, ace_res) in iterator.enumerate() {
                                        let ace = ace_res?;
                                        assert!(index < acl.count.into());
                                        println!(
                                            "{:width$}  AceV1: {:?}",
                                            "",
                                            ace,
                                            width = depth + 4
                                        );
                                    }
                                }
                            }
                        }
                        phys::DmuType::DeadListHeader => (),
                        phys::DmuType::SystemAttribute => (),
                        _ => todo!("bonus type {} {:?}", dnode.bonus_type, dnode),
                    }

                    if is_zap {
                        dnode_dump_zap(blk_devs, &dnode, depth + 4)?;
                        println!();
                    } else if let phys::DmuType::PackedNvList = dnode.dmu {
                        let decoder = phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                        let nv_list_size = decoder.get_u64()?;
                        let nv_list_size = usize::try_from(nv_list_size)?;
                        let (_endian, nv_list_bytes) =
                            dnode_read_block(blk_devs, &dnode, 0)?.unwrap();
                        // TODO: handle multiple blocks
                        assert!(nv_list_bytes.len() >= nv_list_size);

                        let nv_decoder = phys::NvList::from_bytes(&nv_list_bytes)?;
                        dump_nv_list(&nv_decoder, depth + 4)?;
                    } else if let phys::DmuType::SpaceMap = dnode.dmu {
                        let decoder = phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                        let sm_header = phys::SpaceMapHeader::from_decoder(&decoder)?;
                        println!(
                            "{:width$} SpaceMapHeader: {sm_header:?}",
                            "",
                            width = depth + 4
                        );

                        let mut idx: usize = 0;
                        let mut block_id = 0;
                        let mut todo = sm_header.length_bytes;
                        while todo > 0 {
                            let (order, data) =
                                dnode_read_block(blk_devs, &dnode, block_id)?.unwrap();
                            let mut data_to_process = &data[0..data.len()];

                            if data.len() as u64 > todo {
                                data_to_process = &data[0..(todo as usize)];
                            }
                            todo -= data_to_process.len() as u64;

                            let decoder = phys::EndianDecoder::from_bytes(data_to_process, order);

                            while !decoder.is_empty() {
                                let space_map_entry = phys::SpaceMapEntry::from_decoder(&decoder)?;
                                println!(
                                    "{:width$}  {idx:03}: {space_map_entry:?}",
                                    "",
                                    width = depth + 4
                                );

                                idx += 1;
                            }

                            block_id += 1;
                        }

                        println!("{:width$} Dnode: {:?}", "", dnode, width = depth + 4);
                        println!();
                    } else if let phys::DmuType::DslDataSet = dnode.dmu {
                    } else if let phys::DmuType::DslDirectory = dnode.dmu {
                        assert!(dnode.pointers().len() == 1);
                        assert!(dnode.pointers()[0].is_none());
                    } else if let phys::DmuType::PlainFileContents = dnode.dmu {
                        if let Some((_order, data)) = dnode_read_block(blk_devs, &dnode, 0)? {
                            let mut size = data.len();
                            match dnode.bonus_type {
                                phys::DmuType::Znode => {
                                    let decoder =
                                        phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                                    let znode = phys::Znode::from_decoder(&decoder)?;
                                    if znode.size < (size as u64) {
                                        size = znode.size as usize;
                                    }
                                }
                                phys::DmuType::SystemAttribute => (),
                                _ => todo!(
                                    "Implement other PlainFileContents bonus {}",
                                    dnode.bonus_type
                                ),
                            };

                            for block_id in 0..dnode.max_block_id + 1 {
                                dnode_read_block(blk_devs, &dnode, block_id)?;
                            }

                            println!("File size: {size}");
                            // let stdout = io::stdout();
                            // let mut handle = stdout.lock();
                            // handle.write_all(&data[0..size])?;
                            // handle.flush()?;
                            // if !data.is_empty() {
                            //     println!();
                            // }
                        }
                    } else if let phys::DmuType::BpObject = dnode.dmu {
                        let decoder = phys::EndianDecoder::from_bytes(dnode.bonus_used(), order);
                        let bp_header = phys::BpObjectHeader::from_decoder(&decoder)?;
                        println!(
                            "{:width$} BpObjectHeader: {bp_header:?}",
                            "",
                            width = depth + 4
                        );

                        let mut bp_logical_sectors = 0;
                        let mut bp_physical_sectors = 0;
                        let mut dva_allocated = 0;

                        for idx in 0..bp_header.block_pointers_count {
                            let (order, bp_bytes) =
                                dnode_read_object(blk_devs, &dnode, idx, phys::BlockPointer::SIZE)?
                                    .unwrap();
                            let decoder = phys::EndianDecoder::from_bytes(&bp_bytes, order);
                            let bp = phys::BlockPointerRegular::from_decoder(&decoder)?;

                            bp_logical_sectors += bp.logical_sectors;
                            bp_physical_sectors += bp.physical_sectors;

                            for dva in bp.dvas.iter().flatten() {
                                dva_allocated += dva.allocated;
                            }

                            println!(
                                "{:width$} {idx:02} BlockPointer: {bp:?}",
                                "",
                                width = depth + 4
                            );
                        }

                        println!(
                                "{:width$}bp_phys:{bp_physical_sectors} bp_logic:{bp_logical_sectors} dva_alloc: {dva_allocated}",
                                "",
                                width = depth + 4
                            );
                    } else if let phys::DmuType::ObjectArray = dnode.dmu {
                        let (order, data) = dnode_read_block(blk_devs, &dnode, 0)?.unwrap();
                        let decoder = phys::EndianDecoder::from_bytes(&data, order);
                        let mut idx = 0;
                        while !decoder.is_empty() {
                            let v = decoder.get_u64()?;
                            println!("{:width$} {idx:03}: {v:03}", "", width = depth + 4);
                            idx += 1;
                        }
                    } else {
                        println!("{:width$}SKIPPING CONTENTS", "", width = depth);
                        println!();
                    }
                }

                object_id += 1;
            }
        }
    }

    println!(
        "{:width$}======================================",
        "",
        width = depth
    );

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

fn dump_root(
    blk_devs: &[userspace::BlockDevice],
    nv: &phys::NvList,
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
    println!("guid_sum: {}", uberblock.guid_sum);
    println!();

    ////////////////////////////////////
    // let vdev_tree = nv.get_nv_list("vdev_tree")?.unwrap();
    let version = nv.get_u64("version")?.unwrap();
    // let ashift = vdev_tree.get_u64("ashift")?.unwrap();
    let label_txg = nv.get_u64("txg")?.unwrap();

    assert!(uberblock.txg >= label_txg);
    assert_eq!(u64::from(uberblock.version), version);

    ////////////////////////////////////
    // Read Meta ObjectSet.
    let meta_object_set_bytes = block_pointer_read(blk_devs, &uberblock.ptr)?;
    let decoder = phys::EndianDecoder::from_bytes(&meta_object_set_bytes, uberblock.ptr.order());
    let meta_object_set = phys::ObjectSet::from_decoder(&decoder)?;
    println!("os zil: {:?}", meta_object_set.zil_header);
    dump_dsl_dataset(blk_devs, &meta_object_set, 0)?;

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

fn dump_nv_list(list: &phys::NvList, depth: usize) -> Result<(), Box<dyn Error>> {
    for nv_pair_res in list {
        let nv_pair = nv_pair_res?;

        print!("{:width$}", "", width = depth);

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
            phys::NvDecodedDataValue::ByteArray(array) => {
                print!(": [");
                for (idx, b) in array.iter().enumerate() {
                    if idx != 0 {
                        print!(", {b:#02x}");
                    } else {
                        print!("{b:#02x}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int16Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint16Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int32Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint32Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int64Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint64Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::StringArray(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
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
                dump_nv_list(&v, depth + 4)?;
            }
            phys::NvDecodedDataValue::NvListArray(array) => {
                println!();
                for res in &array {
                    let list = res?;
                    dump_nv_list(&list, depth + 4)?;
                }
            }
            phys::NvDecodedDataValue::BooleanValue(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Int8(v) => println!(": {v}"),
            phys::NvDecodedDataValue::Uint8(v) => println!(": {v}"),
            phys::NvDecodedDataValue::BooleanArray(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Int8Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
                    if idx != 0 {
                        print!(", {n}");
                    } else {
                        print!("{n}");
                    }
                }
                println!("]");
            }
            phys::NvDecodedDataValue::Uint8Array(array) => {
                print!(": [");
                for (idx, res) in array.iter().enumerate() {
                    let n = res?;
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

    // Open block devices.
    let mut block_devices = Vec::new();

    for path in &args[1..] {
        let block_device = userspace::BlockDevice::open(path)?;
        println!("Sectors: {}", block_device.sectors);
        block_devices.push(block_device);
    }

    let block_device = &block_devices[0];

    ////////////////////////////////////
    // Read boot block.
    let boot_block_bytes = &mut vec![0; phys::BootBlock::SIZE];
    block_device.read(boot_block_bytes, phys::BootBlock::BLOCK_DEVICE_OFFSET)?;

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
    for (label_idx, label_offset) in label_sectors.into_iter().enumerate() {
        println!();
        println!("Label {label_idx}");
        println!();

        ////////////////////////////////
        // Read blank.
        let blank_bytes = &mut vec![0; phys::LabelBlank::SIZE];
        block_device.read(blank_bytes, label_offset + phys::LabelBlank::LABEL_OFFSET)?;
        let blank = phys::LabelBlank::from_bytes(&blank_bytes[..].try_into().unwrap())?;
        if !is_array_empty(&blank.payload) {
            println!("Blank is not empty");
        }

        ////////////////////////////////
        // Read boot header.
        let boot_header_bytes = &mut vec![0; phys::LabelBootHeader::SIZE];
        let boot_header_offset = label_offset + phys::LabelBootHeader::LABEL_OFFSET;
        block_device.read(boot_header_bytes, boot_header_offset)?;
        let boot_header = phys::LabelBootHeader::from_bytes(
            &boot_header_bytes[..].try_into().unwrap(),
            boot_header_offset,
            &mut sha256,
        )?;
        if !is_array_empty(&boot_header.payload) {
            println!("LabelBootHeader is not empty");
        }

        ////////////////////////////////
        // Read NV pairs.
        let nv_pairs_bytes = &mut vec![0; phys::LabelNvPairs::SIZE];
        let nv_pairs_offset = label_offset + phys::LabelNvPairs::LABEL_OFFSET;
        block_device.read(nv_pairs_bytes, nv_pairs_offset)?;
        let nv_pairs = phys::LabelNvPairs::from_bytes(
            &nv_pairs_bytes[..].try_into().unwrap(),
            nv_pairs_offset,
            &mut sha256,
        )?;

        let nv_decoder = phys::NvList::from_bytes(&nv_pairs.payload)?;
        dump_nv_list(&nv_decoder, 0)?;

        ////////////////////////////////
        // Get the ashift value for the vdev_tree.
        let vdev_tree = nv_decoder.get_nv_list("vdev_tree")?.unwrap();
        let spa_version = phys::SpaVersion::try_from(nv_decoder.get_u64("version")?.unwrap())?;
        let ashift = vdev_tree.get_u64("ashift")?.unwrap();
        let label_txg = nv_decoder.get_u64("txg")?.unwrap();

        let mut max_uberblock: Option<phys::UberBlock> = None;

        ////////////////////////////////
        // Read UberBlocks.
        let uberblock_size =
            1 << phys::UberBlock::get_shift_from_version_ashift(spa_version, ashift);

        for i in 0..phys::UberBlock::TOTAL_SIZE / uberblock_size {
            let uber_offset = label_offset
                + phys::UberBlock::LABEL_OFFSET
                + (((i * uberblock_size) >> phys::SECTOR_SHIFT) as u64);
            let uber_bytes = &mut vec![0; uberblock_size];
            block_device.read(uber_bytes, uber_offset)?;

            let uber_res = phys::UberBlock::from_bytes(uber_bytes, uber_offset, &mut sha256);

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
            dump_root(&block_devices, &nv_decoder, &uberblock)?;
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
