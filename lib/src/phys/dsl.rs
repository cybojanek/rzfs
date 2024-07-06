// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError, EndianDecodeError,
    EndianDecoder, EndianEncodeError, EndianEncoder,
};

////////////////////////////////////////////////////////////////////////////////

/// Breakdown of space used by [`DslDirectory`].
#[derive(Debug)]
pub struct DslDirectoryUsedBreakdown {
    /// ???
    pub head: u64,

    /// ???
    pub snapshot: u64,

    /// ???
    pub child: u64,

    /// ???
    pub child_reserved: u64,

    /// ???
    pub referenced_reservation: u64,
}

impl DslDirectoryUsedBreakdown {
    /// Byte size of an encoded [`DslDirectoryUsedBreakdown`].
    pub const SIZE: usize = 40;
}

/** Dataset Snapshot Layer (DSL) Directory.
 *
 * ### Byte layout.
 *
 * - Bytes: 256
 *
 * ```text
 * +---------------------+------+-------------+
 * | Field               | Size | SPA Version |
 * +---------------------+------+-------------+
 * | creation time       |    8 |           1 |
 * | head dataset obj    |    8 |           1 |
 * | parent obj          |    8 |           1 |
 * | origin obj          |    8 |           1 |
 * | child dir zap obj   |    8 |           1 |
 * | used bytes          |    8 |           1 |
 * | compressed bytes    |    8 |           1 |
 * | uncompressed bytes  |    8 |           1 |
 * | quota               |    8 |           1 |
 * | reserved            |    8 |           1 |
 * | properties zap obj  |    8 |           1 |
 * | delegation zap obj  |    8 |           8 |
 * | flags               |    8 |          13 |
 * | used head           |    8 |          13 |
 * | used snap           |    8 |          13 |
 * | used child          |    8 |          13 |
 * | used child reserved |    8 |          13 |
 * | used ref reserved   |    8 |          13 |
 * | clones              |    8 |          26 |
 * | padding             |  104 |             |
 * +---------------------+------+-------------+
 * ```
 */
#[derive(Debug)]
pub struct DslDirectory {
    /// Creation  time since January 1st, 1970 (GMT).
    pub creation_time: u64,

    /** Object number of [`DslDataSet`] for this [`DslDirectory`].
     *
     * Will be [None] for:
     * - `$MOS` [`DslDirectory`].
     */
    pub head_dataset_obj: Option<u64>,

    /** Object number of parent [`crate::phys::DslDirectory`].
     *
     * Will be [None] for:
     * - `root_dataset` [`DslDirectory`].
     */
    pub parent_directory_obj: Option<u64>,

    /** Object number of origin [`DslDataSet`].
     *
     * - Will be [None] for non clones.
     * - Will be [Some] for clones.
     */
    pub origin_dataset_obj: Option<u64>,

    /// Object number of [`crate::phys::DmuType::DslDirectoryChildMap`] ZAP for this [`DslDirectory`].
    pub child_directory_zap_obj: u64,

    /// ???
    pub used_bytes: u64,

    /// ???
    pub compressed_bytes: u64,

    /// ???
    pub uncompressed_bytes: u64,

    /// ???
    pub quota: u64,

    /// ???
    pub reserved: u64,

    /// Object number of [`crate::phys::DmuType::DslProperties`] for this [`DslDirectory`].
    pub properties_zap_obj: u64,

    /// Object number of [`crate::phys::DmuType::DslPermissions`] for this [`DslDirectory`].
    pub delegation_zap_obj: Option<u64>,

    /// Breakdown of `used_bytes` for this [`DslDirectory`].
    pub used_breakdown: Option<DslDirectoryUsedBreakdown>,

    /// ???
    pub clones: u64,
}

impl DslDirectory {
    /// Byte size of an encoded [`DslDirectory`].
    pub const SIZE: usize = 256;

    const PADDING_SIZE: usize = 104;

    /// [`DslDirectory`] contains a breakdown of used space.
    const FLAG_USED_BREAKDOWN: u64 = 1 << 0;

    /// All flags for [`DslDirectory`] flags.
    const FLAG_ALL: u64 = DslDirectory::FLAG_USED_BREAKDOWN;

    /** Decodes a [`DslDirectory`].
     *
     * # Errors
     *
     * Returns [`DslDirectoryDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<DslDirectory, DslDirectoryDecodeError> {
        ////////////////////////////////
        // Decode values.
        let creation_time = decoder.get_u64()?;

        let head_dataset_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let parent_directory_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let origin_dataset_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let child_directory_zap_obj = match decoder.get_u64()? {
            0 => return Err(DslDirectoryDecodeError::MissingChildDirectory {}),
            v => v,
        };

        let used_bytes = decoder.get_u64()?;
        let compressed_bytes = decoder.get_u64()?;
        let uncompressed_bytes = decoder.get_u64()?;
        let quota = decoder.get_u64()?;
        let reserved = decoder.get_u64()?;

        let properties_zap_obj = match decoder.get_u64()? {
            0 => return Err(DslDirectoryDecodeError::MissingProperties {}),
            v => v,
        };

        let delegation_zap_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;
        if (flags & DslDirectory::FLAG_ALL) != flags {
            return Err(DslDirectoryDecodeError::Flags { flags });
        }

        let used_breakdown = if (flags & DslDirectory::FLAG_USED_BREAKDOWN) == 0 {
            decoder.skip_zero_padding(DslDirectoryUsedBreakdown::SIZE)?;
            None
        } else {
            Some(DslDirectoryUsedBreakdown {
                head: decoder.get_u64()?,
                snapshot: decoder.get_u64()?,
                child: decoder.get_u64()?,
                child_reserved: decoder.get_u64()?,
                referenced_reservation: decoder.get_u64()?,
            })
        };

        let clones = decoder.get_u64()?;

        ////////////////////////////////
        // Skip padding.
        decoder.skip_zero_padding(DslDirectory::PADDING_SIZE)?;

        ////////////////////////////////
        // Success.
        Ok(DslDirectory {
            creation_time,
            head_dataset_obj,
            parent_directory_obj,
            origin_dataset_obj,
            child_directory_zap_obj,
            used_bytes,
            compressed_bytes,
            uncompressed_bytes,
            quota,
            reserved,
            properties_zap_obj,
            delegation_zap_obj,
            used_breakdown,
            clones,
        })
    }

    /** Encodes a [`DslDirectory`].
     *
     * # Errors
     *
     * Returns [`DslDirectoryEncodeError`] in case of encoding error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), DslDirectoryEncodeError> {
        ////////////////////////////////
        // Encode values.
        encoder.put_u64(self.creation_time)?;
        encoder.put_u64(self.head_dataset_obj.unwrap_or(0))?;
        encoder.put_u64(self.parent_directory_obj.unwrap_or(0))?;
        encoder.put_u64(self.origin_dataset_obj.unwrap_or(0))?;

        if self.child_directory_zap_obj == 0 {
            return Err(DslDirectoryEncodeError::MissingChildDirectory {});
        }
        encoder.put_u64(self.child_directory_zap_obj)?;

        encoder.put_u64(self.used_bytes)?;
        encoder.put_u64(self.compressed_bytes)?;
        encoder.put_u64(self.uncompressed_bytes)?;
        encoder.put_u64(self.quota)?;
        encoder.put_u64(self.reserved)?;

        encoder.put_u64(self.properties_zap_obj)?;
        if self.properties_zap_obj == 0 {
            return Err(DslDirectoryEncodeError::MissingProperties {});
        }

        encoder.put_u64(self.delegation_zap_obj.unwrap_or(0))?;

        ////////////////////////////////
        // Encode flags.
        let flags = if self.used_breakdown.is_none() {
            0
        } else {
            DslDirectory::FLAG_USED_BREAKDOWN
        };
        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode used.
        match &self.used_breakdown {
            Some(used_breakdown) => {
                encoder.put_u64(used_breakdown.head)?;
                encoder.put_u64(used_breakdown.snapshot)?;
                encoder.put_u64(used_breakdown.child)?;
                encoder.put_u64(used_breakdown.child_reserved)?;
                encoder.put_u64(used_breakdown.referenced_reservation)?;
            }
            None => encoder.put_zero_padding(DslDirectoryUsedBreakdown::SIZE)?,
        }

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(DslDirectory::PADDING_SIZE)?;

        Ok(())
    }
}

/// [`DslDirectory`] decode error.
#[derive(Debug)]
pub enum DslDirectoryDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown flags.
    Flags {
        /// Flags.
        flags: u64,
    },

    /// Child directory ZAP object is 0.
    MissingChildDirectory {},

    /// Properties ZAP object is 0.
    MissingProperties {},
}

impl From<EndianDecodeError> for DslDirectoryDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        DslDirectoryDecodeError::Endian { err }
    }
}

impl fmt::Display for DslDirectoryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DslDirectoryDecodeError::Endian { err } => {
                write!(f, "DslDirectory decode error | {err}")
            }
            DslDirectoryDecodeError::Flags { flags } => {
                write!(f, "DslDirectory decode error, unknown flags {flags}")
            }
            DslDirectoryDecodeError::MissingChildDirectory {} => {
                write!(
                    f,
                    "DslDirectory decode error, child directory ZAP object is 0"
                )
            }
            DslDirectoryDecodeError::MissingProperties {} => {
                write!(f, "DslDirectory decode error, properties ZAP object is 0")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DslDirectoryDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DslDirectoryDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`DslDirectory`] encode error.
#[derive(Debug)]
pub enum DslDirectoryEncodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Child directory ZAP object is 0.
    MissingChildDirectory {},

    /// Properties ZAP object is 0.
    MissingProperties {},
}

impl From<EndianEncodeError> for DslDirectoryEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        DslDirectoryEncodeError::Endian { err }
    }
}

impl fmt::Display for DslDirectoryEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DslDirectoryEncodeError::Endian { err } => {
                write!(f, "DslDirectory encode error | {err}")
            }
            DslDirectoryEncodeError::MissingChildDirectory {} => {
                write!(
                    f,
                    "DslDirectory encode error, child directory ZAP object is 0"
                )
            }
            DslDirectoryEncodeError::MissingProperties {} => {
                write!(f, "DslDirectory encode error, properties ZAP object is 0")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DslDirectoryEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DslDirectoryEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// DSL data set.
#[derive(Debug)]
pub struct DslDataSet {
    /// Object number of [`DslDirectory`] for this [`DslDataSet`].
    pub dir_obj: u64,

    /** Object number of previous [`DslDataSet`] snapshot for this [`DslDataSet`].
     *
     * Will be [None] for:
     * - A [`DslDataSet`] with no snapshots.
     * - The first (oldest) [`DslDataSet`] snapshot.
     */
    pub prev_snapshot_obj: Option<u64>,

    /** Transaction group number of the previous [`DslDataSet`] snapshot for this [`DslDataSet`].
     *
     * Will be [None] when `prev_snapshot_obj` is [None], and [Some], when
     * `prev_snapshot_obj` is [Some].
     */
    pub prev_snapshot_txg: Option<u64>,

    /** Object number of next [`DslDataSet`] snapshot for this [`DslDataSet`].
     *
     * Will be [None] for:
     * - A [`DslDataSet`] with no snapshots.
     * - The live (youngest) [`DslDataSet`].
     */
    pub next_snapshot_obj: Option<u64>,

    /** Object number of [`crate::phys::DmuType::DslDsSnapshotMap`] for this [`DslDataSet`].
     *
     * Will be [Some] for the top level [`DslDataSet`] that is part of the
     * `root_dataset` [`DslDirectory`].
     *
     * Will be [None] for all others.
     */
    pub snapshot_names_zap_obj: Option<u64>,

    /// Number of clones or snapshots referencing this [`DslDataSet`].
    pub num_children: u64,

    /// Creation time in seconds since January 1st, 1970 (GMT).
    pub creation_time: u64,

    /// Transaction group number when this [`DslDataSet`] was created.
    pub creation_txg: u64,

    /// Object number of [`crate::phys::DmuType::BpObject`] with deleted objects.
    pub deadlist_obj: u64,

    /// ???
    pub referenced_bytes: u64,

    /// ???
    pub compressed_bytes: u64,

    /// ???
    pub uncompressed_bytes: u64,

    /// ???
    pub unique_bytes: u64,

    /// ???
    pub fsid_guid: u64,

    /// ???
    pub guid: u64,

    /// ???
    pub flags: u64,

    /// ???
    pub block_pointer: Option<BlockPointer>,

    /// ???
    pub next_clones_obj: u64,

    /** Object number of [`crate::phys::DmuType::DslProperties`] for this [`DslDataSet`] snapshot.
     *
     * Will be [None] for:
     * - A [`DslDataSet`] that is not a snapshot.
     * - A snapshot with no properties, even though [`DslDirectory`] always has
     *   a properties object, even when empty.
     */
    pub snapshot_props_obj: Option<u64>,

    /// ???
    pub user_refs_obj: u64,
}

impl DslDataSet {
    /// Byte size of an encoded [`DslDataSet`].
    pub const SIZE: usize = 320;

    const PADDING_SIZE: usize = 40;

    /// ???
    const FLAG_INCONSISTENT: u64 = (1 << 0);

    /// ???
    const FLAG_NO_PROMOTE: u64 = (1 << 1);

    /// ???
    const FLAG_UNIQUE_ACCURATE: u64 = (1 << 2);

    /// ???
    const FLAG_DEFER_DESTROY: u64 = (1 << 3);

    /// ???
    const FLAG_CASE_INSENSITIVE_FS: u64 = (1 << 16);

    /// ???
    const FLAG_NO_DIRTY: u64 = (1 << 24);

    /// All flags for [`DslDataSet`] flags.
    const FLAG_ALL: u64 = DslDataSet::FLAG_INCONSISTENT
        | DslDataSet::FLAG_NO_PROMOTE
        | DslDataSet::FLAG_UNIQUE_ACCURATE
        | DslDataSet::FLAG_DEFER_DESTROY
        | DslDataSet::FLAG_CASE_INSENSITIVE_FS
        | DslDataSet::FLAG_NO_DIRTY;

    /** Decodes a [`DslDataSet`].
     *
     * # Errors
     *
     * Returns [`DslDataSetDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<DslDataSet, DslDataSetDecodeError> {
        ////////////////////////////////
        // Decode values.
        let dir_obj = match decoder.get_u64()? {
            0 => return Err(DslDataSetDecodeError::MissingDirectory {}),
            v => v,
        };

        let prev_snapshot_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let prev_snapshot_txg = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        if prev_snapshot_obj.is_none() != prev_snapshot_txg.is_none() {
            return Err(DslDataSetDecodeError::PreviousSnapshot {
                prev_snapshot_obj: prev_snapshot_obj.unwrap_or(0),
                prev_snapshot_txg: prev_snapshot_txg.unwrap_or(0),
            });
        }

        let next_snapshot_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let snapshot_names_zap_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let num_children = decoder.get_u64()?;
        let creation_time = decoder.get_u64()?;
        let creation_txg = decoder.get_u64()?;
        let deadlist_obj = decoder.get_u64()?;
        let referenced_bytes = decoder.get_u64()?;
        let compressed_bytes = decoder.get_u64()?;
        let uncompressed_bytes = decoder.get_u64()?;
        let unique_bytes = decoder.get_u64()?;
        let fsid_guid = decoder.get_u64()?;
        let guid = decoder.get_u64()?;

        let flags = decoder.get_u64()?;
        if (flags & DslDataSet::FLAG_ALL) != flags {
            return Err(DslDataSetDecodeError::Flags { flags });
        }

        let block_pointer = BlockPointer::from_decoder(decoder)?;
        let next_clones_obj = decoder.get_u64()?;

        let snapshot_props_obj = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };

        let user_refs_obj = decoder.get_u64()?;

        decoder.skip_zero_padding(DslDataSet::PADDING_SIZE)?;

        Ok(DslDataSet {
            dir_obj,
            prev_snapshot_obj,
            prev_snapshot_txg,
            next_snapshot_obj,
            snapshot_names_zap_obj,
            num_children,
            creation_time,
            creation_txg,
            deadlist_obj,
            referenced_bytes,
            compressed_bytes,
            uncompressed_bytes,
            unique_bytes,
            fsid_guid,
            guid,
            flags,
            block_pointer,
            next_clones_obj,
            snapshot_props_obj,
            user_refs_obj,
        })
    }

    /** Encodes a [`DslDataSet`].
     *
     * # Errors
     *
     * Returns [`DslDataSetEncodeError`] in case of encoding error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), DslDataSetEncodeError> {
        if self.dir_obj == 0 {
            return Err(DslDataSetEncodeError::MissingDirectory {});
        }
        encoder.put_u64(self.dir_obj)?;

        if (self.prev_snapshot_obj.unwrap_or(0) == 0) != (self.prev_snapshot_txg.unwrap_or(0) == 0)
        {
            return Err(DslDataSetEncodeError::PreviousSnapshot {
                prev_snapshot_obj: self.prev_snapshot_obj.unwrap_or(0),
                prev_snapshot_txg: self.prev_snapshot_txg.unwrap_or(0),
            });
        }
        encoder.put_u64(self.prev_snapshot_obj.unwrap_or(0))?;
        encoder.put_u64(self.prev_snapshot_txg.unwrap_or(0))?;

        encoder.put_u64(self.next_snapshot_obj.unwrap_or(0))?;
        encoder.put_u64(self.snapshot_names_zap_obj.unwrap_or(0))?;
        encoder.put_u64(self.num_children)?;
        encoder.put_u64(self.creation_time)?;
        encoder.put_u64(self.creation_txg)?;
        encoder.put_u64(self.deadlist_obj)?;
        encoder.put_u64(self.referenced_bytes)?;
        encoder.put_u64(self.compressed_bytes)?;
        encoder.put_u64(self.uncompressed_bytes)?;
        encoder.put_u64(self.unique_bytes)?;
        encoder.put_u64(self.fsid_guid)?;
        encoder.put_u64(self.guid)?;
        encoder.put_u64(self.flags)?;
        BlockPointer::option_to_encoder(&self.block_pointer, encoder)?;
        encoder.put_u64(self.next_clones_obj)?;
        encoder.put_u64(self.snapshot_props_obj.unwrap_or(0))?;
        encoder.put_u64(self.user_refs_obj)?;

        encoder.put_zero_padding(DslDataSet::PADDING_SIZE)?;

        Ok(())
    }
}

/// [`DslDataSet`] decode error.
#[derive(Debug)]
pub enum DslDataSetDecodeError {
    /// [`BlockPointer`] decode error.
    BlockPointer {
        /// Error.
        err: BlockPointerDecodeError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown flags.
    Flags {
        /// Flags.
        flags: u64,
    },

    /// Missing [`DslDirectory`] object number.
    MissingDirectory {},

    /// Previous snapshot object and transaction group errorr.
    PreviousSnapshot {
        /// Previous snapshot object.
        prev_snapshot_obj: u64,

        /// Previous snapshot transaction group.
        prev_snapshot_txg: u64,
    },
}

impl From<BlockPointerDecodeError> for DslDataSetDecodeError {
    fn from(err: BlockPointerDecodeError) -> Self {
        DslDataSetDecodeError::BlockPointer { err }
    }
}

impl From<EndianDecodeError> for DslDataSetDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        DslDataSetDecodeError::Endian { err }
    }
}

impl fmt::Display for DslDataSetDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DslDataSetDecodeError::BlockPointer { err } => {
                write!(f, "DslDataSet decode error | {err}")
            }
            DslDataSetDecodeError::Endian { err } => {
                write!(f, "DslDataSet decode error | {err}")
            }
            DslDataSetDecodeError::Flags { flags } => {
                write!(f, "ObjectSet decode error, unknown flags {flags:#016x}")
            }
            DslDataSetDecodeError::MissingDirectory {} => {
                write!(f, "DslDataSet decode error, missing directory object")
            }
            DslDataSetDecodeError::PreviousSnapshot {
                prev_snapshot_obj,
                prev_snapshot_txg,
            } => {
                write!(f, "DslDataSet decode error, previous snapshot, obj: {prev_snapshot_obj} txg: {prev_snapshot_txg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DslDataSetDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DslDataSetDecodeError::BlockPointer { err } => Some(err),
            DslDataSetDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`DslDataSet`] encode error.
#[derive(Debug)]
pub enum DslDataSetEncodeError {
    /// [`BlockPointer`] encode error.
    BlockPointer {
        /// Error.
        err: BlockPointerEncodeError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Missing [`DslDirectory`] object number.
    MissingDirectory {},

    /// Previous snapshot object and transaction group errorr.
    PreviousSnapshot {
        /// Previous snapshot object.
        prev_snapshot_obj: u64,

        /// Previous snapshot transaction group.
        prev_snapshot_txg: u64,
    },
}

impl From<BlockPointerEncodeError> for DslDataSetEncodeError {
    fn from(err: BlockPointerEncodeError) -> Self {
        DslDataSetEncodeError::BlockPointer { err }
    }
}

impl From<EndianEncodeError> for DslDataSetEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        DslDataSetEncodeError::Endian { err }
    }
}

impl fmt::Display for DslDataSetEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DslDataSetEncodeError::BlockPointer { err } => {
                write!(f, "DslDataSet encode error | {err}")
            }
            DslDataSetEncodeError::Endian { err } => {
                write!(f, "DslDataSet encode error | {err}")
            }
            DslDataSetEncodeError::MissingDirectory {} => {
                write!(f, "DslDataSet encode error, missing directory object")
            }
            DslDataSetEncodeError::PreviousSnapshot {
                prev_snapshot_obj,
                prev_snapshot_txg,
            } => {
                write!(f, "DslDataSet encode error, previous snapshot, obj: {prev_snapshot_obj} txg: {prev_snapshot_txg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DslDataSetEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DslDataSetEncodeError::BlockPointer { err } => Some(err),
            DslDataSetEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}
