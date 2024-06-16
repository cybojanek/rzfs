// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError, ChecksumType,
    ChecksumTypeError, CompressionType, CompressionTypeError, DmuType, DmuTypeError,
    EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder,
};

/// Is used field of [`Dnode`] in bytes (else in sectors).
const DNODE_FLAG_USED_BYTES: u8 = 1;

/// TODO: What does this mean?
const DNODE_FLAG_USER_USED_ACCOUNTED: u8 = 2;

/// Is a spill block pointer present in [`Dnode`].
const DNODE_FLAG_SPILL_BLOCK_POINTER: u8 = 4;

/// TODO: What does this mean?
const DNODE_FLAG_USER_OBJ_USED_ACCOUNTED: u8 = 8;

/// All known values of flags field of [`Dnode`].
const DNODE_FLAG_ALL: u8 = DNODE_FLAG_USED_BYTES
    | DNODE_FLAG_USER_USED_ACCOUNTED
    | DNODE_FLAG_SPILL_BLOCK_POINTER
    | DNODE_FLAG_USER_OBJ_USED_ACCOUNTED;

////////////////////////////////////////////////////////////////////////////////

/** Dnode.
 *
 * ### Byte layout.
 *
 * - Bytes: 512
 *
 * ```text
 * +-------------------------+------+---------+----------------------+
 * | Field                   | Size | Version | Feature              |
 * +-------------------------+------+---------+----------------------+
 * | dmu                     |    1 |       1 |
 * +-------------------------+------+---------+
 * | indirect block shift    |    1 |       1 |
 * +-------------------------+------+---------+
 * | levels                  |    1 |       1 |
 * +-------------------------+------+---------+
 * | block pointers count    |    1 |       1 |
 * +-------------------------+------+---------+
 * | bonus type              |    1 |       1 |
 * +-------------------------+------+---------+
 * | checksum                |    1 |       1 |
 * +-------------------------+------+---------+
 * | compression             |    1 |       1 |
 * +-------------------------+------+---------+
 * | flags                   |    1 |       3 |
 * +-------------------------+------+---------+
 * | data block size sectors |    2 |       1 |
 * +-------------------------+------+---------+
 * | bonus_len               |    2 |       1 |
 * +-------------------------+------+---------+----------------------+
 * | extra_slots             |    1 |    5000 | com.datto:encryption |
 * +-------------------------+------+---------+----------------------+
 * | padding                 |    3 |
 * +-------------------------+------+---------+
 * | max block id            |    8 |       1 |
 * +-------------------------+------+---------+
 * | used                    |    8 |       1 |
 * +-------------------------+------+---------+
 * | padding                 |   32 |
 * +-------------------------+------+---------+
 * | tail                    |  448 |       1 |
 * +-------------------------+------+---------+
 * ```
 */
#[derive(Debug)]
pub struct Dnode {
    /// Length of bonus data.
    pub bonus_len: usize,

    /// [`DmuType`] of bonus data.
    pub bonus_type: DmuType,

    /// ???
    pub checksum: ChecksumType,

    /// ???
    pub compression: CompressionType,

    /// Size in [crate::phys::SECTOR_SHIFT] of data blocks.
    pub data_block_size_sectors: u16,

    /// ???
    pub extra_slots: u8,

    /// The object type referenced.
    pub dmu: DmuType,

    /// Byte size of an indirect block in log base 2.
    pub indirect_block_shift: u8,

    /** Number of [`BlockPointer`] levels to data.
     *
     * A level of `1` means that the [`BlockPointer`] in [`DnodeTail`] point
     * to data blocks of logical size `data_block_size_sectors`.
     *
     * A level of `2` means that the [`BlockPointer`] in [`DnodeTail] point
     * to intermediate blocks of logical size [`indirect_block_shift`]. The
     * contents of one of these blocks is an array of packed [`BlockPointer`],
     * which point to data blocks of logical size `data_block_size_sectors`.
     *
     * A level of `3` or more indicates additional levels of indirection.
     */
    pub levels: u8,

    /** The maximum block id referenced.
     *
     * The value is inclusive, meaning that if `max_block_id` is `1`, there
     * are two blocks, block `0` and block `1`.
     */
    pub max_block_id: u64,

    /// Data at the end of this [`Dnode`].
    pub tail: DnodeTail,

    /// Number of bytes or sectors used by this [`Dnode`] and its data.
    pub used: DnodeUsed,

    /// ???
    pub user_obj_used_accounted: bool,

    /// ???
    pub user_used_accounted: bool,
}

/// Number of bytes or sectors used by the [`Dnode`] and its data.
#[derive(Debug)]
pub enum DnodeUsed {
    /// Bytes used.
    Bytes(u64),

    /// [crate::phys::SECTOR_SHIFT] sized sectors used.
    Sectors(u64),
}

/// Tail of a [`Dnode`].
#[derive(Debug)]
pub enum DnodeTail {
    /// Zero block pointers, all bonus (up to 448 bytes).
    Zero(DnodeTailZero),

    /// One block pointers, some bonus (up to 320 bytes).
    One(DnodeTailOne),

    /// Two block pointers, some bonus (up to 192 bytes).
    Two(DnodeTailTwo),

    /// Three block pointers, some bonus (up to 64 bytes).
    Three(DnodeTailThree),

    /// One block pointer, with a spill pointer, some bonus (up to 192 bytes).
    Spill(DnodeTailSpill),
}

/** [`DnodeTail`] with zero block pointers (all bonus).
 *
 * ### Byte layout.
 *
 * - Bytes: 448
 *
 * ```text
 * +-------+-----+
 * | bonus | 448 |
 * +-------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailZero {
    /// Block pointers.
    pub ptrs: [Option<BlockPointer>; 0],

    /// Bonus.
    pub bonus: [u8; DnodeTailZero::BONUS_SIZE],
}

impl DnodeTailZero {
    /// Bonus byte size of [`DnodeTailZero`].
    pub const BONUS_SIZE: usize = 448;
}

/** [`DnodeTail`] with one block pointer (320 bytes of bonus).
 *
 * ### Byte layout.
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+------+
 * | Field            | Size |
 * +------------------+------+
 * | block_pointer[0] |  128 |
 * +------------------+------+
 * | bonus            |  320 |
 * +------------------+------+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailOne {
    /// Block pointers.
    pub ptrs: [Option<BlockPointer>; 1],

    /// Bonus.
    pub bonus: [u8; DnodeTailOne::BONUS_SIZE],
}

impl DnodeTailOne {
    /// Bonus byte size of [`DnodeTailOne`].
    pub const BONUS_SIZE: usize = DnodeTailZero::BONUS_SIZE - BlockPointer::SIZE;
}

/** [`DnodeTail`] with two block pointers (192 bytes of bonus).
 *
 * ### Byte layout.
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+------+
 * | Field            | Size |
 * +------------------+------+
 * | block_pointer[0] |  128 |
 * +------------------+------+
 * | block_pointer[1] |  128 |
 * +------------------+------+
 * | bonus            |  192 |
 * +------------------+------+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailTwo {
    /// Block pointers.
    pub ptrs: [Option<BlockPointer>; 2],

    /// Bonus.
    pub bonus: [u8; DnodeTailTwo::BONUS_SIZE],
}

impl DnodeTailTwo {
    /// Bonus byte size of [`DnodeTailTwo`].
    pub const BONUS_SIZE: usize = DnodeTailOne::BONUS_SIZE - BlockPointer::SIZE;
}

/** [`DnodeTail`] with three block pointers (64 bytes of bonus).
 *
 * ### Byte layout.
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+------+
 * | Field            | Size |
 * +------------------+------+
 * | block_pointer[0] |  128 |
 * +------------------+------+
 * | block_pointer[1] |  128 |
 * +------------------+------+
 * | block_pointer[2] |  128 |
 * +------------------+------+
 * | bonus            |   64 |
 * +------------------+------+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailThree {
    /// Block pointers.
    pub ptrs: [Option<BlockPointer>; 3],

    /// Bonus.
    pub bonus: [u8; 64],
}

impl DnodeTailThree {
    /// Bonus byte size of [`DnodeTailThree`].
    pub const BONUS_SIZE: usize = DnodeTailTwo::BONUS_SIZE - BlockPointer::SIZE;
}

/** [`DnodeTail`] with one block pointer, and one spill (192 bytes of bonus).
 *
 * ### Byte layout.
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+------+
 * | Field            | Size |
 * +------------------+------+
 * | block_pointer[0] |  128 |
 * +------------------+------+
 * | bonus            |  192 |
 * +------------------+------+
 * | spill            |  128 |
 * +------------------+------+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailSpill {
    /// Block pointers.
    pub ptrs: [Option<BlockPointer>; 1],

    /// Bonus.
    pub bonus: [u8; DnodeTailSpill::BONUS_SIZE],

    /// Spill block pointers.
    pub spill: Option<BlockPointer>,
}

impl DnodeTailSpill {
    /// Bonus byte size of [`DnodeTailSpill`].
    pub const BONUS_SIZE: usize = DnodeTailOne::BONUS_SIZE - BlockPointer::SIZE;
}

////////////////////////////////////////////////////////////////////////////////

impl Dnode {
    /// Byte size of an encoded [`Dnode`].
    pub const SIZE: usize = 512;

    /** Decodes a [`Dnode`]. Returns [`None`] if [`Dnode`] is empty.
     *
     * # Errors
     *
     * Returns [`DnodeDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<Option<Dnode>, DnodeDecodeError> {
        ////////////////////////////////
        // Check for an empty Dnode.
        if decoder.is_zero_skip(Dnode::SIZE)? {
            return Ok(None);
        }

        ////////////////////////////////
        // Decode DMU type.
        let dmu = DmuType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode indirect block shift.
        let indirect_block_shift = decoder.get_u8()?;

        ////////////////////////////////
        // Decode levels.
        let levels = decoder.get_u8()?;

        ////////////////////////////////
        // Decode number of block pointers.
        let block_pointers_n = decoder.get_u8()?;

        ////////////////////////////////
        // Decode bonus type.
        let bonus_type = DmuType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum = ChecksumType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode compression.
        let compression = CompressionType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u8()?;
        if (flags & DNODE_FLAG_ALL) != flags {
            return Err(DnodeDecodeError::Flags { flags });
        }

        // Check for spill, which only makes sense if block pointers is 1.
        let is_spill = (flags & DNODE_FLAG_SPILL_BLOCK_POINTER) != 0;
        if is_spill && block_pointers_n != 1 {
            return Err(DnodeDecodeError::SpillBlockPointerCount {
                count: block_pointers_n,
            });
        }

        ////////////////////////////////
        // Decode block size sectors.
        let data_block_size_sectors = decoder.get_u16()?;

        ////////////////////////////////
        // Decode bonus length.
        let bonus_len = usize::from(decoder.get_u16()?);

        ////////////////////////////////
        // Decode extra slots.
        let extra_slots = decoder.get_u8()?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(3)?;

        ////////////////////////////////
        // Decode max block id.
        let max_block_id = decoder.get_u64()?;

        ////////////////////////////////
        // Decode used.
        let used = decoder.get_u64()?;
        let used = if (flags & DNODE_FLAG_USED_BYTES) != 0 {
            DnodeUsed::Bytes(used)
        } else {
            DnodeUsed::Sectors(used)
        };

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(32)?;

        ////////////////////////////////
        // Decode tail.
        let max_bonus_len: usize;
        let tail = match block_pointers_n {
            0 => {
                let tail = DnodeTailZero {
                    ptrs: [],
                    bonus: decoder
                        .get_bytes(DnodeTailZero::BONUS_SIZE)?
                        .try_into()
                        .unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Zero(tail)
            }
            1 => {
                if is_spill {
                    let tail = DnodeTailSpill {
                        ptrs: [BlockPointer::from_decoder(decoder)?],
                        bonus: decoder
                            .get_bytes(DnodeTailSpill::BONUS_SIZE)?
                            .try_into()
                            .unwrap(),
                        spill: BlockPointer::from_decoder(decoder)?,
                    };
                    max_bonus_len = tail.bonus.len();
                    DnodeTail::Spill(tail)
                } else {
                    let tail = DnodeTailOne {
                        ptrs: [BlockPointer::from_decoder(decoder)?],
                        bonus: decoder
                            .get_bytes(DnodeTailOne::BONUS_SIZE)?
                            .try_into()
                            .unwrap(),
                    };
                    max_bonus_len = tail.bonus.len();
                    DnodeTail::One(tail)
                }
            }
            2 => {
                let tail = DnodeTailTwo {
                    ptrs: [
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                    ],
                    bonus: decoder
                        .get_bytes(DnodeTailTwo::BONUS_SIZE)?
                        .try_into()
                        .unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Two(tail)
            }
            3 => {
                let tail = DnodeTailThree {
                    ptrs: [
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                    ],
                    bonus: decoder
                        .get_bytes(DnodeTailThree::BONUS_SIZE)?
                        .try_into()
                        .unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Three(tail)
            }
            count => return Err(DnodeDecodeError::BlockPointerCount { count }),
        };

        // Check bonus length.
        if bonus_len > max_bonus_len {
            return Err(DnodeDecodeError::BonusLength { length: bonus_len });
        }

        ////////////////////////////////
        // Success.
        Ok(Some(Dnode {
            bonus_len,
            bonus_type,
            checksum,
            compression,
            data_block_size_sectors,
            dmu,
            extra_slots,
            indirect_block_shift,
            levels,
            max_block_id,
            tail,
            used,
            user_obj_used_accounted: (flags & DNODE_FLAG_USER_OBJ_USED_ACCOUNTED) != 0,
            user_used_accounted: (flags & DNODE_FLAG_USER_USED_ACCOUNTED) != 0,
        }))
    }

    /** Encodes a [`Dnode`].
     *
     * # Errors
     *
     * Returns [`DnodeEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), DnodeEncodeError> {
        ////////////////////////////////
        // Encode DMU type.
        encoder.put_u8(self.dmu.into())?;

        ////////////////////////////////
        // Encode indirect block shift.
        encoder.put_u8(self.indirect_block_shift)?;

        ////////////////////////////////
        // Encode levels.
        encoder.put_u8(self.levels)?;

        ////////////////////////////////
        // Encode number of block pointers.
        // NOTE(cybojanek): Safe to cast as u8, because length is limited.
        encoder.put_u8(self.pointers().len() as u8)?;

        ////////////////////////////////
        // Encode bonus type.
        encoder.put_u8(self.bonus_type.into())?;

        ////////////////////////////////
        // Encode checksum.
        encoder.put_u8(self.checksum.into())?;

        ////////////////////////////////
        // Encode compression.
        encoder.put_u8(self.compression.into())?;

        ////////////////////////////////
        // Encode flags.
        let flags = match self.used {
            DnodeUsed::Bytes(_) => DNODE_FLAG_USED_BYTES,
            _ => 0,
        } | if self.user_used_accounted {
            DNODE_FLAG_USER_USED_ACCOUNTED
        } else {
            0
        } | if self.user_obj_used_accounted {
            DNODE_FLAG_USER_OBJ_USED_ACCOUNTED
        } else {
            0
        } | match &self.tail {
            DnodeTail::Spill(_) => DNODE_FLAG_SPILL_BLOCK_POINTER,
            _ => 0,
        };

        encoder.put_u8(flags)?;

        ////////////////////////////////
        // Encode block size sectors.
        encoder.put_u16(self.data_block_size_sectors)?;

        ////////////////////////////////
        // Encode bonus length.
        // NOTE: Safe to cast, because bonus_capacity is at most 448 bytes.
        if self.bonus_len > self.bonus_capacity().len() {
            return Err(DnodeEncodeError::BonusLength {
                length: self.bonus_len,
            });
        }
        encoder.put_u16(self.bonus_len as u16)?;

        ////////////////////////////////
        // Encode extra slots.
        encoder.put_u8(self.extra_slots)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(3)?;

        ////////////////////////////////
        // Encode max block id.
        encoder.put_u64(self.max_block_id)?;

        ////////////////////////////////
        // Encode used.
        encoder.put_u64(match self.used {
            DnodeUsed::Bytes(v) => v,
            DnodeUsed::Sectors(v) => v,
        })?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(32)?;

        ////////////////////////////////
        // Encode tail.
        for ptr in self.pointers() {
            match ptr {
                Some(ptr) => ptr.to_encoder(encoder)?,
                None => BlockPointer::empty_to_encoder(encoder)?,
            }
        }
        encoder.put_bytes(self.bonus_capacity())?;

        if let DnodeTail::Spill(tail) = &self.tail {
            match &tail.spill {
                Some(ptr) => ptr.to_encoder(encoder)?,
                None => BlockPointer::empty_to_encoder(encoder)?,
            }
        }

        ////////////////////////////////
        // Success.
        Ok(())
    }

    /** Encodes an empty [`Dnode`].
     *
     * # Errors
     *
     * Returns [`DnodeEncodeError`] on error.
     */
    pub fn empty_to_encoder(encoder: &mut EndianEncoder<'_>) -> Result<(), DnodeEncodeError> {
        Ok(encoder.put_zero_padding(Dnode::SIZE)?)
    }

    /** Encode an `[Option<Dnode>`].
     *
     * # Errors
     *
     * Returns [`DnodeEncodeError`] on error.
     */
    pub fn option_to_encoder(
        dnode: &Option<Dnode>,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), DnodeEncodeError> {
        match dnode {
            Some(v) => v.to_encoder(encoder),
            None => Ok(Dnode::empty_to_encoder(encoder)?),
        }
    }

    /** Gets capacity bonus slice. */
    pub fn bonus_capacity(&self) -> &[u8] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.bonus,
            DnodeTail::One(tail) => &tail.bonus,
            DnodeTail::Two(tail) => &tail.bonus,
            DnodeTail::Three(tail) => &tail.bonus,
            DnodeTail::Spill(tail) => &tail.bonus,
        }
    }

    /** Gets used bonus slice. */
    pub fn bonus_used(&self) -> &[u8] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.bonus[0..(self.bonus_len)],
            DnodeTail::One(tail) => &tail.bonus[0..(self.bonus_len)],
            DnodeTail::Two(tail) => &tail.bonus[0..(self.bonus_len)],
            DnodeTail::Three(tail) => &tail.bonus[0..(self.bonus_len)],
            DnodeTail::Spill(tail) => &tail.bonus[0..(self.bonus_len)],
        }
    }

    /** Gets pointers. */
    pub fn pointers(&self) -> &[Option<BlockPointer>] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.ptrs,
            DnodeTail::One(tail) => &tail.ptrs,
            DnodeTail::Two(tail) => &tail.ptrs,
            DnodeTail::Three(tail) => &tail.ptrs,
            DnodeTail::Spill(tail) => &tail.ptrs,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Dnode`] decode error.
#[derive(Debug)]
pub enum DnodeDecodeError {
    /// [`BlockPointer`] decode error.
    BlockPointer {
        /// Error.
        err: BlockPointerDecodeError,
    },

    /// Invalid block pointer count.
    BlockPointerCount {
        /// Count.
        count: u8,
    },

    /// Invalid bonus length.
    BonusLength {
        /// Length.
        length: usize,
    },

    /// Invalid checksum type.
    ChecksumType {
        /// Error.
        err: ChecksumTypeError,
    },

    /// Invalid compression type.
    CompressionType {
        /// Error.
        err: CompressionTypeError,
    },

    /// Invalid DMU type.
    DmuType {
        /// Error.
        err: DmuTypeError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invlaid flags.
    Flags {
        /// Flags.
        flags: u8,
    },

    /// Invlaid spill block pointer count.
    SpillBlockPointerCount {
        /// Count.
        count: u8,
    },
}

impl From<BlockPointerDecodeError> for DnodeDecodeError {
    fn from(err: BlockPointerDecodeError) -> Self {
        DnodeDecodeError::BlockPointer { err }
    }
}

impl From<ChecksumTypeError> for DnodeDecodeError {
    fn from(err: ChecksumTypeError) -> Self {
        DnodeDecodeError::ChecksumType { err }
    }
}

impl From<CompressionTypeError> for DnodeDecodeError {
    fn from(err: CompressionTypeError) -> Self {
        DnodeDecodeError::CompressionType { err }
    }
}

impl From<DmuTypeError> for DnodeDecodeError {
    fn from(err: DmuTypeError) -> Self {
        DnodeDecodeError::DmuType { err }
    }
}

impl From<EndianDecodeError> for DnodeDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        DnodeDecodeError::Endian { err }
    }
}

impl fmt::Display for DnodeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnodeDecodeError::BlockPointer { err } => {
                write!(f, "Dnode decode error, block pointer: [{err}]")
            }
            DnodeDecodeError::BlockPointerCount { count } => {
                write!(f, "Dnode decode error, block pointer count:{count}")
            }
            DnodeDecodeError::BonusLength { length } => {
                write!(f, "Dnode decode error, invalid bonus length:{length}")
            }
            DnodeDecodeError::ChecksumType { err } => {
                write!(f, "Dnode decode error, checksum type: [{err}]")
            }
            DnodeDecodeError::CompressionType { err } => {
                write!(f, "Dnode decode error, compression type: [{err}]")
            }
            DnodeDecodeError::DmuType { err } => {
                write!(f, "Dnode decode error, DMU type: [{err}]")
            }
            DnodeDecodeError::Endian { err } => {
                write!(f, "Dnode decode error, endian: [{err}]")
            }
            DnodeDecodeError::Flags { flags } => {
                write!(f, "Dnode decode error, invalid flags:{flags}")
            }
            DnodeDecodeError::SpillBlockPointerCount { count } => {
                write!(
                    f,
                    "Dnode decode error, invalid spill block pointer count:{count}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeDecodeError::BlockPointer { err } => Some(err),
            DnodeDecodeError::ChecksumType { err } => Some(err),
            DnodeDecodeError::CompressionType { err } => Some(err),
            DnodeDecodeError::DmuType { err } => Some(err),
            DnodeDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Dnode`] encode error.
#[derive(Debug)]
pub enum DnodeEncodeError {
    /// [`BlockPointer`] encode error.
    BlockPointer {
        /// Error.
        err: BlockPointerEncodeError,
    },

    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Invalid bonus length.
    BonusLength {
        /// Length.
        length: usize,
    },
}

impl From<BlockPointerEncodeError> for DnodeEncodeError {
    fn from(err: BlockPointerEncodeError) -> Self {
        DnodeEncodeError::BlockPointer { err }
    }
}

impl From<EndianEncodeError> for DnodeEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        DnodeEncodeError::Endian { err }
    }
}

impl fmt::Display for DnodeEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnodeEncodeError::BlockPointer { err } => {
                write!(f, "Dnode encode error, block pointer: [{err}]")
            }
            DnodeEncodeError::Endian { err } => {
                write!(f, "Dnode encode error, endian: [{err}]")
            }
            DnodeEncodeError::BonusLength { length } => {
                write!(f, "Dnode encode error, invalid bonus length:{length}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeEncodeError::BlockPointer { err } => Some(err),
            DnodeEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}
