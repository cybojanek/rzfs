// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    BootBlock, EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder, Label,
    SECTOR_SHIFT,
};

////////////////////////////////////////////////////////////////////////////////

/// Shift for paddinf field.
const PADDING_SHIFT: usize = 56;

////////////////////////////////////////////////////////////////////////////////

/// Mask for vdev field.
const VDEV_MASK_LOW: u64 = 0x0000000000ffffff;

/// Shift for vdev field.
const VDEV_SHIFT: usize = 32;

////////////////////////////////////////////////////////////////////////////////

/// Shift for grid field.
const GRID_SHIFT: usize = 24;

////////////////////////////////////////////////////////////////////////////////

/// Mask for asize field.
const ASIZE_MASK_LOW: u64 = 0x0000000000ffffff;

/// Shift for asize field.
const ASIZE_SHIFT: usize = 0;

////////////////////////////////////////////////////////////////////////////////

/// Mask for gang bit.
const GANG_MASK_HIGH: u64 = 0x8000000000000000;

////////////////////////////////////////////////////////////////////////////////

/// Mask for offset field.
const OFFSET_MASK_LOW: u64 = 0x7fffffffffffffff;

////////////////////////////////////////////////////////////////////////////////

/** Data Virtual Address.
 *
 * ### Byte layout.
 *
 * - Bytes: 16
 *
 * ```text
 * +----------+------+
 * | Field    | Size |
 * +----------+------+
 * | flags    |    8 |
 * | offset   |    8 |
 * +----------+------+
 * ```
 *
 * ### Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |  padding (8)  |                   vdev (24)                   |    grid (8)   |                   asize (24)                  |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |g|                                                         offset (63)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * asize  allocated (size - 1) in 512 byte sectors
 * g      gang block (contains block pointers to actual data)
 * grid   RAID-Z layout, reserved for future use
 * offset in 512 byte sectors after BASE_OFFSET_SECTORS
 * vdev   device index
 * ```
 *
 * ### padding
 *
 * Unused.
 *
 * ### grid
 *
 * `grid` has been present since V1, but is unused.
 *
 * ### allocated
 *
 * Range: [`Dva::ALLOCATED_MIN`] to [`Dva::ALLOCATED_MAX`].
 *
 * The `allocated` size is in sectors. A [`Dva`] must have at least one
 * allocated sector. When a [`Dva`] with `allocated = N` sectors, is encoded to
 * bytes, the `allocated` field is encoded as `N - 1`. As a result, a [`Dva`]
 * with 0 `allocated` sectors is not valid.
 *
 * Given the above constraint, and that the encoded value is limited to 24 bits,
 * the maximum allowed `allocated` field in a [`Dva`] is `0xffffff + 1`. When
 * shifted by [`SECTOR_SHIFT`], this translates to exactly 8 GiB.
 *
 * ### offset
 *
 * Range: [`Dva::OFFSET_MIN`] to [`Dva::OFFSET_MAX`].
 *
 * The `offset` is in sectors from the start of the device. When a [`Dva`]
 * with `offset = N` sectors is encoded to bytes, the `offset` is encoded as
 * `offset - M`, where `M` is the size in sectors of the BootBlock and first
 * two Label. As a result, a [`Dva`] cannot point to any data in the BootBlock
 * or first two Label (it must also not point to any data in the Label at the
 * end of the device).
 *
 * Given the above constraint, and that and that the encoded value is limited
 * to 63 bits, the minimum allowed `offset` in a [`Dva`] is 8192, while the
 * maximum allowed `offset` in a [`Dva`] is: `0x7fffffffffffffff + 8192`.
 * When shifted by [`SECTOR_SHIFT`], this translates to about 4 ZiB.
 *
 * ### is_gang
 *
 * TODO: Document.
 *
 * ### vdev
 *
 * Range: 0 to [`Dva::VDEV_MAX`].
 *
 * The `vdev` number is the virtual device number for pools that span multiple
 * block devices. The encoded value is limited to 24 bits. Combined with
 * `offset`, a [`Dva`] could refer to up to about 64 RiB.
 */
#[derive(Debug)]
pub struct Dva {
    /** Number of sectors (512 bytes) allocated.
     *
     * Range is 1 to [`Dva::ALLOCATED_MAX`].
     */
    pub allocated: u32,

    /** Offset in sectors (512 bytes) from start of device.
     *
     * Range is [`Dva::OFFSET_MIN`] to [`Dva::OFFSET_MAX`].
     */
    pub offset: u64,

    /// Is gang block.
    pub is_gang: bool,

    /** Virtual device.
     *
     * Range is 0 to [`Dva::VDEV_MAX`].
     */
    pub vdev: u32,
}

impl Dva {
    /// Byte length of an encoded [`Dva`].
    pub const SIZE: usize = 16;

    /// Minimum number of allocated sectors.
    pub const ALLOCATED_MIN: u32 = 1;

    /// Maximimum number of allocated sectors.
    pub const ALLOCATED_MAX: u32 = 0x00ffffff + 1;

    /// Minimum offset in sectors.
    pub const OFFSET_MIN: u64 = ((2 * Label::SIZE + BootBlock::SIZE) as u64) >> SECTOR_SHIFT;

    /// Maximum offset in sectors.
    pub const OFFSET_MAX: u64 = Dva::OFFSET_MIN + OFFSET_MASK_LOW;

    /// Maximum vdev.
    pub const VDEV_MAX: u32 = 0x00ffffff;

    /** Decodes a [`Dva`]. Returns [`None`] if [`Dva`] is empty.
     *
     * # Errors
     *
     * Returns [`DvaDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<Option<Dva>, DvaDecodeError> {
        ////////////////////////////////
        // Decode values.
        let a = decoder.get_u64()?;
        let b = decoder.get_u64()?;

        ////////////////////////////////
        // Check for empty Dva.
        if a == 0 && b == 0 {
            return Ok(None);
        }

        ////////////////////////////////
        // Check for non-zero grid.
        let grid = (a >> GRID_SHIFT) as u8;
        if grid != 0 {
            return Err(DvaDecodeError::NonZeroGrid { grid });
        }

        ////////////////////////////////
        // Check for non-zero padding.
        let padding = (a >> PADDING_SHIFT) as u8;
        if padding != 0 {
            return Err(DvaDecodeError::NonZeroPadding { padding });
        }

        ////////////////////////////////
        // Success!
        Ok(Some(Dva {
            vdev: ((a >> VDEV_SHIFT) & VDEV_MASK_LOW) as u32,
            allocated: (((a >> ASIZE_SHIFT) & ASIZE_MASK_LOW) + 1) as u32,
            offset: (b & OFFSET_MASK_LOW) + Dva::OFFSET_MIN,
            is_gang: (b & GANG_MASK_HIGH) != 0,
        }))
    }

    /** Encodes a non empty [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), DvaEncodeError> {
        ////////////////////////////////
        // Check vdev.
        if self.vdev > Dva::VDEV_MAX {
            return Err(DvaEncodeError::InvalidVdev { vdev: self.vdev });
        }

        ////////////////////////////////
        // Check allocated.
        if self.allocated > Dva::ALLOCATED_MAX || self.allocated < Dva::ALLOCATED_MIN {
            return Err(DvaEncodeError::InvalidAllocated {
                allocated: self.allocated,
            });
        }

        ////////////////////////////////
        // Check offset.
        if self.offset > Dva::OFFSET_MAX || self.offset < Dva::OFFSET_MIN {
            return Err(DvaEncodeError::InvalidOffset {
                offset: self.offset,
            });
        }

        ////////////////////////////////
        // Encode.
        let a = (u64::from(self.vdev) << VDEV_SHIFT)
            | (0 << GRID_SHIFT)
            | (u64::from(self.allocated - 1) << ASIZE_SHIFT);
        let b = (if self.is_gang { GANG_MASK_HIGH } else { 0 }) | (self.offset - Dva::OFFSET_MIN);

        encoder.put_u64(a)?;
        encoder.put_u64(b)?;

        Ok(())
    }

    /** Encodes an empty [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaEncodeError`] in case of encoding error.
     */
    pub fn empty_to_encoder(encoder: &mut EndianEncoder<'_>) -> Result<(), DvaEncodeError> {
        Ok(encoder.put_zero_padding(Dva::SIZE)?)
    }

    /** Encode an `[Option<Dva>`].
     *
     * # Errors
     *
     * Returns [`DvaEncodeError`] in case of encoding error.
     */
    pub fn option_to_encoder(
        dva: &Option<Dva>,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), DvaEncodeError> {
        match dva {
            Some(v) => v.to_encoder(encoder),
            None => Ok(Dva::empty_to_encoder(encoder)?),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Dva`] decode error.
#[derive(Debug)]
pub enum DvaDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid offset error.
    InvalidOffset {
        /// Invalid offset value.
        offset: u64,
    },

    /// Non-zero grid.
    NonZeroGrid {
        /// Invalid grid value.
        grid: u8,
    },

    /// Non-zero padding.
    NonZeroPadding {
        /// Invalid padding.
        padding: u8,
    },
}

impl From<EndianDecodeError> for DvaDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        DvaDecodeError::Endian { err }
    }
}

impl fmt::Display for DvaDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DvaDecodeError::Endian { err } => {
                write!(f, "DVA decode error, endian: [{err}]")
            }
            DvaDecodeError::InvalidOffset { offset } => {
                write!(f, "DVA decode error, invalid offset: {offset}")
            }
            DvaDecodeError::NonZeroGrid { grid } => {
                write!(f, "DVA decode error, non-zero grid: {grid}")
            }
            DvaDecodeError::NonZeroPadding { padding } => {
                write!(f, "DVA decode error, non-zero padding: {padding}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DvaDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DvaDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Dva`] encode error.
#[derive(Debug)]
pub enum DvaEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Invalid allocated error.
    InvalidAllocated {
        /// Invalid allocated value.
        allocated: u32,
    },

    /// Invalid offset error.
    InvalidOffset {
        /// Invalid offset value.
        offset: u64,
    },

    /// Invalid vdev error.
    InvalidVdev {
        /// Invalid vdev value.
        vdev: u32,
    },
}

impl From<EndianEncodeError> for DvaEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        DvaEncodeError::Endian { err }
    }
}

impl fmt::Display for DvaEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DvaEncodeError::Endian { err } => {
                write!(f, "DVA encode error, endian: [{err}]")
            }
            DvaEncodeError::InvalidAllocated { allocated } => {
                write!(f, "DVA encode error, invalid allocated: {allocated}")
            }
            DvaEncodeError::InvalidOffset { offset } => {
                write!(f, "DVA encode error, invalid offset: {offset}")
            }
            DvaEncodeError::InvalidVdev { vdev } => {
                write!(f, "DVA encode error, invalid vdev: {vdev}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DvaEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DvaEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}
