// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder};

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
 * asize  Dva allocated
 * g      Dva is_gang
 * grid   RAID-Z layout, reserved for future use
 * offset Dva offset
 * vdev   Dva vdev
 * ```
 *
 * ### padding
 *
 * Unused.
 *
 * ### grid
 *
 * `grid` has been present since V1, but is unused.
 */
#[derive(Debug)]
pub struct Dva {
    /** Number of sectors (512 bytes) allocated.
     *
     * - Range is [`Dva::ALLOCATED_MIN`] to [`Dva::ALLOCATED_MAX`].
     * - A [`Dva`] must have at least one allocated sector.
     * - This includes sectors for for RAIDZ parity data, and gang block headers.
     * - The encoded value is limited to 24 bits. When shifted by
     *   [`crate::phys::SECTOR_SHIFT`], this computes to 512 bytes short of 8 GiB.
     */
    pub allocated: u32,

    /** Offset in sectors (512 bytes) from start of the virtual device.
     *
     * - Range is 0 to [`Dva::OFFSET_MAX`].
     * - Note that this does not mean the offset in sectors from the start of
     *   the physical device.
     * - For a single disk, RAID1 (mirror), RAID0 (stripe), or RAID10 virtual
     *   device, this offset is the number of sectors after the `L1` label of
     *   [`crate::phys::Label`].
     * * For a RAIDZ (RAID5, RAID6, RAID7) virtual device, this is the logical
     *   offset into the entire RAIDZ pool, and maps to multiple sectors across
     *   the child virtual devices.
     * * For a stripped RAIDZ (RAID50, RAID60, RAID70), this is the number of
     *   sectors from the start of the child virtual RAIDZ device.
     * - The value is limited to 63 bits. With a [`crate::phys::SECTOR_SHIFT`],
     *   this computes to 512 bytes short of 4 ZiB.
     */
    pub offset: u64,

    /** Is gang block.
     *
     * A gang block contains block pointers to data.
     *
     * TODO: Document.
     */
    pub is_gang: bool,

    /** Virtual device index.
     *
     * - Range is 0 to [`Dva::VDEV_MAX`].
     * - For a single disk, the `vdev` is 0.
     * - For a RAID1 (mirror) pool, the `vdev` is 0, and the mirror module
     *   handles replicating writes to all leaf devices.
     * - For a RAID0 (stripe) pool, the `vdev` specifies the leaf device that
     *   holds all the data for this [`Dva`].
     * - For a RAIDZ pool, the `vdev` is 0, and the raidz module handles reads
     *   and writes to leaf devices.
     * - For a stripped RAIDZ, the `vdev` specifies the child RAIDZ device that
     *   holds all the data for this [`Dva`].
     */
    pub vdev: u32,
}

impl Dva {
    /// Byte length of an encoded [`Dva`].
    pub const SIZE: usize = 16;

    /// Minimum number of allocated sectors.
    pub const ALLOCATED_MIN: u32 = 1;

    /// Maximimum number of allocated sectors.
    pub const ALLOCATED_MAX: u32 = (1 << 24) - 1;

    /// Maximum offset in sectors.
    pub const OFFSET_MAX: u64 = Dva::OFFSET_MASK;

    /// Maximum vdev.
    pub const VDEV_MAX: u32 = (1 << 24) - 1;

    /// Mask for asize field.
    const ASIZE_MASK_DOWN_SHIFTED: u64 = (1 << 24) - 1;

    /// Shift for asize field.
    const ASIZE_SHIFT: usize = 0;

    /// Shift for grid field.
    const GRID_SHIFT: usize = 24;

    /// Mask for vdev field.
    const VDEV_MASK_DOWN_SHIFTED: u64 = (1 << 24) - 1;

    /// Shift for vdev field.
    const VDEV_SHIFT: usize = 32;

    /// Shift for padding field.
    const PADDING_SHIFT: usize = 56;

    /// Mask for gang bit.
    const GANG_MASK_BIT_FLAG: u64 = 0x8000000000000000;

    /// Mask for offset field.
    const OFFSET_MASK: u64 = (1 << 63) - 1;

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
        let grid = (a >> Dva::GRID_SHIFT) as u8;
        if grid != 0 {
            return Err(DvaDecodeError::NonZeroGrid { grid });
        }

        ////////////////////////////////
        // Check for non-zero padding.
        let padding = (a >> Dva::PADDING_SHIFT) as u8;
        if padding != 0 {
            return Err(DvaDecodeError::NonZeroPadding { padding });
        }

        ////////////////////////////////
        // Success!
        Ok(Some(Dva {
            vdev: ((a >> Dva::VDEV_SHIFT) & Dva::VDEV_MASK_DOWN_SHIFTED) as u32,
            allocated: ((a >> Dva::ASIZE_SHIFT) & Dva::ASIZE_MASK_DOWN_SHIFTED) as u32,
            offset: (b & Dva::OFFSET_MASK),
            is_gang: (b & Dva::GANG_MASK_BIT_FLAG) != 0,
        }))
    }

    /** Encodes a non empty [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaEncodeError`] on error.
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
        if self.offset > Dva::OFFSET_MAX {
            return Err(DvaEncodeError::InvalidOffset {
                offset: self.offset,
            });
        }

        ////////////////////////////////
        // Encode.
        let a = (u64::from(self.vdev) << Dva::VDEV_SHIFT)
            | (0 << Dva::GRID_SHIFT)
            | (u64::from(self.allocated) << Dva::ASIZE_SHIFT);
        let b = (if self.is_gang {
            Dva::GANG_MASK_BIT_FLAG
        } else {
            0
        }) | (self.offset);

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
                write!(f, "DVA decode error | {err}")
            }
            DvaDecodeError::InvalidOffset { offset } => {
                write!(f, "DVA decode error, invalid offset {offset}")
            }
            DvaDecodeError::NonZeroGrid { grid } => {
                write!(f, "DVA decode error, non-zero grid {grid}")
            }
            DvaDecodeError::NonZeroPadding { padding } => {
                write!(f, "DVA decode error, non-zero padding {padding}")
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
                write!(f, "DVA encode error | {err}")
            }
            DvaEncodeError::InvalidAllocated { allocated } => {
                write!(f, "DVA encode error, invalid allocated {allocated}")
            }
            DvaEncodeError::InvalidOffset { offset } => {
                write!(f, "DVA encode error, invalid offset {offset}")
            }
            DvaEncodeError::InvalidVdev { vdev } => {
                write!(f, "DVA encode error, invalid vdev {vdev}")
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
