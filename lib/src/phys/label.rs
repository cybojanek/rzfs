// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_checksum, label_verify, LabelChecksumError, LabelVerifyError, Sha256};
use crate::phys::{is_multiple_of_sector_size, ChecksumTail, EndianOrder, UberBlock, SECTOR_SHIFT};

////////////////////////////////////////////////////////////////////////////////

/**
 * Boot block portion of label.
 *
 * ### Byte layout.
 *
 * - Bytes: 3670016 (3584 KiB, 3.5 MiB)
 *
 * ```text
 * +---------+---------+
 * | payload | 3670016 |
 * +---------+---------+
 * ```
 *
 * ### BootBlock layout in block device.
 *
 * ```text
 * +----+----+-----------+-----+----+----+
 * | L0 | L1 | BootBlock | ... | L2 | L3 |
 * +----+----+-----------+-----+----+----+
 * ```
 */
pub struct BootBlock {
    /// Payload.
    pub payload: [u8; BootBlock::PAYLOAD_SIZE],
}

impl BootBlock {
    /// Byte size of an encoded [`BootBlock`].
    pub const SIZE: usize = 3584 * 1024;

    /// Offset in sectors from the start of a block device.
    pub const BLOCK_DEVICE_OFFSET: u64 = 2 * Label::SECTORS;

    /// Byte size of the payload (3670016).
    pub const PAYLOAD_SIZE: usize = BootBlock::SIZE - ChecksumTail::SIZE;

    /// Size of an encoded [`BootBlock] in sectors.
    pub const SECTORS: u64 = (BootBlock::SIZE >> SECTOR_SHIFT) as u64;

    /** Decodes a [`BootBlock`].
     *
     * # Errors.
     *
     * Returns [`BootBlockDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8; BootBlock::SIZE]) -> Result<BootBlock, BootBlockDecodeError> {
        Ok(BootBlock {
            payload: bytes[0..BootBlock::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`BootBlock`].
     *
     * # Errors
     *
     * Returns [`BootBlockEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(&self, bytes: &mut [u8; BootBlock::SIZE]) -> Result<(), BootBlockEncodeError> {
        bytes.copy_from_slice(&self.payload);
        Ok(())
    }
}

/// [`BootBlock`] decode error.
#[derive(Debug)]
pub enum BootBlockDecodeError {}

impl fmt::Display for BootBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BootBlockDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// [`BootBlock`] encode error.
#[derive(Debug)]
pub enum BootBlockEncodeError {}

impl fmt::Display for BootBlockEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BootBlockEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Blank portion of label.
 *
 * ### Byte layout.
 *
 * - Bytes: 8192
 *
 * ```text
 * +---------+------+
 * | payload | 8192 |
 * +---------+------+
 * ```
 */
pub struct LabelBlank {
    /// Payload.
    pub payload: [u8; LabelBlank::PAYLOAD_SIZE],
}

impl LabelBlank {
    /// Byte size of an encoded [`LabelBlank`].
    pub const SIZE: usize = 8 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 = 0;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = LabelBlank::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`LabelBlank`].
     *
     * # Errors.
     *
     * Returns [`LabelBlankDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8; LabelBlank::SIZE]) -> Result<LabelBlank, LabelBlankDecodeError> {
        Ok(LabelBlank {
            payload: bytes[0..LabelBlank::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`LabelBlank`].
     *
     * # Errors
     *
     * Returns [`LabelBlankEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; LabelBlank::SIZE],
    ) -> Result<(), LabelBlankEncodeError> {
        bytes.copy_from_slice(&self.payload);
        Ok(())
    }
}

/// [`LabelBlank`] decode error.
#[derive(Debug)]
pub enum LabelBlankDecodeError {}

impl fmt::Display for LabelBlankDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBlankDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// [`LabelBlank`] encode error.
#[derive(Debug)]
pub enum LabelBlankEncodeError {}

impl fmt::Display for LabelBlankEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBlankEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Boot header portion of label.
 *
 * ### Byte layout.
 *
 * - Bytes: 8192
 *
 * ```text
 * +---------------+------+
 * | payload       | 8152 |
 * +---------------+------+
 * | checksum tail |   40 |
 * +---------------+------+
 * ```
 */
pub struct LabelBootHeader {
    /// Payload.
    pub payload: [u8; LabelBootHeader::PAYLOAD_SIZE],
}

impl LabelBootHeader {
    /// Byte size of an encoded [`LabelBootHeader`].
    pub const SIZE: usize = 8 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 = (LabelBlank::SIZE >> SECTOR_SHIFT) as u64;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = LabelBootHeader::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`LabelBootHeader`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelBootHeader`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelBootHeaderDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; LabelBootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<LabelBootHeader, LabelBootHeaderDecodeError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        // Copy payload.
        Ok(LabelBootHeader {
            payload: bytes[0..LabelBootHeader::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`LabelBootHeader`].
     *
     * - `bytes` to encode into
     * - `offset` in bytes of [`LabelBootHeader`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelBootHeaderEncodeError`] on error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; LabelBootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelBootHeaderEncodeError> {
        // Copy payload.
        bytes[0..LabelBootHeader::SIZE].copy_from_slice(&self.payload);

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /**
     * Checksums a [`LabelBootHeader`].
     *
     * - `bytes` to checksum
     * - `offset` in bytes of [`LabelBootHeader`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelChecksumError`] on error.
     */
    pub fn checksum(
        bytes: &mut [u8; LabelBootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelChecksumError> {
        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)
    }

    /** Verifies a [`LabelBootHeader`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelBootHeader`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelVerifyError`] on error.
     */
    pub fn verify(
        bytes: &[u8; LabelBootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelVerifyError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)
    }
}

/// [`LabelBootHeader`] decode error.
#[derive(Debug)]
pub enum LabelBootHeaderDecodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for LabelBootHeaderDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        LabelBootHeaderDecodeError::Label { err }
    }
}

impl fmt::Display for LabelBootHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBootHeaderDecodeError::Label { err } => {
                write!(f, "LabelBootHeader decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBootHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelBootHeaderDecodeError::Label { err } => Some(err),
        }
    }
}

/// [`LabelBootHeader`] encode error.
#[derive(Debug)]
pub enum LabelBootHeaderEncodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for LabelBootHeaderEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        LabelBootHeaderEncodeError::Label { err }
    }
}

impl fmt::Display for LabelBootHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBootHeaderEncodeError::Label { err } => {
                write!(f, "LabelBootHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBootHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelBootHeaderEncodeError::Label { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * NV Pairs portion of a [`Label`].
 *
 * ### Byte layout.
 *
 * - Bytes: 114688 (112 KiB)
 *
 * ```text
 * +---------------+--------+
 * | payload       | 114648 |
 * +---------------+--------+
 * | checksum tail |     40 |
 * +---------------+--------+
 * ```
 */
pub struct LabelNvPairs {
    /// Payload.
    pub payload: [u8; LabelNvPairs::PAYLOAD_SIZE],
}

impl LabelNvPairs {
    /// Byte size of an encoded [`LabelNvPairs`].
    pub const SIZE: usize = 112 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 =
        LabelBootHeader::LABEL_OFFSET + ((LabelBootHeader::SIZE >> SECTOR_SHIFT) as u64);

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = LabelNvPairs::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`LabelNvPairs`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelNvPairs`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelNvPairsDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; LabelNvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<LabelNvPairs, LabelNvPairsDecodeError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        // Copy payload.
        Ok(LabelNvPairs {
            payload: bytes[0..LabelNvPairs::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`LabelNvPairs`].
     *
     * - `bytes` to encode into
     * - `offset` in bytes of [`LabelNvPairs`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelNvPairsEncodeError`] on error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; LabelNvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelNvPairsEncodeError> {
        // Copy payload.
        bytes[0..LabelNvPairs::SIZE].copy_from_slice(&self.payload);

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /**
     * Checksums a [`LabelNvPairs`].
     *
     * - `bytes` to checksum
     * - `offset` in bytes of [`LabelNvPairs`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelChecksumError`] on error.
     */
    pub fn checksum(
        bytes: &mut [u8; LabelNvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelChecksumError> {
        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)
    }

    /** Verifies a [`LabelNvPairs`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelNvPairs`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelVerifyError`] on error.
     */
    pub fn verify(
        bytes: &[u8; LabelNvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelVerifyError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)
    }
}

/// [`LabelNvPairs`] decode error.
#[derive(Debug)]
pub enum LabelNvPairsDecodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for LabelNvPairsDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        LabelNvPairsDecodeError::Label { err }
    }
}

impl fmt::Display for LabelNvPairsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelNvPairsDecodeError::Label { err } => {
                write!(f, "LabelNvPairs decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelNvPairsDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelNvPairsDecodeError::Label { err } => Some(err),
        }
    }
}

/// [`LabelNvPairs`] encode error.
#[derive(Debug)]
pub enum LabelNvPairsEncodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for LabelNvPairsEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        LabelNvPairsEncodeError::Label { err }
    }
}

impl fmt::Display for LabelNvPairsEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelNvPairsEncodeError::Label { err } => {
                write!(f, "LabelNvPairs encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelNvPairsEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelNvPairsEncodeError::Label { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Label of a block device.
 *
 * ### Byte layout.
 *
 * - Bytes: 262144 (256 KiB)
 *
 * ```text
 * +--------------+--------+
 * | Blank        |   8192 |
 * | BootHeader   |   8192 |
 * | NvPairs      | 114688 |
 * | UberBlock[0] |      X |
 * | ...          |    ... |
 * | UberBlock[N] |      X |
 * +--------------+--------+
 *
 * X: Refer to UberBlock documentation.
 * N: (128 * KiB / X) - 1
 *    Minus one for 0 offset indexing
 * ```
 *
 * ### Label layout in block device.
 *
 * ```text
 * +----+----+-----------+-----+----+----+
 * | L0 | L1 | BootBlock | ... | L2 | L3 |
 * +----+----+-----------+-----+----+----+
 * ```
 */
pub struct Label {}

impl Label {
    /// Count of [`Label`] in a vdev.
    pub const COUNT: usize = 4;

    /// Byte size of an encoded [`Label`] (256 KiB).
    pub const SIZE: usize =
        LabelBlank::SIZE + LabelBootHeader::SIZE + LabelNvPairs::SIZE + UberBlock::TOTAL_SIZE;

    /// Size of and encoded [`Label`] in sectors.
    pub const SECTORS: u64 = (Label::SIZE >> SECTOR_SHIFT) as u64;

    /** Gets label sector offsets for a virtual device size in sectors.
     *
     * # Errors
     *
     * Returns [`LabelSectorsError`] if vdev_sectors is too small.
     */
    pub fn sectors(vdev_sectors: u64) -> Result<[u64; 4], LabelSectorsError> {
        debug_assert!(is_multiple_of_sector_size(Label::SIZE));

        // Check if vdev is too small.
        if vdev_sectors < Label::SECTORS * 4 {
            return Err(LabelSectorsError::TooSmall {
                sectors: vdev_sectors,
            });
        }

        Ok([
            // L0
            0,
            // L1
            Label::SECTORS,
            // L2
            vdev_sectors - 2 * Label::SECTORS,
            // L3
            vdev_sectors - Label::SECTORS,
        ])
    }
}

/// [`Label`] offset error.
#[derive(Debug)]
pub enum LabelSectorsError {
    /// Not enough sectors for [`Label::sectors`].
    TooSmall {
        /// Sectors.
        sectors: u64,
    },
}

impl fmt::Display for LabelSectorsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelSectorsError::TooSmall { sectors } => {
                write!(f, "Not enough sectors for Label {sectors}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelSectorsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
