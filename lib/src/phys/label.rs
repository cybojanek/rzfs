// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_checksum, label_verify, LabelChecksumError, LabelVerifyError, Sha256};
use crate::phys::{is_multiple_of_sector_size, ChecksumTail, EndianOrder, UberBlock, SECTOR_SHIFT};

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
pub struct Blank {
    /// Payload.
    pub payload: [u8; Blank::PAYLOAD_SIZE],
}

impl Blank {
    /// Byte size of an encoded [`Blank`].
    pub const SIZE: usize = 8 * 1024;

    /// Byte offset into a [`Label`].
    pub const LABEL_OFFSET: usize = 0;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = Blank::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`Blank`].
     *
     * # Errors.
     *
     * Returns [`BlankDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8; Blank::SIZE]) -> Result<Blank, BlankDecodeError> {
        Ok(Blank {
            payload: bytes[0..Blank::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`Blank`].
     *
     * # Errors
     *
     * Returns [`BlankEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(&self, bytes: &mut [u8; Blank::SIZE]) -> Result<(), BlankEncodeError> {
        bytes.copy_from_slice(&self.payload);
        Ok(())
    }
}

/// [`Blank`] decode error.
#[derive(Debug)]
pub enum BlankDecodeError {}

impl fmt::Display for BlankDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BlankDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// [`Blank`] encode error.
#[derive(Debug)]
pub enum BlankEncodeError {}

impl fmt::Display for BlankEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BlankEncodeError {
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
pub struct BootHeader {
    /// Payload.
    pub payload: [u8; BootHeader::PAYLOAD_SIZE],
}

impl BootHeader {
    /// Byte size of an encoded [`BootHeader`].
    pub const SIZE: usize = 8 * 1024;

    /// Byte offset into a [`Label`].
    pub const LABEL_OFFSET: usize = Blank::SIZE;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = BootHeader::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`BootHeader`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`BootHeader`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`BootHeaderDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; BootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<BootHeader, BootHeaderDecodeError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        // Copy payload.
        Ok(BootHeader {
            payload: bytes[0..BootHeader::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`BootHeader`].
     *
     * - `bytes` to encode into
     * - `offset` in bytes of [`BootHeader`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`BootHeaderEncodeError`] on error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; BootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), BootHeaderEncodeError> {
        // Copy payload.
        bytes[0..BootHeader::SIZE].copy_from_slice(&self.payload);

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /**
     * Checksums a [`BootHeader`].
     *
     * - `bytes` to checksum
     * - `offset` in bytes of [`BootHeader`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelChecksumError`] on error.
     */
    pub fn checksum(
        &self,
        bytes: &mut [u8; BootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelChecksumError> {
        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)
    }

    /** Verifies a [`BootHeader`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`BootHeader`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelVerifyError`] on error.
     */
    pub fn verify(
        bytes: &[u8; BootHeader::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelVerifyError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)
    }
}

/// [`BootHeader`] decode error.
#[derive(Debug)]
pub enum BootHeaderDecodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for BootHeaderDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        BootHeaderDecodeError::Label { err }
    }
}

impl fmt::Display for BootHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootHeaderDecodeError::Label { err } => {
                write!(f, "BootHeader decode error, checksum: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BootHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BootHeaderDecodeError::Label { err } => Some(err),
        }
    }
}

/// [`BootHeader`] encode error.
#[derive(Debug)]
pub enum BootHeaderEncodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for BootHeaderEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        BootHeaderEncodeError::Label { err }
    }
}

impl fmt::Display for BootHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootHeaderEncodeError::Label { err } => {
                write!(f, "BootHeader encode error, checksum: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BootHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BootHeaderEncodeError::Label { err } => Some(err),
        }
    }
}

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
 */
pub struct BootBlock {
    /// Payload.
    pub payload: [u8; BootBlock::PAYLOAD_SIZE],
}

impl BootBlock {
    /// Byte size of an encoded [`BootBlock`].
    pub const SIZE: usize = 3584 * 1024;

    /// Byte offset into a virtual block device.
    pub const VDEV_OFFSET: u64 = (2 * Label::SIZE) as u64;

    /// Byte size of the payload (3670016).
    pub const PAYLOAD_SIZE: usize = BootBlock::SIZE - ChecksumTail::SIZE;

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
pub struct NvPairs {
    /// Payload.
    pub payload: [u8; NvPairs::PAYLOAD_SIZE],
}

impl NvPairs {
    /// Byte size of an encoded [`NvPairs`].
    pub const SIZE: usize = 112 * 1024;

    /// Byte offset into a [`Label`].
    pub const LABEL_OFFSET: usize = BootHeader::LABEL_OFFSET + BootHeader::SIZE;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = NvPairs::SIZE - ChecksumTail::SIZE;

    /** Decodes a [`NvPairs`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`NvPairs`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`NvPairsDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; NvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<NvPairs, NvPairsDecodeError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        // Copy payload.
        Ok(NvPairs {
            payload: bytes[0..NvPairs::PAYLOAD_SIZE].try_into().unwrap(),
        })
    }

    /** Encodes a [`NvPairs`].
     *
     * - `bytes` to encode into
     * - `offset` in bytes of [`NvPairs`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`NvPairsEncodeError`] on error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; NvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), NvPairsEncodeError> {
        // Copy payload.
        bytes[0..NvPairs::SIZE].copy_from_slice(&self.payload);

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /**
     * Checksums a [`NvPairs`].
     *
     * - `bytes` to checksum
     * - `offset` in bytes of [`NvPairs`] from start of device
     * - `sha256` instance to use for checksum
     * - `order` to use for checksum
     *
     * # Errors
     *
     * Returns [`LabelChecksumError`] on error.
     */
    pub fn checksum(
        &self,
        bytes: &mut [u8; NvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelChecksumError> {
        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)
    }

    /** Verifies a [`NvPairs`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`NvPairs`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelVerifyError`] on error.
     */
    pub fn verify(
        bytes: &[u8; NvPairs::SIZE],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelVerifyError> {
        // Verify the checksum.
        label_verify(bytes, offset, sha256)
    }
}

/// [`NvPairs`] decode error.
#[derive(Debug)]
pub enum NvPairsDecodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for NvPairsDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        NvPairsDecodeError::Label { err }
    }
}

impl fmt::Display for NvPairsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvPairsDecodeError::Label { err } => {
                write!(f, "NvPairs decode error, checksum: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for NvPairsDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            NvPairsDecodeError::Label { err } => Some(err),
        }
    }
}

/// [`NvPairs`] encode error.
#[derive(Debug)]
pub enum NvPairsEncodeError {
    /// Label error.
    Label {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for NvPairsEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        NvPairsEncodeError::Label { err }
    }
}

impl fmt::Display for NvPairsEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvPairsEncodeError::Label { err } => {
                write!(f, "NvPairs encode error, checksum: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for NvPairsEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            NvPairsEncodeError::Label { err } => Some(err),
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
 * +--------------+--------+
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
    pub const SIZE: usize = Blank::SIZE + BootHeader::SIZE + NvPairs::SIZE + UberBlock::TOTAL_SIZE;

    /** Gets label sector offsets for a virtual device size in sectors.
     *
     * # Errors
     *
     * Returns [`LabelSectorsError`] if vdev_sectors is too small.
     */
    pub fn sectors(vdev_sectors: u64) -> Result<[u64; 4], LabelSectorsError> {
        debug_assert!(is_multiple_of_sector_size(Label::SIZE));

        let size_sectors: u64 = (Label::SIZE >> SECTOR_SHIFT) as u64;

        // Check if vdev is too small.
        if vdev_sectors < size_sectors * 4 {
            return Err(LabelSectorsError::TooSmall {
                sectors: vdev_sectors,
            });
        }

        Ok([
            // L0
            0,
            // L1
            size_sectors,
            // L2
            vdev_sectors - 2 * size_sectors,
            // L3
            vdev_sectors - size_sectors,
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
                write!(f, "Not enough sectors for Label::sectors: {sectors}")
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
