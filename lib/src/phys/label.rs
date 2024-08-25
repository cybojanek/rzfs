// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_checksum, label_verify, LabelChecksumError, LabelVerifyError, Sha256};
use crate::phys::{
    is_multiple_of_sector_size, ChecksumTail, Compatibility, EndianOrder, FeatureSet,
    FeatureSetDecodeError, NvArray, NvDecodeError, NvList, PoolConfigKey, PoolErrata,
    PoolErrataDecodeError, PoolState, PoolStateDecodeError, SpaVersion, SpaVersionError, UberBlock,
    VdevTreeKey, VdevType, SECTOR_SHIFT,
};

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
pub struct BootBlock<'a> {
    /// Payload of length [`BootBlock::PAYLOAD_SIZE`].
    pub payload: &'a [u8],
}

impl BootBlock<'_> {
    /// Byte size of an encoded [`BootBlock`].
    pub const SIZE: usize = 3584 * 1024;

    /// Offset in sectors from the start of a block device.
    pub const BLOCK_DEVICE_OFFSET: u64 = 2 * Label::SECTORS;

    /// Byte size of the payload (3670016).
    pub const PAYLOAD_SIZE: usize = Self::SIZE;

    /// Size of an encoded [`BootBlock] in sectors.
    pub const SECTORS: u64 = (Self::SIZE >> SECTOR_SHIFT) as u64;

    /** Decodes a [`BootBlock`].
     *
     * # Errors.
     *
     * Returns [`BootBlockDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<BootBlock<'_>, BootBlockDecodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(BootBlockDecodeError::InvalidSize { size: bytes.len() });
        }

        // No special encoding, just reference all the bytes.
        Ok(BootBlock { payload: bytes })
    }

    /** Encodes a [`BootBlock`].
     *
     * # Errors
     *
     * Returns [`BootBlockEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Result<(), BootBlockEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(BootBlockEncodeError::InvalidSize { size: bytes.len() });
        }

        if self.payload.len() != Self::PAYLOAD_SIZE {
            return Err(BootBlockEncodeError::InvalidPayloadSize {
                size: self.payload.len(),
            });
        }

        // No special encoding, just copy to destination.
        bytes.copy_from_slice(self.payload);

        Ok(())
    }
}

/// [`BootBlock`] decode error.
#[derive(Debug)]
pub enum BootBlockDecodeError {
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
}

impl fmt::Display for BootBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootBlockDecodeError::InvalidSize { size } => {
                write!(f, "BootBlock decode error, invalid size {size}")
            }
        }
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
pub enum BootBlockEncodeError {
    /// Invalid payload size.
    InvalidPayloadSize {
        /// Size in bytes.
        size: usize,
    },
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
}

impl fmt::Display for BootBlockEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootBlockEncodeError::InvalidPayloadSize { size } => {
                write!(f, "BootBlock encode error, invalid payload size {size}")
            }
            BootBlockEncodeError::InvalidSize { size } => {
                write!(f, "BootBlock encode error, invalid size {size}")
            }
        }
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
pub struct LabelBlank<'a> {
    /// Payload of length [`LabelBlank::PAYLOAD_SIZE`].
    pub payload: &'a [u8],
}

impl LabelBlank<'_> {
    /// Byte size of an encoded [`LabelBlank`].
    pub const SIZE: usize = 8 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 = 0;

    /// Byte size of the blank payload (8192).
    pub const PAYLOAD_SIZE: usize = Self::SIZE;

    /** Decodes a [`LabelBlank`].
     *
     * # Errors.
     *
     * Returns [`LabelBlankDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<LabelBlank<'_>, LabelBlankDecodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBlankDecodeError::InvalidSize { size: bytes.len() });
        }

        // No special encoding, just reference all the bytes.
        Ok(LabelBlank { payload: bytes })
    }

    /** Encodes a [`LabelBlank`].
     *
     * # Errors
     *
     * Returns [`LabelBlankEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Result<(), LabelBlankEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBlankEncodeError::InvalidSize { size: bytes.len() });
        }

        if self.payload.len() != Self::PAYLOAD_SIZE {
            return Err(LabelBlankEncodeError::InvalidPayloadSize {
                size: self.payload.len(),
            });
        }

        // No special encoding, just copy to destination.
        bytes.copy_from_slice(self.payload);

        Ok(())
    }
}

/// [`LabelBlank`] decode error.
#[derive(Debug)]
pub enum LabelBlankDecodeError {
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
}

impl fmt::Display for LabelBlankDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBlankDecodeError::InvalidSize { size } => {
                write!(f, "LabelBlank decode error, invalid size {size}")
            }
        }
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
pub enum LabelBlankEncodeError {
    /// Invalid payload size.
    InvalidPayloadSize {
        /// Size in bytes.
        size: usize,
    },
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
}

impl fmt::Display for LabelBlankEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBlankEncodeError::InvalidPayloadSize { size } => {
                write!(f, "LabelBlank encode error, invalid payload size {size}")
            }
            LabelBlankEncodeError::InvalidSize { size } => {
                write!(f, "LabelBlank encode error, invalid size {size}")
            }
        }
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
pub struct LabelBootHeader<'a> {
    /// Payload of length [`LabelBootHeader::PAYLOAD_SIZE`].
    pub payload: &'a [u8],
}

impl LabelBootHeader<'_> {
    /// Byte size of an encoded [`LabelBootHeader`].
    pub const SIZE: usize = 8 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 =
        LabelBlank::LABEL_OFFSET + (LabelBlank::SIZE >> SECTOR_SHIFT) as u64;

    /// Byte size of the blank payload (8152).
    pub const PAYLOAD_SIZE: usize = Self::SIZE - ChecksumTail::SIZE;

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
    pub fn from_bytes<'a>(
        bytes: &'a [u8],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<LabelBootHeader<'a>, LabelBootHeaderDecodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBootHeaderDecodeError::InvalidSize { size: bytes.len() });
        }

        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        Ok(LabelBootHeader {
            payload: &bytes[0..Self::PAYLOAD_SIZE],
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
        bytes: &mut [u8],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelBootHeaderEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBootHeaderEncodeError::InvalidSize { size: bytes.len() });
        }

        if self.payload.len() != Self::PAYLOAD_SIZE {
            return Err(LabelBootHeaderEncodeError::InvalidPayloadSize {
                size: self.payload.len(),
            });
        }

        // Copy payload.
        bytes[0..Self::PAYLOAD_SIZE].copy_from_slice(self.payload);

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
     * Returns [`LabelBootHeaderEncodeError`] on error.
     */
    pub fn checksum(
        bytes: &mut [u8],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelBootHeaderEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBootHeaderEncodeError::InvalidSize { size: bytes.len() });
        }

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /** Verifies a [`LabelBootHeader`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelBootHeader`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelBootHeaderDecodeError`] on error.
     */
    pub fn verify(
        bytes: &[u8],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelBootHeaderDecodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelBootHeaderDecodeError::InvalidSize { size: bytes.len() });
        }

        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        Ok(())
    }
}

/// [`LabelBootHeader`] decode error.
#[derive(Debug)]
pub enum LabelBootHeaderDecodeError {
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
    /// Label error.
    LabelVerify {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for LabelBootHeaderDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        LabelBootHeaderDecodeError::LabelVerify { err }
    }
}

impl fmt::Display for LabelBootHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBootHeaderDecodeError::InvalidSize { size } => {
                write!(f, "LabelBootHeader decode error, invalid size {size}")
            }
            LabelBootHeaderDecodeError::LabelVerify { err } => {
                write!(f, "LabelBootHeader decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBootHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelBootHeaderDecodeError::LabelVerify { err } => Some(err),
            _ => None,
        }
    }
}

/// [`LabelBootHeader`] encode error.
#[derive(Debug)]
pub enum LabelBootHeaderEncodeError {
    /// Invalid payload size.
    InvalidPayloadSize {
        /// Size in bytes.
        size: usize,
    },
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
    /// Label error.
    LabelChecksum {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for LabelBootHeaderEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        LabelBootHeaderEncodeError::LabelChecksum { err }
    }
}

impl fmt::Display for LabelBootHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelBootHeaderEncodeError::InvalidPayloadSize { size } => {
                write!(
                    f,
                    "LabelBootHeader encode error, invalid payload size {size}"
                )
            }
            LabelBootHeaderEncodeError::InvalidSize { size } => {
                write!(f, "LabelBootHeader encode error, invalid size {size}")
            }
            LabelBootHeaderEncodeError::LabelChecksum { err } => {
                write!(f, "LabelBootHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelBootHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelBootHeaderEncodeError::LabelChecksum { err } => Some(err),
            _ => None,
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
pub struct LabelNvPairs<'a> {
    /// Payload of length [`LabelNvPairs::PAYLOAD_SIZE`].
    pub payload: &'a [u8],
}

impl LabelNvPairs<'_> {
    /// Byte size of an encoded [`LabelNvPairs`].
    pub const SIZE: usize = 112 * 1024;

    /// Offset in sectors from the start of a [`Label`].
    pub const LABEL_OFFSET: u64 =
        LabelBootHeader::LABEL_OFFSET + (LabelBootHeader::SIZE >> SECTOR_SHIFT) as u64;

    /// Byte size of the nv pairs payload (114648).
    pub const PAYLOAD_SIZE: usize = Self::SIZE - ChecksumTail::SIZE;

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
    pub fn from_bytes<'a>(
        bytes: &'a [u8],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<LabelNvPairs<'a>, LabelNvPairsDecodeError> {
        if bytes.len() != Self::SIZE {
            return Err(LabelNvPairsDecodeError::InvalidSize { size: bytes.len() });
        }

        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        Ok(LabelNvPairs {
            payload: &bytes[0..Self::PAYLOAD_SIZE],
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
        bytes: &mut [u8],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelNvPairsEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelNvPairsEncodeError::InvalidSize { size: bytes.len() });
        }

        if self.payload.len() != Self::PAYLOAD_SIZE {
            return Err(LabelNvPairsEncodeError::InvalidPayloadSize {
                size: self.payload.len(),
            });
        }

        // Copy payload.
        bytes[0..Self::PAYLOAD_SIZE].copy_from_slice(self.payload);

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
     * Returns [`LabelNvPairsEncodeError`] on error.
     */
    pub fn checksum(
        bytes: &mut [u8],
        offset: u64,
        sha256: &mut Sha256,
        order: EndianOrder,
    ) -> Result<(), LabelNvPairsEncodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelNvPairsEncodeError::InvalidSize { size: bytes.len() });
        }

        // Compute checksum.
        label_checksum(bytes, offset, sha256, order)?;

        Ok(())
    }

    /** Verifies a [`LabelNvPairs`].
     *
     * - `bytes` to decode from
     * - `offset` in bytes of [`LabelNvPairs`] from start of device
     * - `sha256` instance to use for checksum
     *
     * # Errors.
     *
     * Returns [`LabelNvPairsDecodeError`] on error.
     */
    pub fn verify(
        bytes: &[u8],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), LabelNvPairsDecodeError> {
        // Check size.
        if bytes.len() != Self::SIZE {
            return Err(LabelNvPairsDecodeError::InvalidSize { size: bytes.len() });
        }

        // Verify the checksum.
        label_verify(bytes, offset, sha256)?;

        Ok(())
    }
}

/// [`LabelNvPairs`] decode error.
#[derive(Debug)]
pub enum LabelNvPairsDecodeError {
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
    /// Label error.
    LabelVerify {
        /// Error.
        err: LabelVerifyError,
    },
}

impl From<LabelVerifyError> for LabelNvPairsDecodeError {
    fn from(err: LabelVerifyError) -> Self {
        LabelNvPairsDecodeError::LabelVerify { err }
    }
}

impl fmt::Display for LabelNvPairsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelNvPairsDecodeError::InvalidSize { size } => {
                write!(f, "LabelNvPairs decode error, invalid size {size}")
            }
            LabelNvPairsDecodeError::LabelVerify { err } => {
                write!(f, "LabelNvPairs decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelNvPairsDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelNvPairsDecodeError::LabelVerify { err } => Some(err),
            _ => None,
        }
    }
}

/// [`LabelNvPairs`] encode error.
#[derive(Debug)]
pub enum LabelNvPairsEncodeError {
    /// Invalid payload size.
    InvalidPayloadSize {
        /// Size in bytes.
        size: usize,
    },
    /// Invalid size.
    InvalidSize {
        /// Size in bytes.
        size: usize,
    },
    /// Label error.
    LabelChecksum {
        /// Error.
        err: LabelChecksumError,
    },
}

impl From<LabelChecksumError> for LabelNvPairsEncodeError {
    fn from(err: LabelChecksumError) -> Self {
        LabelNvPairsEncodeError::LabelChecksum { err }
    }
}

impl fmt::Display for LabelNvPairsEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelNvPairsEncodeError::InvalidPayloadSize { size } => {
                write!(f, "LabelNvPairs encode error, invalid payload size {size}")
            }
            LabelNvPairsEncodeError::InvalidSize { size } => {
                write!(f, "LabelNvPairs encode error, invalid size {size}")
            }
            LabelNvPairsEncodeError::LabelChecksum { err } => {
                write!(f, "LabelNvPairs encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelNvPairsEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelNvPairsEncodeError::LabelChecksum { err } => Some(err),
            _ => None,
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
    pub const SECTORS: u64 = (Self::SIZE >> SECTOR_SHIFT) as u64;

    /** Gets label offsets for a virtual device size in sectors.
     *
     * # Errors
     *
     * Returns [`LabelSectorsError`] if vdev_sectors is too small.
     */
    pub fn offsets(vdev_sectors: u64) -> Result<[u64; 4], LabelSectorsError> {
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
    /// Not enough sectors for [`Label::offsets`].
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

////////////////////////////////////////////////////////////////////////////////

/// Label configuration information from [`LabelNvPairs`].
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum LabelConfig<'a> {
    /// [`PoolState::L2Cache`].
    L2Cache(LabelConfigL2Cache),

    /// [`PoolState::Spare`].
    Spare(LabelConfigSpare),

    /// [`PoolState::Active`], [`PoolState::Exported`], or [`PoolState::Destroyed`].
    Storage(LabelConfigStorage<'a>),
}

impl LabelConfig<'_> {
    /** Decodes a [`LabelConfigL2Cache`].
     *
     * # Errors
     *
     * Returns [`LabelConfigDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(list: &NvList<'a>) -> Result<LabelConfig<'a>, LabelConfigDecodeError<'a>> {
        // State.
        let state_str = PoolConfigKey::State.into();
        let state = PoolState::try_from(match list.get_u64(state_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: state_str }),
        })?;

        match state {
            PoolState::Active | PoolState::Exported | PoolState::Destroyed => {
                Ok(LabelConfig::Storage(LabelConfigStorage::from_list(list)?))
            }
            PoolState::Spare => Ok(LabelConfig::Spare(LabelConfigSpare::from_list(list)?)),
            PoolState::L2Cache => Ok(LabelConfig::L2Cache(LabelConfigL2Cache::from_list(list)?)),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`PoolState::L2Cache`] information from [`LabelNvPairs`].
#[derive(Debug)]
pub struct LabelConfigL2Cache {
    /// [`PoolConfigKey::AllocateShift`].
    pub allocate_shift: u64,

    /// [`PoolConfigKey::Guid`]
    pub guid: u64,

    /// [`PoolConfigKey::Version`].
    pub version: SpaVersion,
}

impl LabelConfigL2Cache {
    /// Expected [`PoolConfigKey`] values in [`PoolConfigKey`].
    const EXPECTED: [PoolConfigKey; 4] = [
        PoolConfigKey::AllocateShift,
        PoolConfigKey::Guid,
        PoolConfigKey::State,
        PoolConfigKey::Version,
    ];

    /** Decodes a [`LabelConfigL2Cache`].
     *
     * # Errors
     *
     * Returns [`LabelConfigDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelConfigL2Cache, LabelConfigDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.

        // State.
        let state_str = PoolConfigKey::State.into();
        let state = PoolState::try_from(match list.get_u64(state_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: state_str }),
        })?;

        if !matches!(state, PoolState::L2Cache) {
            return Err(LabelConfigDecodeError::UnexpectedState { state });
        }

        // AllocateShift.
        let allocate_shift_str = PoolConfigKey::AllocateShift.into();
        let allocate_shift = match list.get_u64(allocate_shift_str)? {
            Some(v) => v,
            None => {
                return Err(LabelConfigDecodeError::Missing {
                    name: allocate_shift_str,
                })
            }
        };

        // Guid.
        let guid_str = PoolConfigKey::Guid.into();
        let guid = match list.get_u64(guid_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: guid_str }),
        };

        // Version.
        let version_str = PoolConfigKey::Version.into();
        let version = SpaVersion::try_from(match list.get_u64(version_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: version_str }),
        })?;

        ////////////////////////////////
        // Check for unknown values.
        for pair_res in list {
            let pair = pair_res?;

            // Value is unknown.
            let pool_nv_name = match PoolConfigKey::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(LabelConfigDecodeError::UnknownField { name: pair.name }),
            };

            // Value is known, but not expected.
            if !LabelConfigL2Cache::EXPECTED.contains(&pool_nv_name) {
                return Err(LabelConfigDecodeError::UnexpectedField { name: pool_nv_name });
            }
        }

        ////////////////////////////////
        // Success.
        Ok(LabelConfigL2Cache {
            allocate_shift,
            guid,
            version,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`PoolState::Spare`] information from [`LabelNvPairs`].
#[derive(Debug)]
pub struct LabelConfigSpare {
    /// [`PoolConfigKey::Guid`]
    pub guid: u64,

    /// [`PoolConfigKey::Version`].
    pub version: SpaVersion,
}

impl LabelConfigSpare {
    /// Expected [`PoolConfigKey`] values in [`PoolConfigKey`].
    const EXPECTED: [PoolConfigKey; 3] = [
        PoolConfigKey::Guid,
        PoolConfigKey::State,
        PoolConfigKey::Version,
    ];

    /** Decodes a [`LabelConfigSpare`].
     *
     * # Errors
     *
     * Returns [`LabelConfigDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelConfigSpare, LabelConfigDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.

        // State.
        let state_str = PoolConfigKey::State.into();
        let state = PoolState::try_from(match list.get_u64(state_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: state_str }),
        })?;

        if !matches!(state, PoolState::Spare) {
            return Err(LabelConfigDecodeError::UnexpectedState { state });
        }

        // Guid.
        let guid_str = PoolConfigKey::Guid.into();
        let guid = match list.get_u64(guid_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: guid_str }),
        };

        // Version.
        let version_str = PoolConfigKey::Version.into();
        let version = SpaVersion::try_from(match list.get_u64(version_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: version_str }),
        })?;

        ////////////////////////////////
        // Check for unknown values.
        for pair_res in list {
            let pair = pair_res?;

            // Value is unknown.
            let pool_nv_name = match PoolConfigKey::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(LabelConfigDecodeError::UnknownField { name: pair.name }),
            };

            // Value is known, but not expected.
            if !LabelConfigSpare::EXPECTED.contains(&pool_nv_name) {
                return Err(LabelConfigDecodeError::UnexpectedField { name: pool_nv_name });
            }
        }

        ////////////////////////////////
        // Success.
        Ok(LabelConfigSpare { guid, version })
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Storage information from [`LabelNvPairs`].
 *
 * - [`PoolState::Active`], [`PoolState::Exported`], or [`PoolState::Destroyed`]
 *
 * The information encoded here is a subset of the pool information from the
 * [`crate::phys::DmuType::PackedNvList`] `config` in the MOS.
 */
#[derive(Debug)]
pub struct LabelConfigStorage<'a> {
    /// [`PoolConfigKey::Guid`]
    pub guid: u64,

    /// [`PoolConfigKey::Name`]
    pub name: &'a str,

    /// [`PoolConfigKey::PoolGuid`]
    pub pool_guid: u64,

    /// [`PoolConfigKey::State`]
    pub state: PoolState,

    /// [`PoolConfigKey::TopGuid`]
    pub top_guid: u64,

    /// [`PoolConfigKey::Txg`]
    pub txg: u64,

    /// [`PoolConfigKey::VdevTree`]
    pub vdev_tree: LabelVdevTree<'a>,

    /// [`PoolConfigKey::Version`].
    pub version: SpaVersion,

    /// [`PoolConfigKey::Comment`]
    pub comment: Option<&'a str>,

    /// [`PoolConfigKey::Compatibility`]
    pub compatibility: Option<Compatibility<'a>>,

    /// [`PoolConfigKey::Errata`]
    pub errata: Option<PoolErrata>,

    /// [`PoolConfigKey::HostId`]
    pub host_id: Option<u64>,

    /// [`PoolConfigKey::HostName`]
    pub host_name: Option<&'a str>,

    /// [`PoolConfigKey::IsLog`].
    pub is_log: Option<bool>,

    /// [`PoolConfigKey::IsSpare`].
    pub is_spare: Option<bool>,

    /// [`PoolConfigKey::FeaturesForRead`]
    pub features_for_read: Option<FeatureSet>,

    /// [`PoolConfigKey::SplitGuid`].
    pub split_guid: Option<u64>,

    /// [`PoolConfigKey::VdevChildren`]
    pub vdev_children: Option<u64>,
}

impl LabelConfigStorage<'_> {
    /// Expected [`PoolConfigKey`] values in [`PoolConfigKey`].
    const EXPECTED: [PoolConfigKey; 18] = [
        PoolConfigKey::Comment,
        PoolConfigKey::Compatibility,
        PoolConfigKey::Guid,
        PoolConfigKey::Errata,
        PoolConfigKey::FeaturesForRead,
        PoolConfigKey::HostId,
        PoolConfigKey::HostName,
        PoolConfigKey::IsLog,
        PoolConfigKey::IsSpare,
        PoolConfigKey::Name,
        PoolConfigKey::PoolGuid,
        PoolConfigKey::SplitGuid,
        PoolConfigKey::State,
        PoolConfigKey::TopGuid,
        PoolConfigKey::Txg,
        PoolConfigKey::VdevChildren,
        PoolConfigKey::VdevTree,
        PoolConfigKey::Version,
    ];

    /** Decodes a [`LabelConfigStorage`].
     *
     * # Errors
     *
     * Returns [`LabelConfigDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelConfigStorage<'a>, LabelConfigDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let guid_str = PoolConfigKey::Guid.into();
        let guid = match list.get_u64(guid_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: guid_str }),
        };

        let name_str = PoolConfigKey::Name.into();
        let name = match list.get_str(name_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: name_str }),
        };

        let pool_guid_str = PoolConfigKey::PoolGuid.into();
        let pool_guid = match list.get_u64(pool_guid_str)? {
            Some(v) => v,
            None => {
                return Err(LabelConfigDecodeError::Missing {
                    name: pool_guid_str,
                })
            }
        };

        let state_str = PoolConfigKey::State.into();
        let state = PoolState::try_from(match list.get_u64(state_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: state_str }),
        })?;

        match state {
            PoolState::Active | PoolState::Exported | PoolState::Destroyed => (),
            _ => return Err(LabelConfigDecodeError::UnexpectedState { state }),
        };

        let top_guid_str = PoolConfigKey::TopGuid.into();
        let top_guid = match list.get_u64(top_guid_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: top_guid_str }),
        };

        let txg_str = PoolConfigKey::Txg.into();
        let txg = match list.get_u64(txg_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: txg_str }),
        };

        let vdev_tree_str = PoolConfigKey::VdevTree.into();
        let vdev_tree_list = match list.get_nv_list(vdev_tree_str)? {
            Some(v) => v,
            None => {
                return Err(LabelConfigDecodeError::Missing {
                    name: vdev_tree_str,
                })
            }
        };
        let vdev_tree = LabelVdevTree::from_list(&vdev_tree_list)?;

        let version_str = PoolConfigKey::Version.into();
        let version = SpaVersion::try_from(match list.get_u64(version_str)? {
            Some(v) => v,
            None => return Err(LabelConfigDecodeError::Missing { name: version_str }),
        })?;

        ////////////////////////////////
        // Decode optional values.
        let comment = list.get_str(PoolConfigKey::Comment.into())?;

        let compatibility = list
            .get_str(PoolConfigKey::Compatibility.into())?
            .map(Compatibility::from);

        let errata = match list.get_u64(PoolConfigKey::Errata.into())? {
            Some(v) => Some(PoolErrata::try_from(v)?),
            None => None,
        };

        let host_id = list.get_u64(PoolConfigKey::HostId.into())?;
        let host_name = list.get_str(PoolConfigKey::HostName.into())?;

        let is_log = list.get_u64(PoolConfigKey::IsLog.into())?.map(|v| v != 0);

        let is_spare = list.get_u64(PoolConfigKey::IsSpare.into())?.map(|v| v != 0);

        let features_for_read = match list.get_nv_list(PoolConfigKey::FeaturesForRead.into())? {
            Some(v) => Some(FeatureSet::from_list(&v)?),
            None => None,
        };

        let split_guid_str = PoolConfigKey::SplitGuid.into();
        let split_guid = list.get_u64(split_guid_str)?;

        let vdev_children = list.get_u64(PoolConfigKey::VdevChildren.into())?;

        ////////////////////////////////
        // Check for unknown values.
        for pair_res in list {
            let pair = pair_res?;

            // Value is unknown.
            let pool_nv_name = match PoolConfigKey::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(LabelConfigDecodeError::UnknownField { name: pair.name }),
            };

            // Value is known, but not expected.
            if !LabelConfigStorage::EXPECTED.contains(&pool_nv_name) {
                return Err(LabelConfigDecodeError::UnexpectedField { name: pool_nv_name });
            }
        }

        ////////////////////////////////
        // Success.
        Ok(LabelConfigStorage {
            guid,
            name,
            pool_guid,
            state,
            top_guid,
            txg,
            vdev_tree,
            version,
            comment,
            compatibility,
            errata,
            features_for_read,
            host_id,
            host_name,
            is_log,
            is_spare,
            split_guid,
            vdev_children,
        })
    }
}

/// [`LabelConfig`] decode error.
#[derive(Debug)]
pub enum LabelConfigDecodeError<'a> {
    /// [`FeatureSet`] decode error.
    FeatureSet {
        /// Error.
        err: FeatureSetDecodeError<'a>,
    },

    /// Missing expected value.
    Missing {
        /// Name of missing key.
        name: &'a str,
    },

    /// [`PoolErrata`] decode error.
    PoolErrata {
        /// Error.
        err: PoolErrataDecodeError,
    },

    /// [`PoolState`] decode error.
    PoolState {
        /// Error.
        err: PoolStateDecodeError,
    },

    /// [`crate::phys::nv::NvList`] decode error.
    Nv {
        /// Error.
        err: NvDecodeError,
    },

    /// Unexpected field.
    UnexpectedField {
        /// Field.
        name: PoolConfigKey,
    },

    /// Unexpected state.
    UnexpectedState {
        /// State.
        state: PoolState,
    },

    /// Unknown field.
    UnknownField {
        /// Unknown field.
        name: &'a str,
    },

    /// [`LabelVdevTree`] decode error.
    VdevTree {
        /// Error.
        err: LabelVdevTreeDecodeError<'a>,
    },

    /// Unknown verison.
    Version {
        /// Error.
        err: SpaVersionError,
    },
}

impl<'a> From<FeatureSetDecodeError<'a>> for LabelConfigDecodeError<'a> {
    fn from(err: FeatureSetDecodeError<'a>) -> Self {
        LabelConfigDecodeError::FeatureSet { err }
    }
}

impl From<NvDecodeError> for LabelConfigDecodeError<'_> {
    fn from(err: NvDecodeError) -> Self {
        LabelConfigDecodeError::Nv { err }
    }
}

impl From<PoolErrataDecodeError> for LabelConfigDecodeError<'_> {
    fn from(err: PoolErrataDecodeError) -> Self {
        LabelConfigDecodeError::PoolErrata { err }
    }
}

impl From<PoolStateDecodeError> for LabelConfigDecodeError<'_> {
    fn from(err: PoolStateDecodeError) -> Self {
        LabelConfigDecodeError::PoolState { err }
    }
}

impl From<SpaVersionError> for LabelConfigDecodeError<'_> {
    fn from(err: SpaVersionError) -> Self {
        LabelConfigDecodeError::Version { err }
    }
}

impl<'a> From<LabelVdevTreeDecodeError<'a>> for LabelConfigDecodeError<'a> {
    fn from(err: LabelVdevTreeDecodeError<'a>) -> Self {
        LabelConfigDecodeError::VdevTree { err }
    }
}

impl fmt::Display for LabelConfigDecodeError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelConfigDecodeError::FeatureSet { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
            LabelConfigDecodeError::Missing { name } => {
                write!(f, "LabelConfig decode error, missing field '{name}'")
            }
            LabelConfigDecodeError::Nv { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
            LabelConfigDecodeError::PoolErrata { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
            LabelConfigDecodeError::PoolState { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
            LabelConfigDecodeError::UnexpectedField { name } => {
                write!(f, "LabelConfig decode error, unexpected field '{name}'")
            }
            LabelConfigDecodeError::UnexpectedState { state } => {
                write!(f, "LabelConfig decode error, unexpected state '{state}'")
            }
            LabelConfigDecodeError::UnknownField { name } => {
                write!(f, "LabelConfig decode error, unknown field '{name}'")
            }
            LabelConfigDecodeError::VdevTree { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
            LabelConfigDecodeError::Version { err } => {
                write!(f, "LabelConfig decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelConfigDecodeError<'_> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            // TODO(cybojanek): Is there a workaround for non-static lifetime?
            // LabelConfigDecodeError::FeatureSet { err } => Some(err),
            LabelConfigDecodeError::Nv { err } => Some(err),
            LabelConfigDecodeError::PoolErrata { err } => Some(err),
            LabelConfigDecodeError::PoolState { err } => Some(err),
            // TODO(cybojanek): Is there a workaround for non-static lifetime?
            // LabelConfigDecodeError::VdevTree { err } => Some(err),
            LabelConfigDecodeError::Version { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`VdevTreeKey::VdevType`] specific fields for [`PoolConfigKey::VdevTree`].
#[derive(Debug)]
pub enum LabelVdevTreeType<'a> {
    /// [`VdevType::Disk`].
    Disk(LabelVdevTreeDisk<'a>),

    /// [`VdevType::File`].
    File(LabelVdevTreeFile<'a>),

    /// [`VdevType::Mirror`].
    Mirror(LabelVdevTreeMirror<'a>),

    /// [`VdevType::RaidZ`].
    RaidZ(LabelVdevTreeRaidZ<'a>),
}

impl<'a> LabelVdevTreeType<'a> {
    /// Gets the children from the vdev tree.
    pub fn children(&self) -> Option<NvArray<'a, NvList<'a>>> {
        match self {
            LabelVdevTreeType::Disk(_) | LabelVdevTreeType::File(_) => None,
            LabelVdevTreeType::Mirror(mirror) => Some(mirror.children),
            LabelVdevTreeType::RaidZ(raidz) => Some(raidz.children),
        }
    }
}

/// Fields for [`PoolConfigKey::VdevTree`].
#[derive(Debug)]
pub struct LabelVdevTree<'a> {
    /// [`VdevTreeKey::AllocateShift`].
    pub allocate_shift: u64,

    /// [`VdevTreeKey::AllocateSize`].
    pub allocate_size: u64,

    /// [`VdevTreeKey::Guid`].
    pub guid: u64,

    /// [`VdevTreeKey::Id`].
    pub id: u64,

    /// [`VdevTreeKey::MetaSlabArray`].
    pub metaslab_array: u64,

    /// [`VdevTreeKey::MetaSlabShift`].
    pub metaslab_shift: u64,

    /// [`VdevTreeKey::VdevType`].
    pub vdev_type: LabelVdevTreeType<'a>,

    /// [`VdevTreeKey::CreateTxg`].
    pub create_txg: Option<u64>,

    /// [`VdevTreeKey::IsLog`].
    pub is_log: Option<bool>,
}

impl LabelVdevTree<'_> {
    /// Expected [`VdevTreeKey`] values in [`VdevTreeKey`].
    const EXPECTED: [VdevTreeKey; 9] = [
        VdevTreeKey::AllocateShift,
        VdevTreeKey::AllocateSize,
        VdevTreeKey::CreateTxg,
        VdevTreeKey::Guid,
        VdevTreeKey::Id,
        VdevTreeKey::IsLog,
        VdevTreeKey::MetaSlabArray,
        VdevTreeKey::MetaSlabShift,
        VdevTreeKey::VdevType,
    ];

    /** Decodes a [`LabelVdevTree`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevTree<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let allocate_shift_str = VdevTreeKey::AllocateShift.into();
        let allocate_shift = match list.get_u64(allocate_shift_str)? {
            Some(v) => v,
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: allocate_shift_str,
                })
            }
        };

        let allocate_size_str = VdevTreeKey::AllocateSize.into();
        let allocate_size = match list.get_u64(allocate_size_str)? {
            Some(v) => v,
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: allocate_size_str,
                })
            }
        };

        let guid_str = VdevTreeKey::Guid.into();
        let guid = match list.get_u64(guid_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: guid_str }),
        };

        let id_str = VdevTreeKey::Id.into();
        let id = match list.get_u64(id_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: id_str }),
        };

        let metaslab_array_str = VdevTreeKey::MetaSlabArray.into();
        let metaslab_array = match list.get_u64(metaslab_array_str)? {
            Some(v) => v,
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: metaslab_array_str,
                })
            }
        };

        let metaslab_shift_str = VdevTreeKey::MetaSlabShift.into();
        let metaslab_shift = match list.get_u64(metaslab_shift_str)? {
            Some(v) => v,
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: metaslab_shift_str,
                })
            }
        };

        ////////////////////////////////
        // Decode optional values.
        let create_txg = list.get_u64(VdevTreeKey::CreateTxg.into())?;

        let is_log = list.get_u64(VdevTreeKey::IsLog.into())?.map(|v| v != 0);

        ////////////////////////////////
        // Decode type.
        let vdev_type_str = VdevTreeKey::VdevType.into();
        let vdev_type = match list.get_str(vdev_type_str)? {
            Some(v) => match VdevType::try_from(v) {
                Ok(v) => v,
                Err(_) => return Err(LabelVdevTreeDecodeError::UnknownVdevType { vdev_type: v }),
            },
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: vdev_type_str,
                })
            }
        };

        let vdev_type_expected_fields: &[VdevTreeKey];

        let vdev_type = match vdev_type {
            VdevType::Disk => {
                vdev_type_expected_fields = &LabelVdevTreeDisk::EXPECTED;
                LabelVdevTreeType::Disk(LabelVdevTreeDisk::from_list(list)?)
            }
            VdevType::File => {
                vdev_type_expected_fields = &LabelVdevTreeFile::EXPECTED;
                LabelVdevTreeType::File(LabelVdevTreeFile::from_list(list)?)
            }
            VdevType::Mirror => {
                vdev_type_expected_fields = &LabelVdevTreeMirror::EXPECTED;
                LabelVdevTreeType::Mirror(LabelVdevTreeMirror::from_list(list)?)
            }
            VdevType::RaidZ => {
                vdev_type_expected_fields = &LabelVdevTreeRaidZ::EXPECTED;
                LabelVdevTreeType::RaidZ(LabelVdevTreeRaidZ::from_list(list)?)
            }
            _ => return Err(LabelVdevTreeDecodeError::UnsupportedVdevType { vdev_type }),
        };

        ////////////////////////////////
        // Check for unknown values.
        for pair_res in list {
            let pair = pair_res?;

            // Value is unknown.
            let pool_nv_name = match VdevTreeKey::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(LabelVdevTreeDecodeError::Unknown { name: pair.name }),
            };

            // Value is known, but not expected.
            if !LabelVdevTree::EXPECTED.contains(&pool_nv_name)
                && !vdev_type_expected_fields.contains(&pool_nv_name)
            {
                return Err(LabelVdevTreeDecodeError::Unexpected { name: pool_nv_name });
            }
        }

        ////////////////////////////////
        // Success.
        Ok(LabelVdevTree {
            allocate_shift,
            allocate_size,
            guid,
            id,
            metaslab_array,
            metaslab_shift,
            vdev_type,
            create_txg,
            is_log,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`VdevType::Disk`] fields of a [`LabelVdevTree`].
#[derive(Debug)]
pub struct LabelVdevTreeDisk<'a> {
    /// [`VdevTreeKey::Path`].
    pub path: &'a str,

    /// [`VdevTreeKey::DevId`].
    pub dev_id: Option<&'a str>,

    /// [`VdevTreeKey::PhysPath`].
    pub phys_path: Option<&'a str>,

    /// [`VdevTreeKey::WholeDisk`].
    pub whole_disk: Option<bool>,
}

impl LabelVdevTreeDisk<'_> {
    /// Expected [`VdevTreeKey`] values in [`LabelVdevTreeDisk`].
    const EXPECTED: [VdevTreeKey; 4] = [
        VdevTreeKey::DevId,
        VdevTreeKey::Path,
        VdevTreeKey::PhysPath,
        VdevTreeKey::WholeDisk,
    ];

    /** Decodes a [`LabelVdevTreeDisk`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevTreeDisk<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let path_str = VdevTreeKey::Path.into();
        let path = match list.get_str(path_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: path_str }),
        };

        ////////////////////////////////
        // Decode optional values.
        let dev_id = list.get_str(VdevTreeKey::DevId.into())?;
        let phys_path = list.get_str(VdevTreeKey::PhysPath.into())?;

        let whole_disk = list.get_u64(VdevTreeKey::WholeDisk.into())?.map(|v| v != 0);

        ////////////////////////////////
        // Success.
        Ok(LabelVdevTreeDisk {
            path,
            dev_id,
            phys_path,
            whole_disk,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`VdevType::File`] fields of a [`LabelVdevTree`].
#[derive(Debug)]
pub struct LabelVdevTreeFile<'a> {
    /// [`VdevTreeKey::Path`].
    pub path: &'a str,
}

impl LabelVdevTreeFile<'_> {
    /// Expected [`VdevTreeKey`] values in [`LabelVdevTreeFile`].
    const EXPECTED: [VdevTreeKey; 1] = [VdevTreeKey::Path];

    /** Decodes a [`LabelVdevTreeFile`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevTreeFile<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let path_str = VdevTreeKey::Path.into();
        let path = match list.get_str(path_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: path_str }),
        };

        ////////////////////////////////
        // Success.
        Ok(LabelVdevTreeFile { path })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`VdevType::Mirror`] fields of a [`LabelVdevTree`].
pub struct LabelVdevTreeMirror<'a> {
    /// [`VdevTreeKey::Children`].
    pub children: NvArray<'a, NvList<'a>>,
}

impl fmt::Debug for LabelVdevTreeMirror<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("LabelVdevTreeMirror")
            .field("count", &self.children.len())
            .finish()
    }
}

impl LabelVdevTreeMirror<'_> {
    /// Expected [`VdevTreeKey`] values in [`LabelVdevTreeMirror`].
    const EXPECTED: [VdevTreeKey; 1] = [VdevTreeKey::Children];

    /** Decodes a [`LabelVdevTreeMirror`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevTreeMirror<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let children_str = VdevTreeKey::Children.into();
        let children = match list.get_nv_list_array(children_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: children_str }),
        };

        ////////////////////////////////
        // Success.
        Ok(LabelVdevTreeMirror { children })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`VdevType::RaidZ`] fields of a [`LabelVdevTree`].
pub struct LabelVdevTreeRaidZ<'a> {
    /// [`VdevTreeKey::Children`].
    pub children: NvArray<'a, NvList<'a>>,

    /// [`VdevTreeKey::NParity`].
    pub parity: Option<u64>,
}

impl fmt::Debug for LabelVdevTreeRaidZ<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("LabelVdevTreeRaidZ")
            .field("count", &self.children.len())
            .field("parity", &self.parity)
            .finish()
    }
}

impl LabelVdevTreeRaidZ<'_> {
    /// Expected [`VdevTreeKey`] values in [`LabelVdevTreeRaidZ`].
    const EXPECTED: [VdevTreeKey; 2] = [VdevTreeKey::Children, VdevTreeKey::NParity];

    /** Decodes a [`LabelVdevTreeRaidZ`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevTreeRaidZ<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let children_str = VdevTreeKey::Children.into();
        let children = match list.get_nv_list_array(children_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: children_str }),
        };

        ////////////////////////////////
        // Decode optional values.
        let parity = list.get_u64(VdevTreeKey::NParity.into())?;

        ////////////////////////////////
        // Success.
        Ok(LabelVdevTreeRaidZ { children, parity })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A child entry from the `children` array of a a [`VdevType::Mirror`] or [`VdevType::RaidZ`].
#[derive(Debug)]
pub struct LabelVdevChild<'a> {
    /// [`PoolConfigKey::Guid`]
    pub guid: u64,

    /// [`VdevTreeKey::Id`].
    pub id: u64,

    /// [`VdevTreeKey::Path`].
    pub path: &'a str,

    /// [`VdevTreeKey::VdevType`].
    pub vdev_type: VdevType,

    /// [`VdevTreeKey::CreateTxg`].
    pub create_txg: Option<u64>,
}

impl LabelVdevChild<'_> {
    /// Expected [`VdevTreeKey`] values in [`LabelVdevChild`].
    const EXPECTED: [VdevTreeKey; 5] = [
        VdevTreeKey::CreateTxg,
        VdevTreeKey::Guid,
        VdevTreeKey::Id,
        VdevTreeKey::Path,
        VdevTreeKey::VdevType,
    ];

    /** Decodes a [`LabelVdevChild`].
     *
     * # Errors
     *
     * Returns [`LabelVdevTreeDecodeError`] in case of decoding error.
     */
    pub fn from_list<'a>(
        list: &NvList<'a>,
    ) -> Result<LabelVdevChild<'a>, LabelVdevTreeDecodeError<'a>> {
        ////////////////////////////////
        // Decode required values.
        let id_str = VdevTreeKey::Id.into();
        let id = match list.get_u64(id_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: id_str }),
        };

        let guid_str = VdevTreeKey::Guid.into();
        let guid = match list.get_u64(guid_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: guid_str }),
        };

        let path_str = VdevTreeKey::Path.into();
        let path = match list.get_str(path_str)? {
            Some(v) => v,
            None => return Err(LabelVdevTreeDecodeError::Missing { name: path_str }),
        };

        let vdev_type_str = VdevTreeKey::VdevType.into();
        let vdev_type = match list.get_str(vdev_type_str)? {
            Some(v) => match VdevType::try_from(v) {
                Ok(v) => v,
                Err(_) => return Err(LabelVdevTreeDecodeError::UnknownVdevType { vdev_type: v }),
            },
            None => {
                return Err(LabelVdevTreeDecodeError::Missing {
                    name: vdev_type_str,
                })
            }
        };

        ////////////////////////////////
        // Decode optional values.
        let create_txg = list.get_u64(VdevTreeKey::CreateTxg.into())?;

        ////////////////////////////////
        // Check for unknown values.
        for pair_res in list {
            let pair = pair_res?;

            // Value is unknown.
            let pool_nv_name = match VdevTreeKey::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(LabelVdevTreeDecodeError::Unknown { name: pair.name }),
            };

            // Value is known, but not expected.
            if !LabelVdevChild::EXPECTED.contains(&pool_nv_name) {
                return Err(LabelVdevTreeDecodeError::Unexpected { name: pool_nv_name });
            }
        }

        ////////////////////////////////
        // Success.
        Ok(LabelVdevChild {
            guid,
            id,
            path,
            vdev_type,
            create_txg,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`LabelVdevTree`] decode error.
#[derive(Debug)]
pub enum LabelVdevTreeDecodeError<'a> {
    /// Missing expected value.
    Missing {
        /// Name of missing key.
        name: &'static str,
    },

    /// [`crate::phys::nv::NvList`] decode error.
    Nv {
        /// Error.
        err: NvDecodeError,
    },

    /// Unexpected field.
    Unexpected {
        /// Field.
        name: VdevTreeKey,
    },

    /// Unknown field.
    Unknown {
        /// Unknown field.
        name: &'a str,
    },

    /// Unknown vdev type.
    UnknownVdevType {
        /// Unknown vdev type.
        vdev_type: &'a str,
    },

    /// Unsupported vdev type.
    UnsupportedVdevType {
        /// Unsupported vdev type.
        vdev_type: VdevType,
    },
}

impl From<NvDecodeError> for LabelVdevTreeDecodeError<'_> {
    fn from(err: NvDecodeError) -> Self {
        LabelVdevTreeDecodeError::Nv { err }
    }
}

impl fmt::Display for LabelVdevTreeDecodeError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelVdevTreeDecodeError::Missing { name } => {
                write!(f, "LabelVdevTree decode error, missing field '{name}'")
            }
            LabelVdevTreeDecodeError::Nv { err } => {
                write!(f, "LabelVdevTree decode error | {err}")
            }
            LabelVdevTreeDecodeError::Unexpected { name } => {
                write!(f, "LabelVdevTree decode error, unexpected field '{name}'")
            }
            LabelVdevTreeDecodeError::Unknown { name } => {
                write!(f, "LabelVdevTree decode error, unknown field '{name}'")
            }
            LabelVdevTreeDecodeError::UnknownVdevType { vdev_type } => {
                write!(
                    f,
                    "LabelVdevTree decode error, unknown vdev type '{vdev_type}'"
                )
            }
            LabelVdevTreeDecodeError::UnsupportedVdevType { vdev_type } => {
                write!(
                    f,
                    "LabelVdevTree decode error, unsupported vdev type '{vdev_type}'"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelVdevTreeDecodeError<'_> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelVdevTreeDecodeError::Nv { err } => Some(err),
            _ => None,
        }
    }
}
