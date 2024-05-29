// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_checksum, label_verify, LabelChecksumError, LabelVerifyError, Sha256};
use crate::phys::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError, ChecksumTail,
    EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder, EndianOrder, NvPairs,
    Version, VersionError,
};

////////////////////////////////////////////////////////////////////////////////

/** Uberblock.
 *
 * ### Byte layout.
 *
 * - Bytes: 1024
 * - It looks like MMP was added without a version flag.
 *
 * ```text
 * +------------------+------+---------+------------------------------+
 * | Field            | Size | Version | Feature                      |
 * +------------------+------+---------+------------------------------+
 * | magic            |   8 |        1 |
 * +------------------+------+---------+
 * | version          |   8 |        1 |
 * +------------------+------+---------+
 * | txg              |   8 |        1 |
 * +------------------+------+---------+
 * | guid sum         |   8 |        1 |
 * +------------------+------+---------+
 * | timestamp        |   8 |        1 |
 * +------------------+------+---------+
 * | block pointer    | 128 |        1 |
 * +------------------+------+---------+
 * | software version |   8 |       26 |
 * +------------------+------+---------+
 * | mmp              |  24 |     5000 |
 * +------------------+------+---------+------------------------------+
 * | checkpoint txg   |   8 |     5000 | com.delphix:zpool_checkpoint |
 * +------------------+------+---------+------------------------------+
 * | padding          | 776 |          |
 * +------------------+------+---------+
 * | checksum tail    |  40 |        1 |
 * +------------------+------+---------+
 * ```
 *
 * ### order
 *
 * The `magic` field must match [`UberBlock::MAGIC`], and its byte order
 * determines the value of `order`.
 *
 * ### other fields
 *
 * TODO: Document.
 */
#[derive(Debug)]
pub struct UberBlock {
    /// Zpool checkpoint transaction group.
    pub checkpoint_txg: u64,

    /// Endian order.
    pub order: EndianOrder,

    /// Sum of all leaf vdev GUIDs.
    pub guid_sum: u64,

    /// Multi-Modifier protection.
    pub mmp: Option<UberBlockMmp>,

    /// [`BlockPointer`] to root ObjectSet.
    pub ptr: BlockPointer,

    /// Maximum [`Version`] supported by software that wrote out this txg.
    pub software_version: Option<Version>,

    /** UTC timestamp of this [`UberBlock`] being written out.
     *
     * In seconds since January 1st 1970 (GMT).
     */
    pub timestamp: u64,

    /// Transaction group number for this [`UberBlock`].
    pub txg: u64,

    /// Format of on disk data.
    pub version: Version,
}

impl UberBlock {
    /// Byte length of an encoded [`UberBlock`].
    pub const LENGTH: usize = 1024;

    /// Byte offset into a [`Label`] of first [`UberBlock`].
    pub const LABEL_OFFSET: usize = NvPairs::LABEL_OFFSET + NvPairs::LENGTH;

    /// Padding size.
    const PADDING_SIZE: usize = 776;

    /// Magic value for an encoded [`UberBlock`].
    pub const MAGIC: u64 = 0x0000000000bab10c;

    /** Checks if the bytes match an empty [`UberBlock`] pattern.
     */
    fn bytes_are_empty(bytes: &[u8; UberBlock::LENGTH], exclude_checksum: bool) -> bool {
        // NOTE: It looks like some ZFS implementations write an empty
        //       UberBlock as all zero, except for the version.
        //       Others, write out all zero, except for the version, and
        //       checksum.
        let decoder = EndianDecoder::from_bytes(bytes, EndianOrder::Little);

        // If magic is zero.
        if let Ok(magic_is_zero) = decoder.is_zero_skip(8) {
            if magic_is_zero {
                // Skip version.
                if let Ok(_e) = decoder.skip(8) {
                    // If the rest is zero.
                    let rest_size = UberBlock::LENGTH
                        - 16
                        - (if exclude_checksum {
                            ChecksumTail::LENGTH
                        } else {
                            0
                        });
                    if let Ok(rest_is_zero) = decoder.is_zero_skip(rest_size) {
                        if rest_is_zero {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /** Decodes an [`UberBlock`]. Returns [`None`] if [`UberBlock`] is empty.
     *
     * # Errors
     *
     * Returns [`UberBlockDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; UberBlock::LENGTH],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<Option<UberBlock>, UberBlockDecodeError> {
        ////////////////////////////////
        // Verify checksum.
        if let Err(checksum_err) = label_verify(bytes, offset, sha256) {
            // Check if the entire UberBlock is empty.
            if UberBlock::bytes_are_empty(bytes, false) {
                return Ok(None);
            }

            // Else, return the error.
            return Err(UberBlockDecodeError::LabelVerify { err: checksum_err });
        }

        ////////////////////////////////
        // Create decoder.
        let decoder = match EndianDecoder::from_u64_magic(bytes, UberBlock::MAGIC) {
            Ok(v) => v,
            Err(
                e @ EndianDecodeError::InvalidMagic {
                    expected: _,
                    actual: _,
                },
            ) => {
                // Check if the entire UberBlock up to the checksum is empty.
                if UberBlock::bytes_are_empty(bytes, true) {
                    return Ok(None);
                }

                // Else, re-raise error.
                return Err(UberBlockDecodeError::Endian { err: e });
            }
            // Else, re-raise error.
            Err(e) => return Err(UberBlockDecodeError::Endian { err: e }),
        };

        ////////////////////////////////
        // Decode fields.
        let version = Version::try_from(decoder.get_u64()?)?;
        let txg = decoder.get_u64()?;
        let guid_sum = decoder.get_u64()?;
        let timestamp = decoder.get_u64()?;

        ////////////////////////////////
        // Decode block pointer.
        let block_ptr = match BlockPointer::from_decoder(&decoder)? {
            Some(ptr) => ptr,
            None => return Err(UberBlockDecodeError::EmptyBlockPointer {}),
        };

        ////////////////////////////////
        // Decode software version.
        let software_version = match decoder.get_u64()? {
            0 => None,
            v => Some(Version::try_from(v)?),
        };

        ////////////////////////////////
        // Decode MMP.
        let mmp = UberBlockMmp::from_decoder(&decoder)?;

        ////////////////////////////////
        // Decode checkpoint transaction group.
        let checkpoint_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Check that the rest of the uber block (up to the checksum at the
        // tail) is all zeroes.
        decoder.skip_zero_padding(UberBlock::PADDING_SIZE)?;

        ////////////////////////////////
        // Success.
        Ok(Some(UberBlock {
            checkpoint_txg,
            order: decoder.order(),
            guid_sum,
            mmp,
            ptr: block_ptr,
            software_version,
            timestamp,
            txg,
            version,
        }))
    }

    /** Encodes an [`UberBlock`].
     *
     * # Errors
     *
     * Returns [`UberBlockEncodeError`] on error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; UberBlock::LENGTH],
        offset: u64,
        sha256: &mut Sha256,
    ) -> Result<(), UberBlockEncodeError> {
        ////////////////////////////////
        // Create encoder.
        let mut encoder = EndianEncoder::to_bytes(bytes, self.order);
        encoder.put_u64(UberBlock::MAGIC)?;

        ////////////////////////////////
        // Encode fields.
        encoder.put_u64(self.version.into())?;
        encoder.put_u64(self.txg)?;
        encoder.put_u64(self.guid_sum)?;
        encoder.put_u64(self.timestamp)?;

        ////////////////////////////////
        // Encode block pointer.
        self.ptr.to_encoder(&mut encoder)?;

        ////////////////////////////////
        // Encode software version (conditionally).
        match self.software_version {
            Some(v) => encoder.put_u64(v.into())?,
            None => encoder.put_u64(0)?,
        };

        ////////////////////////////////
        // Encode MMP (conditionally).
        match &self.mmp {
            Some(mmp) => mmp.to_encoder(&mut encoder)?,
            None => {
                encoder.put_zero_padding(UberBlockMmp::LENGTH)?;
            }
        }

        ////////////////////////////////
        // Encode checkpoint transaction group.
        encoder.put_u64(self.checkpoint_txg)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(UberBlock::PADDING_SIZE)?;

        ////////////////////////////////
        // Compute checksum.
        label_checksum(bytes, offset, sha256, self.order)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/// [`UberBlock`] decode error.
#[derive(Debug)]
pub enum UberBlockDecodeError {
    /// [`BlockPointer`] decode error.
    BlockPointer {
        /// Error.
        err: BlockPointerDecodeError,
    },

    /// [`BlockPointer`] is empty. */
    EmptyBlockPointer {},

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Label checksum verification error.
    LabelVerify {
        /// Error.
        err: LabelVerifyError,
    },

    /// [`Version`] decode error.
    Version {
        /// Error.
        err: VersionError,
    },

    /// [`UberBlockMmp`] decode error.
    UberBlockMmp {
        /// Error.
        err: UberBlockMmpDecodeError,
    },
}

impl From<LabelVerifyError> for UberBlockDecodeError {
    fn from(value: LabelVerifyError) -> Self {
        UberBlockDecodeError::LabelVerify { err: value }
    }
}

impl From<BlockPointerDecodeError> for UberBlockDecodeError {
    fn from(value: BlockPointerDecodeError) -> Self {
        UberBlockDecodeError::BlockPointer { err: value }
    }
}

impl From<EndianDecodeError> for UberBlockDecodeError {
    fn from(value: EndianDecodeError) -> Self {
        UberBlockDecodeError::Endian { err: value }
    }
}

impl From<UberBlockMmpDecodeError> for UberBlockDecodeError {
    fn from(value: UberBlockMmpDecodeError) -> Self {
        UberBlockDecodeError::UberBlockMmp { err: value }
    }
}

impl From<VersionError> for UberBlockDecodeError {
    fn from(value: VersionError) -> Self {
        UberBlockDecodeError::Version { err: value }
    }
}

impl fmt::Display for UberBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockDecodeError::BlockPointer { err } => {
                write!(f, "UberBlock decode error, block pointer: [{err}]")
            }
            UberBlockDecodeError::EmptyBlockPointer {} => {
                write!(f, "UberBlock decode error, empty block[ pointer]")
            }
            UberBlockDecodeError::Endian { err } => {
                write!(f, "UberBlock decode error, endian: [{err}]")
            }
            UberBlockDecodeError::LabelVerify { err } => {
                write!(f, "UberBlock decode error, label verify: [{err}]")
            }
            UberBlockDecodeError::UberBlockMmp { err } => {
                write!(f, "UberBlock decode error, MMP: [{err}]")
            }
            UberBlockDecodeError::Version { err } => {
                write!(f, "UberBlock decode error, version: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockDecodeError::BlockPointer { err } => Some(err),
            UberBlockDecodeError::EmptyBlockPointer {} => None,
            UberBlockDecodeError::Endian { err } => Some(err),
            UberBlockDecodeError::LabelVerify { err } => Some(err),
            UberBlockDecodeError::UberBlockMmp { err } => Some(err),
            UberBlockDecodeError::Version { err } => Some(err),
        }
    }
}

/// [`UberBlock`] encode error.
#[derive(Debug)]
pub enum UberBlockEncodeError {
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

    /// Label checksum error.
    LabelChecksum {
        /// Error.
        err: LabelChecksumError,
    },

    /// [`UberBlockMmp`] encode error.
    UberBlockMmp {
        /// Error.
        err: UberBlockMmpEncodeError,
    },
}

impl From<LabelChecksumError> for UberBlockEncodeError {
    fn from(value: LabelChecksumError) -> Self {
        UberBlockEncodeError::LabelChecksum { err: value }
    }
}

impl From<BlockPointerEncodeError> for UberBlockEncodeError {
    fn from(value: BlockPointerEncodeError) -> Self {
        UberBlockEncodeError::BlockPointer { err: value }
    }
}

impl From<EndianEncodeError> for UberBlockEncodeError {
    fn from(value: EndianEncodeError) -> Self {
        UberBlockEncodeError::Endian { err: value }
    }
}

impl From<UberBlockMmpEncodeError> for UberBlockEncodeError {
    fn from(value: UberBlockMmpEncodeError) -> Self {
        UberBlockEncodeError::UberBlockMmp { err: value }
    }
}

impl fmt::Display for UberBlockEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockEncodeError::BlockPointer { err } => {
                write!(f, "UberBlock encode error, BlockPointer: [{err}]")
            }
            UberBlockEncodeError::Endian { err } => {
                write!(f, "UberBlock encode error, endian: [{err}]")
            }
            UberBlockEncodeError::LabelChecksum { err } => {
                write!(f, "UberBlock encode error, label checksum: [{err}]")
            }
            UberBlockEncodeError::UberBlockMmp { err } => {
                write!(f, "UberBlock encode error, MMP: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockEncodeError::BlockPointer { err } => Some(err),
            UberBlockEncodeError::Endian { err } => Some(err),
            UberBlockEncodeError::LabelChecksum { err } => Some(err),
            UberBlockEncodeError::UberBlockMmp { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** UberBlock MMP configuration.
 *
 * ### Byte layout.
 *
 * - Bytes: 24
 *
 * ```text
 * +--------+------+
 * | Field  | Size |
 * +--------+------+
 * | magic  |    8 |
 * +--------+------+
 * | delay  |    8 |
 * +--------+------+
 * | config |    8 |
 * +--------+------+
 * ```
 *
 * ### Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           magic (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           delay (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |      fail intervals (16)     |         sequence (16)         |             write interval ms (24)            |   xxxx x f s w |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * w: write interval is valid
 * s: sequence is valid
 * f: fail intervals is valid
 * x: reserved
 * ```
 *
 * ### magic
 *
 * The `magic` field must match [`UberBlockMmp::MAGIC`], and its byte order is
 * determined by the parent [`UberBlock`].
 *
 * ### delay
 *
 * Nanoseconds since last MMP write. (TODO: explain)
 *
 * ### f s w
 *
 * Bits that determine if fail intervals, sequnce, and write interval are set.
 *
 * ### write interval
 *
 * Milliseconds between writing out successive [`UberBlockMmp`].
 *
 * ### sequence
 *
 * Sequence counter to distinguish writes, when two [`UberBlock`] have the same
 * timestamp. Reset back to 1 (TODO: or 2?) when [`UberBlock`] timestamp changes.
 *
 * ### fail intervals
 *
 * When `fail_intervals == 0`, MMP write failures are ignored.
 *
 * When `fail_intervals > 0`, pool will be suspended if
 * `fail_intervals * write_interval` amount of time passes between
 * [`UberBlockMmp`] writes.
 */
#[derive(Debug)]
pub struct UberBlockMmp {
    /// Nanoseconds since last MMP write.
    pub delay: u64,

    /// Number of allowed failed write intervals.
    pub fail_intervals: Option<u16>,

    /// Sequence counter for matching uberblock timestamp.
    pub sequence: Option<u16>,

    /// MMP write interval in milliseconds.
    pub write_interval: Option<u32>,
}

/// Write interval is valid bit of [`UberBlockMmp`] config.
const MMP_CONFIG_WRITE_INTERVAL_BIT: u64 = 0x01;

/// Sequence is valid bit of [`UberBlockMmp`] config.
const MMP_CONFIG_SEQUENCE_BIT: u64 = 0x02;

/// Fail intervals is valid bit of [`UberBlockMmp`] config.
const MMP_CONFIG_FAIL_INTERVALS_BIT: u64 = 0x04;

/// Reserved bits of [`UberBlockMmp`] config.
const MMP_CONFIG_RESERVED_BITS: u64 =
    0xff ^ MMP_CONFIG_FAIL_INTERVALS_BIT ^ MMP_CONFIG_SEQUENCE_BIT ^ MMP_CONFIG_WRITE_INTERVAL_BIT;

/// Write interval shift of [`UberBlockMmp`] config.
const MMP_CONFIG_WRITE_INTERVAL_SHIFT: u64 = 8;

/// Shifted write interval mask of [`UberBlockMmp`] config.
const MMP_CONFIG_WRITE_INTERVAL_MASK_LOW: u64 = 0xffffff;

/// Sequence shift of [`UberBlockMmp`] config.
const MMP_CONFIG_SEQUENCE_SHIFT: u64 = 32;

/// Fail intervals shift of [`UberBlockMmp`] config.
const MMP_CONFIG_FAIL_INTERVALS_SHIFT: u64 = 48;

impl UberBlockMmp {
    /// Byte length of an encoded [`UberBlockMmp`].
    pub const LENGTH: usize = 24;

    /// Magic value for an encoded [`UberBlockMmp`].
    pub const MAGIC: u64 = 0x00000000a11cea11;

    /// Maximum write interval.
    pub const WRITE_INTERVAL_MAX: u32 = 0xffffff;

    /** Decodes an [`UberBlockMmp`].
     *
     * # Errors
     *
     * Returns [`UberBlockMmpDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<Option<UberBlockMmp>, UberBlockMmpDecodeError> {
        ////////////////////////////////
        // Decode values.
        let magic = decoder.get_u64()?;
        let delay = decoder.get_u64()?;
        let config = decoder.get_u64()?;

        let fail_intervals = (config >> MMP_CONFIG_FAIL_INTERVALS_SHIFT) as u16;
        let sequence = (config >> MMP_CONFIG_SEQUENCE_SHIFT) as u16;
        let write_interval = ((config >> MMP_CONFIG_WRITE_INTERVAL_SHIFT)
            & MMP_CONFIG_WRITE_INTERVAL_MASK_LOW) as u32;

        ////////////////////////////////
        // Check MMP magic.
        match magic {
            0 => {
                ////////////////////////
                // If magic is 0, then MMP should not be configured, and the
                // following two values should be zero.
                if delay != 0 || config != 0 {
                    return Err(UberBlockMmpDecodeError::NonZeroValues {
                        magic,
                        delay,
                        config,
                    });
                }
                Ok(None)
            }
            UberBlockMmp::MAGIC => {
                ////////////////////////
                // Check that reserved bits are not set.
                if (config & MMP_CONFIG_RESERVED_BITS) != 0 {
                    return Err(UberBlockMmpDecodeError::NonZeroReservedConfigBits { config });
                }

                ////////////////////////
                // Decode config.
                Ok(Some(UberBlockMmp {
                    delay,
                    fail_intervals: if (config & MMP_CONFIG_FAIL_INTERVALS_BIT) != 0 {
                        Some(fail_intervals)
                    } else if fail_intervals != 0 {
                        // The fail intervals bit is not set, and the fail
                        // intervals value is not 0.
                        return Err(UberBlockMmpDecodeError::NonZeroValues {
                            magic,
                            delay,
                            config,
                        });
                    } else {
                        None
                    },
                    sequence: if (config & MMP_CONFIG_SEQUENCE_BIT) != 0 {
                        Some(sequence)
                    } else if sequence != 0 {
                        // The sequence bit is not set, and the sequence value
                        // is not 0.
                        return Err(UberBlockMmpDecodeError::NonZeroValues {
                            magic,
                            delay,
                            config,
                        });
                    } else {
                        None
                    },
                    write_interval: if (config & MMP_CONFIG_WRITE_INTERVAL_BIT) != 0 {
                        Some(write_interval)
                    } else if write_interval != 0 {
                        // The write interval bit is not set, and the write
                        // interval value is not 0.
                        return Err(UberBlockMmpDecodeError::NonZeroValues {
                            magic,
                            delay,
                            config,
                        });
                    } else {
                        None
                    },
                }))
            }
            _ => Err(UberBlockMmpDecodeError::InvalidMagic { magic }),
        }
    }

    /** Encodes an [`UberBlockMmp`].
     *
     * # Errors
     *
     * Returns [`UberBlockMmpEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), UberBlockMmpEncodeError> {
        ////////////////////////////////
        // Encode magic.
        encoder.put_u64(UberBlockMmp::MAGIC)?;

        ////////////////////////////////
        // Encode delay.
        encoder.put_u64(self.delay)?;

        ////////////////////////////////
        // Encode config.
        let config: u64 = (match self.fail_intervals {
            Some(v) => {
                (u64::from(v) << MMP_CONFIG_FAIL_INTERVALS_SHIFT) | MMP_CONFIG_FAIL_INTERVALS_BIT
            }
            None => 0,
        } | match self.sequence {
            Some(v) => (u64::from(v) << MMP_CONFIG_SEQUENCE_SHIFT) | MMP_CONFIG_SEQUENCE_BIT,
            None => 0,
        } | match self.write_interval {
            Some(v) => {
                if u64::from(v) > MMP_CONFIG_WRITE_INTERVAL_MASK_LOW {
                    return Err(UberBlockMmpEncodeError::WriteIntervalTooLarge {
                        write_interval: v,
                    });
                }
                (u64::from(v) << MMP_CONFIG_WRITE_INTERVAL_SHIFT) | MMP_CONFIG_WRITE_INTERVAL_BIT
            }
            None => 0,
        });

        encoder.put_u64(config)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/// [`UberBlockMmp`] encode error.
#[derive(Debug)]
pub enum UberBlockMmpDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid magic.
    InvalidMagic {
        /// Invalid magic value.
        magic: u64,
    },

    /// Non-zero reserved config bits.
    NonZeroReservedConfigBits {
        /// Invalid config value.
        config: u64,
    },

    /// Non-zero MMP values.
    NonZeroValues {
        /// Magic value.
        magic: u64,
        /// Delay value.
        delay: u64,
        /// Config value.
        config: u64,
    },
}

impl From<EndianDecodeError> for UberBlockMmpDecodeError {
    fn from(value: EndianDecodeError) -> Self {
        UberBlockMmpDecodeError::Endian { err: value }
    }
}

impl fmt::Display for UberBlockMmpDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockMmpDecodeError::Endian { err } => {
                write!(f, "UberBlockMmp decode error, endian: [{err}]")
            }
            UberBlockMmpDecodeError::InvalidMagic { magic } => {
                write!(f, "UberBlockMmp decode error, invalid magic 0x{magic:016x}")
            }
            UberBlockMmpDecodeError::NonZeroReservedConfigBits { config } => {
                write!(
                    f,
                    "UberBlockMmp decode error: non-zero reserved config bits config 0x{config:016x}"
                )
            }
            UberBlockMmpDecodeError::NonZeroValues {
                magic,
                delay,
                config,
            } => {
                write!(
                    f,
                    "UberBlockMmp decode error: non-zero values delay 0x{delay:016x} config 0x{config:016x} for magic:{magic:016x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockMmpDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockMmpDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`UberBlockMmp`] decode error.
#[derive(Debug)]
pub enum UberBlockMmpEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Write interval is too large.
    WriteIntervalTooLarge {
        /// Invalid write interval.
        write_interval: u32,
    },
}

impl From<EndianEncodeError> for UberBlockMmpEncodeError {
    fn from(value: EndianEncodeError) -> Self {
        UberBlockMmpEncodeError::Endian { err: value }
    }
}

impl fmt::Display for UberBlockMmpEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockMmpEncodeError::Endian { err } => {
                write!(f, "UberBlockMmp encode error, endian: [{err}]")
            }
            UberBlockMmpEncodeError::WriteIntervalTooLarge { write_interval } => {
                write!(
                    f,
                    "UberBlockMmp encode error, write interval is too large: {write_interval} > {}",
                    MMP_CONFIG_WRITE_INTERVAL_MASK_LOW
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockMmpEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockMmpEncodeError::Endian { err } => Some(err),
            UberBlockMmpEncodeError::WriteIntervalTooLarge { write_interval: _ } => None,
        }
    }
}
