// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! Label checksum.
 *
 * - The `label` checksum is embedded at the tail end of a block.
 * - It uses `sha256`, where the checksum endian encoding is specified using the magic.
 * - It is used to checksum blocks in the label (boot block, nv list, uber blocks).
 * - The checksum is calculated over the entire block (including the tail).
 * - When calculating the checksum, `checksum 0` is set to the byte `offset` of the
 *   block from the start of the block device, and `checksum 1`, `checksum 2`,
 *   `checksum 3` are all set to `0`.
 *
 * Embedded at tail of data.
 *
 * ### Byte layout.
 *
 * - Bytes: N
 *
 * ```text
 * +----------+--------+
 * | Field    | Size   |
 * +----------+--------+
 * | payload  | N - 40 |
 * +----------+--------+
 * | checksum |     40 |
 * +----------+--------+
 * ```
 */
use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{Checksum, ChecksumError, Sha256};
use crate::phys::{
    ChecksumTail, ChecksumTailDecodeError, ChecksumTailEncodeError, ChecksumValue,
    EndianDecodeError, EndianEncodeError, EndianOrder,
};

////////////////////////////////////////////////////////////////////////////////

/// Offset encoded into [`ChecksumTail`] bytes.
fn offset_tail(
    offset: u64,
    order: EndianOrder,
) -> Result<[u8; ChecksumTail::SIZE], ChecksumTailEncodeError> {
    // Encode tail with offset.
    let offset_tail = ChecksumTail {
        order,
        value: ChecksumValue {
            words: [offset, 0, 0, 0],
        },
    };

    let mut offset_tail_bytes = [0; ChecksumTail::SIZE];
    offset_tail.to_bytes(&mut offset_tail_bytes)?;

    Ok(offset_tail_bytes)
}

/** Compute the checksum of the `data` block and encode it at the end of `data`.
 *
 * - `data` to checksum
 * - `offset` in bytes of `data` from start of device, included in checksum
 * - `sha256` instance to use for checksum
 * - `order` to use for checksum
 *
 * # Errors
 *
 * Returns [`LabelChecksumError`] in case of encoding error.
 */
pub fn label_checksum(
    data: &mut [u8],
    offset: u64,
    sha256: &mut Sha256,
    order: EndianOrder,
) -> Result<(), LabelChecksumError> {
    // Check length.
    let length = data.len();
    if length < ChecksumTail::SIZE {
        return Err(LabelChecksumError::InvalidLength { length });
    }

    // Encode tail with offset.
    let offset_tail_bytes = offset_tail(offset, order)?;

    // Compute checksum.
    sha256.reset(order)?;
    sha256.update(&data[0..length - ChecksumTail::SIZE])?;
    sha256.update(&offset_tail_bytes)?;
    let checksum = sha256.finalize()?;

    // Encode tail with checksum.
    let tail = ChecksumTail {
        order,
        value: ChecksumValue { words: checksum },
    };
    let tail_bytes = &mut data[length - ChecksumTail::SIZE..length];
    tail.to_bytes(tail_bytes.try_into().unwrap())?;

    Ok(())
}

/** Verify the checksum of the `data` block.
 *
 * - `data` to checksum
 * - `offset` in bytes of `data` from start of device, included in checksum
 * - `sha256` instance to use for checksum
 *
 * # Errors
 *
 * Returns [`LabelVerifyError`] in case of decoding error or checksum mismatch.
 */
pub fn label_verify(data: &[u8], offset: u64, sha256: &mut Sha256) -> Result<(), LabelVerifyError> {
    // Check length.
    let length = data.len();
    if length < ChecksumTail::SIZE {
        return Err(LabelVerifyError::InvalidLength { length });
    }

    // Decode ChecksumTail.
    let tail = &data[length - ChecksumTail::SIZE..length];
    let tail = ChecksumTail::from_bytes(tail.try_into().unwrap())?;

    // Encode tail with offset.
    let offset_tail_bytes = offset_tail(offset, tail.order)?;

    // Compute checksum.
    sha256.reset(tail.order)?;
    sha256.update(&data[0..length - ChecksumTail::SIZE])?;
    sha256.update(&offset_tail_bytes)?;
    let computed_checksum = sha256.finalize()?;

    // Compare checksum.
    if tail.value.words == computed_checksum {
        Ok(())
    } else {
        Err(LabelVerifyError::Mismatch {
            computed: computed_checksum,
            stored: tail.value.words,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Label checksum error.
#[derive(Debug)]
pub enum LabelChecksumError {
    /// [`Checksum`] error.
    Checksum {
        /// Error.
        err: ChecksumError,
    },

    /// [`ChecksumTail`] error.
    ChecksumTail {
        /// Error.
        err: ChecksumTailEncodeError,
    },

    /// [`crate::phys::EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Invalid length.
    InvalidLength {
        /// Length.
        length: usize,
    },
}

impl From<ChecksumError> for LabelChecksumError {
    fn from(value: ChecksumError) -> Self {
        LabelChecksumError::Checksum { err: value }
    }
}

impl From<ChecksumTailEncodeError> for LabelChecksumError {
    fn from(value: ChecksumTailEncodeError) -> Self {
        LabelChecksumError::ChecksumTail { err: value }
    }
}

impl From<EndianEncodeError> for LabelChecksumError {
    fn from(value: EndianEncodeError) -> Self {
        LabelChecksumError::Endian { err: value }
    }
}

impl fmt::Display for LabelChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelChecksumError::Checksum { err } => {
                write!(f, "Label checksum error, checksum: [{err}]")
            }
            LabelChecksumError::ChecksumTail { err } => {
                write!(f, "Label checksum error, checksum tail: [{err}]")
            }
            LabelChecksumError::Endian { err } => {
                write!(f, "Label checksum error, endian: [{err}]")
            }
            LabelChecksumError::InvalidLength { length } => {
                write!(f, "Label checksum error, invalid length: {length}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelChecksumError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelChecksumError::Checksum { err } => Some(err),
            LabelChecksumError::ChecksumTail { err } => Some(err),
            LabelChecksumError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Label verify error.
#[derive(Debug)]
pub enum LabelVerifyError {
    /// [`Checksum`] error.
    Checksum {
        /// Error.
        err: ChecksumError,
    },

    /// [`ChecksumTail`] error.
    ChecksumTailDecode {
        /// Error.
        err: ChecksumTailDecodeError,
    },

    /// [`ChecksumTail`] error.
    ChecksumTailEncode {
        /// Error.
        err: ChecksumTailEncodeError,
    },

    /// [`crate::phys::EndianEncoder`] error.
    EndianEncode {
        /// Error.
        err: EndianEncodeError,
    },

    /// [`crate::phys::EndianDecoder`] error.
    EndianDecode {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid length.
    InvalidLength {
        /// Length.
        length: usize,
    },

    /// Checksum mismatch.
    Mismatch {
        /// Computed checksum.
        computed: [u64; 4],
        /// Stored checksum.
        stored: [u64; 4],
    },
}

impl From<ChecksumError> for LabelVerifyError {
    fn from(value: ChecksumError) -> Self {
        LabelVerifyError::Checksum { err: value }
    }
}

impl From<ChecksumTailDecodeError> for LabelVerifyError {
    fn from(value: ChecksumTailDecodeError) -> Self {
        LabelVerifyError::ChecksumTailDecode { err: value }
    }
}

impl From<ChecksumTailEncodeError> for LabelVerifyError {
    fn from(value: ChecksumTailEncodeError) -> Self {
        LabelVerifyError::ChecksumTailEncode { err: value }
    }
}

impl From<EndianEncodeError> for LabelVerifyError {
    fn from(value: EndianEncodeError) -> Self {
        LabelVerifyError::EndianEncode { err: value }
    }
}

impl From<EndianDecodeError> for LabelVerifyError {
    fn from(value: EndianDecodeError) -> Self {
        LabelVerifyError::EndianDecode { err: value }
    }
}

impl fmt::Display for LabelVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelVerifyError::Checksum { err } => {
                write!(f, "Label verify error, checksum: [{err}]")
            }
            LabelVerifyError::ChecksumTailDecode { err } => {
                write!(f, "Label verify error, checksum tail decode: [{err}]")
            }
            LabelVerifyError::ChecksumTailEncode { err } => {
                write!(f, "Label verify error, checksum tail encode: [{err}]")
            }
            LabelVerifyError::EndianEncode { err } => {
                write!(f, "Label verify error, endian encode: [{err}]")
            }
            LabelVerifyError::EndianDecode { err } => {
                write!(f, "Label verify error, endian decode: [{err}]")
            }
            LabelVerifyError::InvalidLength { length } => {
                write!(f, "Label verify error, invalid length: {length}")
            }
            LabelVerifyError::Mismatch { computed, stored } => write!(
                f,
                concat!(
                    "Label verify checksum mismatch, ",
                    "computed: 0x{:016x} 0x{:016x} 0x{:016x} 0x{:016x}, ",
                    "stored: 0x{:016x} 0x{:016x} 0x{:016x} 0x{:016x}"
                ),
                computed[0],
                computed[1],
                computed[2],
                computed[3],
                stored[0],
                stored[1],
                stored[2],
                stored[3],
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelVerifyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelVerifyError::Checksum { err } => Some(err),
            LabelVerifyError::ChecksumTailDecode { err } => Some(err),
            LabelVerifyError::ChecksumTailEncode { err } => Some(err),
            LabelVerifyError::EndianEncode { err } => Some(err),
            LabelVerifyError::EndianDecode { err } => Some(err),
            _ => None,
        }
    }
}
