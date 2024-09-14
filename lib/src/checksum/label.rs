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
    BinaryDecodeError, BinaryEncodeError, ChecksumTail, ChecksumTailDecodeError,
    ChecksumTailEncodeError, ChecksumValue, EndianOrder, SECTOR_SHIFT,
};

////////////////////////////////////////////////////////////////////////////////

/** Offset encoded into [`ChecksumTail`] bytes.
 *
 * - `offset` in bytes
 * - `order`  to use for encoding
 */
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
 * - `offset` in sectors of `data` from start of device, included in checksum
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

    // Encode tail with offset in bytes.
    let offset = match offset.checked_shl(SECTOR_SHIFT) {
        Some(v) => v,
        None => return Err(LabelChecksumError::OffsetTooLarge { offset }),
    };
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
 * - `offset` in sectors of `data` from start of device, included in checksum
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

    // Encode tail with offset in bytes.
    let offset = match offset.checked_shl(SECTOR_SHIFT) {
        Some(v) => v,
        None => return Err(LabelVerifyError::OffsetTooLarge { offset }),
    };
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
    /// [`crate::phys::BinaryEncoder`] error.
    Binary {
        /// Error.
        err: BinaryEncodeError,
    },

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

    /// Invalid length.
    InvalidLength {
        /// Length.
        length: usize,
    },

    /// Offset is too large.
    OffsetTooLarge {
        /// Offset.
        offset: u64,
    },
}

impl From<BinaryEncodeError> for LabelChecksumError {
    fn from(value: BinaryEncodeError) -> Self {
        LabelChecksumError::Binary { err: value }
    }
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

impl fmt::Display for LabelChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelChecksumError::Binary { err } => {
                write!(f, "Label checksum error | {err}")
            }
            LabelChecksumError::Checksum { err } => {
                write!(f, "Label checksum error | {err}")
            }
            LabelChecksumError::ChecksumTail { err } => {
                write!(f, "Label checksum error | {err}")
            }
            LabelChecksumError::InvalidLength { length } => {
                write!(f, "Label checksum error, invalid length {length}")
            }
            LabelChecksumError::OffsetTooLarge { offset } => {
                write!(f, "Label checksum error, offset is too large {offset}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelChecksumError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelChecksumError::Binary { err } => Some(err),
            LabelChecksumError::Checksum { err } => Some(err),
            LabelChecksumError::ChecksumTail { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Label verify error.
#[derive(Debug)]
pub enum LabelVerifyError {
    /// [`crate::phys::BinaryDecoder`] error.
    BinaryDecode {
        /// Error.
        err: BinaryDecodeError,
    },

    /// [`crate::phys::BinaryEncoder`] error.
    BinaryEncode {
        /// Error.
        err: BinaryEncodeError,
    },

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

    /// Offset is too large.
    OffsetTooLarge {
        /// Offset.
        offset: u64,
    },
}

impl From<BinaryDecodeError> for LabelVerifyError {
    fn from(value: BinaryDecodeError) -> Self {
        LabelVerifyError::BinaryDecode { err: value }
    }
}

impl From<BinaryEncodeError> for LabelVerifyError {
    fn from(value: BinaryEncodeError) -> Self {
        LabelVerifyError::BinaryEncode { err: value }
    }
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

impl fmt::Display for LabelVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelVerifyError::BinaryDecode { err } => {
                write!(f, "Label verify error | {err}")
            }
            LabelVerifyError::BinaryEncode { err } => {
                write!(f, "Label verify error | {err}")
            }
            LabelVerifyError::Checksum { err } => {
                write!(f, "Label verify error | {err}")
            }
            LabelVerifyError::ChecksumTailDecode { err } => {
                write!(f, "Label verify error | {err}")
            }
            LabelVerifyError::ChecksumTailEncode { err } => {
                write!(f, "Label verify error | {err}")
            }
            LabelVerifyError::InvalidLength { length } => {
                write!(f, "Label verify error, invalid length {length}")
            }
            LabelVerifyError::Mismatch { computed, stored } => write!(
                f,
                "Label verify checksum mismatch, computed {:#016x?} stored {:#016x?}",
                computed, stored,
            ),
            LabelVerifyError::OffsetTooLarge { offset } => {
                write!(f, "Label verify error, offset is too large {offset}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelVerifyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelVerifyError::BinaryDecode { err } => Some(err),
            LabelVerifyError::BinaryEncode { err } => Some(err),
            LabelVerifyError::Checksum { err } => Some(err),
            LabelVerifyError::ChecksumTailDecode { err } => Some(err),
            LabelVerifyError::ChecksumTailEncode { err } => Some(err),
            _ => None,
        }
    }
}
