// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError, EndianDecodeError,
    EndianDecoder, EndianEncodeError, EndianEncoder,
};

////////////////////////////////////////////////////////////////////////////////

/** ZIL header.
 *
 * ### Byte layout.
 *
 * - Bytes: 192
 *
 * ```text
 * +---------------+------+---------+
 * | Field         | Size | Version |
 * +---------------+------+---------+
 * |     claim_txg |    8 |       1 |
 * +---------------+------+---------+
 * |    replay_seq |    8 |       1 |
 * +---------------+------+---------+
 * |           log |  128 |       1 |
 * +---------------+------+---------+
 * | claim_blk_seq |    8 |       3 |
 * +---------------+------+---------+
 * |         flags |    8 |      15 |
 * +---------------+------+---------+
 * |  claim_lr_seq |    8 |      21 |
 * +---------------+------+---------+
 * |       padding |   24 |         |
 * +---------------+------+---------+
 * ```
 */
#[derive(Debug)]
pub struct ZilHeader {
    /// ???
    pub claim_blk_seq: u64,

    /// ???
    pub claim_lr_seq: u64,

    /// ???
    pub claim_txg: u64,

    /// ???
    pub flags: u64,

    /// ???
    pub log: Option<BlockPointer>,

    /// ???
    pub replay_seq: u64,
}

impl ZilHeader {
    /// Byte size of an encoded [`ZilHeader`] (192).
    pub const SIZE: usize = BlockPointer::SIZE + 64;

    /** Decodes a [`ZilHeader`].
     *
     * # Errors
     *
     * Returns [`ZilHeaderDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<ZilHeader, ZilHeaderDecodeError> {
        let zil_header = ZilHeader {
            claim_txg: decoder.get_u64()?,
            replay_seq: decoder.get_u64()?,
            log: BlockPointer::from_decoder(decoder)?,
            claim_blk_seq: decoder.get_u64()?,
            flags: decoder.get_u64()?,
            claim_lr_seq: decoder.get_u64()?,
        };

        decoder.skip_zero_padding(24)?;

        Ok(zil_header)
    }

    /** Encodes a [`ZilHeader`].
     *
     * # Errors
     *
     * Returns [`ZilHeaderEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), ZilHeaderEncodeError> {
        encoder.put_u64(self.claim_txg)?;
        encoder.put_u64(self.replay_seq)?;
        match &self.log {
            Some(ptr) => ptr.to_encoder(encoder)?,
            None => BlockPointer::empty_to_encoder(encoder)?,
        };
        encoder.put_u64(self.claim_blk_seq)?;
        encoder.put_u64(self.flags)?;
        encoder.put_u64(self.claim_lr_seq)?;
        encoder.put_zero_padding(24)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ZilHeader`] decode error.
#[derive(Debug)]
pub enum ZilHeaderDecodeError {
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
}

impl From<BlockPointerDecodeError> for ZilHeaderDecodeError {
    fn from(err: BlockPointerDecodeError) -> Self {
        ZilHeaderDecodeError::BlockPointer { err }
    }
}

impl From<EndianDecodeError> for ZilHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZilHeaderDecodeError::Endian { err }
    }
}

impl fmt::Display for ZilHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZilHeaderDecodeError::BlockPointer { err } => {
                write!(f, "ZIL header decode error, block pointer: [{err}]")
            }
            ZilHeaderDecodeError::Endian { err } => {
                write!(f, "ZIL header decode error, endian: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZilHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZilHeaderDecodeError::BlockPointer { err } => Some(err),
            ZilHeaderDecodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ZilHeader`] encode error.
#[derive(Debug)]
pub enum ZilHeaderEncodeError {
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
}

impl From<BlockPointerEncodeError> for ZilHeaderEncodeError {
    fn from(err: BlockPointerEncodeError) -> Self {
        ZilHeaderEncodeError::BlockPointer { err }
    }
}

impl From<EndianEncodeError> for ZilHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZilHeaderEncodeError::Endian { err }
    }
}

impl fmt::Display for ZilHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZilHeaderEncodeError::BlockPointer { err } => {
                write!(f, "ZIL header encode error, block pointer: [{err}]")
            }
            ZilHeaderEncodeError::Endian { err } => {
                write!(f, "ZIL header encode error, endian: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZilHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZilHeaderEncodeError::BlockPointer { err } => Some(err),
            ZilHeaderEncodeError::Endian { err } => Some(err),
        }
    }
}
