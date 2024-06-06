// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::phys::CompressionType;
use core::fmt;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/// Compression error.
#[derive(Debug)]
pub enum CompressionError {
    /// Not compressable. Output would be larger than input.
    NotCompressable {},

    /// Unsupported [`CompressionType`].
    Unsupported {
        /// Unsupported compression.
        compression: CompressionType,
    },
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionError::NotCompressable {} => {
                write!(f, "Compression error, not compressable")
            }
            CompressionError::Unsupported { compression } => {
                write!(f, "Compression error, unsupported {compression}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for CompressionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

/** Compression.
 */
pub trait Compression {
    /**
     * Compresses data from source to destination.
     *
     * On success, returns the number of bytes used in `dst`.
     *
     * # Errors
     *
     * Returns [`CompressionError`] in case of error.
     */
    fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        level: u32,
    ) -> Result<usize, CompressionError>;
}

////////////////////////////////////////////////////////////////////////////////

/// Decompression error.
#[derive(Debug)]
pub enum DecompressionError {
    /// Truncated source.
    EndOfInput {
        /// Byte offset of data.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
    },

    /// Invalid input.
    InvalidInput {
        /// Offset of invalid data.
        offset: usize,
    },

    /// Unsupported [`CompressionType`].
    Unsupported {
        /// Unsupported value.
        compression: CompressionType,
    },
}

impl fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompressionError::EndOfInput {
                offset,
                capacity,
                count,
            } => {
                write!(f, "Decompression error, end of input at offset:{offset} capacity:{capacity} count:{count}")
            }
            DecompressionError::InvalidInput { offset } => {
                write!(f, "Decompression error, invalid input at offset:{offset}")
            }
            DecompressionError::Unsupported { compression } => {
                write!(f, "Decompression error, unsupported {compression}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DecompressionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

/** Decompression.
 */
pub trait Decompression {
    /**
     * Decompresses data from source to destination.
     *
     * Uses the size of `dst` as the target decompressed size.
     *
     * # Errors
     *
     * Returns [`DecompressionError`] in case of error.
     */
    fn decompress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        level: u32,
    ) -> Result<(), DecompressionError>;
}
