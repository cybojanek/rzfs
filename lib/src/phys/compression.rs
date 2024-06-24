// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Compression type.
 *
 * ```text
 * +-------------+-------------+---------------------------+
 * | Compression | SPA Version | Feature                   |
 * +-------------+-------------+---------------------------+
 * | Inherit     |           1 |                           |
 * | On          |           1 |                           |
 * | Off         |           1 |                           |
 * | Lzjb        |           1 |                           |
 * | Empty       |           4 |                           |
 * | Gzip        |           5 |                           |
 * | Zle         |           6 |                           |
 * | Lz4         |        5000 | org.illumos:lz4_compress  |
 * | Zstd        |        5000 | org.freebsd:zstd_compress |
 * +-------------+-------------+---------------------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum CompressionType {
    /// Use compression value from parent.
    Inherit = 0,

    /// Use [`CompressionType::Lz4`] (if active), else [`CompressionType::Lzjb`].
    On = 1,

    /// No compression.
    Off = 2,

    /// Lempel-Ziv family compression created by Jeff Bonwick.
    Lzjb = 3,

    /// Empty data. May be zeroes, but depends on context.
    Empty = 4,

    /// gzip level 1.
    Gzip1 = 5,

    /// gzip level 2.
    Gzip2 = 6,

    /// gzip level 3.
    Gzip3 = 7,

    /// gzip level 4.
    Gzip4 = 8,

    /// gzip level 5.
    Gzip5 = 9,

    /// gzip level 6.
    Gzip6 = 10,

    /// gzip level 7.
    Gzip7 = 11,

    /// gzip level 8.
    Gzip8 = 12,

    /// gzip level 9.
    Gzip9 = 13,

    /** Zero Length Encoding.
     *
     * Only compresses continous runs of zeros
     */
    Zle = 14,

    /// LZ4.
    Lz4 = 15,

    /// Zstandard.
    Zstd = 16,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for CompressionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionType::Inherit => write!(f, "Inherit"),
            CompressionType::On => write!(f, "On"),
            CompressionType::Off => write!(f, "Off"),
            CompressionType::Lzjb => write!(f, "Lzjb"),
            CompressionType::Empty => write!(f, "Empty"),
            CompressionType::Gzip1 => write!(f, "Gzip1"),
            CompressionType::Gzip2 => write!(f, "Gzip2"),
            CompressionType::Gzip3 => write!(f, "Gzip3"),
            CompressionType::Gzip4 => write!(f, "Gzip4"),
            CompressionType::Gzip5 => write!(f, "Gzip5"),
            CompressionType::Gzip6 => write!(f, "Gzip6"),
            CompressionType::Gzip7 => write!(f, "Gzip7"),
            CompressionType::Gzip8 => write!(f, "Gzip8"),
            CompressionType::Gzip9 => write!(f, "Gzip9"),
            CompressionType::Zle => write!(f, "Zle"),
            CompressionType::Lz4 => write!(f, "Lz4"),
            CompressionType::Zstd => write!(f, "Zstd"),
        }
    }
}

impl From<CompressionType> for u8 {
    fn from(val: CompressionType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for CompressionType {
    type Error = CompressionTypeError;

    /** Try converting from a [`u8`] to a [`CompressionType`].
     *
     * # Errors
     *
     * Returns [`CompressionTypeError`] in case of an invalid [`CompressionType`].
     */
    fn try_from(compression: u8) -> Result<Self, Self::Error> {
        match compression {
            0 => Ok(CompressionType::Inherit),
            1 => Ok(CompressionType::On),
            2 => Ok(CompressionType::Off),
            3 => Ok(CompressionType::Lzjb),
            4 => Ok(CompressionType::Empty),
            5 => Ok(CompressionType::Gzip1),
            6 => Ok(CompressionType::Gzip2),
            7 => Ok(CompressionType::Gzip3),
            8 => Ok(CompressionType::Gzip4),
            9 => Ok(CompressionType::Gzip5),
            10 => Ok(CompressionType::Gzip6),
            11 => Ok(CompressionType::Gzip7),
            12 => Ok(CompressionType::Gzip8),
            13 => Ok(CompressionType::Gzip9),
            14 => Ok(CompressionType::Zle),
            15 => Ok(CompressionType::Lz4),
            16 => Ok(CompressionType::Zstd),
            _ => Err(CompressionTypeError::Unknown { compression }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`CompressionType`] conversion error.
#[derive(Debug)]
pub enum CompressionTypeError {
    /// Unknown [`CompressionType`].
    Unknown {
        /// Unknown compression.
        compression: u8,
    },
}

impl fmt::Display for CompressionTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionTypeError::Unknown { compression } => {
                write!(f, "CompressionType unknown: {compression}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for CompressionTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
