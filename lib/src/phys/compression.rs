// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Compression type.
 *
 * - [`CompressionType::Inherit`] uses the value from the parent.
 * - [`CompressionType::On`] uses [`CompressionType::Lz4`] (if active), else it
 *   falls back to [`CompressionType::Lzjb`].
 * - [`CompressionType::Lzjb`] is a Lempel-Ziv family compression created by
 *   Jeff Bonwick.
 * - [`CompressionType::Empty`]
 * - [`CompressionType::Zle`] (Zero Length Encoding) only compresses continous
 *   runs of zeros.
 *
 * ```text
 * +-------------+---------+---------------------------+
 * | Compression | Version | Feature                   |
 * +-------------+---------+---------------------------+
 * | Inherit     |       1 |                           |
 * +-------------+---------+---------------------------+
 * | On          |       1 |                           |
 * +-------------+---------+---------------------------+
 * | Off         |       1 |                           |
 * +-------------+---------+---------------------------+
 * | Lzjb        |       1 |                           |
 * +-------------+---------+---------------------------+
 * | Empty       |       4 |                           |
 * +-------------+---------+---------------------------+
 * | Gzip        |       5 |                           |
 * +-------------+---------+---------------------------+
 * | Zle         |       6 |                           |
 * +-------------+---------+---------------------------+
 * | Lz4         |    5000 | org.illumos:lz4_compress  |
 * +-------------+---------+---------------------------+
 * | Zstd        |    5000 | org.freebsd:zstd_compress |
 * +-------------+---------+---------------------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum CompressionType {
    Inherit = 0,
    On = 1,
    Off = 2,
    Lzjb = 3,
    Empty = 4,
    Gzip1 = 5,
    Gzip2 = 6,
    Gzip3 = 7,
    Gzip4 = 8,
    Gzip5 = 9,
    Gzip6 = 10,
    Gzip7 = 11,
    Gzip8 = 12,
    Gzip9 = 13,
    Zle = 14,
    Lz4 = 15,
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
            _ => Err(CompressionTypeError::InvalidCompression { value: compression }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`CompressionType`] conversion error.
 */
#[derive(Debug)]
pub enum CompressionTypeError {
    /** Invalid [`CompressionType`].
     *
     * - `value` - Invalid value.
     */
    InvalidCompression { value: u8 },
}

impl fmt::Display for CompressionTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionTypeError::InvalidCompression { value } => {
                write!(f, "CompressionType invalid value: {value}")
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
