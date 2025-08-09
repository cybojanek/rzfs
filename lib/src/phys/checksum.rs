// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    BigLittleEndianDecoder, BigLittleEndianEncoder, BinaryDecodeError, BinaryDecoder,
    BinaryEncodeError, BinaryEncoder, EndianOrder,
};

////////////////////////////////////////////////////////////////////////////////

/** Checksum type.
 *
 * - [`ChecksumType::NoParity`] was added at the same time as
 *   [`ChecksumType::Sha512_256`], [`ChecksumType::Skein`], and
 *   [`ChecksumType::Edonr`], but it does not have a feature flag.
 * - Other ZFS implementations refer to [`ChecksumType::Sha512_256`] as just
 *   `Sha512`, but here it is purposefully `Sha512_256`, because Sha512-256 is
 *   not the same as Sha512 truncated to 256 bits.
 *
 * ```text
 * +------------+-------------+--------------------+
 * | Checksum   | SPA Version | Feature            |
 * +------------+-------------+--------------------+
 * | Inherit    |           1 |                    |
 * | On         |           1 |                    |
 * | Off        |           1 |                    |
 * | Label      |           1 |                    |
 * | GangHeader |           1 |                    |
 * | Zilog      |           1 |                    |
 * | Fletcher2  |           1 |                    |
 * | Fletcher4  |           1 |                    |
 * | Sha256     |           1 |                    |
 * | Zilog2     |          26 |                    |
 * | NoParity   |        5000 |                    |
 * | Sha512_256 |        5000 | org.illumos:sha512 |
 * | Skein      |        5000 | org.illumos:skein  |
 * | Edonr      |        5000 | org.illumos:edonr  |
 * | Blake3     |        5000 | org.openzfs:blake3 |
 * +------------+-------------+--------------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum ChecksumType {
    /// Use checksum value from parent.
    Inherit = 0,

    /// [`ChecksumType::Fletcher4`], and [`ChecksumType::Sha256`] for dedup.
    On = 1,

    /// No checksum.
    Off = 2,

    /// Sha256 checksum over ZFS Label (Blank, BootHeader, NvPairs, UberBlock).
    Label = 3,

    /// TODO: Document.
    GangHeader = 4,

    /// TODO: Document.
    Zilog = 5,

    /// Fletcher error-detection checksum.
    Fletcher2 = 6,

    /// Fletcher error-detection checksum.
    Fletcher4 = 7,

    /// SHA-2 256 cryptographic hash.
    Sha256 = 8,

    /// TODO: Document.
    Zilog2 = 9,

    /// TODO: Document.
    NoParity = 10,

    /// SHA-2 512-256 cryptographic hash.
    Sha512_256 = 11,

    /// Skein cryptographic hash.
    Skein = 12,

    /// Edon-R cryptographic hash.
    Edonr = 13,

    /// Blake3 cryptographic hash.
    Blake3 = 14,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for ChecksumType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumType::Inherit => write!(f, "Inherit"),
            ChecksumType::On => write!(f, "On"),
            ChecksumType::Off => write!(f, "Off"),
            ChecksumType::Label => write!(f, "Label"),
            ChecksumType::GangHeader => write!(f, "GangHeader"),
            ChecksumType::Zilog => write!(f, "Zilog"),
            ChecksumType::Fletcher2 => write!(f, "Fletcher2"),
            ChecksumType::Fletcher4 => write!(f, "Fletcher4"),
            ChecksumType::Sha256 => write!(f, "Sha256"),
            ChecksumType::Zilog2 => write!(f, "Zilog2"),
            ChecksumType::NoParity => write!(f, "NoParity"),
            ChecksumType::Sha512_256 => write!(f, "Sha512_256"),
            ChecksumType::Skein => write!(f, "Skein"),
            ChecksumType::Edonr => write!(f, "Edonr"),
            ChecksumType::Blake3 => write!(f, "Blake3"),
        }
    }
}

impl From<ChecksumType> for u8 {
    fn from(val: ChecksumType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for ChecksumType {
    type Error = ChecksumTypeError;

    /** Try converting from a [`u8`] to a [`ChecksumType`].
     *
     * # Errors
     *
     * Returns [`ChecksumTypeError`] in case of an unknown [`ChecksumType`].
     */
    fn try_from(checksum: u8) -> Result<Self, Self::Error> {
        match checksum {
            0 => Ok(ChecksumType::Inherit),
            1 => Ok(ChecksumType::On),
            2 => Ok(ChecksumType::Off),
            3 => Ok(ChecksumType::Label),
            4 => Ok(ChecksumType::GangHeader),
            5 => Ok(ChecksumType::Zilog),
            6 => Ok(ChecksumType::Fletcher2),
            7 => Ok(ChecksumType::Fletcher4),
            8 => Ok(ChecksumType::Sha256),
            9 => Ok(ChecksumType::Zilog2),
            10 => Ok(ChecksumType::NoParity),
            11 => Ok(ChecksumType::Sha512_256),
            12 => Ok(ChecksumType::Skein),
            13 => Ok(ChecksumType::Edonr),
            14 => Ok(ChecksumType::Blake3),
            _ => Err(ChecksumTypeError::Unknown { checksum }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ChecksumType`] conversion error.
#[derive(Debug)]
pub enum ChecksumTypeError {
    /// Unknown [`ChecksumType`].
    Unknown {
        /// Checksum.
        checksum: u8,
    },
}

impl fmt::Display for ChecksumTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTypeError::Unknown { checksum } => {
                write!(f, "Unknown ChecksumType {checksum}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Checksum value.
 *
 * ### Byte layout.
 *
 * - Bytes: 32
 *
 * ```text
 * +----------+------+
 * | Field    | Size |
 * +----------+------+
 * | words[0] |    8 |
 * | words[1] |    8 |
 * | words[2] |    8 |
 * | words[3] |    8 |
 * +----------+------+
 * ```
 *
 * ### words
 *
 * 256 bit checksum, stored as 4 [`u64`] values.
 */
#[derive(Debug)]
pub struct ChecksumValue {
    /// Checksum value split across four [`u64`].
    pub words: [u64; 4],
}

impl ChecksumValue {
    /// Byte size of an encoded [`ChecksumValue`].
    pub const SIZE: usize = 32;

    /** Decodes a [`ChecksumValue`].
     *
     * # Errors
     *
     * Returns [`ChecksumValueDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(
        decoder: &mut dyn BinaryDecoder<'_>,
    ) -> Result<ChecksumValue, ChecksumValueDecodeError> {
        Ok(ChecksumValue {
            words: [
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
            ],
        })
    }

    /** Encodes a [`ChecksumValue`].
     *
     * # Errors
     *
     * Returns [`ChecksumValueEncodeError`] in case of encoding error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut dyn BinaryEncoder<'_>,
    ) -> Result<(), ChecksumValueEncodeError> {
        encoder.put_u64(self.words[0])?;
        encoder.put_u64(self.words[1])?;
        encoder.put_u64(self.words[2])?;
        encoder.put_u64(self.words[3])?;

        Ok(())
    }
}

/// [`ChecksumValue`] decode error.
#[derive(Debug)]
pub enum ChecksumValueDecodeError {
    /// [`BinaryDecoder`] error.
    Binary {
        /// Error.
        err: BinaryDecodeError,
    },
}

impl From<BinaryDecodeError> for ChecksumValueDecodeError {
    fn from(err: BinaryDecodeError) -> Self {
        ChecksumValueDecodeError::Binary { err }
    }
}

impl fmt::Display for ChecksumValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumValueDecodeError::Binary { err } => {
                write!(f, "ChecksumValue decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumValueDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumValueDecodeError::Binary { err } => Some(err),
        }
    }
}

/// [`ChecksumValue`] encode error.
#[derive(Debug)]
pub enum ChecksumValueEncodeError {
    /// [`BinaryEncoder`] error.
    Binary {
        /// Error.
        err: BinaryEncodeError,
    },
}

impl From<BinaryEncodeError> for ChecksumValueEncodeError {
    fn from(err: BinaryEncodeError) -> Self {
        ChecksumValueEncodeError::Binary { err }
    }
}

impl fmt::Display for ChecksumValueEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumValueEncodeError::Binary { err } => {
                write!(f, "ChecksumValue encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumValueEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumValueEncodeError::Binary { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
 *
 * ### Byte layout.
 *
 * - Bytes: 40
 *
 * ```text
 * +----------+------+
 * | Field    | Size |
 * +----------+------+
 * | magic    |    8 |
 * | checksum |   32 |
 * +----------+------+
 * ```
 *
 * ### order
 *
 * The `magic` field must match [`ChecksumTail::MAGIC`], and its byte order
 * determines the value of `order`.
 *
 * ### value
 *
 * 256 bit checksum. The byte order is determined by `order`.
 */
#[derive(Debug)]
pub struct ChecksumTail {
    /// Endian order.
    pub order: EndianOrder,

    /// Checksum value.
    pub value: ChecksumValue,
}

impl ChecksumTail {
    /// Byte size of an encoded [`ChecksumTail`] (40).
    pub const SIZE: usize = 8 + ChecksumValue::SIZE;

    /// Magic value for an encoded [`ChecksumTail`].
    pub const MAGIC: u64 = 0x0210da7ab10c7a11;

    /** Decodes a [`ChecksumTail`].
     *
     * # Errors
     *
     * Returns [`ChecksumTailDecodeError`] in case of decoding error.
     */
    pub fn from_bytes(
        bytes: &[u8; ChecksumTail::SIZE],
    ) -> Result<ChecksumTail, ChecksumTailDecodeError> {
        let mut bele_decoder = BigLittleEndianDecoder::from_u64_magic(bytes, ChecksumTail::MAGIC)?;
        let decoder = bele_decoder.decoder_as_mut();

        Ok(ChecksumTail {
            order: decoder.order(),
            value: ChecksumValue::from_decoder(decoder)?,
        })
    }

    /** Encodes a [`ChecksumTail`].
     *
     * # Errors
     *
     * Returns [`ChecksumTailEncodeError`] in case of encoding error.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; ChecksumTail::SIZE],
    ) -> Result<(), ChecksumTailEncodeError> {
        let mut bl_encoder = BigLittleEndianEncoder::to_bytes(bytes, self.order);
        let encoder = bl_encoder.encoder();

        encoder.put_u64(ChecksumTail::MAGIC)?;
        self.value.to_encoder(encoder)?;

        Ok(())
    }
}

/// [`ChecksumTail`] decode error.
#[derive(Debug)]
pub enum ChecksumTailDecodeError {
    /// [`BinaryDecoder`] error.
    Binary {
        /// Error.
        err: BinaryDecodeError,
    },

    /// [`ChecksumValue`] decode error.
    ChecksumValue {
        /// Error.
        err: ChecksumValueDecodeError,
    },
}

impl From<BinaryDecodeError> for ChecksumTailDecodeError {
    fn from(value: BinaryDecodeError) -> Self {
        ChecksumTailDecodeError::Binary { err: value }
    }
}

impl From<ChecksumValueDecodeError> for ChecksumTailDecodeError {
    fn from(value: ChecksumValueDecodeError) -> Self {
        ChecksumTailDecodeError::ChecksumValue { err: value }
    }
}

impl fmt::Display for ChecksumTailDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTailDecodeError::Binary { err } => {
                write!(f, "ChecksumTail decode error | {err}")
            }
            ChecksumTailDecodeError::ChecksumValue { err } => {
                write!(f, "ChecksumTail decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTailDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumTailDecodeError::Binary { err } => Some(err),
            ChecksumTailDecodeError::ChecksumValue { err } => Some(err),
        }
    }
}

/// [`ChecksumTail`] encode error.
#[derive(Debug)]
pub enum ChecksumTailEncodeError {
    /// [`BinaryEncoder`] error.
    Binary {
        /// Error.
        err: BinaryEncodeError,
    },

    /// [`ChecksumValue`] encode error.
    ChecksumValue {
        /// Error.
        err: ChecksumValueEncodeError,
    },
}

impl From<BinaryEncodeError> for ChecksumTailEncodeError {
    fn from(err: BinaryEncodeError) -> Self {
        ChecksumTailEncodeError::Binary { err }
    }
}

impl From<ChecksumValueEncodeError> for ChecksumTailEncodeError {
    fn from(err: ChecksumValueEncodeError) -> Self {
        ChecksumTailEncodeError::ChecksumValue { err }
    }
}

impl fmt::Display for ChecksumTailEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTailEncodeError::Binary { err } => {
                write!(f, "ChecksumTail encode error | {err}")
            }
            ChecksumTailEncodeError::ChecksumValue { err } => {
                write!(f, "ChecksumTail encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTailEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumTailEncodeError::Binary { err } => Some(err),
            ChecksumTailEncodeError::ChecksumValue { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
