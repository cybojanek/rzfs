// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder, EndianOrder,
};

////////////////////////////////////////////////////////////////////////////////

/** Checksum type.
 *
 * - [`ChecksumType::Inherit`] uses the value from the parent.
 * - [`ChecksumType::On`] uses [`ChecksumType::Fletcher4`], and
 *   [`ChecksumType::Sha256`] for dedup.
 * - [`ChecksumType::Label`] is for data in the ZFS Label (Blank, BootHeader,
 *   NvPairs, UberBlock).
 * - [`ChecksumType::GangHeader`] is for verifying Gang blocks.
 * - [`ChecksumType::Zilog`] and [`ChecksumType::Zilog2`] are for data in the
 *   ZFS Intent Log.
 * - [`ChecksumType::NoParity`] was added at the same time as
 *   [`ChecksumType::Sha512_256`], [`ChecksumType::Skein`], and
 *   [`ChecksumType::Edonr`], but it does not have a feature flag.
 * - Other ZFS implementations refer to [`ChecksumType::Sha512_256`] as just
 *   `Sha512`, but here it is purposefully `Sha512_256`, because Sha512-256 is
 *   not the same as Sha512 truncated to 256 bits.
 *
 * ```text
 * +------------+---------+--------------------+
 * | Checksum   | Version | Feature            |
 * +------------+---------+--------------------+
 * | Inherit    |       1 |                    |
 * +------------+---------+--------------------+
 * | On         |       1 |                    |
 * +------------+---------+--------------------+
 * | Off        |       1 |                    |
 * +------------+---------+--------------------+
 * | Label      |       1 |                    |
 * +------------+---------+--------------------+
 * | GangHeader |       1 |                    |
 * +------------+---------+--------------------+
 * | Zilog      |       1 |                    |
 * +------------+---------+--------------------+
 * | Fletcher2  |       1 |                    |
 * +------------+---------+--------------------+
 * | Fletcher4  |       1 |                    |
 * +------------+---------+--------------------+
 * | Sha256     |       1 |                    |
 * +------------+---------+--------------------+
 * | Zilog2     |      26 |                    |
 * +------------+---------+--------------------+
 * | NoParity   |    5000 |                    |
 * +------------+---------+--------------------+
 * | Sha512_256 |    5000 | org.illumos:sha512 |
 * +------------+---------+--------------------+
 * | Skein      |    5000 | org.illumos:skein  |
 * +------------+---------+--------------------+
 * | Edonr      |    5000 | org.illumos:edonr  |
 * +------------+---------+--------------------+
 * | Blake3     |    5000 | org.openzfs:blake3 |
 * +------------+---------+--------------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum ChecksumType {
    Inherit = 0,
    On = 1,
    Off = 2,
    Label = 3,
    GangHeader = 4,
    Zilog = 5,
    Fletcher2 = 6,
    Fletcher4 = 7,
    Sha256 = 8,
    Zilog2 = 9,
    NoParity = 10,
    Sha512_256 = 11,
    Skein = 12,
    Edonr = 13,
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
     * Returns [`ChecksumTypeError`] in case of an invalid [`ChecksumType`].
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
            _ => Err(ChecksumTypeError::InvalidChecksum { value: checksum }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`ChecksumType`] conversion error.
 */
#[derive(Debug)]
pub enum ChecksumTypeError {
    /** Invalid [`ChecksumType`].
     *
     * - `value` - Invalid value.
     */
    InvalidChecksum { value: u8 },
}

impl fmt::Display for ChecksumTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTypeError::InvalidChecksum { value } => {
                write!(f, "ChecksumType invalid value: {value}")
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
 * +----------+------+
 * | words[1] |    8 |
 * +----------+------+
 * | words[2] |    8 |
 * +----------+------+
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
    pub words: [u64; 4],
}

impl ChecksumValue {
    /// Byte length of an encoded [`ChecksumValue`].
    pub const LENGTH: usize = 32;

    /** Decodes a [`ChecksumValue`].
     *
     * # Errors
     *
     * Returns [`ChecksumValueDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
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
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ChecksumValueEncodeError> {
        encoder.put_u64(self.words[0])?;
        encoder.put_u64(self.words[1])?;
        encoder.put_u64(self.words[2])?;
        encoder.put_u64(self.words[3])?;

        Ok(())
    }
}

/** [`ChecksumValue`] decode error.
 */
#[derive(Debug)]
pub enum ChecksumValueDecodeError {
    /** [`EndianDecoder`] error.
     *
     * - `err` - [`EndianDecodeError`]
     */
    EndianDecodeError { err: EndianDecodeError },
}

impl From<EndianDecodeError> for ChecksumValueDecodeError {
    fn from(value: EndianDecodeError) -> Self {
        ChecksumValueDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for ChecksumValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumValueDecodeError::EndianDecodeError { err } => {
                write!(f, "ChecksumValue decode error, endian: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumValueDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumValueDecodeError::EndianDecodeError { err } => Some(err),
        }
    }
}

/** [`ChecksumValue`] encode error.
 */
#[derive(Debug)]
pub enum ChecksumValueEncodeError {
    /** [`EndianDecoder`] error.
     *
     * - `err` - [`EndianEncodeError`]
     */
    EndianEncodeError { err: EndianEncodeError },
}

impl From<EndianEncodeError> for ChecksumValueEncodeError {
    fn from(value: EndianEncodeError) -> Self {
        ChecksumValueEncodeError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for ChecksumValueEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumValueEncodeError::EndianEncodeError { err } => {
                write!(f, "ChecksumValue encode error, endian: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumValueEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumValueEncodeError::EndianEncodeError { err } => Some(err),
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
 * +----------+------+
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
    /// Byte length of an encoded [`ChecksumTail`] (40).
    pub const LENGTH: usize = 8 + ChecksumValue::LENGTH;

    /// Magic value for an encoded [`ChecksumTail`].
    pub const MAGIC: u64 = 0x210da7ab10c7a11;

    /** Decodes a [`ChecksumTail`].
     *
     * # Errors
     *
     * Returns [`ChecksumTailDecodeError`] in case of decoding error.
     */
    pub fn from_bytes(
        bytes: &[u8; ChecksumTail::LENGTH],
    ) -> Result<ChecksumTail, ChecksumTailDecodeError> {
        let decoder = EndianDecoder::from_u64_magic(bytes, ChecksumTail::MAGIC)?;

        Ok(ChecksumTail {
            order: decoder.order(),
            value: ChecksumValue::from_decoder(&decoder)?,
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
        bytes: &mut [u8; ChecksumTail::LENGTH],
    ) -> Result<(), ChecksumTailEncodeError> {
        let mut encoder = EndianEncoder::to_bytes(bytes, self.order);

        encoder.put_u64(ChecksumTail::MAGIC)?;
        self.value.to_encoder(&mut encoder)?;

        Ok(())
    }
}

/** [`ChecksumTail`] decode error.
 */
#[derive(Debug)]
pub enum ChecksumTailDecodeError {
    /** [`EndianDecoder`] error.
     *
     * - `err` - [`EndianDecodeError`]
     */
    EndianDecodeError { err: EndianDecodeError },

    /** [`ChecksumValue`] decode error.
     *
     * - `err` - [`ChecksumValueDecodeError`]
     */
    ChecksumValueDecodeError { err: ChecksumValueDecodeError },
}

impl From<EndianDecodeError> for ChecksumTailDecodeError {
    fn from(value: EndianDecodeError) -> Self {
        ChecksumTailDecodeError::EndianDecodeError { err: value }
    }
}

impl From<ChecksumValueDecodeError> for ChecksumTailDecodeError {
    fn from(value: ChecksumValueDecodeError) -> Self {
        ChecksumTailDecodeError::ChecksumValueDecodeError { err: value }
    }
}

impl fmt::Display for ChecksumTailDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTailDecodeError::EndianDecodeError { err } => {
                write!(f, "ChecksumTail decode error, endian: [{err}]")
            }
            ChecksumTailDecodeError::ChecksumValueDecodeError { err } => {
                write!(f, "ChecksumTail decode error, value: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTailDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumTailDecodeError::EndianDecodeError { err } => Some(err),
            ChecksumTailDecodeError::ChecksumValueDecodeError { err } => Some(err),
        }
    }
}

/** [`ChecksumTail`] encode error.
 */
#[derive(Debug)]
pub enum ChecksumTailEncodeError {
    /** [`EndianEncoder`] error.
     *
     * - `err` - [`EndianEncodeError`]
     */
    EndianEncodeError { err: EndianEncodeError },

    /** [`ChecksumValue`] encode error.
     *
     * - `err` - [`ChecksumValueEncodeError`]
     */
    ChecksumValueEncodeError { err: ChecksumValueEncodeError },
}

impl From<EndianEncodeError> for ChecksumTailEncodeError {
    fn from(value: EndianEncodeError) -> Self {
        ChecksumTailEncodeError::EndianEncodeError { err: value }
    }
}

impl From<ChecksumValueEncodeError> for ChecksumTailEncodeError {
    fn from(value: ChecksumValueEncodeError) -> Self {
        ChecksumTailEncodeError::ChecksumValueEncodeError { err: value }
    }
}

impl fmt::Display for ChecksumTailEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTailEncodeError::EndianEncodeError { err } => {
                write!(f, "ChecksumTail encode error, endian: [{err}]")
            }
            ChecksumTailEncodeError::ChecksumValueEncodeError { err } => {
                write!(f, "ChecksumTail encode error, value: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTailEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ChecksumTailEncodeError::EndianEncodeError { err } => Some(err),
            ChecksumTailEncodeError::ChecksumValueEncodeError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
