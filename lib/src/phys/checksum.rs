// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! Checksum type, value, and tail encoding.
 */
use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

use crate::phys::endian::{DecodeError, Decoder, EncodeError, Encoder, Order};

////////////////////////////////////////////////////////////////////////////////

/** Checksum type.
 *
 * - `Inherit` uses the value from the parent.
 * - `On` uses Fletcher4, and Sha256 for dedup.
 * - `Label` is for data in the ZFS Label (Blank, BootHeader, NvPairs, UberBlock).
 * - `GangHeader` is for verifying Gang blocks.
 * - `Zilog` and `Zilog2` are for data in the ZFS Intent Log.
 * - `NoParity` was added at the same time as Sha512-256, Skein, and Edonr, but
 *   it does not have a feature flag.
 * - Other ZFS implementations refer to Sha512-256 as just Sha512, but here it
 *   is purposefully Sha512-256, because Sha512-256 is not the same as Sha512
 *   truncated to 256 bits.
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
 * | Sha512-256 |    5000 | org.illumos:sha512 |
 * +------------+---------+--------------------+
 * | Skein      |    5000 | org.illumos:skein  |
 * +------------+---------+--------------------+
 * | Edonr      |    5000 | org.illumos:edonr  |
 * +------------+---------+--------------------+
 * | Blake3     |    5000 | org.openzfs:blake3 |
 * +------------+---------+--------------------+
 * ```
 */
#[derive(Debug)]
pub enum Type {
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

impl Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Inherit => write!(f, "Inherit"),
            Type::On => write!(f, "On"),
            Type::Off => write!(f, "Off"),
            Type::Label => write!(f, "Label"),
            Type::GangHeader => write!(f, "GangHeader"),
            Type::Zilog => write!(f, "Zilog"),
            Type::Fletcher2 => write!(f, "Fletcher2"),
            Type::Fletcher4 => write!(f, "Fletcher4"),
            Type::Sha256 => write!(f, "Sha256"),
            Type::Zilog2 => write!(f, "Zilog2"),
            Type::NoParity => write!(f, "NoParity"),
            Type::Sha512_256 => write!(f, "Sha512_256"),
            Type::Skein => write!(f, "Skein"),
            Type::Edonr => write!(f, "Edonr"),
            Type::Blake3 => write!(f, "Blake3"),
        }
    }
}

impl From<Type> for u8 {
    fn from(val: Type) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for Type {
    type Error = TypeError;

    /** Try converting from a [`u8`] to a [`Type`].
     *
     * # Errors
     *
     * Returns [`TypeError`] in case of an invalid checksum.
     */
    fn try_from(checksum: u8) -> Result<Self, Self::Error> {
        match checksum {
            0 => Ok(Type::Inherit),
            1 => Ok(Type::On),
            2 => Ok(Type::Off),
            3 => Ok(Type::Label),
            4 => Ok(Type::GangHeader),
            5 => Ok(Type::Zilog),
            6 => Ok(Type::Fletcher2),
            7 => Ok(Type::Fletcher4),
            8 => Ok(Type::Sha256),
            9 => Ok(Type::Zilog2),
            10 => Ok(Type::NoParity),
            11 => Ok(Type::Sha512_256),
            12 => Ok(Type::Skein),
            13 => Ok(Type::Edonr),
            14 => Ok(Type::Blake3),
            _ => Err(TypeError::InvalidChecksum { value: checksum }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum TypeError {
    /** Invalid checksum type value.
     *
     * - `value` - Invalid value.
     */
    InvalidChecksum { value: u8 },
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeError::InvalidChecksum { value } => {
                write!(f, "Checksum Type invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for TypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Checksum value.
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
 */
#[derive(Debug)]
pub struct Value {
    pub words: [u64; 4],
}

impl Value {
    /// Byte length of an encoded [`Value`].
    pub const LENGTH: usize = 32;

    /** Decodes a [`Value`].
     *
     * # Errors
     *
     * Returns [`ValueDecodeError`] if there are not enough bytes.
     */
    pub fn from_decoder(decoder: &Decoder<'_>) -> Result<Value, ValueDecodeError> {
        Ok(Value {
            words: [
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
            ],
        })
    }

    /** Encodes a [`Value`].
     *
     * # Errors
     *
     * Returns [`ValueEncodeError`] if there is not enough space.
     */
    pub fn to_encoder(&self, encoder: &mut Encoder<'_>) -> Result<(), ValueEncodeError> {
        encoder.put_u64(self.words[0])?;
        encoder.put_u64(self.words[1])?;
        encoder.put_u64(self.words[2])?;
        encoder.put_u64(self.words[3])?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum ValueDecodeError {
    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },
}

impl From<DecodeError> for ValueDecodeError {
    fn from(value: DecodeError) -> Self {
        ValueDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for ValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueDecodeError::EndianDecodeError { err } => {
                write!(f, "Check Value Endian decode: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ValueDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ValueDecodeError::EndianDecodeError { err } => Some(err),
        }
    }
}

#[derive(Debug)]
pub enum ValueEncodeError {
    /** Endian encode error.
     *
     * - `err` - [`EncodeError`]
     */
    EndianEncodeError { err: EncodeError },
}

impl From<EncodeError> for ValueEncodeError {
    fn from(value: EncodeError) -> Self {
        ValueEncodeError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for ValueEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueEncodeError::EndianEncodeError { err } => {
                write!(f, "Checksum Value Endian encode: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ValueEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ValueEncodeError::EndianEncodeError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
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
 */
#[derive(Debug)]
pub struct Tail {
    /// Endian order.
    pub order: Order,

    /// Checksum value.
    pub value: Value,
}

impl Tail {
    /// Byte length of an encoded [`Tail`] (40).
    pub const LENGTH: usize = 8 + Value::LENGTH;

    /// Magic value for an encoded [`Tail`].
    pub const MAGIC: u64 = 0x210da7ab10c7a11;

    /** Decodes a [`Tail`].
     *
     * # Errors
     *
     * Returns [`TailDecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_bytes(bytes: &[u8; Tail::LENGTH]) -> Result<Tail, TailDecodeError> {
        let decoder = Decoder::from_u64_magic(bytes, Tail::MAGIC)?;

        Ok(Tail {
            order: decoder.order(),
            value: Value::from_decoder(&decoder)?,
        })
    }

    /** Encodes a [`Tail`].
     *
     * # Errors
     *
     * Returns [`TailEncodeError`] if there are not enough bytes.
     */
    pub fn to_bytes(&self, bytes: &mut [u8; Tail::LENGTH]) -> Result<(), TailEncodeError> {
        let mut encoder = Encoder::to_bytes(bytes, self.order);

        encoder.put_u64(Tail::MAGIC)?;
        self.value.to_encoder(&mut encoder)?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum TailDecodeError {
    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },

    /** Value decode error.
     *
     * - `err` - [`ValueDecodeError`]
     */
    ValueDecodeError { err: ValueDecodeError },
}

impl From<DecodeError> for TailDecodeError {
    fn from(value: DecodeError) -> Self {
        TailDecodeError::EndianDecodeError { err: value }
    }
}

impl From<ValueDecodeError> for TailDecodeError {
    fn from(value: ValueDecodeError) -> Self {
        TailDecodeError::ValueDecodeError { err: value }
    }
}

impl fmt::Display for TailDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TailDecodeError::EndianDecodeError { err } => {
                write!(f, "Check Tail Endian decode: {err}")
            }
            TailDecodeError::ValueDecodeError { err } => {
                write!(f, "Check Tail Value decode: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for TailDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            TailDecodeError::EndianDecodeError { err } => Some(err),
            TailDecodeError::ValueDecodeError { err } => Some(err),
        }
    }
}

#[derive(Debug)]
pub enum TailEncodeError {
    /** Endian encode error.
     *
     * - `err` - [`EncodeError`]
     */
    EndianEncodeError { err: EncodeError },

    /** Value encode error.
     *
     * - `err` - [`ValueEncodeError`]
     */
    ValueEncodeError { err: ValueEncodeError },
}

impl From<EncodeError> for TailEncodeError {
    fn from(value: EncodeError) -> Self {
        TailEncodeError::EndianEncodeError { err: value }
    }
}

impl From<ValueEncodeError> for TailEncodeError {
    fn from(value: ValueEncodeError) -> Self {
        TailEncodeError::ValueEncodeError { err: value }
    }
}

impl fmt::Display for TailEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TailEncodeError::EndianEncodeError { err } => {
                write!(f, "Checksum Tail Endian encode: {err}")
            }
            TailEncodeError::ValueEncodeError { err } => {
                write!(f, "Checksum Tail Value encode: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for TailEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            TailEncodeError::EndianEncodeError { err } => Some(err),
            TailEncodeError::ValueEncodeError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
