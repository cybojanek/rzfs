// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder, SECTOR_SHIFT,
};

////////////////////////////////////////////////////////////////////////////////

/// ZAP name case normalization.
#[derive(Clone, Copy, Debug)]
pub enum ZapCaseNormalization {
    /// No case normalization.
    None = 0x00,

    /// Normalize to upper case.
    Upper = 0x02,

    /// Normalize to lower case.
    Lower = 0x04,
}

impl ZapCaseNormalization {
    /// Mask of all [`ZapCaseNormalization`] values.
    const MASK_ALL: u64 = 0x02 | 0x04;
}

impl From<ZapCaseNormalization> for u64 {
    fn from(val: ZapCaseNormalization) -> u64 {
        val as u64
    }
}

impl Display for ZapCaseNormalization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapCaseNormalization::None => write!(f, "None"),
            ZapCaseNormalization::Upper => write!(f, "Upper"),
            ZapCaseNormalization::Lower => write!(f, "Lower"),
        }
    }
}

impl TryFrom<u64> for ZapCaseNormalization {
    type Error = ZapCaseNormalizationError;

    /** Try converting from a [`u64`] to a [`ZapCaseNormalization`].
     *
     * # Errors
     *
     * Returns [`ZapCaseNormalizationError`] in case of an unknown [`ZapCaseNormalization`].
     */
    fn try_from(case_normalization: u64) -> Result<Self, Self::Error> {
        match case_normalization {
            0x00 => Ok(ZapCaseNormalization::None),
            0x02 => Ok(ZapCaseNormalization::Upper),
            0x04 => Ok(ZapCaseNormalization::Lower),
            _ => Err(ZapCaseNormalizationError::Unknown { case_normalization }),
        }
    }
}

/// [`ZapCaseNormalization`] conversion error.
#[derive(Debug)]
pub enum ZapCaseNormalizationError {
    /// Unknown [`ZapCaseNormalization`].
    Unknown {
        /// Unknown case normalization.
        case_normalization: u64,
    },
}

impl fmt::Display for ZapCaseNormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapCaseNormalizationError::Unknown { case_normalization } => {
                write!(f, "Unknown ZapCaseNormalization {case_normalization}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapCaseNormalizationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// ZAP name unicode normalization.
#[derive(Clone, Copy, Debug)]
pub enum ZapUnicodeNormalization {
    /// No unicode normalization.
    None = 0x00,

    /// NF canonical decomposition.
    NFD = 0x10,

    /// NF compatibility decomposition.
    NFKD = 0x20,

    /// NF canonical composition.
    NFC = 0x50,

    /// NF compatibility composition.
    NFKC = 0x60,
}

impl ZapUnicodeNormalization {
    /// Mask of all [`ZapUnicodeNormalization`] values.
    const MASK_ALL: u64 = 0x10 | 0x20 | 0x50 | 0x60;
}

impl From<ZapUnicodeNormalization> for u64 {
    fn from(val: ZapUnicodeNormalization) -> u64 {
        val as u64
    }
}

impl Display for ZapUnicodeNormalization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapUnicodeNormalization::None => write!(f, "None"),
            ZapUnicodeNormalization::NFD => write!(f, "NFD"),
            ZapUnicodeNormalization::NFKD => write!(f, "NFKD"),
            ZapUnicodeNormalization::NFC => write!(f, "NFC"),
            ZapUnicodeNormalization::NFKC => write!(f, "NFKC"),
        }
    }
}

impl TryFrom<u64> for ZapUnicodeNormalization {
    type Error = ZapUnicodeNormalizationError;

    /** Try converting from a [`u64`] to a [`ZapUnicodeNormalization`].
     *
     * # Errors
     *
     * Returns [`ZapUnicodeNormalizationError`] in case of an unknown [`ZapUnicodeNormalization`].
     */
    fn try_from(unicode_normalization: u64) -> Result<Self, Self::Error> {
        match unicode_normalization {
            0x00 => Ok(ZapUnicodeNormalization::None),
            0x10 => Ok(ZapUnicodeNormalization::NFD),
            0x20 => Ok(ZapUnicodeNormalization::NFKD),
            0x50 => Ok(ZapUnicodeNormalization::NFC),
            0x60 => Ok(ZapUnicodeNormalization::NFKC),
            _ => Err(ZapUnicodeNormalizationError::Unknown {
                unicode_normalization,
            }),
        }
    }
}

/// [`ZapUnicodeNormalization`] conversion error.
#[derive(Debug)]
pub enum ZapUnicodeNormalizationError {
    /// Unknown [`ZapUnicodeNormalization`].
    Unknown {
        /// Unknown unicode normalization.
        unicode_normalization: u64,
    },
}

impl fmt::Display for ZapUnicodeNormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapUnicodeNormalizationError::Unknown {
                unicode_normalization,
            } => {
                write!(f, "Unknown ZapUnicodeNormalization {unicode_normalization}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapUnicodeNormalizationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Micro ZAP header.
 *
 * ### Byte layout.
 *
 * - Bytes: 64
 *
 * ```text
 * +------------+------+-------------+
 * | Field      | Size | SPA Version |
 * +------------+------+-------------+
 * | block_type |    8 |             |
 * | salt       |    8 |             |
 * | norm flags |    8 |           9 |
 * | padding    |   40 |             |
 * +------------+------+-------------+
 * ```
 *
 * A Micro ZAP is only one block. The Micro ZAP header is located at the start
 * of the block, and the remaining space is used for Micro ZAP entries. There is
 * no count for how many entries are in use, nor any ordering to the entries.
 * Instead, all entries must be decoded and scanned. The key for a Micro ZAP
 * entry is limited to 49 bytes (plus one more for NULL), and the value is a
 * 64 bit unsigned integer.
 *
 * The layout of the block on disk can be visualized as:
 *
 * ```text
 * +----------------+---------------+---------------+-----+---------------+
 * | ZapMicroHeader | ZapMicroEntry | ZapMicroEntry | ... | ZapMicroEntry |
 * +----------------+---------------+---------------+-----+---------------+
 * ```
 */
#[derive(Debug)]
pub struct ZapMicroHeader {
    /// Salt for ZAP hash computation.
    pub salt: u64,

    /// [`ZapCaseNormalization`] of [`ZapMicroEntry::name`].
    pub case_normalization: ZapCaseNormalization,

    /// [`ZapUnicodeNormalization`] of [`ZapMicroEntry::name`].
    pub unicode_normalization: ZapUnicodeNormalization,
}

impl ZapMicroHeader {
    /// Byte size of an encoded [`ZapMicroHeader`].
    pub const SIZE: usize = 64;

    /// [`ZapMicroHeader`] block type.
    pub const BLOCK_TYPE: u64 = 0x8000000000000003;

    /// Padding byte size.
    const PADDING_SIZE: usize = 40;

    /// Normalization mask.
    const NORMALIZATION_MASK: u64 =
        ZapCaseNormalization::MASK_ALL | ZapUnicodeNormalization::MASK_ALL;

    /** Decodes a [`ZapMicroHeader`].
     *
     * # Errors
     *
     * Returns [`ZapMicroHeaderDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapMicroHeader, ZapMicroHeaderDecodeError> {
        ////////////////////////////////
        // Decode block type.
        let block_type = decoder.get_u64()?;
        if block_type != ZapMicroHeader::BLOCK_TYPE {
            return Err(ZapMicroHeaderDecodeError::BlockType { block_type });
        }

        ////////////////////////////////
        // Decode salt.
        let salt = decoder.get_u64()?;

        ////////////////////////////////
        // Decode normalization.
        let normalization = decoder.get_u64()?;

        if (normalization & ZapMicroHeader::NORMALIZATION_MASK) != normalization {
            return Err(ZapMicroHeaderDecodeError::Normalization { normalization });
        }

        let case_normalization =
            ZapCaseNormalization::try_from(normalization & ZapCaseNormalization::MASK_ALL)?;

        let unicode_normalization =
            ZapUnicodeNormalization::try_from(normalization & ZapUnicodeNormalization::MASK_ALL)?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ZapMicroHeader::PADDING_SIZE)?;

        ////////////////////////////////
        // Success.
        Ok(ZapMicroHeader {
            salt,
            case_normalization,
            unicode_normalization,
        })
    }

    /** Encodes a [`ZapMicroHeader`].
     *
     * # Errors
     *
     * Returns [`ZapMicroHeaderEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroHeaderEncodeError> {
        ////////////////////////////////
        // Encode block type.
        encoder.put_u64(ZapMicroHeader::BLOCK_TYPE)?;

        ////////////////////////////////
        // Encode salt.
        encoder.put_u64(self.salt)?;

        ////////////////////////////////
        // Encode normalization.
        let normalization =
            u64::from(self.case_normalization) | u64::from(self.unicode_normalization);
        encoder.put_u64(normalization)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapMicroHeader::PADDING_SIZE)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/// [`ZapMicroHeader`] decode error.
#[derive(Debug)]
pub enum ZapMicroHeaderDecodeError {
    /// Invalid block type.
    BlockType {
        /// Block type.
        block_type: u64,
    },

    /// Unknown [`ZapCaseNormalization`].
    CaseNormalization {
        /// Error.
        err: ZapCaseNormalizationError,
    },

    /// Unknown normalization.
    Normalization {
        /// Unknown normalization.
        normalization: u64,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown [`ZapUnicodeNormalization`].
    UnicodeNormalization {
        /// Error.
        err: ZapUnicodeNormalizationError,
    },
}

impl From<ZapCaseNormalizationError> for ZapMicroHeaderDecodeError {
    fn from(err: ZapCaseNormalizationError) -> Self {
        ZapMicroHeaderDecodeError::CaseNormalization { err }
    }
}

impl From<EndianDecodeError> for ZapMicroHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapMicroHeaderDecodeError::Endian { err }
    }
}

impl From<ZapUnicodeNormalizationError> for ZapMicroHeaderDecodeError {
    fn from(err: ZapUnicodeNormalizationError) -> Self {
        ZapMicroHeaderDecodeError::UnicodeNormalization { err }
    }
}

impl fmt::Display for ZapMicroHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMicroHeaderDecodeError::CaseNormalization { err } => {
                write!(f, "ZapMicroHeader decode error | {err}")
            }
            ZapMicroHeaderDecodeError::BlockType { block_type } => {
                write!(
                    f,
                    "ZapMicroHeader decode error, invalid block_type {block_type}"
                )
            }
            ZapMicroHeaderDecodeError::Normalization { normalization } => {
                write!(
                    f,
                    "ZapMicroHeader decode error, unknown normalization {normalization}"
                )
            }
            ZapMicroHeaderDecodeError::Endian { err } => {
                write!(f, "ZapMicroHeader decode error | {err}")
            }
            ZapMicroHeaderDecodeError::UnicodeNormalization { err } => {
                write!(f, "ZapMicroHeader decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMicroHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMicroHeaderDecodeError::CaseNormalization { err } => Some(err),
            ZapMicroHeaderDecodeError::Endian { err } => Some(err),
            ZapMicroHeaderDecodeError::UnicodeNormalization { err } => Some(err),
            _ => None,
        }
    }
}

/// [`ZapMicroHeader`] encode error.
#[derive(Debug)]
pub enum ZapMicroHeaderEncodeError {
    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for ZapMicroHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapMicroHeaderEncodeError::Endian { err }
    }
}

impl fmt::Display for ZapMicroHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMicroHeaderEncodeError::Endian { err } => {
                write!(f, "ZapMicroHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMicroHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMicroHeaderEncodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Micro ZAP entry.
 *
 * ### Byte layout.
 *
 * - Bytes: 64
 *
 * ```text
 * +---------+------+
 * | Field   | Size |
 * +---------+------+
 * | value   |    8 |
 * | cd      |    4 |
 * | padding |    2 |
 * | name    |   50 |
 * +---------+------+
 *
 * name must be NULL terminated, so maximum string length is 49 + 1 for NULL
 * ```
 */
#[derive(Debug)]
pub struct ZapMicroEntry {
    /// Collision differentiator.
    pub cd: u32,

    /// Name bytes, excluding NULL byte.
    pub name: [u8; ZapMicroEntry::NAME_MAX],

    /// Value.
    pub value: u64,
}

impl ZapMicroEntry {
    /// Byte size of an encoded [`ZapMicroEntry`].
    pub const SIZE: usize = 64;

    /// Maximum length of a name.
    pub const NAME_MAX: usize = 49;

    /// Padding size.
    const PADDING_SIZE: usize = 2;

    /** Decodes a [`ZapMicroEntry`]. Returns [`None`] if [`ZapMicroEntry`] is empty.
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<Option<ZapMicroEntry>, ZapMicroEntryDecodeError> {
        ////////////////////////////////
        // Check for an empty ZapMicroEntry.
        if decoder.is_zero_skip(ZapMicroEntry::SIZE)? {
            return Ok(None);
        }

        ////////////////////////////////
        // Decode value.
        let value = decoder.get_u64()?;

        ////////////////////////////////
        // Decode collision differentiator.
        let cd = decoder.get_u32()?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ZapMicroEntry::PADDING_SIZE)?;

        ////////////////////////////////
        // Decode name.
        let name = decoder.get_bytes(ZapMicroEntry::NAME_MAX + 1)?;

        ////////////////////////////////
        // Error if it was not NULL terminated.
        let mut null_found = false;
        for byte in name {
            if *byte == 0 {
                null_found = true;
                break;
            }
        }
        if !null_found {
            return Err(ZapMicroEntryDecodeError::NameNotNullTerminated {});
        }

        ////////////////////////////////
        // Success.
        Ok(Some(ZapMicroEntry {
            cd,
            name: name[0..ZapMicroEntry::NAME_MAX].try_into().unwrap(),
            value,
        }))
    }

    /** Encodes a [`ZapMicroEntry`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        ////////////////////////////////
        // Encode value.
        encoder.put_u64(self.value)?;

        ////////////////////////////////
        // Encode collision differentiator.
        encoder.put_u32(self.cd)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapMicroEntry::PADDING_SIZE)?;

        ////////////////////////////////
        // Encode name.
        encoder.put_bytes(&self.name)?;

        // Add NULL termination.
        encoder.put_u8(0)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }

    /** Encodes an empty [`ZapMicroEntry`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn empty_to_encoder(
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        Ok(encoder.put_zero_padding(ZapMicroEntry::SIZE)?)
    }

    /** Encode an `[Option<ZapMicroEntry>`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn option_to_encoder(
        ptr: &Option<ZapMicroEntry>,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        match ptr {
            Some(v) => v.to_encoder(encoder),
            None => Ok(ZapMicroEntry::empty_to_encoder(encoder)?),
        }
    }
}

/// An alternate representation of a [`ZapMicroEntry`] that uses a string reference.
pub struct ZapMicroEntryRef<'a> {
    /// Collision differentiator.
    pub cd: u32,

    /// Name.
    pub name: &'a str,

    /// Value.
    pub value: u64,
}

impl ZapMicroEntryRef<'_> {
    /// Byte size of an encoded [`ZapMicroEntryRef`].
    pub const SIZE: usize = 64;

    /// Maximum length of a name.
    pub const NAME_MAX: usize = 49;

    /// Padding size.
    const PADDING_SIZE: usize = 2;

    /** Decodes a [`ZapMicroEntryRef`]. Returns [`None`] if [`ZapMicroEntryRef`] is empty.
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryDecodeError`] on error.
     */
    pub fn from_decoder<'a>(
        decoder: &EndianDecoder<'a>,
    ) -> Result<Option<ZapMicroEntryRef<'a>>, ZapMicroEntryDecodeError> {
        ////////////////////////////////
        // Check for an empty ZapMicroEntryRef.
        if decoder.is_zero_skip(ZapMicroEntryRef::SIZE)? {
            return Ok(None);
        }

        ////////////////////////////////
        // Decode value.
        let value = decoder.get_u64()?;

        ////////////////////////////////
        // Decode collision differentiator.
        let cd = decoder.get_u32()?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ZapMicroEntryRef::PADDING_SIZE)?;

        ////////////////////////////////
        // Decode name.
        let name = decoder.get_bytes(ZapMicroEntryRef::NAME_MAX + 1)?;

        ////////////////////////////////
        // Error if it was not NULL terminated.
        let mut null_found = false;
        let mut length = 0;
        for byte in name {
            if *byte == 0 {
                null_found = true;
                break;
            }
            length += 1;
        }
        if !null_found {
            return Err(ZapMicroEntryDecodeError::NameNotNullTerminated {});
        }

        ////////////////////////////////
        // Now try and convert it to a string.
        let data = &name[0..length];
        let name = match core::str::from_utf8(data) {
            Ok(v) => v,
            Err(err) => return Err(ZapMicroEntryDecodeError::InvalidStr { err }),
        };

        ////////////////////////////////
        // Success.
        Ok(Some(ZapMicroEntryRef { cd, name, value }))
    }

    /** Encodes a [`ZapMicroEntryRef`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        ////////////////////////////////
        // Encode value.
        encoder.put_u64(self.value)?;

        ////////////////////////////////
        // Encode collision differentiator.
        encoder.put_u32(self.cd)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapMicroEntryRef::PADDING_SIZE)?;

        ////////////////////////////////
        // Encode name.
        let length = self.name.len();
        if length > ZapMicroEntryRef::NAME_MAX {
            return Err(ZapMicroEntryEncodeError::NameTooLong { length });
        }
        // FIXME(cybojanek): Normalization.
        encoder.put_bytes(self.name.as_bytes())?;
        encoder.put_zero_padding((ZapMicroEntryRef::NAME_MAX + 1) - length)?;

        // Ensure NULL terminated.
        encoder.put_u8(0)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }

    /** Encodes an empty [`ZapMicroEntryRef`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn empty_to_encoder(
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        Ok(encoder.put_zero_padding(ZapMicroEntryRef::SIZE)?)
    }

    /** Encode an `[Option<ZapMicroEntryRef>`].
     *
     * # Errors
     *
     * Returns [`ZapMicroEntryEncodeError`] on error.
     */
    pub fn option_to_encoder(
        ptr: &Option<ZapMicroEntryRef<'_>>,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMicroEntryEncodeError> {
        match ptr {
            Some(v) => v.to_encoder(encoder),
            None => Ok(ZapMicroEntryRef::empty_to_encoder(encoder)?),
        }
    }
}

/// [`ZapMicroEntry`] decode error.
#[derive(Debug)]
pub enum ZapMicroEntryDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Name is not NULL terminated.
    NameNotNullTerminated {},

    /// Invalid str.
    InvalidStr {
        /// Error.
        err: core::str::Utf8Error,
    },
}

impl From<EndianDecodeError> for ZapMicroEntryDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapMicroEntryDecodeError::Endian { err }
    }
}

impl fmt::Display for ZapMicroEntryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMicroEntryDecodeError::Endian { err } => {
                write!(f, "ZapMicroEntry decode error | {err}")
            }
            ZapMicroEntryDecodeError::NameNotNullTerminated {} => {
                write!(f, "ZapMicroEntry decode error, name is not NULL terminated")
            }
            ZapMicroEntryDecodeError::InvalidStr { err } => {
                write!(f, "ZapMicroEntry decode error, invalid UTF8 str | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMicroEntryDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMicroEntryDecodeError::Endian { err } => Some(err),
            ZapMicroEntryDecodeError::InvalidStr { err } => Some(err),
            ZapMicroEntryDecodeError::NameNotNullTerminated {} => None,
        }
    }
}

/// [`ZapMicroEntry`] encode error.
#[derive(Debug)]
pub enum ZapMicroEntryEncodeError {
    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Name is too long.
    NameTooLong {
        /// Name length.
        length: usize,
    },
}

impl From<EndianEncodeError> for ZapMicroEntryEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapMicroEntryEncodeError::Endian { err }
    }
}

impl fmt::Display for ZapMicroEntryEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMicroEntryEncodeError::Endian { err } => {
                write!(f, "ZapMicroEntry encode error | {err}")
            }
            ZapMicroEntryEncodeError::NameTooLong { length } => write!(
                f,
                "ZapMicroEntry encode error, name is too long: {length} > {}",
                ZapMicroEntry::NAME_MAX,
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMicroEntryEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMicroEntryEncodeError::Endian { err } => Some(err),
            ZapMicroEntryEncodeError::NameTooLong { .. } => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A Micro ZAP iterator.
pub struct ZapMicroIterator<'a> {
    /// Micro ZAP header.
    pub header: ZapMicroHeader,

    /// Entries decoder.
    decoder: EndianDecoder<'a>,
}

impl ZapMicroIterator<'_> {
    /** Decodes a [`ZapMicroIterator`].
     *
     * # Errors
     *
     * Returns [`ZapMicroIteratorError`] on error.
     */
    pub fn from_decoder<'a>(
        decoder: &EndianDecoder<'a>,
    ) -> Result<ZapMicroIterator<'a>, ZapMicroIteratorError> {
        ////////////////////////////////
        // Decode header.
        let header = ZapMicroHeader::from_decoder(decoder)?;

        // Get the rest of the bytes as the entries.
        let entries = decoder.get_bytes(decoder.len())?;

        // Check entries is a multiple of ZapMicroEntry.
        if entries.len() % ZapMicroEntry::SIZE != 0 {
            return Err(ZapMicroIteratorError::Size {
                size: entries.len(),
            });
        }

        Ok(ZapMicroIterator {
            header,
            decoder: EndianDecoder::from_bytes(entries, decoder.order()),
        })
    }

    /// Resets the iterator.
    pub fn reset(&mut self) {
        self.decoder.reset();
    }
}

impl<'a> Iterator for ZapMicroIterator<'a> {
    type Item = Result<ZapMicroEntryRef<'a>, ZapMicroEntryDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        while !self.decoder.is_empty() {
            // Get the next entry.
            let entry_opt = match ZapMicroEntryRef::from_decoder(&self.decoder) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            match entry_opt {
                Some(entry) => return Some(Ok(entry)),
                None => continue,
            };
        }

        None
    }
}

/// [`ZapMicroIterator`] decode error.
#[derive(Debug)]
pub enum ZapMicroIteratorError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid entries size.
    Size {
        /// Size.
        size: usize,
    },

    /// [`ZapMicroHeader`] error.
    ZapMicroHeader {
        /// Error.
        err: ZapMicroHeaderDecodeError,
    },
}

impl From<EndianDecodeError> for ZapMicroIteratorError {
    fn from(err: EndianDecodeError) -> Self {
        ZapMicroIteratorError::Endian { err }
    }
}

impl From<ZapMicroHeaderDecodeError> for ZapMicroIteratorError {
    fn from(err: ZapMicroHeaderDecodeError) -> Self {
        ZapMicroIteratorError::ZapMicroHeader { err }
    }
}

impl fmt::Display for ZapMicroIteratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMicroIteratorError::Endian { err } => {
                write!(f, "ZapMicroIterator decode error | {err}")
            }
            ZapMicroIteratorError::Size { size } => {
                write!(
                    f,
                    "ZapMicroIterator decode error, entries size {size} is not a multiple of {}",
                    ZapMicroEntry::SIZE
                )
            }
            ZapMicroIteratorError::ZapMicroHeader { err } => {
                write!(f, "ZapMicroIterator decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMicroIteratorError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMicroIteratorError::Endian { err } => Some(err),
            ZapMicroIteratorError::Size { .. } => None,
            ZapMicroIteratorError::ZapMicroHeader { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** ZAP Mega pointer table.
 *
 * ### Byte layout
 *
 * - Bytes: 40
 *
 * ```text
 * +----------------+------+
 * | Field          | Size |
 * +----------------+------+
 * | starting block |    8 |
 * | blocks         |    8 |
 * | hash bits      |    8 |
 * | next block     |    8 |
 * | blocks copied  |    8 |
 * +----------------+------+
 * ```
 *
 * # Growing
 *
 * At some point, the ZAP leaf pointer table may need to be grown. When that
 * happens, the [`ZapMegaPointerTable`] is used to store the copy progress, and
 * eventually the state of the new leaf pointers.
 *
 * The following table is used as an example for how this process occurs.
 * The example assumes a ZAP block size of 16384.
 *
 * ```text
 * +------+----------------+--------+-----------+------------+---------------+
 * | step | starting_block | blocks | hash_bits | next_block | blocks_copied |
 * +------+----------------+--------+-----------+------------+---------------+
 * |    0 |              0 |      0 |        10 |          0 |             0 |
 * |    1 |              N |      1 |        11 |          0 |             0 |
 * |    2 |              N |      1 |        11 |          M |             0 |
 * |    3 |              N |      1 |        11 |          M |             1 |
 * |    4 |              M |      2 |        12 |          0 |             0 |
 * |    5 |              M |      2 |        12 |          P |             0 |
 * |    6 |              M |      2 |        12 |          P |             1 |
 * |    7 |              M |      2 |        12 |          P |             2 |
 * |    8 |              P |      4 |        13 |          0 |             0 |
 * +------+----------------+--------+-----------+------------+---------------+
 * ```
 *
 * At step 0, the leaf pointers are stored along with the ZAP header in the
 * first block. This is indicated by `blocks` being zero. In a well formed
 * table, `starting_block`, `next_block`, and `blocks_copied` should also all
 * be zero.
 *
 * At step 1, a block at index `N` is allocated, and the block pointers are
 * copied from the embedded block pointer table, to the new block. Since the
 * table is now using an entire block (rather than half), the `hash_bits` is
 * incremented by one.
 *
 * At step 2, twice as many blocks are allocated, starting at block index `M`.
 * The other fields remain unchanged.
 *
 * At step 3, the existing block at N is copied, and `blocks_copied` is
 * incremented by 1.
 *
 * At step 4, because all the blocks have been copied (`blocks_copied`
 * is equal to `blocks`), the `starting_block` is set to `next_block`,
 * `blocks` is doubled, `hash_bits` is incremented, and both `next_block`
 * and `blocks_copied` are zeroed.
 *
 * Steps 5 through 8 show the doubling process from 2 to 4 blocks.
 *
 * # Copying
 *
 * When the ZAP leaf pointer table grows, the indices need to be copied.
 * Each index is copied into two locations:
 *
 * ```text
 * block_number = src[i]
 * dst[(2 * i) + 0] = block_number
 * dst[(2 * i) + 1] = block_number
 * ```
 *
 * To see why this is the case, assume an initial table of size two, where
 * only the top most hash bit is used.
 *
 * ```text
 * +-------+------------+--------------+
 * | Index | Index Bits | Block Number |
 * +-------+------------+--------------+
 * |     0 |          0 |            A |
 * |     1 |          1 |            B |
 * +-------+------------+--------------+
 * ```
 *
 * The new table is of size four, and will use two hash bits.
 *
 * ```text
 * +-------+------------+--------------+
 * | Index | Index Bits | Block Number |
 * +-------+------------+--------------+
 * |     0 |         00 |            A |
 * |     1 |         01 |            A |
 * |     2 |         10 |            B |
 * |     3 |         11 |            B |
 * +-------+------------+--------------+
 * ```
 *
 * Notice that in the old table, the hash keys that index to `A` have the top
 * bit of `0`. For their second bit, they may have either a `0` or `1`.
 * Because the new table must handle both cases `0?`, we put `A` at both
 * `00` and `01`. The same goes for `B` - the old table handled `1?`, and so
 * the new table must handle `10` and `11`.
 *
 * This procedure continues every time the table is grown, and avoids rehashing
 * all the data. This is possible, because the top hash bits are used (rather
 * than taking a modulus of the table size).
 *
 * # Copying in progress
 *
 * TODO: Describe further how copying is done, because it looks like the blocks
 * are copied from the source on demand as they are updated. If that is the
 * case, then lookup needs to check if the new copied block is allocated? Else
 * fall back to the old block?
 */
#[derive(Debug)]
pub struct ZapMegaPointerTable {
    /** Starting block number for this table.
     *
     * A value of 0 indicates the table is embedded in the first ZAP block
     * along with the header.
     */
    pub starting_block: u64,

    /** Number of blocks used by this table.
     *
     * A value of 0 indicates the table is embedded in the first ZAP block
     * along with the header.
     */
    pub blocks: u64,

    /// Number of top hash bits used for indexing into this table.
    pub hash_bits: u64,

    /** Next (larger) copy start block.
     *
     * A value of 0 indicates that no copy is in progress.
     */
    pub next_block: u64,

    /** Number of source blocks copied.
     *
     * Copy progress, when `next_block` is non-zero.
     */
    pub blocks_copied: u64,
}

impl ZapMegaPointerTable {
    /// Byte size of an encoded [`ZapMegaPointerTable`].
    pub const SIZE: usize = 40;

    /** Decodes a [`ZapMegaPointerTable`].
     *
     * # Errors
     *
     * Returns [`ZapMegaPointerTableDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapMegaPointerTable, ZapMegaPointerTableDecodeError> {
        // Success.
        Ok(ZapMegaPointerTable {
            starting_block: decoder.get_u64()?,
            blocks: decoder.get_u64()?,
            hash_bits: decoder.get_u64()?,
            next_block: decoder.get_u64()?,
            blocks_copied: decoder.get_u64()?,
        })
    }

    /** Encodes a [`ZapMegaPointerTable`].
     *
     * # Errors
     *
     * Returns [`ZapMegaPointerTableEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMegaPointerTableEncodeError> {
        ////////////////////////////////
        // Encode values
        encoder.put_u64(self.starting_block)?;
        encoder.put_u64(self.blocks)?;
        encoder.put_u64(self.hash_bits)?;
        encoder.put_u64(self.next_block)?;
        encoder.put_u64(self.blocks_copied)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/// [`ZapMegaPointerTable`] decode error.
#[derive(Debug)]
pub enum ZapMegaPointerTableDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },
}

impl From<EndianDecodeError> for ZapMegaPointerTableDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapMegaPointerTableDecodeError::Endian { err }
    }
}

impl fmt::Display for ZapMegaPointerTableDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMegaPointerTableDecodeError::Endian { err } => {
                write!(f, "ZapMegaPointerTable decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMegaPointerTableDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMegaPointerTableDecodeError::Endian { err } => Some(err),
        }
    }
}

/// [`ZapMegaPointerTable`] encode error.
#[derive(Debug)]
pub enum ZapMegaPointerTableEncodeError {
    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for ZapMegaPointerTableEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapMegaPointerTableEncodeError::Endian { err }
    }
}

impl fmt::Display for ZapMegaPointerTableEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMegaPointerTableEncodeError::Endian { err } => {
                write!(f, "ZapMegaPointerTable encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMegaPointerTableEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMegaPointerTableEncodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** ZAP Mega header.
 *
 * ### Byte layout
 *
 * - Bytes:
 *   - Fixed size: 104
 *   - Total size: 512, 1024, 2048, ..., 131072
 *
 * ```text
 * +-----------------+-------+-------------+
 * | Field           |  Size | SPA Version |
 * +-----------------+-------+-------------+
 * | block_type      |     8 |             |
 * | magic           |     8 |             |
 * | zap table       |    40 |             |
 * | next free block |     8 |             |
 * | leafs_n         |     8 |             |
 * | entries_n       |     8 |             |
 * | salt            |     8 |             |
 * | norm flags      |     8 |           9 |
 * | flags           |     8 |          26 |
 * | padding         |     M |             |
 * | leaves          |     N |             |
 * +-----------------+-------+-------------+
 *
 * block_type ZAP_BLOCK_TYPE_HEADER
 * magic      ZAP_MEGA_MAGIC
 * zap_table  ZapMegaPointerTable
 * padding    up to first half of total size
 * leaves     second half of total size
 * ```
 *
 * A Mega ZAP (also known as a ZAP or a fat ZAP), uses multiple blocks. A Mega
 * ZAP consists of a header, leaf pointers (array of [`u64`]), and leaf blocks.
 *
 * The first block in a Mega ZAP contains the header, followed by padding, and
 * an array of leaf pointers. The leaf pointers are only used if `table.blocks`
 * is 0. Otherwise, the leaf pointers are stored outside of the first block.
 * This allows for the pointer table to initially be stored along with the
 * header in the first block, but then grow and span multiple blocks if needed.
 *
 * The layout of the first block on disk can be visualized as:
 *
 * ```text
 * +---------------+---------+---------------+
 * | ZapMegaHeader | Padding | Leaf Pointers |
 * +---------------+---------+---------------+
 * ```
 *
 * The size of the `Padding` and `Leaf Pointers` depends on the size of the
 * block. The `ZapMegaHeader` and `Padding` use half of the block. The
 * `Leaf Pointers` use the other half.
 *
 * In ZFS version 1, the block was always 128 KiB, but version 2 onwards allows
 * for smaller block sizes (TODO: does it also allow for larger?). Use
 * [`ZapMegaHeader::get_padding_size_and_embedded_leaf_pointer_count`] to get
 * the size of the padding in bytes, and the number of [`u64`] entries in the
 * leaf pointer table.
 *
 * The following table summarizes the padding and leaf pointers for different
 * block sizes. Due to limitations that are described in [`ZapLeafHeader`], it
 * is not space efficient to use blocks larger than 1 or 2 MiB.
 *
 * ```text
 * +-------+------------+---------+---------------+-----------+
 * | Shift | Block Size | Padding | Leaf Pointers | Hash Bits |
 * |       | (bytes)    | (bytes) | (count)       |           |
 * +-------+------------+---------+---------------+-----------+
 * |     9 |        512 |     152 |            32 |         5 |
 * |    10 |       1024 |     408 |            64 |         6 |
 * |    11 |       2048 |     920 |           128 |         7 |
 * |    12 |       4096 |    1944 |           256 |         8 |
 * |    13 |       8192 |    3992 |           512 |         9 |
 * |    14 |      16384 |    8088 |          1024 |        10 |
 * |    15 |      32768 |   16280 |          2048 |        11 |
 * |    16 |      65536 |   32664 |          4096 |        12 |
 * |    17 |     131072 |   65432 |          8192 |        13 |
 * |    18 |     262144 |  130968 |         16384 |        14 |
 * |    19 |     524288 |  262040 |         32768 |        15 |
 * |    20 |    1048576 |  524184 |         65536 |        16 |
 * |    21 |    2097152 | 1048472 |        131072 |        17 |
 * +-------+------------+---------+---------------+-----------+
 * ```
 *
 * The `Leaf Pointers` table is an array of [`u64`], where each entry points to
 * a block that contains a [`ZapLeafHeader`] and its array of [`ZapLeafChunk`].
 *
 * To look up a given key, normalize it according to the flags in the
 * [`ZapMegaHeader`], and pass it with the `salt` to the ZAP hash function.
 * Then take the top `table.hash_bits` to get the index into the leaf pointer
 * table. The value at that index will be the block number at which the ZAP
 * leaf is stored. Multiple indices can point to the same block.
 *
 * TODO: Document lookup when copy is in progress: `table.next_block != 0`.
 *
 * For example, if the hash is `0xa582710a5e902f9d` and `table.hash_bits` is 11,
 * then the index is: `h >> (64 - 11)`, which is `0x52c`. This differs from
 * more conventional hashing, where the `%` (modulus) function is used to index
 * using the lower bits. Look at [`ZapMegaPointerTable`] documentation for how
 * this hashing method is more efficient for growing the table.
 */
#[derive(Debug)]
pub struct ZapMegaHeader {
    /// ZAP table.
    pub table: ZapMegaPointerTable,

    /// The next ZAP block that can be used to allocate a new ZAP leaf.
    pub next_free_block: u64,

    /// The number of ZAP leafs contained in this ZAP object.
    pub number_of_leafs: u64,

    /// The number of key value entries across all ZAP leaves in this object.
    pub number_of_entries: u64,

    /// Salt for ZAP hash computation.
    pub salt: u64,

    /// [`ZapCaseNormalization`] of [`ZapMicroEntry::name`].
    pub case_normalization: ZapCaseNormalization,

    /// [`ZapUnicodeNormalization`] of [`ZapMicroEntry::name`].
    pub unicode_normalization: ZapUnicodeNormalization,

    /// Use 48 bit hash values (instead of default 28 bit).
    pub hash_bits_48: bool,

    /// Keys are [`u64`] values.
    pub key_u64: bool,

    /// Use the first [`u64`] of the key as the hash.
    pub pre_hashed_key: bool,
}

impl ZapMegaHeader {
    /// Byte size of an encoded [`ZapMegaHeader`].
    pub const SIZE: usize = 104;

    /// [`ZapMegaHeader`] block type.
    pub const BLOCK_TYPE: u64 = 0x8000000000000001;

    /// [`ZapMegaHeader`] magic.
    pub const MAGIC: u64 = 0x00000002f52ab2ab;

    /// Flags mask to store 48 bits of ZAP hash.
    const FLAG_HASH_BITS_48: u64 = 1 << 0;

    /// Flags mask that keys are 64 bit numbers.
    const FLAG_KEY_U64: u64 = 1 << 1;

    /** Flags mask that first word of key (which is an array of [`u64`]) is
     * already randomly distributed.
     */
    const FLAG_PRE_HASHED_KEY: u64 = 1 << 2;

    /// Mask for all flags.
    const FLAG_ALL: u64 = ZapMegaHeader::FLAG_HASH_BITS_48
        | ZapMegaHeader::FLAG_KEY_U64
        | ZapMegaHeader::FLAG_PRE_HASHED_KEY;

    /** Decodes a [`ZapMegaHeader`].
     *
     * # Errors
     *
     * Returns [`ZapMegaHeaderDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapMegaHeader, ZapMegaHeaderDecodeError> {
        ////////////////////////////////
        // Decode block type.
        let block_type = decoder.get_u64()?;
        if block_type != ZapMegaHeader::BLOCK_TYPE {
            return Err(ZapMegaHeaderDecodeError::BlockType { block_type });
        }

        ////////////////////////////////
        // Decode magic.
        let magic = decoder.get_u64()?;
        if magic != ZapMegaHeader::MAGIC {
            return Err(ZapMegaHeaderDecodeError::Magic { magic });
        }

        ////////////////////////////////
        // Decode table;
        let table = ZapMegaPointerTable::from_decoder(decoder)?;

        ////////////////////////////////
        // Decode next free block.
        let next_free_block = decoder.get_u64()?;

        ////////////////////////////////
        // Decode number of leafs.
        let number_of_leafs = decoder.get_u64()?;

        ////////////////////////////////
        // Decode number of entries.
        let number_of_entries = decoder.get_u64()?;

        ////////////////////////////////
        // Decode salt.
        let salt = decoder.get_u64()?;

        ////////////////////////////////
        // Decode normalization.
        let normalization = decoder.get_u64()?;

        if (normalization & ZapMicroHeader::NORMALIZATION_MASK) != normalization {
            return Err(ZapMegaHeaderDecodeError::Normalization { normalization });
        }

        let case_normalization =
            ZapCaseNormalization::try_from(normalization & ZapCaseNormalization::MASK_ALL)?;

        let unicode_normalization =
            ZapUnicodeNormalization::try_from(normalization & ZapUnicodeNormalization::MASK_ALL)?;

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;
        if (flags & ZapMegaHeader::FLAG_ALL) != flags {
            return Err(ZapMegaHeaderDecodeError::Flags { flags });
        }

        ////////////////////////////////
        // Success.
        Ok(ZapMegaHeader {
            table,
            next_free_block,
            number_of_leafs,
            number_of_entries,
            salt,
            case_normalization,
            unicode_normalization,
            hash_bits_48: (flags & ZapMegaHeader::FLAG_HASH_BITS_48) != 0,
            key_u64: (flags & ZapMegaHeader::FLAG_KEY_U64) != 0,
            pre_hashed_key: (flags & ZapMegaHeader::FLAG_PRE_HASHED_KEY) != 0,
        })
    }

    /** Encodes a [`ZapMegaHeader`].
     *
     * # Errors
     *
     * Returns [`ZapMegaHeaderEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapMegaHeaderEncodeError> {
        ////////////////////////////////
        // Encode block type.
        encoder.put_u64(ZapMegaHeader::BLOCK_TYPE)?;

        ////////////////////////////////
        // Encode magic.
        encoder.put_u64(ZapMegaHeader::MAGIC)?;

        ////////////////////////////////
        // Encode table.
        self.table.to_encoder(encoder)?;

        ////////////////////////////////
        // Encode next free block.
        encoder.put_u64(self.next_free_block)?;

        ////////////////////////////////
        // Encode number of leafs.
        encoder.put_u64(self.number_of_leafs)?;

        ////////////////////////////////
        // Encode number of entries.
        encoder.put_u64(self.number_of_entries)?;

        ////////////////////////////////
        // Encode salt.
        encoder.put_u64(self.salt)?;

        ////////////////////////////////
        // Encode normalization.
        let normalization =
            u64::from(self.case_normalization) | u64::from(self.unicode_normalization);
        encoder.put_u64(normalization)?;

        ////////////////////////////////
        // Encode flags.
        let flags = (if self.hash_bits_48 {
            ZapMegaHeader::FLAG_HASH_BITS_48
        } else {
            0
        } | if self.key_u64 {
            ZapMegaHeader::FLAG_KEY_U64
        } else {
            0
        } | if self.pre_hashed_key {
            ZapMegaHeader::FLAG_PRE_HASHED_KEY
        } else {
            0
        });
        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }

    /** Gets the padding size (in bytes) and embedded leaf pointer table count
     * (in u64) for the given block size (in bytes).
     *
     * # Errors
     *
     * Returns [`ZapMegaHeaderDecodeError`] if block size is not valid.
     */
    pub fn get_padding_size_and_embedded_leaf_pointer_count(
        block_size: usize,
    ) -> Result<(usize, usize), ZapMegaHeaderDecodeError> {
        ////////////////////////////////
        // Check that the block size is a power of 2 and at least one sector.
        if block_size < (1 << SECTOR_SHIFT) || !block_size.is_power_of_two() {
            return Err(ZapMegaHeaderDecodeError::BlockSize { block_size });
        }

        ////////////////////////////////
        // Split block into two halves.
        let half = block_size / 2;

        ////////////////////////////////
        // Padding is half of block, minus header size.
        let padding = half - ZapMegaHeader::SIZE;

        ////////////////////////////////
        // Number of leaves, is half divided by u64 size.
        let leaves = half / 8;

        ////////////////////////////////
        Ok((padding, leaves))
    }
}

/// [`ZapMegaHeader`] decode error.
#[derive(Debug)]
pub enum ZapMegaHeaderDecodeError {
    /// Invalid block size.
    BlockSize {
        /// Block size.
        block_size: usize,
    },

    /// Invalid block type.
    BlockType {
        /// Block type.
        block_type: u64,
    },

    /// Unknown [`ZapCaseNormalization`].
    CaseNormalization {
        /// Error.
        err: ZapCaseNormalizationError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown flags.
    Flags {
        /// Unknown flags.
        flags: u64,
    },

    /// Invalid magic.
    Magic {
        /// Magic.
        magic: u64,
    },

    /// Unknown normalization.
    Normalization {
        /// Unknown normalization.
        normalization: u64,
    },

    /// Unknown [`ZapUnicodeNormalization`].
    UnicodeNormalization {
        /// Error.
        err: ZapUnicodeNormalizationError,
    },

    /// [`ZapMegaPointerTable`] error.
    ZapMegaPointerTable {
        /// Error.
        err: ZapMegaPointerTableDecodeError,
    },
}

impl From<ZapCaseNormalizationError> for ZapMegaHeaderDecodeError {
    fn from(err: ZapCaseNormalizationError) -> Self {
        ZapMegaHeaderDecodeError::CaseNormalization { err }
    }
}

impl From<EndianDecodeError> for ZapMegaHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapMegaHeaderDecodeError::Endian { err }
    }
}

impl From<ZapMegaPointerTableDecodeError> for ZapMegaHeaderDecodeError {
    fn from(err: ZapMegaPointerTableDecodeError) -> Self {
        ZapMegaHeaderDecodeError::ZapMegaPointerTable { err }
    }
}

impl From<ZapUnicodeNormalizationError> for ZapMegaHeaderDecodeError {
    fn from(err: ZapUnicodeNormalizationError) -> Self {
        ZapMegaHeaderDecodeError::UnicodeNormalization { err }
    }
}

impl fmt::Display for ZapMegaHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMegaHeaderDecodeError::BlockSize { block_size } => {
                write!(
                    f,
                    "ZapMegaHeader decode error, invalid block size {block_size}"
                )
            }
            ZapMegaHeaderDecodeError::BlockType { block_type } => {
                write!(
                    f,
                    "ZapMegaHeader decode error, invalid block type {block_type}"
                )
            }
            ZapMegaHeaderDecodeError::CaseNormalization { err } => {
                write!(f, "ZapMegaHeader decode error | {err}")
            }
            ZapMegaHeaderDecodeError::Endian { err } => {
                write!(f, "ZapMegaHeader decode error | {err}")
            }
            ZapMegaHeaderDecodeError::Flags { flags } => {
                write!(f, "ZapMegaHeader decode error unknown flags {flags:#016x}")
            }
            ZapMegaHeaderDecodeError::Magic { magic } => {
                write!(f, "ZapMegaHeader decode error, invalid magic {magic}")
            }
            ZapMegaHeaderDecodeError::Normalization { normalization } => {
                write!(
                    f,
                    "ZapMegaHeader decode error, unknown normalization {normalization}"
                )
            }
            ZapMegaHeaderDecodeError::UnicodeNormalization { err } => {
                write!(f, "ZapMegaHeader decode error | {err}")
            }
            ZapMegaHeaderDecodeError::ZapMegaPointerTable { err } => {
                write!(f, "ZapMegaHeader decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMegaHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMegaHeaderDecodeError::CaseNormalization { err } => Some(err),
            ZapMegaHeaderDecodeError::Endian { err } => Some(err),
            ZapMegaHeaderDecodeError::UnicodeNormalization { err } => Some(err),
            ZapMegaHeaderDecodeError::ZapMegaPointerTable { err } => Some(err),
            _ => None,
        }
    }
}

/// [`ZapMegaHeader`] encode error.
#[derive(Debug)]
pub enum ZapMegaHeaderEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// [`ZapMegaPointerTable`] error.
    ZapMegaPointerTable {
        /// Error.
        err: ZapMegaPointerTableEncodeError,
    },
}

impl From<EndianEncodeError> for ZapMegaHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapMegaHeaderEncodeError::Endian { err }
    }
}

impl From<ZapMegaPointerTableEncodeError> for ZapMegaHeaderEncodeError {
    fn from(value: ZapMegaPointerTableEncodeError) -> Self {
        ZapMegaHeaderEncodeError::ZapMegaPointerTable { err: value }
    }
}

impl fmt::Display for ZapMegaHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapMegaHeaderEncodeError::Endian { err } => {
                write!(f, "ZapMegaHeader encode error | {err}")
            }
            ZapMegaHeaderEncodeError::ZapMegaPointerTable { err } => {
                write!(f, "ZapMegaHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapMegaHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapMegaHeaderEncodeError::Endian { err } => Some(err),
            ZapMegaHeaderEncodeError::ZapMegaPointerTable { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** ZAP header
 *
 * ### Byte layout
 *
 * - Bytes: 64 or 104
 */
#[derive(Debug)]
pub enum ZapHeader {
    /// [`ZapMegaHeader]`.
    Mega(ZapMegaHeader),

    /// [`ZapMicroHeader`].
    Micro(ZapMicroHeader),
}

impl ZapHeader {
    /** Decodes a [`ZapHeader`].
     *
     * # Errors
     *
     * Returns [`ZapHeaderDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<ZapHeader, ZapHeaderDecodeError> {
        let block_type = decoder.get_u64()?;
        decoder.rewind(8)?;

        match block_type {
            ZapMegaHeader::BLOCK_TYPE => Ok(ZapHeader::Mega(ZapMegaHeader::from_decoder(decoder)?)),
            ZapMicroHeader::BLOCK_TYPE => {
                Ok(ZapHeader::Micro(ZapMicroHeader::from_decoder(decoder)?))
            }
            _ => Err(ZapHeaderDecodeError::BlockType { block_type }),
        }
    }

    /** Encodes a [`ZapHeader`].
     *
     * # Errors
     *
     * Returns [`ZapHeaderEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), ZapHeaderEncodeError> {
        match self {
            ZapHeader::Mega(header) => header.to_encoder(encoder)?,
            ZapHeader::Micro(header) => header.to_encoder(encoder)?,
        }

        Ok(())
    }
}

/// [`ZapHeader`] decode error.
#[derive(Debug)]
pub enum ZapHeaderDecodeError {
    /// Unknown block type.
    BlockType {
        /// Block type.
        block_type: u64,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// [`ZapMegaHeader`] decode error.
    ZapMegaHeader {
        /// Error.
        err: ZapMegaHeaderDecodeError,
    },

    /// [`ZapMicroHeader`] decode error.
    ZapMicroHeader {
        /// Error.
        err: ZapMicroHeaderDecodeError,
    },
}

impl From<EndianDecodeError> for ZapHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapHeaderDecodeError::Endian { err }
    }
}

impl From<ZapMegaHeaderDecodeError> for ZapHeaderDecodeError {
    fn from(err: ZapMegaHeaderDecodeError) -> Self {
        ZapHeaderDecodeError::ZapMegaHeader { err }
    }
}

impl From<ZapMicroHeaderDecodeError> for ZapHeaderDecodeError {
    fn from(err: ZapMicroHeaderDecodeError) -> Self {
        ZapHeaderDecodeError::ZapMicroHeader { err }
    }
}

impl fmt::Display for ZapHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapHeaderDecodeError::Endian { err } => {
                write!(f, "ZapHeader decode error | {err}")
            }
            ZapHeaderDecodeError::BlockType { block_type } => {
                write!(f, "ZapHeader decode error, unknown block type {block_type}")
            }
            ZapHeaderDecodeError::ZapMicroHeader { err } => {
                write!(f, "ZapHeader decode error | {err}")
            }
            ZapHeaderDecodeError::ZapMegaHeader { err } => {
                write!(f, "ZapHeader decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapHeaderDecodeError::Endian { err } => Some(err),
            ZapHeaderDecodeError::ZapMegaHeader { err } => Some(err),
            ZapHeaderDecodeError::ZapMicroHeader { err } => Some(err),
            _ => None,
        }
    }
}

/// [`ZapHeader`] encode error.
#[derive(Debug)]
pub enum ZapHeaderEncodeError {
    /// [`ZapMegaHeader`] encode error.
    ZapMegaHeader {
        /// Error.
        err: ZapMegaHeaderEncodeError,
    },

    /// [`ZapMicroHeader`] encode error.
    ZapMicroHeader {
        /// Error.
        err: ZapMicroHeaderEncodeError,
    },
}

impl From<ZapMegaHeaderEncodeError> for ZapHeaderEncodeError {
    fn from(err: ZapMegaHeaderEncodeError) -> Self {
        ZapHeaderEncodeError::ZapMegaHeader { err }
    }
}

impl From<ZapMicroHeaderEncodeError> for ZapHeaderEncodeError {
    fn from(err: ZapMicroHeaderEncodeError) -> Self {
        ZapHeaderEncodeError::ZapMicroHeader { err }
    }
}

impl fmt::Display for ZapHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapHeaderEncodeError::ZapMicroHeader { err } => {
                write!(f, "ZapHeader encode error | {err}")
            }
            ZapHeaderEncodeError::ZapMegaHeader { err } => {
                write!(f, "ZapHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapHeaderEncodeError::ZapMegaHeader { err } => Some(err),
            ZapHeaderEncodeError::ZapMicroHeader { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

const ZAP_LEAF_EOL: u16 = 0xffff;

/** Mask for [`ZapLeafHeader`] indicating if the entry chain is sorted by
 * increasing collision differentiator.
 */
const ZAP_LEAF_HEADER_FLAG_CD_SORTED_MASK: u8 = 1;

/// Mask for all [`ZapLeafHeader`] flags.
const ZAP_LEAF_HEADER_FLAG_ALL: u8 = ZAP_LEAF_HEADER_FLAG_CD_SORTED_MASK;

/** ZAP Leaf header.
 *
 * ### Byte layout
 *
 * - Bytes:
 *   - Fixed size: 48
 *   - Total size: 512, 1024, 2048, ..., 131072
 *
 * ```text
 * +---------------+------+-------------+
 * | Field         | Size | SPA Version |
 * +---------------+------+-------------+
 * | block_type    |    8 |             |
 * | padding       |    8 |           2 |
 * | prefix        |    8 |             |
 * | magic         |    4 |             |
 * | free chunks   |    2 |             |
 * | entries       |    2 |             |
 * | prefix length |    2 |             |
 * | free list     |    2 |             |
 * | flags         |    1 |             |
 * | padding       |   11 |             |
 * | hash          |    M |             |
 * | chunks        |    N |             |
 * +---------------+------+-------------+
 *
 * block_type ZAP_BLOCK_TYPE_LEAF
 * padding    This was designed for block chaining, but was never implemented
 *            and was officially deprecated by v2.
 * ```
 *
 * A ZAP leaf blocks holds the data that a Mega ZAP leaf pointer references.
 *
 * Each ZAP leaf block consists of a header, followed by a [`u16`] hash table,
 * and then an array of ZAP leaf chunks. The leaf chunks are arranged as
 * linked lists using [`u16`] offsets into the leaf chunks array.
 *
 * The layout of the leaf block on disk can be visualzied as:
 *
 * ```text
 * +---------------+------------+--------------+-----+--------------+
 * | ZapLeafHeader | Hash Table | ZapLeafChunk | ... | ZapLeafChunk |
 * +---------------+------------+--------------+-----+--------------+
 * ```
 *
 * In ZFS version 1, the block was always 128 KiB, but version 2 onwards allows
 * for smaller block sizes (TODO: does it also allow for larger?).
 * Use [`ZapLeafHeader::get_entries_and_chunks_counts`] to get the length of
 * the hash table, and the number of leaf chunks.
 *
 * The following table summarizes the hash table and leaf pointers for different
 * block sizes. Since indices into the [`ZapLeafChunk`] array use a [`u16`],
 * it is not space efficient to use blocks larger than 1 or 2 MiB. At 1 MiB,
 * all the leaf chunks can still be used. At 2 MiB, more chunks can be used,
 * but about 20% are unreferenced due to [`u16`] size limit.
 *
 * ```text
 * +-------+------------+------------+-------------+
 * | Shift | Block Size | Hash Table | Leaf Chunks |
 * |       | (bytes)    | (count)    | (count)     |
 * +-------+------------+------------+-------------+
 * |     9 |        512 |         16 |          18 |
 * |    10 |       1024 |         32 |          38 |
 * |    11 |       2048 |         64 |          78 |
 * |    12 |       4096 |        128 |         158 |
 * |    13 |       8192 |        256 |         318 |
 * |    14 |      16384 |        512 |         638 |
 * |    15 |      32768 |       1024 |        1278 |
 * |    16 |      65536 |       2048 |        2558 |
 * |    17 |     131072 |       4096 |        5118 |
 * |    18 |     262144 |       8192 |       10238 |
 * |    19 |     524288 |      16384 |       20478 |
 * |    20 |    1048576 |      32768 |       40958 |
 * |    21 |    2097152 |      65536 |       81918 |
 * +-------+------------+------------+-------------+
 * ```
 *
 * The original ZFS implementation at version 1 used a block size of 128 KiB,
 * and declared constants of 4096 and 5118 for the count of hash table and
 * leaf chunks. The 4096, corresponds to dividing 128 KiB by 32, and the 5118
 * is the rest of the space divided by the size of a leaf chunk (24 bytes).
 *
 * Given a block shift `B` and a leaf chunk count `N`, the the following byte
 * size equality can be written out:
 *
 * ```text
 * 2^B                          = 48 + 2 * (2^(B - 5)) + N * 24
 * 2^B                          = 48 +      2^(B - 4)  + N * 24
 * 2^B - 2^(B - 4)              = 48     + N * 24
 * 2^B - 2^(B - 4)              = 2 * 24 + N * 24
 * 2^B - 2^(B - 4)              = 24 * (2 + N)
 * (2^B - 2^(B - 4)) / 24       = 2 + N
 * ((2^B - 2^(B - 4)) / 24) - 2 = N
 * ```
 *
 * Given the above, the difference of the powers must be a multiple of 24. This
 * first occurs at `B = 7`, where `N` will equal `3`. increasing `B` by one,
 * will double the difference between the powers, so the above equation will
 * always hold for whole numbers and power of two sized blocks, where `B >= 7`.
 *
 * To look up a given key, take the hash computed when looking up the key in
 * the [`ZapMegaHeader`] and [`ZapMegaPointerTable`], and use the top `N` bits,
 * where `N` is the number of bits needed to index the hash table, between
 * the [`ZapLeafHeader`] and the [`ZapLeafChunk`]. The value at that index, will
 * point to the index into the [`ZapLeafChunk`] array, containing
 * a [`ZapLeafChunkEntry`]. If the value is `ZAP_LEAF_EOL`, then there is no
 * entry for this hash table index.
 */
#[derive(Debug)]
pub struct ZapLeafHeader {
    /** Hash prefix of length `hash_prefix_len` of all entries in this leaf.
     *
     * Can be zero.
     */
    pub hash_prefix: u64,

    /** Hash prefix length of `hash_prefix` of all entries in this leaf.
     *
     * Can be zero.
     */
    pub hash_prefix_len: u16,

    /// Number of [`ZapLeafChunkFree`] in this ZAP leaf block.
    pub number_of_free_chunks: u16,

    /// Number of [`ZapLeafChunkEntry`] in this ZAP leaf block.
    pub number_of_entries: u16,

    /// Next [`ZapLeafChunkFree`] index in this ZAP leaf block.
    pub next_free_chunk: Option<u16>,

    /// Are entries with the same hash sorted by increasing collision differentiator.
    pub cd_sorted: bool,
}

impl ZapLeafHeader {
    /// Byte length of an encoded [`ZapLeafHeader`].
    pub const SIZE: usize = 48;

    /// [`ZapLeafHeader`] block type.
    pub const BLOCK_TYPE: u64 = 0x8000000000000000;

    /// [`ZapLeafHeader`] magic.
    pub const MAGIC: u32 = 0x02AB1EAF;

    /// Padding A byte size.
    const PADDING_SIZE_A: usize = 8;

    /// Padding B byte size.
    const PADDING_SIZE_B: usize = 11;

    /** Decodes a [`ZapLeafHeader`].
     *
     * # Errors
     *
     * Returns [`ZapLeafHeaderDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapLeafHeader, ZapLeafHeaderDecodeError> {
        ////////////////////////////////
        // Decode block type.
        let block_type = decoder.get_u64()?;
        if block_type != ZapLeafHeader::BLOCK_TYPE {
            return Err(ZapLeafHeaderDecodeError::BlockType { block_type });
        }

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ZapLeafHeader::PADDING_SIZE_A)?;

        ////////////////////////////////
        // Decode hash prefix.
        let hash_prefix = decoder.get_u64()?;

        ////////////////////////////////
        // Decode magic.
        let magic = decoder.get_u32()?;
        if magic != ZapLeafHeader::MAGIC {
            return Err(ZapLeafHeaderDecodeError::Magic { magic });
        }

        ////////////////////////////////
        // Decode number of free chunks.
        let number_of_free_chunks = decoder.get_u16()?;

        ////////////////////////////////
        // Decode number of entries.
        let number_of_entries = decoder.get_u16()?;

        ////////////////////////////////
        // Decode hash prefix length.
        let hash_prefix_len = decoder.get_u16()?;

        ////////////////////////////////
        // Decode next free chunk.
        let next_free_chunk = match decoder.get_u16()? {
            ZAP_LEAF_EOL => None,
            v => Some(v),
        };

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u8()?;

        if (flags & ZAP_LEAF_HEADER_FLAG_ALL) != flags {
            return Err(ZapLeafHeaderDecodeError::Flags { flags });
        }

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ZapLeafHeader::PADDING_SIZE_B)?;

        ////////////////////////////////
        // Success.
        Ok(ZapLeafHeader {
            hash_prefix,
            number_of_free_chunks,
            number_of_entries,
            hash_prefix_len,
            next_free_chunk,
            cd_sorted: (flags & ZAP_LEAF_HEADER_FLAG_CD_SORTED_MASK) != 0,
        })
    }

    /** Encodes a [`ZapLeafHeader`].
     *
     * # Errors
     *
     * Returns [`ZapLeafHeaderEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapLeafHeaderEncodeError> {
        ////////////////////////////////
        // Encode block type.
        encoder.put_u64(ZapLeafHeader::BLOCK_TYPE)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapLeafHeader::PADDING_SIZE_A)?;

        ////////////////////////////////
        // Encode hash prefix.
        encoder.put_u64(self.hash_prefix)?;

        ////////////////////////////////
        // Encode magic.
        encoder.put_u32(ZapLeafHeader::MAGIC)?;

        ////////////////////////////////
        // Encode number of free chunks.
        encoder.put_u16(self.number_of_free_chunks)?;

        ////////////////////////////////
        // Encode number of entries.
        encoder.put_u16(self.number_of_entries)?;

        ////////////////////////////////
        // Encode hash prefix length.
        encoder.put_u16(self.hash_prefix_len)?;

        ////////////////////////////////
        // Encode next free chunk.
        encoder.put_u16(self.next_free_chunk.unwrap_or(ZAP_LEAF_EOL))?;

        ////////////////////////////////
        // Encode flags.
        let flags = if self.cd_sorted {
            ZAP_LEAF_HEADER_FLAG_CD_SORTED_MASK
        } else {
            0
        };
        encoder.put_u8(flags)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapLeafHeader::PADDING_SIZE_B)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }

    /** Gets the number [u16] hash table entries and the number of
     * [`ZapLeafChunk`] chunks.
     *
     * # Errors
     *
     * Returns [`ZapMegaHeaderDecodeError`] if block size is not valid.
     */
    pub fn get_entries_and_chunks_counts(
        block_size: usize,
    ) -> Result<(usize, usize), ZapMegaHeaderDecodeError> {
        ////////////////////////////////
        // Check that the block size is a power of 2 and at least one sector.
        if block_size < (1 << SECTOR_SHIFT) || !block_size.is_power_of_two() {
            return Err(ZapMegaHeaderDecodeError::BlockSize { block_size });
        }

        ////////////////////////////////
        // Divide by 32 (shift by 5) to get the length of the entries table.
        let entries_count = block_size >> 5;

        ////////////////////////////////
        // The number of chunks is everything else.
        let chunks_count =
            (block_size - (ZapLeafHeader::SIZE + 2 * entries_count)) / ZapLeafChunk::SIZE;

        // Due to selected sizes of header, entries, and chunks, this should
        // always be true.
        debug_assert!(
            ZapLeafHeader::SIZE + 2 * entries_count + chunks_count * ZapLeafChunk::SIZE
                == block_size
        );

        ////////////////////////////////
        // Success.
        Ok((entries_count, chunks_count))
    }
}

/// [`ZapLeafHeader`] decode error.
#[derive(Debug)]
pub enum ZapLeafHeaderDecodeError {
    /// Invalid block size.
    BlockSize {
        /// Block size.
        block_size: usize,
    },

    /// Invalid block type.
    BlockType {
        /// Block type.
        block_type: u64,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown flags.
    Flags {
        /// Flags.
        flags: u8,
    },

    /// Invalid magic.
    Magic {
        /// Magic.
        magic: u32,
    },
}

impl From<EndianDecodeError> for ZapLeafHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapLeafHeaderDecodeError::Endian { err }
    }
}

impl fmt::Display for ZapLeafHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapLeafHeaderDecodeError::BlockSize { block_size } => {
                write!(
                    f,
                    "ZapLeafHeader decode error, invalid block size {block_size}"
                )
            }
            ZapLeafHeaderDecodeError::BlockType { block_type } => {
                write!(
                    f,
                    "ZapLeafHeader decode error, invalid block type {block_type}"
                )
            }
            ZapLeafHeaderDecodeError::Endian { err } => {
                write!(f, "ZapLeafHeader decode error | {err}")
            }
            ZapLeafHeaderDecodeError::Flags { flags } => {
                write!(f, "ZapLeafHeader decode error, unknown flags {flags}")
            }
            ZapLeafHeaderDecodeError::Magic { magic } => {
                write!(f, "ZapLeafHeader decode error, invalid magic {magic}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapLeafHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapLeafHeaderDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`ZapLeafHeader`] encode error.
#[derive(Debug)]
pub enum ZapLeafHeaderEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for ZapLeafHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapLeafHeaderEncodeError::Endian { err }
    }
}

impl fmt::Display for ZapLeafHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapLeafHeaderEncodeError::Endian { err } => {
                write!(f, "ZapLeafHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapLeafHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapLeafHeaderEncodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** ZAP Leaf Chunk that is array data.
 *
 * ### Byte layout
 *
 * - Bytes: 24
 *
 * ```text
 * +------------+------+
 * | Field      | Size |
 * +------------+------+
 * | chunk type |    1 |
 * | data       |   21 |
 * | next       |    2 |
 * +------------+------+
 *
 * chunk type ZapLeafChunkData::CHUNK_TYPE
 * next       next free chunk index or ZAP_LEAF_EOL
 * ```
 */
#[derive(Debug)]
pub struct ZapLeafChunkData {
    /// Array data.
    pub data: [u8; ZapLeafChunkData::ZAP_LEAF_DATA_SIZE],

    /// Next chunk.
    pub next: Option<u16>,
}

impl ZapLeafChunkData {
    /// [`ZapLeafChunkData`] chunk type.
    pub const CHUNK_TYPE: u8 = 251;

    /// [`ZapLeafChunkData`] data size.
    pub const ZAP_LEAF_DATA_SIZE: usize = 21;

    /** Decodes a [`ZapLeafChunkData`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapLeafChunkData, ZapLeafChunkDecodeError> {
        ////////////////////////////////
        // Decode leaf type.
        let chunk_type = decoder.get_u8()?;

        if chunk_type != ZapLeafChunkData::CHUNK_TYPE {
            return Err(ZapLeafChunkDecodeError::ChunkType { chunk_type });
        }

        ////////////////////////////////
        // Get data.
        let data = decoder.get_bytes(ZapLeafChunkData::ZAP_LEAF_DATA_SIZE)?;

        ////////////////////////////////
        // Decode next.
        let next = match decoder.get_u16()? {
            ZAP_LEAF_EOL => None,
            v => Some(v),
        };

        ////////////////////////////////
        // Success.
        Ok(ZapLeafChunkData {
            data: data.try_into().unwrap(),
            next,
        })
    }

    /** Encodes a [`ZapLeafChunkData`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapLeafChunkEncodeError> {
        ////////////////////////////////
        // Encode leaf type.
        encoder.put_u8(ZapLeafChunkData::CHUNK_TYPE)?;

        ////////////////////////////////
        // Encode data.
        encoder.put_bytes(&self.data)?;

        ////////////////////////////////
        // Encode next.
        encoder.put_u16(self.next.unwrap_or(ZAP_LEAF_EOL))?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/** ZAP Leaf Chunk that is an entry.
 *
 * ### Byte layout
 *
 * - Bytes: 24
 *
 * ```text
 * +----------------+------+
 * | Field          | Size |
 * +----------------+------+
 * | chunk type     |    1 |
 * | value int size |    1 |
 * | next           |    2 |
 * | name chunk     |    2 |
 * | name length    |    2 |
 * | value chunk    |    2 |
 * | value length   |    2 |
 * | cd             |    2 |
 * | hash           |    2 |
 * +----------------+------+
 *
 * chunk type ZapLeafChunkEntry::CHUNK_TYPE
 * next       next free chunk index or ZAP_LEAF_EOL
 * ```
 *
 * To look up a given key, take the hash computed by ZAP hash, mask off the
 * top bits according to the [`ZapMegaHeader`] flags (`hash_bits_u48`,
 * `key_u64`, `pre_hashed_key`), and compare the result to the `hash` field of
 * the [`ZapLeafChunkEntry`].
 *
 * If the hash matches, then look up the name of this entry, by accessing the
 * [`ZapLeafChunkData`] at `name_chunk`. The length of the name (in bytes) will
 * be `name_length`, and split across a chain of [`ZapLeafChunkData`] (
 * if the name is too long for one [`ZapLeafChunkData`]).
 *
 * TODO(cybojanek): Are names NULL terminated?
 *
 * If the hashes or name do not match, then check `next` for the next
 * [`ZapLeafChunkEntry`] with the same top bits, and check its name.
 *
 * If the hash and name match, then access the value of this entry, by
 * accessing the [`ZapLeafChunkData`] at `value_chunk`. The `value_length`
 * is the number of `value_int_size` (in bytes) entries in the
 * [`ZapLeafChunkData`] chain. For example, a single [`u64`] will be stored
 * as `value_length = 1`, and `value_int_size = 8`.
 *
 * Data in the [`ZapLeafChunkData`] is not aligned in any way, and a [`u64`]
 * can be split across two chunks.
 */
#[derive(Debug)]
pub struct ZapLeafChunkEntry {
    /// Hash of key.
    pub hash: u64,

    /// Collision differentiator.
    pub cd: u32,

    /// [`ZapLeafChunkData`] with full name of this key.
    pub name_chunk: u16,

    /// Length of name in [`ZapLeafChunkData`].
    pub name_length: u16,

    /// [`ZapLeafChunkData`] with value of this key.
    pub value_chunk: u16,

    /// Length of value in `value_int_size` byte sized units.
    pub value_length: u16,

    /// Length of value unit in bytes.
    pub value_int_size: u8,

    /// Next [`ZapLeafChunkEntry`] for the colliding hash.
    pub next: Option<u16>,
}

impl ZapLeafChunkEntry {
    /// [`ZapLeafChunkEntry`] chunk type.
    pub const CHUNK_TYPE: u8 = 252;

    /** Decodes a [`ZapLeafChunkEntry`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapLeafChunkEntry, ZapLeafChunkDecodeError> {
        ////////////////////////////////
        // Decode leaf type.
        let chunk_type = decoder.get_u8()?;

        if chunk_type != ZapLeafChunkEntry::CHUNK_TYPE {
            return Err(ZapLeafChunkDecodeError::ChunkType { chunk_type });
        }

        ////////////////////////////////
        // Decode value int size.
        let value_int_size = decoder.get_u8()?;

        ////////////////////////////////
        // Decode next.
        let next = match decoder.get_u16()? {
            ZAP_LEAF_EOL => None,
            v => Some(v),
        };

        ////////////////////////////////
        // Decode name chunk and length.
        let name_chunk = decoder.get_u16()?;
        let name_length = decoder.get_u16()?;

        ////////////////////////////////
        // Decode value chunk and length.
        let value_chunk = decoder.get_u16()?;
        let value_length = decoder.get_u16()?;

        ////////////////////////////////
        // Decode collision differentiator.
        let cd = decoder.get_u32()?;

        ////////////////////////////////
        // Decode hash.
        let hash = decoder.get_u64()?;

        ////////////////////////////////
        // Success.
        Ok(ZapLeafChunkEntry {
            hash,
            cd,
            name_chunk,
            name_length,
            value_chunk,
            value_length,
            value_int_size,
            next,
        })
    }

    /** Encodes a [`ZapLeafChunkEntry`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapLeafChunkEncodeError> {
        ////////////////////////////////
        // Encode leaf type.
        encoder.put_u8(ZapLeafChunkEntry::CHUNK_TYPE)?;

        ////////////////////////////////
        // Encode value int size.
        encoder.put_u8(self.value_int_size)?;

        ////////////////////////////////
        // Encode next.
        encoder.put_u16(self.next.unwrap_or(ZAP_LEAF_EOL))?;

        ////////////////////////////////
        // Encode name chunk and length.
        encoder.put_u16(self.name_chunk)?;
        encoder.put_u16(self.name_length)?;

        ////////////////////////////////
        // Encode value chunk and length.
        encoder.put_u16(self.value_chunk)?;
        encoder.put_u16(self.value_length)?;

        ////////////////////////////////
        // Encode collision differentiator.
        encoder.put_u32(self.cd)?;

        ////////////////////////////////
        // Encode hash.
        encoder.put_u64(self.hash)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/** ZAP Leaf Chunk that is free.
 *
 * ### Byte layout
 *
 * - Bytes: 24
 *
 * ```text
 * +------------+------+
 * | Field      | Size |
 * +------------+------+
 * | chunk type |    1 |
 * | padding    |   21 |
 * | next       |    2 |
 * +------------+------+
 *
 * chunk type ZapLeafChunkFree::CHUNK_TYPE
 * next       next free chunk index or ZAP_LEAF_EOL
 * ```
 */
#[derive(Debug)]
pub struct ZapLeafChunkFree {
    /// Next [`ZapLeafChunkFree`].
    next: Option<u16>,
}

impl ZapLeafChunkFree {
    /// [`ZapLeafChunkFree`] chunk type.
    pub const CHUNK_TYPE: u8 = 253;

    /** Decodes a [`ZapLeafChunkFree`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapLeafChunkFree, ZapLeafChunkDecodeError> {
        ////////////////////////////////
        // Decode leaf type.
        let chunk_type = decoder.get_u8()?;

        if chunk_type != ZapLeafChunkFree::CHUNK_TYPE {
            return Err(ZapLeafChunkDecodeError::ChunkType { chunk_type });
        }

        ////////////////////////////////
        // Skip padding.
        // TODO(cybojanek): Is it supposed to be zeros?
        decoder.skip(ZapLeafChunkData::ZAP_LEAF_DATA_SIZE)?;

        ////////////////////////////////
        // Decode next.
        let next = match decoder.get_u16()? {
            ZAP_LEAF_EOL => None,
            v => Some(v),
        };

        ////////////////////////////////
        // Success.
        Ok(ZapLeafChunkFree { next })
    }

    /** Encodes a [`ZapLeafChunkFree`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapLeafChunkEncodeError> {
        ////////////////////////////////
        // Encode leaf type.
        encoder.put_u8(ZapLeafChunkFree::CHUNK_TYPE)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ZapLeafChunkData::ZAP_LEAF_DATA_SIZE)?;

        ////////////////////////////////
        // Encode next.
        encoder.put_u16(self.next.unwrap_or(ZAP_LEAF_EOL))?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/** ZAP Leaf chunk
 *
 * - Bytes: 24
 */
#[derive(Debug)]
pub enum ZapLeafChunk {
    /// [`ZapLeafChunkData`].
    Array(ZapLeafChunkData),

    /// [`ZapLeafChunkEntry`].
    Entry(ZapLeafChunkEntry),

    /// [`ZapLeafChunkFree`].
    Free(ZapLeafChunkFree),
}

impl ZapLeafChunk {
    /// Length of an encoded [`ZapLeafChunk`].
    pub const SIZE: usize = 24;

    /** Decodes a [`ZapLeafChunk`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<ZapLeafChunk, ZapLeafChunkDecodeError> {
        ////////////////////////////////
        // Decode leaf type.
        let chunk_type = decoder.get_u8()?;
        decoder.rewind(1)?;

        match chunk_type {
            ZapLeafChunkData::CHUNK_TYPE => Ok(ZapLeafChunk::Array(
                ZapLeafChunkData::from_decoder(decoder)?,
            )),
            ZapLeafChunkEntry::CHUNK_TYPE => Ok(ZapLeafChunk::Entry(
                ZapLeafChunkEntry::from_decoder(decoder)?,
            )),
            ZapLeafChunkFree::CHUNK_TYPE => {
                Ok(ZapLeafChunk::Free(ZapLeafChunkFree::from_decoder(decoder)?))
            }
            _ => Err(ZapLeafChunkDecodeError::ChunkType { chunk_type }),
        }
    }

    /** Encodes a [`ZapLeafChunk`].
     *
     * # Errors
     *
     * Returns [`ZapLeafChunkEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), ZapLeafChunkEncodeError> {
        match self {
            ZapLeafChunk::Array(array) => array.to_encoder(encoder),
            ZapLeafChunk::Entry(entry) => entry.to_encoder(encoder),
            ZapLeafChunk::Free(free) => free.to_encoder(encoder),
        }
    }
}

/// [`ZapLeafChunk`] deocde error.
#[derive(Debug)]
pub enum ZapLeafChunkDecodeError {
    /// Unknown [`ZapLeafChunk`] type.
    ChunkType {
        /// Chunk type.
        chunk_type: u8,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },
}

impl From<EndianDecodeError> for ZapLeafChunkDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ZapLeafChunkDecodeError::Endian { err }
    }
}

impl fmt::Display for ZapLeafChunkDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapLeafChunkDecodeError::ChunkType { chunk_type } => {
                write!(
                    f,
                    "ZapLeafChunk decode error, unknown chunk type {chunk_type}"
                )
            }
            ZapLeafChunkDecodeError::Endian { err } => {
                write!(f, "ZapLeafChunk decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapLeafChunkDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapLeafChunkDecodeError::ChunkType { chunk_type: _ } => None,
            ZapLeafChunkDecodeError::Endian { err } => Some(err),
        }
    }
}

/// [`ZapLeafChunk`] encode error.
#[derive(Debug)]
pub enum ZapLeafChunkEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for ZapLeafChunkEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ZapLeafChunkEncodeError::Endian { err }
    }
}

impl fmt::Display for ZapLeafChunkEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZapLeafChunkEncodeError::Endian { err } => {
                write!(f, "ZapLeafChunk encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZapLeafChunkEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZapLeafChunkEncodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
