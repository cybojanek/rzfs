// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    ChecksumType, ChecksumTypeError, ChecksumValue, ChecksumValueDecodeError,
    ChecksumValueEncodeError, CompressionType, CompressionTypeError, DmuType, DmuTypeError, Dva,
    DvaDecodeError, DvaEncodeError, EndianDecodeError, EndianDecoder, EndianEncodeError,
    EndianEncoder, EndianOrder,
};

////////////////////////////////////////////////////////////////////////////////

/// Mask for shifted compression field.
const COMPRESSION_MASK_SHIFTED: u64 = 0x1f;

/// Shift for compression field.
const COMPRESSION_SHIFT: u64 = 32;

////////////////////////////////////////////////////////////////////////////////

/// Shift for checksum field.
const CHECKSUM_SHIFT: u64 = 40;

////////////////////////////////////////////////////////////////////////////////

/// Shift for DMU field.
const DMU_SHIFT: u64 = 48;

////////////////////////////////////////////////////////////////////////////////

/// Mask for shifted level field.
const LEVEL_MASK_SHIFTED: u64 = 0x1f;

/// Shift for level field.
const LEVEL_SHIFT: u64 = 56;

////////////////////////////////////////////////////////////////////////////////

/// Mask for embedded flag bit.
const EMBEDDED_FLAG_MASK: u64 = 1 << 39;

/// Mask for encrypted flag bit.
const ENCRYPTED_FLAG_MASK: u64 = 1 << 61;

/// Mask for deduplication flag bit.
const DEDUP_FLAG_MASK: u64 = 1 << 62;

/// Mask for little endian flag bit.
const LITTLE_ENDIAN_FLAG_MASK: u64 = 1 << 63;

////////////////////////////////////////////////////////////////////////////////

/// Mask for [`BlockPointerEmbedded`] logical size.
const EMBEDDED_LOGICAL_SIZE_MASK: u64 = 0x1ffffff;

/// Mask for [`BlockPointerEmbedded`] shifted physical size.
const EMBEDDED_PHYSICAL_SIZE_MASK_SHIFTED: u64 = 0x7f;

/// Shift for [`BlockPointerEmbedded`] physical size.
const EMBEDDED_PHYSICAL_SIZE_SHIFT: u64 = 25;

////////////////////////////////////////////////////////////////////////////////

/// Mask for [`BlockPointerEncrypted`] logical sectors.
const ENCRYPTED_LOGICAL_SECTORS_MASK: u64 = 0xffff;

/// Mask for [`BlockPointerEncrypted`] shifted physical sectors.
const ENCRYPTED_PHYSICAL_SECTORS_MASK_SHIFTED: u64 = 0xffff;

/// Shift for [`BlockPointerEncrypted`] physical sectors.
const ENCRYPTED_PHYSICAL_SECTORS_SHIFT: u64 = 16;

/// Shift for [`BlockPointerEncrypted`] iv 2.
const ENCRYPTED_IV_2_SHIFT: u64 = 32;

/// Mask for [`BlockPointerEncrypted`] fill count.
const ENCRYPTED_IV_FILL_MASK: u64 = 0xffffffff;

////////////////////////////////////////////////////////////////////////////////

/// Mask for [`BlockPointerRegular`] logical sectors.
const REGULAR_LOGICAL_SECTORS_MASK: u64 = 0xffff;

/// Mask for [`BlockPointerRegular`] shifted physical sectors.
const REGULAR_PHYSICAL_SECTORS_MASK_SHIFTED: u64 = 0xffff;

/// Shift for [`BlockPointerRegular`] physical sectors.
const REGULAR_PHYSICAL_SECTORS_SHIFT: u64 = 16;

////////////////////////////////////////////////////////////////////////////////

/** Block pointer.
 *
 * - Bytes: 128
 */
#[derive(Debug)]
pub enum BlockPointer {
    /// Block pointer with embedded payload.
    Embedded(BlockPointerEmbedded),

    /// Block pointer with encrypted data.
    Encrypted(BlockPointerEncrypted),

    /// Block pointer with plaintext data.
    Regular(BlockPointerRegular),
}

impl BlockPointer {
    /// Byte size of an encoded [`BlockPointer`] (128).
    pub const SIZE: usize = (3 * Dva::SIZE) + 48 + ChecksumValue::SIZE;

    /// Maximimum number of logical sectors (16 bits + 1).
    pub const LOGICAL_SECTORS_MAX: u32 = 0xffff + 1;

    /// Maximimum number of physical sectors (16 bits + 1).
    pub const PHYSICAL_SECTORS_MAX: u32 = 0xffff + 1;

    /** Decodes a [`BlockPointer`]. Returns [`None`] if [`BlockPointer`] is empty.
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or block pointer is malformed.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<Option<BlockPointer>, BlockPointerDecodeError> {
        ////////////////////////////////
        // Check for an empty BlockPointer.
        if decoder.is_zero_skip(BlockPointer::SIZE)? {
            return Ok(None);
        }

        ////////////////////////////////
        // Peek at flags, and rewind position back to DVA.
        let offset = decoder.offset();
        decoder.skip(3 * Dva::SIZE)?;
        let flags = decoder.get_u64()?;
        decoder.seek(offset)?;

        ////////////////////////////////
        // Decode encrypted and embedded.
        let embedded = (flags & EMBEDDED_FLAG_MASK) != 0;
        let encrypted = (flags & ENCRYPTED_FLAG_MASK) != 0;

        ////////////////////////////////
        // Decode based on combination.
        match (embedded, encrypted) {
            (false, false) => Ok(Some(BlockPointer::Regular(
                BlockPointerRegular::from_decoder(decoder)?,
            ))),
            (false, true) => Ok(Some(BlockPointer::Encrypted(
                BlockPointerEncrypted::from_decoder(decoder)?,
            ))),
            (true, false) => Ok(Some(BlockPointer::Embedded(
                BlockPointerEmbedded::from_decoder(decoder)?,
            ))),
            (true, true) => Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            }),
        }
    }

    /** Encodes a non-empty [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        match self {
            BlockPointer::Embedded(ptr) => ptr.to_encoder(encoder),
            BlockPointer::Encrypted(ptr) => ptr.to_encoder(encoder),
            BlockPointer::Regular(ptr) => ptr.to_encoder(encoder),
        }
    }

    /** Encodes an empty [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space.
     */
    pub fn empty_to_encoder(
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        Ok(encoder.put_zero_padding(BlockPointer::SIZE)?)
    }

    /** Encodes an `[Option<BlockPointer>`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn option_to_encoder(
        ptr: &Option<BlockPointer>,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        match ptr {
            Some(v) => v.to_encoder(encoder),
            None => Ok(BlockPointer::empty_to_encoder(encoder)?),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Embedded block pointer.
 *
 * - Version 5000, com.delphix:embedded_data
 *
 * ```text
 * +-------------------+------+
 * | Field             | Size |
 * +-------------------+------+
 * | payload           |   48 |
 * +-------------------+------+
 * | flags             |    8 |
 * +-------------------+------+
 * | payload           |   24 |
 * +-------------------+------+
 * | logical birth txg |    8 |
 * +-------------------+------+
 * | payload           |   40 |
 * +-------------------+------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                      payload[0..48] (384)                                                     |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  emb type (8) |e|   comp (7)  |   phys (7)  |                logical size (25)                |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                     payload[48..72] (192)                                                     |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                     payload[72.112] (320)                                                     |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b byte order (0: big, 1: little)
 * d dedup      (0)
 * x encryption (0)
 * e embedded   (1)
 *
 * etype    BlockPointerEmbeddedType
 * physical size in bytes
 * logical  size in bytes
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerEmbedded {
    /// Compression type for payload.
    pub compression: CompressionType,

    /// ???
    pub dmu: DmuType,

    /// ???
    pub embedded_type: BlockPointerEmbeddedType,

    /// Endian encoding of payload.
    pub order: EndianOrder,

    /// ???
    pub level: u8,

    /// ???
    pub logical_birth_txg: u64,

    /** Logical (decompressed) size in bytes.
     *
     * Maximum is [`BlockPointerEmbedded::LOGICAL_SIZE_MAX`].
     */
    pub logical_size: usize,

    /** Physical (compressed) size in bytes.
     *
     * Maximum is [`BlockPointerEmbedded::PHYSICAL_SIZE_MAX`].
     */
    pub physical_size: usize,

    /// Physical payload.
    pub payload: [u8; BlockPointerEmbedded::PHYSICAL_SIZE_MAX],
}

////////////////////////////////////////////////////////////////////////////////

/// [`BlockPointerEmbedded`] type.
#[derive(Clone, Copy, Debug)]
pub enum BlockPointerEmbeddedType {
    /// TODO: Document.
    Data = 0,

    /// TODO: Document.
    Reserved = 1,

    /// TODO: Document.
    Redacted = 2,
}

impl Display for BlockPointerEmbeddedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerEmbeddedType::Data => write!(f, "Data"),
            BlockPointerEmbeddedType::Reserved => write!(f, "Reserved"),
            BlockPointerEmbeddedType::Redacted => write!(f, "Redacted"),
        }
    }
}

impl From<BlockPointerEmbeddedType> for u8 {
    fn from(val: BlockPointerEmbeddedType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for BlockPointerEmbeddedType {
    type Error = BlockPointerEmbeddedTypeError;

    /** Try converting from a [`u8`] to a [`BlockPointerEmbeddedType`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEmbeddedTypeError`] in case of an invalid [`BlockPointerEmbeddedType`].
     */
    fn try_from(embedded_type: u8) -> Result<Self, Self::Error> {
        match embedded_type {
            0 => Ok(BlockPointerEmbeddedType::Data),
            1 => Ok(BlockPointerEmbeddedType::Reserved),
            2 => Ok(BlockPointerEmbeddedType::Redacted),
            _ => Err(BlockPointerEmbeddedTypeError::Unknown {
                value: embedded_type,
            }),
        }
    }
}

/// [`BlockPointerEmbeddedType`] conversion error.
#[derive(Debug)]
pub enum BlockPointerEmbeddedTypeError {
    /// Unknown [`BlockPointerEmbeddedType`].
    Unknown {
        /// Unknown value.
        value: u8,
    },
}

impl fmt::Display for BlockPointerEmbeddedTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerEmbeddedTypeError::Unknown { value } => {
                write!(f, "BlockPointerEmbeddedType unknown: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerEmbeddedTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

impl BlockPointerEmbedded {
    /// Maximum logical size in bytes of data embedded in pointer.
    pub const LOGICAL_SIZE_MAX: usize = (EMBEDDED_LOGICAL_SIZE_MASK as usize);

    /// Maximum payload length in bytes of data embedded in pointer.
    pub const PHYSICAL_SIZE_MAX: usize = 112;

    /** Decodes a [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<BlockPointerEmbedded, BlockPointerDecodeError> {
        let mut payload = [0; BlockPointerEmbedded::PHYSICAL_SIZE_MAX];

        ////////////////////////////////
        // Decode embedded payload (part 1).
        payload[0..48].copy_from_slice(decoder.get_bytes(48)?);

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;

        ////////////////////////////////
        // Decode embedded payload (part 2).
        payload[48..72].copy_from_slice(decoder.get_bytes(24)?);

        ////////////////////////////////
        // Decode logical birth transaction group.
        let logical_birth_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode embedded payload (part 3).
        payload[72..112].copy_from_slice(decoder.get_bytes(40)?);

        ////////////////////////////////
        // Decode encrypted and embedded.
        let embedded = (flags & EMBEDDED_FLAG_MASK) != 0;
        let encrypted = (flags & ENCRYPTED_FLAG_MASK) != 0;
        if (embedded, encrypted) != (true, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & DEDUP_FLAG_MASK) != 0;
        if dedup {
            return Err(BlockPointerDecodeError::InvalidDedupValue { dedup });
        }

        ////////////////////////////////
        // Decode endian.
        let order = (flags & LITTLE_ENDIAN_FLAG_MASK) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level = ((flags >> LEVEL_SHIFT) & LEVEL_MASK_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode embedded type.
        // NOTE(cybojanek): Use CHECKSUM_SHIFT, because embedded type uses
        //                  those bits, and checksum is already calculated by
        //                  parent pointer over this DVA.
        let embedded_type = (flags >> CHECKSUM_SHIFT) as u8;
        let embedded_type = BlockPointerEmbeddedType::try_from(embedded_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> COMPRESSION_SHIFT) & COMPRESSION_MASK_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes. Already in bytes.
        let logical_size = (flags & EMBEDDED_LOGICAL_SIZE_MASK) as u32;
        let logical_size = match usize::try_from(logical_size) {
            Ok(v) => v,
            Err(_) => return Err(BlockPointerDecodeError::LogicalSizeTooLarge { logical_size }),
        };

        let physical_size = usize::from(
            ((flags >> EMBEDDED_PHYSICAL_SIZE_SHIFT) & EMBEDDED_PHYSICAL_SIZE_MASK_SHIFTED) as u8,
        );

        ////////////////////////////////
        // Check that physical size is within embedded payload length.
        if physical_size > payload.len() {
            return Err(BlockPointerDecodeError::InvalidEmbeddedLength {
                length: physical_size,
            });
        }

        ////////////////////////////////
        // Success.
        Ok(BlockPointerEmbedded {
            compression,
            dmu,
            embedded_type,
            order,
            level,
            logical_birth_txg,
            logical_size,
            payload,
            physical_size,
        })
    }

    /** Encodes a [`BlockPointerEmbedded`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        ////////////////////////////////
        // Check physical size.
        if self.physical_size > self.payload.len() {
            return Err(BlockPointerEncodeError::InvalidEmbeddedLength {
                length: self.physical_size,
            });
        }

        ////////////////////////////////
        // Encode embedded payload (part 1).
        encoder.put_bytes(&self.payload[0..48])?;

        ////////////////////////////////
        // Encode flags.
        let level: u64 = self.level.into();
        if level > LEVEL_MASK_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let dmu: u8 = self.dmu.into();
        let embedded_type: u8 = self.embedded_type.into();
        let compression: u8 = self.compression.into();

        if self.logical_size > (EMBEDDED_LOGICAL_SIZE_MASK as usize) {
            return Err(BlockPointerEncodeError::InvalidLogicalSize {
                logical_size: self.logical_size,
            });
        }

        let flags = (self.logical_size as u64)
            | (self.physical_size as u64) << EMBEDDED_PHYSICAL_SIZE_SHIFT
            | u64::from(compression) << COMPRESSION_SHIFT
            | EMBEDDED_FLAG_MASK
            | u64::from(embedded_type) << CHECKSUM_SHIFT
            | u64::from(dmu) << DMU_SHIFT
            | level << LEVEL_SHIFT
            | match self.order {
                EndianOrder::Little => LITTLE_ENDIAN_FLAG_MASK,
                EndianOrder::Big => 0,
            };

        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode embedded payload (part 2).
        encoder.put_bytes(&self.payload[48..72])?;

        ////////////////////////////////
        // Encode logical birth transaction group.
        encoder.put_u64(self.logical_birth_txg)?;

        ////////////////////////////////
        // Encode embedded payload (part 3).
        encoder.put_bytes(&self.payload[72..112])?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Encrypted block pointer.
 *
 * - Version 5000, com.datto:encryption
 *
 * ```text
 * +--------------------+------+
 * | Field              | Size |
 * +--------------------+------+
 * | dva[0]             |   16 |
 * +--------------------+------+
 * | dva[1]             |   16 |
 * +--------------------+------+
 * | salt               |    8 |
 * +--------------------+------+
 * | iv1                |    8 |
 * +--------------------+------+
 * | flags              |    8 |
 * +--------------------+------+
 * | padding            |   16 |
 * +--------------------+------+
 * | physical birth txg |    8 |
 * +--------------------+------+
 * | logical birth txg  |    8 |
 * +--------------------+------+
 * | iv2 and fill_count |    8 |
 * +--------------------+------+
 * | checksum[0]        |    8 |
 * +--------------------+------+
 * | checksum[1]        |    8 |
 * +--------------------+------+
 * | mac[0]             |    8 |
 * +--------------------+------+
 * | mac[1]             |    8 |
 * +--------------------+------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[0] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[1] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           salt (64)                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                            iv1 (64)                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  checksum (8) |e|   comp (7)  |       physical size (16)      |       logical_size (16)       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         padding (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    physical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                            iv2 (32)                           |                        fill count (32)                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum[0] (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum[1] (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          mac[0] (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          mac[1] (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b byte order (0: big, 1: little)
 * d dedup      (0 or 1)
 * x encryption (1)
 * e embedded   (0)
 *
 * physical (size - 1) in 512 byte sectors
 * logical  (size - 1) in 512 byte sectors
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerEncrypted {
    /// Checksum type of payload.
    pub checksum_type: ChecksumType,

    /// Checksum value of payload. TODO: Explain truncation?
    pub checksum_value: [u64; 2],

    /// Compression type of payload.
    pub compression: CompressionType,

    /// ???
    pub dedup: bool,

    /// ???
    pub dmu: DmuType,

    /// Data virtual addresses.
    pub dvas: [Option<Dva>; 2],

    /// Endian of payload.
    pub order: EndianOrder,

    /// ???
    pub fill_count: u32,

    /// ???
    pub iv_1: u64,

    /// ???
    pub iv_2: u32,

    /// ???
    pub level: u8,

    /// ???
    pub logical_birth_txg: u64,

    /** Number of logical (decompressed) sectors.
     *
     * Maximum is [`BlockPointer::LOGICAL_SECTORS_MAX`].
     */
    pub logical_sectors: u32,

    /// ???
    pub mac: [u64; 2],

    /// ???
    pub physical_birth_txg: u64,

    /** Number of physical (compressed) sectors.
     *
     * Maximum is [`BlockPointer::PHYSICAL_SECTORS_MAX`].
     */
    pub physical_sectors: u32,

    /// ???
    pub salt: u64,
}

impl BlockPointerEncrypted {
    /** Decodes a [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<BlockPointerEncrypted, BlockPointerDecodeError> {
        ////////////////////////////////
        // Decode DVAs.
        let dvas = [Dva::from_decoder(decoder)?, Dva::from_decoder(decoder)?];

        ////////////////////////////////
        // Decode salt and iv (part 1).
        let salt = decoder.get_u64()?;
        let iv_1 = decoder.get_u64()?;

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;

        ////////////////////////////////
        // Decode encrypted and embedded.
        let embedded = (flags & EMBEDDED_FLAG_MASK) != 0;
        let encrypted = (flags & ENCRYPTED_FLAG_MASK) != 0;
        if (embedded, encrypted) != (false, true) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & DEDUP_FLAG_MASK) != 0;

        ////////////////////////////////
        // Decode endian.
        let order = (flags & LITTLE_ENDIAN_FLAG_MASK) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level = ((flags >> LEVEL_SHIFT) & LEVEL_MASK_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum_type = (flags >> CHECKSUM_SHIFT) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> COMPRESSION_SHIFT) & COMPRESSION_MASK_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes.
        let logical_sectors = ((flags & ENCRYPTED_LOGICAL_SECTORS_MASK) as u32) + 1;
        let physical_sectors = (((flags >> ENCRYPTED_PHYSICAL_SECTORS_SHIFT)
            & ENCRYPTED_PHYSICAL_SECTORS_MASK_SHIFTED) as u32)
            + 1;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(16)?;

        ////////////////////////////////
        // Decode TXGs.
        let physical_birth_txg = decoder.get_u64()?;
        let logical_birth_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode iv2 / fill count.
        let iv_fill = decoder.get_u64()?;
        let iv_2 = (iv_fill >> ENCRYPTED_IV_2_SHIFT) as u32;
        let fill_count = (iv_fill & ENCRYPTED_IV_FILL_MASK) as u32;

        ////////////////////////////////
        // Decode checksum value.
        let checksum_value = [decoder.get_u64()?, decoder.get_u64()?];

        ////////////////////////////////
        // Decode MAC.
        let mac = [decoder.get_u64()?, decoder.get_u64()?];

        ////////////////////////////////
        // Success.
        Ok(BlockPointerEncrypted {
            checksum_type,
            checksum_value,
            compression,
            dedup,
            dmu,
            dvas,
            order,
            fill_count,
            level,
            iv_1,
            iv_2,
            logical_birth_txg,
            logical_sectors,
            mac,
            physical_birth_txg,
            physical_sectors,
            salt,
        })
    }

    /** Encodes a [`BlockPointerEncrypted`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        ////////////////////////////////
        // Encode DVAs.
        for dva in &self.dvas {
            match dva {
                Some(v) => v.to_encoder(encoder)?,
                None => Dva::empty_to_encoder(encoder)?,
            }
        }

        ////////////////////////////////
        // Check sectors.
        if self.logical_sectors < 1 || self.logical_sectors > BlockPointer::LOGICAL_SECTORS_MAX {
            return Err(BlockPointerEncodeError::InvalidLogicalSectors {
                sectors: self.logical_sectors,
            });
        }

        if self.physical_sectors < 1 || self.physical_sectors > BlockPointer::PHYSICAL_SECTORS_MAX {
            return Err(BlockPointerEncodeError::InvalidPhysicalSectors {
                sectors: self.physical_sectors,
            });
        }

        ////////////////////////////////
        // Encode salt and iv1.
        encoder.put_u64(self.salt)?;
        encoder.put_u64(self.iv_1)?;

        ////////////////////////////////
        // Encode flags.
        let level: u64 = self.level.into();
        if level > LEVEL_MASK_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let checksum: u8 = self.checksum_type.into();
        let dmu: u8 = self.dmu.into();
        let compression: u8 = self.compression.into();

        let flags = u64::from(self.logical_sectors - 1)
            | u64::from(self.physical_sectors - 1) << ENCRYPTED_PHYSICAL_SECTORS_SHIFT
            | u64::from(compression) << COMPRESSION_SHIFT
            | u64::from(checksum) << CHECKSUM_SHIFT
            | u64::from(dmu) << DMU_SHIFT
            | level << LEVEL_SHIFT
            | ENCRYPTED_FLAG_MASK
            | if self.dedup { DEDUP_FLAG_MASK } else { 0 }
            | match self.order {
                EndianOrder::Little => LITTLE_ENDIAN_FLAG_MASK,
                EndianOrder::Big => 0,
            };

        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(16)?;

        ////////////////////////////////
        // Encode TXGs.
        encoder.put_u64(self.physical_birth_txg)?;
        encoder.put_u64(self.logical_birth_txg)?;

        ////////////////////////////////
        // Encode iv2 / fill count.
        encoder
            .put_u64(u64::from(self.fill_count) | u64::from(self.iv_2) << ENCRYPTED_IV_2_SHIFT)?;

        ////////////////////////////////
        // Encode checksum value.
        for checksum in self.checksum_value {
            encoder.put_u64(checksum)?;
        }

        ////////////////////////////////
        // Encode mac.
        for mac in self.mac {
            encoder.put_u64(mac)?;
        }

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Regular block pointer.
 *
 * - Version 21, dedup
 *
 * ```text
 * +--------------------+------+
 * | Field              | Size |
 * +--------------------+------+
 * | dva[0]             |   16 |
 * +--------------------+------+
 * | dva[1]             |   16 |
 * +--------------------+------+
 * | dva[2]             |   16 |
 * +--------------------+------+
 * | flags              |    8 |
 * +--------------------+------+
 * | padding            |   16 |
 * +--------------------+------+
 * | physical birth txg |    8 |
 * +--------------------+------+
 * | logical birth txg  |    8 |
 * +--------------------+------+
 * | fill count         |    8 |
 * +--------------------+------+
 * | checksum           |   32 |
 * +--------------------+------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[0] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[1] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[2] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  checksum (8) |e|   comp (7)  |       physical size (16)      |       logical_size (16)       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         padding (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    physical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        fill count (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                         checksum (256)                                                        |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b byte order (0: big, 1: little)
 * d dedup      (0 or 1)
 * x encryption (0)
 * e embedded   (0)
 *
 * physical (size - 1) in 512 byte sectors
 * logical  (size - 1) in 512 byte sectors
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerRegular {
    /// Checksum type of payload.
    pub checksum_type: ChecksumType,

    /// Checksum value of payload.
    pub checksum_value: ChecksumValue,

    /// Compression type of payload.
    pub compression: CompressionType,

    /// ???
    pub dedup: bool,

    /// ???
    pub dmu: DmuType,

    /// Data virtual addresses.
    pub dvas: [Option<Dva>; 3],

    /// Endian of payload.
    pub order: EndianOrder,

    /// ???
    pub fill_count: u64,

    /// ???
    pub level: u8,

    /// ???
    pub logical_birth_txg: u64,

    /** Number of logical (decompressed) sectors.
     *
     * Maximum is [`BlockPointer::LOGICAL_SECTORS_MAX`].
     */
    pub logical_sectors: u32,

    /// ???
    pub physical_birth_txg: u64,

    /** Number of physical (compressed) sectors.
     *
     * Maximum is [`BlockPointer::PHYSICAL_SECTORS_MAX`].
     */
    pub physical_sectors: u32,
}

impl BlockPointerRegular {
    /** Decodes a [`BlockPointerRegular`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<BlockPointerRegular, BlockPointerDecodeError> {
        ////////////////////////////////
        // Decode DVAs.
        let dvas = [
            Dva::from_decoder(decoder)?,
            Dva::from_decoder(decoder)?,
            Dva::from_decoder(decoder)?,
        ];

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;

        ////////////////////////////////
        // Decode encrypted and embedded.
        let embedded = (flags & EMBEDDED_FLAG_MASK) != 0;
        let encrypted = (flags & ENCRYPTED_FLAG_MASK) != 0;
        if (embedded, encrypted) != (false, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & (DEDUP_FLAG_MASK)) != 0;

        ////////////////////////////////
        // Decode endian.
        let order = (flags & LITTLE_ENDIAN_FLAG_MASK) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level = ((flags >> LEVEL_SHIFT) & LEVEL_MASK_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum_type = (flags >> CHECKSUM_SHIFT) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> COMPRESSION_SHIFT) & COMPRESSION_MASK_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes.
        let logical_sectors = ((flags & REGULAR_LOGICAL_SECTORS_MASK) as u32) + 1;
        let physical_sectors = (((flags >> REGULAR_PHYSICAL_SECTORS_SHIFT)
            & REGULAR_PHYSICAL_SECTORS_MASK_SHIFTED) as u32)
            + 1;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(16)?;

        ////////////////////////////////
        // Decode TXGs.
        let physical_birth_txg = decoder.get_u64()?;
        let logical_birth_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode fill count.
        let fill_count = decoder.get_u64()?;

        ////////////////////////////////
        // Decocde checksum value.
        let checksum_value = ChecksumValue::from_decoder(decoder)?;

        ////////////////////////////////
        // Success.
        Ok(BlockPointerRegular {
            checksum_type,
            checksum_value,
            compression,
            dedup,
            dmu,
            dvas,
            order,
            fill_count,
            level,
            logical_birth_txg,
            logical_sectors,
            physical_birth_txg,
            physical_sectors,
        })
    }

    /** Encodes a [`BlockPointerRegular`].
     *
     * # Errors
     *
     * Returns [`BlockPointerEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerEncodeError> {
        // TODO: Check dva sectors are all the same?
        // TODO: Check at least one dva is present?
        // TODO: Check physical_sectors is <= dva.sectors?

        ////////////////////////////////
        // Encode DVAs.
        for dva in &self.dvas {
            match dva {
                Some(v) => v.to_encoder(encoder)?,
                None => Dva::empty_to_encoder(encoder)?,
            }
        }

        ////////////////////////////////
        // Check sectors.
        if self.logical_sectors < 1 || self.logical_sectors > BlockPointer::LOGICAL_SECTORS_MAX {
            return Err(BlockPointerEncodeError::InvalidLogicalSectors {
                sectors: self.logical_sectors,
            });
        }

        if self.physical_sectors < 1 || self.physical_sectors > BlockPointer::PHYSICAL_SECTORS_MAX {
            return Err(BlockPointerEncodeError::InvalidPhysicalSectors {
                sectors: self.physical_sectors,
            });
        }

        ////////////////////////////////
        // Encode flags.
        let level: u64 = self.level.into();
        if level > LEVEL_MASK_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let checksum: u8 = self.checksum_type.into();
        let dmu: u8 = self.dmu.into();
        let compression: u8 = self.compression.into();

        let flags = u64::from(self.logical_sectors - 1)
            | u64::from(self.physical_sectors - 1) << REGULAR_PHYSICAL_SECTORS_SHIFT
            | u64::from(compression) << COMPRESSION_SHIFT
            | u64::from(checksum) << CHECKSUM_SHIFT
            | u64::from(dmu) << DMU_SHIFT
            | level << LEVEL_SHIFT
            | if self.dedup { DEDUP_FLAG_MASK } else { 0 }
            | match self.order {
                EndianOrder::Little => LITTLE_ENDIAN_FLAG_MASK,
                EndianOrder::Big => 0,
            };

        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(16)?;

        ////////////////////////////////
        // Encode TXGs.
        encoder.put_u64(self.physical_birth_txg)?;
        encoder.put_u64(self.logical_birth_txg)?;

        ////////////////////////////////
        // Encode fill count.
        encoder.put_u64(self.fill_count)?;

        ////////////////////////////////
        // Encode checksum.
        self.checksum_value.to_encoder(encoder)?;

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`BlockPointer`] decode error.
#[derive(Debug)]
pub enum BlockPointerDecodeError {
    /// [`BlockPointerEmbeddedType`] decode error.
    BlockPointerEmbeddedType {
        /// Error.
        err: BlockPointerEmbeddedTypeError,
    },

    /// Invalid [`ChecksumType`].
    ChecksumType {
        /// Error.
        err: ChecksumTypeError,
    },

    /// [`ChecksumValue`] decode error.
    ChecksumValue {
        /// Error.
        err: ChecksumValueDecodeError,
    },

    /// Invalid [`CompressionType`].
    CompressionType {
        /// Error.
        err: CompressionTypeError,
    },

    /// Invalid [`DmuType`].
    DmuType {
        /// Error.
        err: DmuTypeError,
    },

    /// [`Dva`] decode error.
    Dva {
        /// Error.
        err: DvaDecodeError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid [`BlockPointer`] type.
    InvalidBlockPointerType {
        /// Is embedded.
        embedded: bool,
        /// Is encrypted.
        encrypted: bool,
    },

    /// Invalid Dedup value.
    InvalidDedupValue {
        /// Invalid dedup value.
        dedup: bool,
    },

    /// Invalid embedded length.
    InvalidEmbeddedLength {
        /// Invalid embedded length value.
        length: usize,
    },

    /// Invalid embedded type.
    InvalidEmbeddedType {
        /// Invalid embedded type value.
        embedded_type: u8,
    },

    /// Logical size is too large to fit in a [`usize`].
    LogicalSizeTooLarge {
        /// Invalid logical size value.
        logical_size: u32,
    },
}

impl From<BlockPointerEmbeddedTypeError> for BlockPointerDecodeError {
    fn from(value: BlockPointerEmbeddedTypeError) -> Self {
        BlockPointerDecodeError::BlockPointerEmbeddedType { err: value }
    }
}

impl From<ChecksumTypeError> for BlockPointerDecodeError {
    fn from(value: ChecksumTypeError) -> Self {
        BlockPointerDecodeError::ChecksumType { err: value }
    }
}

impl From<ChecksumValueDecodeError> for BlockPointerDecodeError {
    fn from(value: ChecksumValueDecodeError) -> Self {
        BlockPointerDecodeError::ChecksumValue { err: value }
    }
}

impl From<CompressionTypeError> for BlockPointerDecodeError {
    fn from(value: CompressionTypeError) -> Self {
        BlockPointerDecodeError::CompressionType { err: value }
    }
}

impl From<DmuTypeError> for BlockPointerDecodeError {
    fn from(value: DmuTypeError) -> Self {
        BlockPointerDecodeError::DmuType { err: value }
    }
}

impl From<DvaDecodeError> for BlockPointerDecodeError {
    fn from(value: DvaDecodeError) -> Self {
        BlockPointerDecodeError::Dva { err: value }
    }
}

impl From<EndianDecodeError> for BlockPointerDecodeError {
    fn from(value: EndianDecodeError) -> Self {
        BlockPointerDecodeError::Endian { err: value }
    }
}

impl fmt::Display for BlockPointerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerDecodeError::BlockPointerEmbeddedType { err } => {
                write!(f, "BlockPointer decode error, embedded type: [{err}]")
            }
            BlockPointerDecodeError::ChecksumType { err } => {
                write!(f, "BlockPointer decode error, checksum type: [{err}]")
            }
            BlockPointerDecodeError::ChecksumValue { err } => {
                write!(f, "BlockPointer decode error, checksum value: [{err}]")
            }
            BlockPointerDecodeError::CompressionType { err } => {
                write!(f, "BlockPointer decode error, compression type: [{err}]")
            }
            BlockPointerDecodeError::DmuType { err } => {
                write!(f, "BlockPointer decode error, DMU type: [{err}]")
            }
            BlockPointerDecodeError::Dva { err } => {
                write!(f, "BlockPointer decode error, DVA: [{err}]")
            }
            BlockPointerDecodeError::Endian { err } => {
                write!(f, "BlockPointer decode error, endian: [{err}]")
            }
            BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            } => {
                write!(
                    f,
                    "BlockPointer decode error, invalid embedded: {embedded}, encrypted: {encrypted}"
                )
            }
            BlockPointerDecodeError::InvalidDedupValue { dedup } => {
                write!(f, "BlockPointer decode error, invalid dedup value: {dedup}")
            }
            BlockPointerDecodeError::InvalidEmbeddedLength { length } => {
                write!(
                    f,
                    "BlockPointer decode error, invalid embdedded length: {length}"
                )
            }
            BlockPointerDecodeError::InvalidEmbeddedType { embedded_type } => {
                write!(
                    f,
                    "BlockPointer decode error, invalid embdedded type: {embedded_type}"
                )
            }
            BlockPointerDecodeError::LogicalSizeTooLarge { logical_size } => {
                write!(
                    f,
                    "BlockPointer decode error, logical size too bit for usize: {logical_size}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockPointerDecodeError::BlockPointerEmbeddedType { err } => Some(err),
            BlockPointerDecodeError::ChecksumType { err } => Some(err),
            BlockPointerDecodeError::ChecksumValue { err } => Some(err),
            BlockPointerDecodeError::CompressionType { err } => Some(err),
            BlockPointerDecodeError::DmuType { err } => Some(err),
            BlockPointerDecodeError::Dva { err } => Some(err),
            BlockPointerDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`BlockPointer`] encode error.
#[derive(Debug)]
pub enum BlockPointerEncodeError {
    /// [`ChecksumValue`] encode error.
    ChecksumValue {
        /// Error.
        err: ChecksumValueEncodeError,
    },

    /// [`Dva`] encode error.
    Dva {
        /// Error.
        err: DvaEncodeError,
    },

    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Invalid embedded length.
    InvalidEmbeddedLength {
        /// Invalid embedded length value.
        length: usize,
    },

    /// Invalid level.
    InvalidLevel {
        /// Invalid level value.
        level: u8,
    },

    /// Invalid logical sectors.
    InvalidLogicalSectors {
        /// Invalid logical sectors value.
        sectors: u32,
    },

    /// Invalid logical size.
    InvalidLogicalSize {
        /// Invalid logical size value.
        logical_size: usize,
    },

    /// Invalid physical sectors.
    InvalidPhysicalSectors {
        /// Invalid physical sectors value.
        sectors: u32,
    },
}

impl From<ChecksumValueEncodeError> for BlockPointerEncodeError {
    fn from(value: ChecksumValueEncodeError) -> Self {
        BlockPointerEncodeError::ChecksumValue { err: value }
    }
}

impl From<DvaEncodeError> for BlockPointerEncodeError {
    fn from(value: DvaEncodeError) -> Self {
        BlockPointerEncodeError::Dva { err: value }
    }
}

impl From<EndianEncodeError> for BlockPointerEncodeError {
    fn from(value: EndianEncodeError) -> Self {
        BlockPointerEncodeError::Endian { err: value }
    }
}

impl fmt::Display for BlockPointerEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerEncodeError::ChecksumValue { err } => {
                write!(f, "BlockPointer encode error, checksum value: [{err}]")
            }
            BlockPointerEncodeError::Dva { err } => {
                write!(f, "BlockPointer encode error, DVA: [{err}]")
            }
            BlockPointerEncodeError::Endian { err } => {
                write!(f, "BlockPointer encode error, endian: [{err}]")
            }
            BlockPointerEncodeError::InvalidEmbeddedLength { length } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid embdedded length: {length}"
                )
            }
            BlockPointerEncodeError::InvalidLevel { level } => {
                write!(f, "BlockPointer encode error, invalid level: {level}")
            }
            BlockPointerEncodeError::InvalidLogicalSectors { sectors } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid logical sectors: {sectors}"
                )
            }
            BlockPointerEncodeError::InvalidLogicalSize { logical_size } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid logical size: {logical_size}"
                )
            }
            BlockPointerEncodeError::InvalidPhysicalSectors { sectors } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid physical sectors: {sectors}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockPointerEncodeError::ChecksumValue { err } => Some(err),
            BlockPointerEncodeError::Dva { err } => Some(err),
            BlockPointerEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}
