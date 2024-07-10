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
    pub const LOGICAL_SECTORS_MAX: u32 = 1 << 16;

    /// Maximimum number of physical sectors (16 bits + 1).
    pub const PHYSICAL_SECTORS_MAX: u32 = 1 << 16;

    /// Mask for down shifted compression field.
    const COMPRESSION_MASK_DOWN_SHIFTED: u64 = 0x1f;

    /// Shift for compression field.
    const COMPRESSION_SHIFT: u64 = 32;

    /// Shift for checksum field.
    const CHECKSUM_SHIFT: u64 = 40;

    /// Shift for DMU field.
    const DMU_SHIFT: u64 = 48;

    /// Mask for down shifted level field.
    const LEVEL_MASK_DOWN_SHIFTED: u64 = 0x1f;

    /// Shift for level field.
    const LEVEL_SHIFT: u64 = 56;

    /// Mask for embedded flag bit.
    const EMBEDDED_BIT_FLAG: u64 = 1 << 39;

    /// Mask for encrypted flag bit.
    const ENCRYPTED_BIT_FLAG: u64 = 1 << 61;

    /// Mask for deduplication flag bit.
    const DEDUP_BIT_FLAG: u64 = 1 << 62;

    /// Mask for little endian flag bit.
    const LITTLE_ENDIAN_BIT_FLAG: u64 = 1 << 63;

    /** Decodes a [`BlockPointer`]. Returns [`None`] if [`BlockPointer`] is empty.
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] on error.
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
        let embedded = (flags & BlockPointer::EMBEDDED_BIT_FLAG) != 0;
        let encrypted = (flags & BlockPointer::ENCRYPTED_BIT_FLAG) != 0;

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
     * Returns [`BlockPointerEncodeError`] on error.
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
     * Returns [`BlockPointerEncodeError`] on error.
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
     * Returns [`BlockPointerEncodeError`] on error.
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

    /// Gets the [`EndianOrder`] of the [`BlockPointer`].
    pub fn order(&self) -> EndianOrder {
        match self {
            BlockPointer::Embedded(ptr) => ptr.order,
            BlockPointer::Encrypted(ptr) => ptr.order,
            BlockPointer::Regular(ptr) => ptr.order,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Embedded block pointer.
 *
 * - SPA Version 5000, feature com.delphix:embedded_data
 *
 * ```text
 * +-------------------+------+
 * | Field             | Size |
 * +-------------------+------+
 * | payload           |   48 |
 * | flags             |    8 |
 * | payload           |   24 |
 * | logical birth txg |    8 |
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
     * Returns [`BlockPointerEmbeddedTypeError`] in case of an unknown [`BlockPointerEmbeddedType`].
     */
    fn try_from(embedded_type: u8) -> Result<Self, Self::Error> {
        match embedded_type {
            0 => Ok(BlockPointerEmbeddedType::Data),
            1 => Ok(BlockPointerEmbeddedType::Reserved),
            2 => Ok(BlockPointerEmbeddedType::Redacted),
            _ => Err(BlockPointerEmbeddedTypeError::Unknown { embedded_type }),
        }
    }
}

/// [`BlockPointerEmbeddedType`] conversion error.
#[derive(Debug)]
pub enum BlockPointerEmbeddedTypeError {
    /// Unknown [`BlockPointerEmbeddedType`].
    Unknown {
        /// Unknown embedded type.
        embedded_type: u8,
    },
}

impl fmt::Display for BlockPointerEmbeddedTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerEmbeddedTypeError::Unknown { embedded_type } => {
                write!(f, "Unknown BlockPointerEmbeddedType {embedded_type}")
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
    pub const LOGICAL_SIZE_MAX: usize = (BlockPointerEmbedded::LOGICAL_SIZE_MASK as usize);

    /// Maximum payload length in bytes of data embedded in pointer.
    pub const PHYSICAL_SIZE_MAX: usize = 112;

    /// Mask for [`BlockPointerEmbedded`] logical size.
    const LOGICAL_SIZE_MASK: u64 = (1 << 25) - 1;

    /// Mask for [`BlockPointerEmbedded`] shifted physical size.
    const PHYSICAL_SIZE_MASK_DOWN_SHIFTED: u64 = 0x7f;

    /// Shift for [`BlockPointerEmbedded`] physical size.
    const PHYSICAL_SIZE_SHIFT: u64 = 25;

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
        let part_1 = &mut payload[0..48];
        part_1.copy_from_slice(decoder.get_bytes(part_1.len())?);

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;

        ////////////////////////////////
        // Decode embedded payload (part 2).
        let part_2 = &mut payload[48..72];
        part_2.copy_from_slice(decoder.get_bytes(part_2.len())?);

        ////////////////////////////////
        // Decode logical birth transaction group.
        let logical_birth_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode embedded payload (part 3).
        let part_3 = &mut payload[72..112];
        part_3.copy_from_slice(decoder.get_bytes(part_3.len())?);

        ////////////////////////////////
        // Decode encrypted and embedded.
        let embedded = (flags & BlockPointer::EMBEDDED_BIT_FLAG) != 0;
        let encrypted = (flags & BlockPointer::ENCRYPTED_BIT_FLAG) != 0;
        if (embedded, encrypted) != (true, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & BlockPointer::DEDUP_BIT_FLAG) != 0;
        if dedup {
            return Err(BlockPointerDecodeError::InvalidDedupValue { dedup });
        }

        ////////////////////////////////
        // Decode endian.
        let order = (flags & BlockPointer::LITTLE_ENDIAN_BIT_FLAG) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level =
            ((flags >> BlockPointer::LEVEL_SHIFT) & BlockPointer::LEVEL_MASK_DOWN_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> BlockPointer::DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode embedded type.
        // NOTE(cybojanek): Use CHECKSUM_SHIFT, because embedded type uses
        //                  those bits, and checksum is already calculated by
        //                  parent pointer over this DVA.
        let embedded_type = (flags >> BlockPointer::CHECKSUM_SHIFT) as u8;
        let embedded_type = BlockPointerEmbeddedType::try_from(embedded_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> BlockPointer::COMPRESSION_SHIFT)
            & BlockPointer::COMPRESSION_MASK_DOWN_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes. Already in bytes.
        let logical_size = (flags & BlockPointerEmbedded::LOGICAL_SIZE_MASK) as u32;
        let logical_size = match usize::try_from(logical_size) {
            Ok(v) => v,
            Err(_) => return Err(BlockPointerDecodeError::LogicalSizeTooLarge { logical_size }),
        };

        let physical_size = usize::from(
            ((flags >> BlockPointerEmbedded::PHYSICAL_SIZE_SHIFT)
                & BlockPointerEmbedded::PHYSICAL_SIZE_MASK_DOWN_SHIFTED) as u8,
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
     * Returns [`BlockPointerEncodeError`] on error.
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
        if level > BlockPointer::LEVEL_MASK_DOWN_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let dmu: u8 = self.dmu.into();
        let embedded_type: u8 = self.embedded_type.into();
        let compression: u8 = self.compression.into();

        if self.logical_size > (BlockPointerEmbedded::LOGICAL_SIZE_MASK as usize) {
            return Err(BlockPointerEncodeError::InvalidLogicalSize {
                logical_size: self.logical_size,
            });
        }

        let flags = (self.logical_size as u64)
            | (self.physical_size as u64) << BlockPointerEmbedded::PHYSICAL_SIZE_SHIFT
            | u64::from(compression) << BlockPointer::COMPRESSION_SHIFT
            | BlockPointer::EMBEDDED_BIT_FLAG
            | u64::from(embedded_type) << BlockPointer::CHECKSUM_SHIFT
            | u64::from(dmu) << BlockPointer::DMU_SHIFT
            | level << BlockPointer::LEVEL_SHIFT
            | match self.order {
                EndianOrder::Little => BlockPointer::LITTLE_ENDIAN_BIT_FLAG,
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
 * - SPA Version 5000, feature com.datto:encryption
 *
 * ```text
 * +--------------------+------+
 * | Field              | Size |
 * +--------------------+------+
 * | dva[0]             |   16 |
 * | dva[1]             |   16 |
 * | salt               |    8 |
 * | iv1                |    8 |
 * | flags              |    8 |
 * | padding            |   16 |
 * | physical birth txg |    8 |
 * | logical birth txg  |    8 |
 * | iv2 and fill_count |    8 |
 * | checksum[0]        |    8 |
 * | checksum[1]        |    8 |
 * | mac[0]             |    8 |
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
    /// Padding byte size.
    const PADDING_SIZE: usize = 16;

    /// Mask for [`BlockPointerEncrypted`] logical sectors.
    const LOGICAL_SECTORS_MASK: u64 = (1 << 16) - 1;

    /// Mask for [`BlockPointerEncrypted`] shifted physical sectors.
    const PHYSICAL_SECTORS_MASK_DOWN_SHIFTED: u64 = (1 << 16) - 1;

    /// Shift for [`BlockPointerEncrypted`] physical sectors.
    const PHYSICAL_SECTORS_SHIFT: u64 = 16;

    /// Shift for [`BlockPointerEncrypted`] iv 2.
    const IV_2_SHIFT: u64 = 32;

    /// Mask for [`BlockPointerEncrypted`] fill count.
    const IV_FILL_MASK: u64 = (1 << 32) - 1;

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
        let embedded = (flags & BlockPointer::EMBEDDED_BIT_FLAG) != 0;
        let encrypted = (flags & BlockPointer::ENCRYPTED_BIT_FLAG) != 0;
        if (embedded, encrypted) != (false, true) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & BlockPointer::DEDUP_BIT_FLAG) != 0;

        ////////////////////////////////
        // Decode endian.
        let order = (flags & BlockPointer::LITTLE_ENDIAN_BIT_FLAG) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level =
            ((flags >> BlockPointer::LEVEL_SHIFT) & BlockPointer::LEVEL_MASK_DOWN_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> BlockPointer::DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum_type = (flags >> BlockPointer::CHECKSUM_SHIFT) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> BlockPointer::COMPRESSION_SHIFT)
            & BlockPointer::COMPRESSION_MASK_DOWN_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes.
        let logical_sectors = ((flags & BlockPointerEncrypted::LOGICAL_SECTORS_MASK) as u32) + 1;
        let physical_sectors = (((flags >> BlockPointerEncrypted::PHYSICAL_SECTORS_SHIFT)
            & BlockPointerEncrypted::PHYSICAL_SECTORS_MASK_DOWN_SHIFTED)
            as u32)
            + 1;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(BlockPointerEncrypted::PADDING_SIZE)?;

        ////////////////////////////////
        // Decode TXGs.
        let physical_birth_txg = decoder.get_u64()?;
        let logical_birth_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode iv2 / fill count.
        let iv_fill = decoder.get_u64()?;
        let iv_2 = (iv_fill >> BlockPointerEncrypted::IV_2_SHIFT) as u32;
        let fill_count = (iv_fill & BlockPointerEncrypted::IV_FILL_MASK) as u32;

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
     * Returns [`BlockPointerEncodeError`] on error.
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
        if level > BlockPointer::LEVEL_MASK_DOWN_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let checksum: u8 = self.checksum_type.into();
        let dmu: u8 = self.dmu.into();
        let compression: u8 = self.compression.into();

        let flags = u64::from(self.logical_sectors - 1)
            | u64::from(self.physical_sectors - 1) << BlockPointerEncrypted::PHYSICAL_SECTORS_SHIFT
            | u64::from(compression) << BlockPointer::COMPRESSION_SHIFT
            | u64::from(checksum) << BlockPointer::CHECKSUM_SHIFT
            | u64::from(dmu) << BlockPointer::DMU_SHIFT
            | level << BlockPointer::LEVEL_SHIFT
            | BlockPointer::ENCRYPTED_BIT_FLAG
            | if self.dedup {
                BlockPointer::DEDUP_BIT_FLAG
            } else {
                0
            }
            | match self.order {
                EndianOrder::Little => BlockPointer::LITTLE_ENDIAN_BIT_FLAG,
                EndianOrder::Big => 0,
            };

        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(BlockPointerEncrypted::PADDING_SIZE)?;

        ////////////////////////////////
        // Encode TXGs.
        encoder.put_u64(self.physical_birth_txg)?;
        encoder.put_u64(self.logical_birth_txg)?;

        ////////////////////////////////
        // Encode iv2 / fill count.
        encoder.put_u64(
            u64::from(self.fill_count) | u64::from(self.iv_2) << BlockPointerEncrypted::IV_2_SHIFT,
        )?;

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
 * - SPA Version 21, dedup
 *
 * ```text
 * +--------------------+------+
 * | Field              | Size |
 * +--------------------+------+
 * | dva[0]             |   16 |
 * | dva[1]             |   16 |
 * | dva[2]             |   16 |
 * | flags              |    8 |
 * | padding            |   16 |
 * | physical birth txg |    8 |
 * | logical birth txg  |    8 |
 * | fill count         |    8 |
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
    /// Padding byte size.
    const PADDING_SIZE: usize = 16;

    /// Mask for logical sectors.
    const LOGICAL_SECTORS_MASK: u64 = (1 << 16) - 1;

    /// Mask for shifted physical sectors.
    const PHYSICAL_SECTORS_MASK_DOWN_SHIFTED: u64 = (1 << 16) - 1;

    /// Shift for physical sectors.
    const PHYSICAL_SECTORS_SHIFT: u64 = 16;

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
        let embedded = (flags & BlockPointer::EMBEDDED_BIT_FLAG) != 0;
        let encrypted = (flags & BlockPointer::ENCRYPTED_BIT_FLAG) != 0;
        if (embedded, encrypted) != (false, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            });
        }

        ////////////////////////////////
        // Decode dedup.
        let dedup = (flags & (BlockPointer::DEDUP_BIT_FLAG)) != 0;

        ////////////////////////////////
        // Decode endian.
        let order = (flags & BlockPointer::LITTLE_ENDIAN_BIT_FLAG) != 0;
        let order = match order {
            true => EndianOrder::Little,
            false => EndianOrder::Big,
        };

        ////////////////////////////////
        // Decode level.
        let level =
            ((flags >> BlockPointer::LEVEL_SHIFT) & BlockPointer::LEVEL_MASK_DOWN_SHIFTED) as u8;

        ////////////////////////////////
        // Decode DMU type.
        let dmu = (flags >> BlockPointer::DMU_SHIFT) as u8;
        let dmu = DmuType::try_from(dmu)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum_type = (flags >> BlockPointer::CHECKSUM_SHIFT) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        ////////////////////////////////
        // Decode compression type.
        let compression = ((flags >> BlockPointer::COMPRESSION_SHIFT)
            & BlockPointer::COMPRESSION_MASK_DOWN_SHIFTED) as u8;
        let compression = CompressionType::try_from(compression)?;

        ////////////////////////////////
        // Decode sizes.
        let logical_sectors = ((flags & BlockPointerRegular::LOGICAL_SECTORS_MASK) as u32) + 1;
        let physical_sectors = (((flags >> BlockPointerRegular::PHYSICAL_SECTORS_SHIFT)
            & BlockPointerRegular::PHYSICAL_SECTORS_MASK_DOWN_SHIFTED)
            as u32)
            + 1;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(BlockPointerRegular::PADDING_SIZE)?;

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
     * Returns [`BlockPointerEncodeError`] on error.
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
        // Encode flags.
        let level: u64 = self.level.into();
        if level > BlockPointer::LEVEL_MASK_DOWN_SHIFTED {
            return Err(BlockPointerEncodeError::InvalidLevel { level: self.level });
        }

        let checksum: u8 = self.checksum_type.into();
        let dmu: u8 = self.dmu.into();
        let compression: u8 = self.compression.into();

        let flags = u64::from(self.logical_sectors - 1)
            | u64::from(self.physical_sectors - 1) << BlockPointerRegular::PHYSICAL_SECTORS_SHIFT
            | u64::from(compression) << BlockPointer::COMPRESSION_SHIFT
            | u64::from(checksum) << BlockPointer::CHECKSUM_SHIFT
            | u64::from(dmu) << BlockPointer::DMU_SHIFT
            | level << BlockPointer::LEVEL_SHIFT
            | if self.dedup {
                BlockPointer::DEDUP_BIT_FLAG
            } else {
                0
            }
            | match self.order {
                EndianOrder::Little => BlockPointer::LITTLE_ENDIAN_BIT_FLAG,
                EndianOrder::Big => 0,
            };

        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(BlockPointerRegular::PADDING_SIZE)?;

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

    /// Unknown [`ChecksumType`].
    ChecksumType {
        /// Error.
        err: ChecksumTypeError,
    },

    /// [`ChecksumValue`] decode error.
    ChecksumValue {
        /// Error.
        err: ChecksumValueDecodeError,
    },

    /// Unknown [`CompressionType`].
    CompressionType {
        /// Error.
        err: CompressionTypeError,
    },

    /// Unknown [`DmuType`].
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

    /// Logical size is too large to fit in a [`usize`].
    LogicalSizeTooLarge {
        /// Invalid logical size value.
        logical_size: u32,
    },
}

impl From<BlockPointerEmbeddedTypeError> for BlockPointerDecodeError {
    fn from(err: BlockPointerEmbeddedTypeError) -> Self {
        BlockPointerDecodeError::BlockPointerEmbeddedType { err }
    }
}

impl From<ChecksumTypeError> for BlockPointerDecodeError {
    fn from(err: ChecksumTypeError) -> Self {
        BlockPointerDecodeError::ChecksumType { err }
    }
}

impl From<ChecksumValueDecodeError> for BlockPointerDecodeError {
    fn from(err: ChecksumValueDecodeError) -> Self {
        BlockPointerDecodeError::ChecksumValue { err }
    }
}

impl From<CompressionTypeError> for BlockPointerDecodeError {
    fn from(err: CompressionTypeError) -> Self {
        BlockPointerDecodeError::CompressionType { err }
    }
}

impl From<DmuTypeError> for BlockPointerDecodeError {
    fn from(err: DmuTypeError) -> Self {
        BlockPointerDecodeError::DmuType { err }
    }
}

impl From<DvaDecodeError> for BlockPointerDecodeError {
    fn from(err: DvaDecodeError) -> Self {
        BlockPointerDecodeError::Dva { err }
    }
}

impl From<EndianDecodeError> for BlockPointerDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        BlockPointerDecodeError::Endian { err }
    }
}

impl fmt::Display for BlockPointerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerDecodeError::BlockPointerEmbeddedType { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::ChecksumType { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::ChecksumValue { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::CompressionType { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::DmuType { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::Dva { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::Endian { err } => {
                write!(f, "BlockPointer decode error | {err}")
            }
            BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            } => {
                write!(
                    f,
                    "BlockPointer decode error, invalid embedded {embedded} encrypted {encrypted}"
                )
            }
            BlockPointerDecodeError::InvalidDedupValue { dedup } => {
                write!(f, "BlockPointer decode error, invalid dedup value {dedup}")
            }
            BlockPointerDecodeError::InvalidEmbeddedLength { length } => {
                write!(
                    f,
                    "BlockPointer decode error, invalid embdedded length {length}"
                )
            }
            BlockPointerDecodeError::LogicalSizeTooLarge { logical_size } => {
                write!(
                    f,
                    "BlockPointer decode error, logical size too big for usize {logical_size}"
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
    fn from(err: ChecksumValueEncodeError) -> Self {
        BlockPointerEncodeError::ChecksumValue { err }
    }
}

impl From<DvaEncodeError> for BlockPointerEncodeError {
    fn from(err: DvaEncodeError) -> Self {
        BlockPointerEncodeError::Dva { err }
    }
}

impl From<EndianEncodeError> for BlockPointerEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        BlockPointerEncodeError::Endian { err }
    }
}

impl fmt::Display for BlockPointerEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerEncodeError::ChecksumValue { err } => {
                write!(f, "BlockPointer encode error | {err}")
            }
            BlockPointerEncodeError::Dva { err } => {
                write!(f, "BlockPointer encode error | {err}")
            }
            BlockPointerEncodeError::Endian { err } => {
                write!(f, "BlockPointer encode error | {err}")
            }
            BlockPointerEncodeError::InvalidEmbeddedLength { length } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid embdedded length {length}"
                )
            }
            BlockPointerEncodeError::InvalidLevel { level } => {
                write!(f, "BlockPointer encode error, invalid level {level}")
            }
            BlockPointerEncodeError::InvalidLogicalSectors { sectors } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid logical sectors {sectors}"
                )
            }
            BlockPointerEncodeError::InvalidLogicalSize { logical_size } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid logical size {logical_size}"
                )
            }
            BlockPointerEncodeError::InvalidPhysicalSectors { sectors } => {
                write!(
                    f,
                    "BlockPointer encode error, invalid physical sectors {sectors}"
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

////////////////////////////////////////////////////////////////////////////////

/** [`BlockPointerObjectHeader`] accounting extensions.
 *
 * Introduced in [`crate::phys::SpaVersion::V3`].
 */
#[derive(Debug)]
pub struct BlockPointerObjectHeaderAccountingExtension {
    /// Total compressed size of ???.
    pub compressed_size: u64,

    /// Total uncompressed size of ???.
    pub uncompressed_size: u64,
}

/** [`BlockPointerObjectHeader`] dead lists extensions.
 *
 * Introduced in [`crate::phys::SpaVersion::V26`].
 */
#[derive(Debug)]
pub struct BlockPointerObjectHeaderDeadListsExtension {
    /// Object number of [`crate::phys::DmuType::BpObjectSubObject`].
    pub sub_objects_obj: Option<u64>,

    /// Number of [`crate::phys::DmuType::BpObject`] object numbers in `sub_objects_obj`.
    pub sub_objects_num: u64,

    /// Number of freed [`BlockPointer`].
    pub block_pointers_freed: u64,
}

/// [`BlockPointerObjectHeader`] extensions.
#[derive(Debug)]
pub enum BlockPointerObjectHeaderExtension {
    /// No extensions.
    Zero {},

    /// Extension One.
    One {
        /// Accounting.
        accounting: BlockPointerObjectHeaderAccountingExtension,
    },

    /// Extension Two.
    Two {
        /// Accounting.
        accounting: BlockPointerObjectHeaderAccountingExtension,

        /// Dead lists.
        dead_lists: BlockPointerObjectHeaderDeadListsExtension,
    },
}

/** Bonus buffer header of type [`crate::phys::DmuType::BpObjectHeader`].
 *
 * For Dnode of type [`crate::phys::DmuType::BpObject`].
 *
 * ### Byte layout.
 *
 * - Bytes: 8, 16, or 40
 *
 * ```text
 * +----------------------+------+-------------+
 * | Field                | Size | SPA Version |
 * +----------------------+------+-------------+
 * | block pointers count |   8  |           1 |
 * | physical size        |   8  |           1 |
 * | compressed size      |   8  |           3 |
 * | uncompressed size    |   8  |           3 |
 * | sub objects object   |   8  |          26 |
 * | sub objects number   |   8  |          26 |
 * | block pointers freed |   8  |          26 |
 * +----------------------+------+-------------+
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerObjectHeader {
    /// Number of [`BlockPointer`] in DMU object.
    pub block_pointers_count: u64,

    /// Total physical byte size ???.
    pub physical_size: u64,

    /// Extensions.
    pub extensions: BlockPointerObjectHeaderExtension,
}

impl BlockPointerObjectHeader {
    /** Decodes a [`BlockPointerRegular`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<BlockPointerObjectHeader, BlockPointerObjectHeaderDecodeError> {
        ////////////////////////////////
        // Decode values.
        let block_pointers_count = decoder.get_u64()?;
        let physical_size = decoder.get_u64()?;

        ////////////////////////////////
        // Check for extensions based on length.
        let mut extensions = BlockPointerObjectHeaderExtension::Zero {};

        if !decoder.is_empty() {
            ////////////////////////////
            // Decode accounting.
            let accounting = BlockPointerObjectHeaderAccountingExtension {
                compressed_size: decoder.get_u64()?,
                uncompressed_size: decoder.get_u64()?,
            };

            if decoder.is_empty() {
                extensions = BlockPointerObjectHeaderExtension::One { accounting };
            } else {
                ////////////////////////
                // Decode deadlists.
                let dead_lists = BlockPointerObjectHeaderDeadListsExtension {
                    sub_objects_obj: match decoder.get_u64()? {
                        0 => None,
                        v => Some(v),
                    },
                    sub_objects_num: decoder.get_u64()?,
                    block_pointers_freed: decoder.get_u64()?,
                };

                extensions = BlockPointerObjectHeaderExtension::Two {
                    accounting,
                    dead_lists,
                };
            }
        }

        if !decoder.is_empty() {
            return Err(BlockPointerObjectHeaderDecodeError::Size {
                size: decoder.len(),
            });
        }

        Ok(BlockPointerObjectHeader {
            block_pointers_count,
            physical_size,
            extensions,
        })
    }

    /** Encodes a non-empty [`BlockPointerObjectHeader`].
     *
     * # Errors
     *
     * Returns [`BlockPointerObjectHeaderEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), BlockPointerObjectHeaderEncodeError> {
        encoder.put_u64(self.block_pointers_count)?;
        encoder.put_u64(self.physical_size)?;

        if let Some(accounting) = self.accounting() {
            encoder.put_u64(accounting.compressed_size)?;
            encoder.put_u64(accounting.uncompressed_size)?;

            if let Some(dead_lists) = self.dead_lists() {
                encoder.put_u64(dead_lists.sub_objects_obj.unwrap_or(0))?;
                encoder.put_u64(dead_lists.sub_objects_num)?;
                encoder.put_u64(dead_lists.block_pointers_freed)?;
            }
        }

        Ok(())
    }

    /// Gets the [`BlockPointerObjectHeaderAccountingExtension`] of the [`BlockPointerObjectHeader`].
    pub fn accounting(&self) -> Option<&BlockPointerObjectHeaderAccountingExtension> {
        match &self.extensions {
            BlockPointerObjectHeaderExtension::Zero {} => None,
            BlockPointerObjectHeaderExtension::One { accounting } => Some(accounting),
            BlockPointerObjectHeaderExtension::Two {
                accounting,
                dead_lists: _,
            } => Some(accounting),
        }
    }

    /// Gets the [`BlockPointerObjectHeaderDeadListsExtension`] of the [`BlockPointerObjectHeader`].
    pub fn dead_lists(&self) -> Option<&BlockPointerObjectHeaderDeadListsExtension> {
        match &self.extensions {
            BlockPointerObjectHeaderExtension::Zero {} => None,
            BlockPointerObjectHeaderExtension::One { accounting: _ } => None,
            BlockPointerObjectHeaderExtension::Two {
                accounting: _,
                dead_lists,
            } => Some(dead_lists),
        }
    }
}

/// [`BlockPointerObjectHeader`] decode error.
#[derive(Debug)]
pub enum BlockPointerObjectHeaderDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown size.
    Size {
        /// Size.
        size: usize,
    },
}

impl From<EndianDecodeError> for BlockPointerObjectHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        BlockPointerObjectHeaderDecodeError::Endian { err }
    }
}

impl fmt::Display for BlockPointerObjectHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerObjectHeaderDecodeError::Endian { err } => {
                write!(f, "BlockPointerObjectHeader decode error | {err}")
            }
            BlockPointerObjectHeaderDecodeError::Size { size } => {
                write!(
                    f,
                    "BlockPointerObjectHeader decode error, unknown size {size}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerObjectHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockPointerObjectHeaderDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`BlockPointerObjectHeader`] encode error.
#[derive(Debug)]
pub enum BlockPointerObjectHeaderEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for BlockPointerObjectHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        BlockPointerObjectHeaderEncodeError::Endian { err }
    }
}

impl fmt::Display for BlockPointerObjectHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerObjectHeaderEncodeError::Endian { err } => {
                write!(f, "BlockPointerObjectHeader encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerObjectHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockPointerObjectHeaderEncodeError::Endian { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
