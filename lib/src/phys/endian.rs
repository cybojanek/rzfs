// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! An Endian decoder and encoder.
 *
 * Decodes and encodes numbers in big or little endian.
 */
use core::cell::Cell;
use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/// Endian order.
#[derive(Copy, Clone, Debug)]
pub enum EndianOrder {
    /// Big endian byte order. Most significant byte first.
    Big,
    /// Little endian byte order. Least significant byte first.
    Little,
}

/// Native encoding.
#[cfg(target_endian = "big")]
pub const ENDIAN_ORDER_NATIVE: EndianOrder = EndianOrder::Big;

/// Native encoding.
#[cfg(target_endian = "little")]
pub const ENDIAN_ORDER_NATIVE: EndianOrder = EndianOrder::Little;

/// Swapped encoding (opposite of [`ENDIAN_ORDER_NATIVE`]).
#[cfg(target_endian = "big")]
pub const ENDIAN_ORDER_SWAP: EndianOrder = EndianOrder::Little;

/// Swapped encoding (opposite of [`ENDIAN_ORDER_NATIVE`]).
#[cfg(target_endian = "little")]
pub const ENDIAN_ORDER_SWAP: EndianOrder = EndianOrder::Big;

impl Display for EndianOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndianOrder::Big => write!(f, "Big"),
            EndianOrder::Little => write!(f, "Little"),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

type U16Decoder = fn(bytes: [u8; 2]) -> u16;
type U32Decoder = fn(bytes: [u8; 4]) -> u32;
type U64Decoder = fn(bytes: [u8; 8]) -> u64;

/// Decoder for an [`EndianOrder`] type.
struct EndianDecoderImpl {
    order: EndianOrder,
    get_u16: U16Decoder,
    get_u32: U32Decoder,
    get_u64: U64Decoder,
}

/// [`EndianOrder::Big`] decoder.
const BIG_ENDIAN_DECODER: EndianDecoderImpl = EndianDecoderImpl {
    order: EndianOrder::Big,
    get_u16: u16::from_be_bytes,
    get_u32: u32::from_be_bytes,
    get_u64: u64::from_be_bytes,
};

/// [`EndianOrder::Little`] decoder.
const LITTLE_ENDIAN_DECODER: EndianDecoderImpl = EndianDecoderImpl {
    order: EndianOrder::Little,
    get_u16: u16::from_le_bytes,
    get_u32: u32::from_le_bytes,
    get_u64: u64::from_le_bytes,
};

/** A binary decoder.
 *
 * Uses an internal [`Cell`] field for the `offset` field in order to implement
 * a split borrow.
 */
pub struct EndianDecoder<'a> {
    data: &'a [u8],
    offset: Cell<usize>,
    decoder: EndianDecoderImpl,
}

impl fmt::Debug for EndianDecoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("EndianDecoder")
            .field("length", &self.data.len())
            .field("offset", &self.offset.get())
            .field("order", &self.decoder.order)
            .finish()
    }
}

impl EndianDecoder<'_> {
    /** Initializes a [`EndianDecoder`] based on the supplied [`EndianOrder`] value.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     *
     * // Error end of input.
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn from_bytes(data: &[u8], order: EndianOrder) -> EndianDecoder<'_> {
        EndianDecoder {
            data,
            offset: Cell::new(0),
            decoder: match order {
                EndianOrder::Big => BIG_ENDIAN_DECODER,
                EndianOrder::Little => LITTLE_ENDIAN_DECODER,
            },
        }
    }

    /** Initializes a [`EndianDecoder`] based on the expected magic value.
     *
     * Picks [`EndianOrder`] to match magic value.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if array is too short or magic does not match.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::EndianDecoder;
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_u64_magic(data, 0x123456789abcdef0).unwrap();
     *
     * // Get u64.
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     *
     * // Some bytes (litle endian).
     * let data = &[
     *     0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
     *     0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_u64_magic(data, 0x123456789abcdef0).unwrap();
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     * ```
     *
     * Magic mismatch
     *
     * ```
     * use rzfs::phys::EndianDecoder;
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_u64_magic(data, 0x123456789abcdef0);
     * assert!(decoder.is_err());
     * ```
     *
     * Slice too short:
     *
     * ```
     * use rzfs::phys::EndianDecoder;
     *
     * // Not enough bytes for magic.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
     * let decoder = EndianDecoder::from_u64_magic(data, 0x123456789abcdef0);
     * assert!(decoder.is_err());
     * ```
     */
    pub fn from_u64_magic(data: &[u8], magic: u64) -> Result<EndianDecoder<'_>, EndianDecodeError> {
        // Initialize decoder assuming little endian.
        let mut decoder = EndianDecoder::from_bytes(data, EndianOrder::Little);

        // Try to get the magic.
        let data_magic = decoder.get_u64()?;

        // If it doesn't match, then swap bytes and compare again.
        if data_magic != magic {
            let data_magic = data_magic.swap_bytes();
            if data_magic != magic {
                // It still doesn't match.
                return Err(EndianDecodeError::InvalidMagic {
                    expected: magic,
                    actual: data_magic.to_le_bytes(),
                });
            }

            // Update decoder to big endian.
            decoder.decoder = BIG_ENDIAN_DECODER;
        }

        Ok(decoder)
    }

    /** Checks if there are enough bytes to decode from the data slice.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     */
    fn check_need(&self, count: usize) -> Result<(), EndianDecodeError> {
        if self.len() >= count {
            Ok(())
        } else {
            Err(EndianDecodeError::EndOfInput {
                offset: self.offset.get(),
                capacity: self.capacity(),
                count,
            })
        }
    }

    /** Returns the source data length.
     *
     * Remains unchanged while decoding values.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     * assert_eq!(decoder.capacity(), data.len());
     *
     * // Capacity remains unchanged while decoding.
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.capacity(), data.len());
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.capacity(), data.len());
     * ```
     */
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /** Returns true if there are no more bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * while !decoder.is_empty() {
     *     assert_eq!(decoder.get_u32().unwrap(), 1);
     * }
     * ```
     */
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /** Returns length of bytes remaining to be decoded.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     * assert_eq!(decoder.len(), 16);
     *
     * // Length decreases while decoding.
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.len(), 8);
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.len(), 0);
     * ```
     */
    pub fn len(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        self.data.len().saturating_sub(self.offset.get())
    }

    /** Gets the current offset in bytes.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     * assert_eq!(decoder.offset(), 0);
     *
     * decoder.get_u16().unwrap();
     * assert_eq!(decoder.offset(), 2);
     *
     * decoder.get_u32().unwrap();
     * assert_eq!(decoder.offset(), 6);
     * ```
     */
    pub fn offset(&self) -> usize {
        self.offset.get()
    }

    /** Returns the [`EndianOrder`] of the decoder.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get endian.
     * assert!(matches!(decoder.order(), EndianOrder::Big));
     * ```
     */
    pub fn order(&self) -> EndianOrder {
        self.decoder.order
    }

    /** Resets the decoder to the start of the data.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     *
     * // Reset to beginning and decode again.
     * decoder.reset();
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     * ```
     */
    pub fn reset(&self) {
        self.offset.set(0);
    }

    /** Rewinds `count` bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to rewind.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u32().unwrap(), 0x12345678);
     *
     * // Rewind position.
     * assert!(decoder.rewind(2).is_ok());
     * assert_eq!(decoder.get_u32().unwrap(), 0x56789abc);
     *
     * // Error rewind past start.
     * assert!(decoder.rewind(8).is_err());
     * ```
     */
    pub fn rewind(&self, count: usize) -> Result<(), EndianDecodeError> {
        let offset = self.offset.get();
        if count > offset {
            return Err(EndianDecodeError::RewindPastStart { offset, count });
        }
        self.offset.set(offset - count);
        Ok(())
    }

    /** Seeks to offset.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if seek is past end of data.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     *
     * // Seek.
     * assert!(decoder.seek(2).is_ok());
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u16().unwrap(), 0x5678);
     *
     * // Error seek past end.
     * assert!(decoder.seek(data.len() + 1).is_err());
     * ```
     */
    pub fn seek(&self, offset: usize) -> Result<(), EndianDecodeError> {
        if offset > self.data.len() {
            return Err(EndianDecodeError::SeekPastEnd {
                offset,
                capacity: self.capacity(),
            });
        }

        self.offset.set(offset);
        Ok(())
    }

    /** Skips the next `count` bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to skip.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u16().unwrap(), 0x1234);
     *
     * // Skip some bytes.
     * assert!(decoder.skip(2).is_ok());
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u16().unwrap(), 0x9abc);
     *
     * // Error end of input.
     * assert!(decoder.skip(4).is_err());
     * ```
     */
    pub fn skip(&self, count: usize) -> Result<(), EndianDecodeError> {
        self.check_need(count)?;
        self.offset.set(self.offset.get() + count);
        Ok(())
    }

    /** Skips the next `count` bytes, if they are all zero, and returns `true`,
     * else leaves the offset unchanged, and returns `false`.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to skip.
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Skip zeroes.
     * assert!(decoder.is_zero_skip(2).unwrap());
     * assert_eq!(decoder.offset(), 2);
     *
     * // Don't skip non-zeroes.
     * assert!(!decoder.is_zero_skip(2).unwrap());
     * assert_eq!(decoder.offset(), 2);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u16().unwrap(), 0x5678);
     * assert_eq!(decoder.offset(), 4);
     *
     * // Don't skip if not everything is zeroes.
     * assert!(!decoder.is_zero_skip(2).unwrap());
     * assert_eq!(decoder.offset(), 4);
     *
     * // Error end of input.
     * assert!(decoder.is_zero_skip(5).is_err());
     * ```
     */
    pub fn is_zero_skip(&self, count: usize) -> Result<bool, EndianDecodeError> {
        self.check_need(count)?;

        let offset = self.offset.get();
        let mut x = 0;

        for idx in offset..offset + count {
            x |= self.data[idx];
        }

        if x == 0 {
            self.offset.set(offset + count);
            return Ok(true);
        }

        Ok(false)
    }

    /** Skips the next `count` bytes as zero padding.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to skip, or the
     * bytes are non-zero.
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Skip zeroes.
     * assert!(decoder.skip_zero_padding(2).is_ok());
     * assert_eq!(decoder.offset(), 2);
     *
     * // Don't skip non-zeroes.
     * assert!(decoder.skip_zero_padding(2).is_err());
     * assert_eq!(decoder.offset(), 2);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u16().unwrap(), 0x5678);
     * assert_eq!(decoder.offset(), 4);
     *
     * // Don't skip if not everything is zeroes.
     * assert!(decoder.skip_zero_padding(2).is_err());
     * assert_eq!(decoder.offset(), 4);
     *
     * // Error end of input.
     * assert!(decoder.skip_zero_padding(5).is_err());
     * ```
     */
    pub fn skip_zero_padding(&self, count: usize) -> Result<(), EndianDecodeError> {
        match self.is_zero_skip(count)? {
            true => Ok(()),
            false => Err(EndianDecodeError::NonZeroPadding {}),
        }
    }

    /** Returns 2 bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     */
    fn get_2_bytes(&self) -> Result<[u8; 2], EndianDecodeError> {
        self.check_need(2)?;

        let start = self.offset.get();
        let end = start + 2;

        self.offset.set(end);

        Ok(<[u8; 2]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 4 bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     */
    fn get_4_bytes(&self) -> Result<[u8; 4], EndianDecodeError> {
        self.check_need(4)?;

        let start = self.offset.get();
        let end = start + 4;

        self.offset.set(end);

        Ok(<[u8; 4]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 8 bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     */
    fn get_8_bytes(&self) -> Result<[u8; 8], EndianDecodeError> {
        self.check_need(8)?;

        let start = self.offset.get();
        let end = start + 8;

        self.offset.set(end);

        Ok(<[u8; 8]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Decodes bytes.
     *
     * [`EndianOrder`] does not matter for order of decoded bytes.
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get bytes.
     * let a = decoder.get_bytes(2).unwrap();
     * let b = decoder.get_bytes(1).unwrap();
     * assert_eq!(a, [0xf2, 0x34]);
     * assert_eq!(b, [0x56]);
     *
     * // Error end of input.
     * assert!(decoder.get_bytes(2).is_err());
     */
    pub fn get_bytes(&self, length: usize) -> Result<&[u8], EndianDecodeError> {
        // Check bounds for length.
        self.check_need(length)?;

        // Start and end of bytes.
        let start = self.offset.get();
        let end = start + length;

        // Consume bytes.
        let value = &self.data[start..end];
        self.offset.set(end);

        // Return bytes.
        Ok(value)
    }

    /** Decodes a [`u8`].
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0xf2];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u8().unwrap(), 0xf2);
     *
     * // Error end of input.
     * assert!(decoder.get_u8().is_err());
     * ```
     */
    pub fn get_u8(&self) -> Result<u8, EndianDecodeError> {
        self.check_need(1)?;

        let offset = self.offset.get();
        let value = self.data[offset];
        self.offset.set(offset + 1);

        Ok(value)
    }

    /** Decodes a [`u16`].
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u16().unwrap(), 0x1234);
     *
     * // Error end of input.
     * assert!(decoder.get_u16().is_err());
     * ```
     */
    pub fn get_u16(&self) -> Result<u16, EndianDecodeError> {
        Ok((self.decoder.get_u16)(self.get_2_bytes()?))
    }

    /** Decodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u32().unwrap(), 0x12345678);
     *
     * // Error end of input.
     * assert!(decoder.get_u32().is_err());
     * ```
     */
    pub fn get_u32(&self) -> Result<u32, EndianDecodeError> {
        Ok((self.decoder.get_u32)(self.get_4_bytes()?))
    }

    /** Decodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`EndianDecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianDecoder, EndianOrder};
     *
     * // Some bytes (big endian).
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = EndianDecoder::from_bytes(data, EndianOrder::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     *
     * // Error end of input.
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn get_u64(&self) -> Result<u64, EndianDecodeError> {
        Ok((self.decoder.get_u64)(self.get_8_bytes()?))
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`EndianDecoder`] error.
#[derive(Debug)]
pub enum EndianDecodeError {
    /// End of input data.
    EndOfInput {
        /// Byte offset of data.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
    },

    /// Magic mismatch.
    InvalidMagic {
        /// Expected magic value.
        expected: u64,
        /// Actual bytes.
        actual: [u8; 8],
    },

    /// Non-zero padding.
    NonZeroPadding {},

    /// Rewind past start.
    RewindPastStart {
        /// Byte offset of data.
        offset: usize,
        /// Number of bytes needed to rewind.
        count: usize,
    },

    /// Seek past end.
    SeekPastEnd {
        /// Requested offset.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
    },
}

impl fmt::Display for EndianDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndianDecodeError::EndOfInput {
                offset,
                capacity,
                count,
            } => {
                write!(
                    f,
                    "Endian end of input at offset:{offset} capacity:{capacity} count:{count}"
                )
            }
            EndianDecodeError::InvalidMagic { expected, actual } => write!(
                f,
                "Endian invalid magic expected 0x{expected:016x} actual {:?}",
                actual
            ),
            EndianDecodeError::NonZeroPadding {} => write!(f, "Endian non-zero padding"),
            EndianDecodeError::RewindPastStart { offset, count } => {
                write!(
                    f,
                    "Endian rewind past start at offset:{offset} count:{count}"
                )
            }
            EndianDecodeError::SeekPastEnd { offset, capacity } => {
                write!(
                    f,
                    "Endian seek past end to offset:{offset} capacity:{capacity}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for EndianDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

type U16Encoder = fn(value: u16) -> [u8; 2];
type U32Encoder = fn(value: u32) -> [u8; 4];
type U64Encoder = fn(value: u64) -> [u8; 8];

/// Encoder for an [`EndianOrder`] type.
struct EndianEncoderImpl {
    order: EndianOrder,
    put_u16: U16Encoder,
    put_u32: U32Encoder,
    put_u64: U64Encoder,
}

/// [`EndianOrder::Big`] encoder.
const BIG_ENDIAN_ENCODER: EndianEncoderImpl = EndianEncoderImpl {
    order: EndianOrder::Big,
    put_u16: u16::to_be_bytes,
    put_u32: u32::to_be_bytes,
    put_u64: u64::to_be_bytes,
};

/// [`EndianOrder::Little`] encoder.
const LITTLE_ENDIAN_ENCODER: EndianEncoderImpl = EndianEncoderImpl {
    order: EndianOrder::Little,
    put_u16: u16::to_le_bytes,
    put_u32: u32::to_le_bytes,
    put_u64: u64::to_le_bytes,
};

/// A binary encoder.
pub struct EndianEncoder<'a> {
    data: &'a mut [u8],
    offset: usize,
    encoder: EndianEncoderImpl,
}

impl fmt::Debug for EndianEncoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("EndianEncoder")
            .field("length", &self.data.len())
            .field("offset", &self.offset)
            .field("order", &self.encoder.order)
            .finish()
    }
}

impl EndianEncoder<'_> {
    /** Initializes an [`EndianEncoder`] based on the supplied [`EndianOrder`] value.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 8] = [0; 8];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put values.
     * assert!(encoder.put_u64(0x123456789abcdef0).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_u8(23).is_err());
     *
     * // Expected result.
     * let exp: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     * assert_eq!(data, exp);
     * ```
     */
    pub fn to_bytes(data: &mut [u8], order: EndianOrder) -> EndianEncoder<'_> {
        EndianEncoder {
            data,
            offset: 0,
            encoder: match order {
                EndianOrder::Big => BIG_ENDIAN_ENCODER,
                EndianOrder::Little => LITTLE_ENDIAN_ENCODER,
            },
        }
    }

    /** Checks if there is enough space in data slice to encode.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     */
    fn check_need(&self, count: usize) -> Result<(), EndianEncodeError> {
        if self.available() >= count {
            Ok(())
        } else {
            Err(EndianEncodeError::EndOfOutput {
                offset: self.offset,
                capacity: self.capacity(),
                count,
            })
        }
    }

    /** Returns the number of bytes still available for encoding in data slice.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * // Initial available is length of data.
     * assert_eq!(encoder.available(), 32);
     *
     * // Decreases by size of value.
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.available(), 24);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.available(), 16);
     * ```
     */
    pub fn available(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        self.data.len().saturating_sub(self.offset)
    }

    /** Returns the destination data capacity.
     *
     * Remains unchanged while encoding values.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     * let data_length = data.len();
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * assert_eq!(encoder.capacity(), data_length);
     *
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.capacity(), data_length);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.capacity(), data_length);
     * ```
     */
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /** Gets the current offset in bytes.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     * let data_length = data.len();
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * assert_eq!(encoder.offset(), 0);
     *
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.offset(), 8);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.offset(), 16);
     * ```
     */
    pub fn offset(&self) -> usize {
        self.offset
    }

    /** Returns the [`EndianOrder`] of the encoder.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Some bytes.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     * assert!(matches!(encoder.order(), EndianOrder::Big));
     * ```
     */
    pub fn order(&self) -> EndianOrder {
        self.encoder.order
    }

    /** Returns true if there is output is empty.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * // Initially empty.
     * assert!(encoder.is_empty());
     *
     * // Put value.
     * encoder.put_u32(1).unwrap();
     * assert!(!encoder.is_empty());
     * ```
     */
    pub fn is_empty(&self) -> bool {
        self.offset == 0
    }

    /** Returns true if there is no more space for values to be encoded.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * // Encode values.
     * let mut x = 0;
     * while !encoder.is_full() {
     *     encoder.put_u32(x);
     *     x += 1;
     * }
     * ```
     */
    pub fn is_full(&self) -> bool {
        self.offset >= self.data.len()
    }

    /** Returns the length of the encoded values.
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(data, EndianOrder::Big);
     *
     * // Initial length is 0.
     * assert_eq!(encoder.len(), 0);
     *
     * // Increases by size of value.
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.len(), 8);
     *
     * encoder.put_u32(0xfedcba98).unwrap();
     * assert_eq!(encoder.len(), 12);
     * ```
     */
    pub fn len(&self) -> usize {
        self.offset
    }

    /** Encodes 2 bytes.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     */
    fn put_2_bytes(&mut self, data: [u8; 2]) -> Result<(), EndianEncodeError> {
        self.check_need(2)?;

        let start = self.offset;
        let end = start + 2;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes 4 bytes.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     */
    fn put_4_bytes(&mut self, data: [u8; 4]) -> Result<(), EndianEncodeError> {
        self.check_need(4)?;

        let start = self.offset;
        let end = start + 4;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes 8 bytes.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     */
    fn put_8_bytes(&mut self, data: [u8; 8]) -> Result<(), EndianEncodeError> {
        self.check_need(8)?;

        let start = self.offset;
        let end = start + 8;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes bytes.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 8] = [1; 8];
     * let src: [u8; 5] = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_bytes(&src).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_bytes(&src).is_err());
     *
     * // Expected result.
     * let exp: [u8; 8] = [0xff, 0xfe, 0xfd, 0xfc, 0xfb, 1, 1, 1];
     * assert_eq!(data, exp);
     */
    pub fn put_bytes(&mut self, data: &[u8]) -> Result<(), EndianEncodeError> {
        let length = data.len();
        self.check_need(length)?;

        let start = self.offset;
        let end = start + length;

        self.offset = end;

        self.data[start..end].copy_from_slice(data);

        Ok(())
    }

    /** Encodes a [`u8`].
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 1] = [0; 1];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_u8(0x12).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_u8(0x11).is_err());
     *
     * // Expected result.
     * let exp: [u8; 1] = [0x12];
     * assert_eq!(data, exp);
     */
    pub fn put_u8(&mut self, value: u8) -> Result<(), EndianEncodeError> {
        self.check_need(1)?;
        self.data[self.offset] = value;
        self.offset += 1;

        Ok(())
    }

    /** Encodes a [`u16`].
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 2] = [0; 2];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_u16(0x1234).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_u16(0x1122).is_err());
     *
     * // Expected result.
     * let exp: [u8; 2] = [0x12, 0x34];
     * assert_eq!(data, exp);
     */
    pub fn put_u16(&mut self, value: u16) -> Result<(), EndianEncodeError> {
        self.put_2_bytes((self.encoder.put_u16)(value))
    }

    /** Encodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 4] = [0; 4];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_u32(0x12345678).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_u32(0x11223344).is_err());
     *
     * // Expected result.
     * let exp: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
     * assert_eq!(data, exp);
     */
    pub fn put_u32(&mut self, value: u32) -> Result<(), EndianEncodeError> {
        self.put_4_bytes((self.encoder.put_u32)(value))
    }

    /** Encodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 8] = [0; 8];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_u64(0x123456789abcdef0).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_u64(0x1122334455667788).is_err());
     *
     * // Expected result.
     * let exp: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     * assert_eq!(data, exp);
     */
    pub fn put_u64(&mut self, value: u64) -> Result<(), EndianEncodeError> {
        self.put_8_bytes((self.encoder.put_u64)(value))
    }

    /** Puts zero bytes as padding.
     *
     * # Errors
     *
     * Returns [`EndianEncodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{EndianEncoder, EndianOrder};
     *
     * // Destination.
     * let mut data: [u8; 8] = [1; 8];
     *
     * // Create encoder.
     * let mut encoder = EndianEncoder::to_bytes(&mut data, EndianOrder::Big);
     *
     * // Put value.
     * assert!(encoder.put_zero_padding(4).is_ok());
     *
     * // Error end of output.
     * assert!(encoder.put_zero_padding(5).is_err());
     *
     * // Expected result.
     * let exp: [u8; 8] = [0, 0, 0, 0, 1, 1, 1, 1];
     * assert_eq!(data, exp);
     */
    pub fn put_zero_padding(&mut self, length: usize) -> Result<(), EndianEncodeError> {
        self.check_need(length)?;

        let start = self.offset;
        let end = start + length;

        self.offset = end;

        self.data[start..end].fill(0);

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`EndianEncoder`] error.
#[derive(Debug)]
pub enum EndianEncodeError {
    /// End of output data.
    EndOfOutput {
        /// Byte offset of data.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
    },
}

impl fmt::Display for EndianEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndianEncodeError::EndOfOutput {
                offset,
                capacity,
                count,
            } => {
                write!(
                    f,
                    "Endian end of output at offset:{offset}, capacity:{capacity} count:{count}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for EndianEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
