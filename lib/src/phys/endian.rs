// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! An Endian decoder and encoder.
 *
 * Decodes and encodes numbers in big or little endian.
 */
use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::EndianOrder;

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
                    "Endian end of output at offset {offset} capacity {capacity} count {count}"
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
