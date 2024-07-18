// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! An XDR decoder and encoder.
 *
 * [XDR](https://www.rfc-editor.org/rfc/rfc4506) is a standard of encoding
 * numbers and strings to bytes.
 *
 * - Boolean values are encoded as the number 0 [`false`], 1 [`true`].
 * - Numbers smaller than 32 bits are encoded as [`i32`] or [`u32`], since that
 *   is the minimum XDR encoding size.
 * - Numbers are encoded in big endian format.
 * - Strings and byte arrays are encoded as a length followed by the bytes,
 *   padded to a multiple of four. The length does not include the padding.
 * - [`XdrDecoder`] uses an internal [`Cell`] field for the `offset` field
 *   in order to implement a split borrow.
 */
use core::cell::Cell;
use core::fmt;
use core::marker::Sized;
use core::num;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** An XDR decoder.
 *
 * Uses an internal [`Cell`] field for the `offset` field in order to implement
 * a split borrow.
 */
pub struct XdrDecoder<'a> {
    data: &'a [u8],
    offset: Cell<usize>,
}

impl fmt::Debug for XdrDecoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("XdrDecoder")
            .field("length", &self.data.len())
            .field("offset", &self.offset.get())
            .finish()
    }
}

impl XdrDecoder<'_> {
    /** EndianDecoder an [`XdrDecoder`] from a slice of bytes.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     * assert_eq!(decoder.len(), 8);
     *
     * // Decode values.
     * let a: bool = decoder.get().unwrap();
     * assert_eq!(decoder.len(), 4);
     *
     * let b: bool = decoder.get().unwrap();
     * assert_eq!(decoder.len(), 0);
     *
     * assert_eq!(decoder.is_empty(), true);
     *
     * assert_eq!(a, true);
     * assert_eq!(b, false);
     * ```
     */
    pub fn from_bytes(data: &[u8]) -> XdrDecoder<'_> {
        XdrDecoder {
            data,
            offset: Cell::new(0),
        }
    }

    /** Finds a sequence of bytes in the decoder data, and returns it.
     *
     * Returns [None] if not found.
     *
     * This is intended for lifetime promotion when returning errors with
     * [str] or [[u8]] references in nested decoders.
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Found.
     * let search = &[0x12, 0x34];
     * assert_eq!(decoder.find_bytes(search).unwrap(), search);
     *
     * let search = &[0x78];
     * assert_eq!(decoder.find_bytes(search).unwrap(), search);
     *
     * let search = data;
     * assert_eq!(decoder.find_bytes(search).unwrap(), search);
     *
     * // Not found.
     * let search = &[0x12, 0xff];
     * assert!(decoder.find_bytes(search).is_none());
     *
     * // Too long
     * let search = &[0x12, 0x34, 0x56, 0x78, 0x9a];
     * assert!(decoder.find_bytes(search).is_none());
     * ```
     */
    pub fn find_bytes<'a>(&'a self, search: &[u8]) -> Option<&'a [u8]> {
        // Maximum index to search. No point searching further, because there
        // would not be enough bytes in data to contain the search bytes.
        let max_index = match self.data.len().checked_sub(search.len()) {
            Some(v) => v,
            None => return None,
        };

        for idx in 0..max_index + 1 {
            let sub_bytes = &self.data[idx..idx + search.len()];
            if sub_bytes == search {
                return Some(sub_bytes);
            }
        }

        None
    }

    /** Checks if there are enough bytes to decode from the data slice.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes to decode.
     */
    fn check_need(&self, count: usize) -> Result<(), XdrDecodeError> {
        if self.len() >= count {
            Ok(())
        } else {
            Err(XdrDecodeError::EndOfInput {
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
     * use rzfs::phys::XdrDecoder;
     *
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     * let decoder = XdrDecoder::from_bytes(data);
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
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * while !decoder.is_empty() {
     *     let a = decoder.get_bool().unwrap();
     *     assert_eq!(a, true);
     * }
     * ```
     */
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /** Returns length of bytes remaining to be processed.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
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
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes (big endian).
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     * assert_eq!(decoder.offset(), 0);
     *
     * decoder.get_u16().unwrap();
     * assert_eq!(decoder.offset(), 4);
     *
     * decoder.get_u32().unwrap();
     * assert_eq!(decoder.offset(), 8);
     * ```
     */
    pub fn offset(&self) -> usize {
        self.offset.get()
    }

    /** Resets the decoder to the start of the data.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
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
     * Returns [`XdrDecodeError`] if there are not enough bytes to rewind, or
     * count is a multiple of 4.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode value.
     * assert_eq!(decoder.get_u32().unwrap(), 0x12345678);
     * assert_eq!(decoder.get_u32().unwrap(), 0x9abcdef0);
     *
     * // Rewind position.
     * assert!(decoder.rewind(4).is_ok());
     * assert_eq!(decoder.get_u32().unwrap(), 0x9abcdef0);
     *
     * // Error rewind past start.
     * assert!(decoder.rewind(12).is_err());
     *
     * // Error alignment.
     * assert!(decoder.rewind(1).is_err());
     * ```
     */
    pub fn rewind(&self, count: usize) -> Result<(), XdrDecodeError> {
        if (count % 4) != 0 {
            return Err(XdrDecodeError::RewindAlignment { count });
        }

        let offset = self.offset.get();
        if count > offset {
            return Err(XdrDecodeError::RewindPastStart { offset, count });
        }
        self.offset.set(offset - count);

        Ok(())
    }

    /** Seeks to offset.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if seek is past end of data, or offset is not
     * a multiple of 4.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     *
     * // Seek.
     * assert!(decoder.seek(4).is_ok());
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u32().unwrap(), 0x9abcdef0);
     *
     * // Error seek is not aligned.
     * assert!(decoder.seek(2).is_err());
     *
     * // Error seek past end.
     * assert!(decoder.seek(data.len() + 4).is_err());
     *
     * ```
     */
    pub fn seek(&self, offset: usize) -> Result<(), XdrDecodeError> {
        if (offset % 4) != 0 {
            return Err(XdrDecodeError::SeekAlignment { offset });
        }

        if offset > self.data.len() {
            return Err(XdrDecodeError::SeekPastEnd {
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
     * Returns [`XdrDecodeError`] if there are not enough bytes to skip,
     * or count is not a multiple of 4.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Skip some bytes.
     * assert!(decoder.skip(4).is_ok());
     *
     * // Decode a value.
     * assert_eq!(decoder.get_u32().unwrap(), 0x9abcdef0);
     *
     * // Rewind for next test.
     * assert!(decoder.rewind(4).is_ok());
     *
     * // Error count is not aligned.
     * assert!(decoder.skip(2).is_err());
     *
     * // Error end of input.
     * assert!(decoder.skip(8).is_err());
     * ```
     */
    pub fn skip(&self, count: usize) -> Result<(), XdrDecodeError> {
        if (count % 4) != 0 {
            return Err(XdrDecodeError::SkipAlignment { count });
        }

        self.check_need(count)?;
        self.offset.set(self.offset.get() + count);
        Ok(())
    }

    /** Returns 4 bytes.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     */
    fn get_4_bytes(&self) -> Result<[u8; 4], XdrDecodeError> {
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
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     */
    fn get_8_bytes(&self) -> Result<[u8; 8], XdrDecodeError> {
        self.check_need(8)?;

        let start = self.offset.get();
        let end = start + 8;

        self.offset.set(end);

        Ok(<[u8; 8]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Decodes bytes.
     *
     * Consumes padding bytes if length is not a multiple of 4.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x62, 0x63, 0x00];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_bytes(5).unwrap();
     * let d = [0x12, 0x34, 0x56, 0x78, 0x61];
     *
     * assert_eq!(a, d);
     *
     * // Reset for next test.
     * decoder.reset();
     *
     * // Need 1 more byte for data.
     * assert!(decoder.get_bytes(9).is_err());
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_bytes(7).is_err());
     * ```
     */
    pub fn get_bytes(&self, length: usize) -> Result<&[u8], XdrDecodeError> {
        // Compute padding.
        let remainder = length % 4;
        let padding = if remainder == 0 { 0 } else { 4 - remainder };

        // If this fails, length is too large.
        let padded_length = match length.checked_add(padding) {
            Some(v) => v,
            None => {
                return Err(XdrDecodeError::EndOfInput {
                    offset: self.offset.get(),
                    capacity: self.capacity(),
                    count: length,
                })
            }
        };

        // Check bounds for length.
        self.check_need(padded_length)?;

        // Start and end of bytes.
        let start = self.offset.get();
        let end = start + length;

        // Consume bytes.
        let value = &self.data[start..end];
        self.offset.set(start + padded_length);

        // TODO(cybojanek): Check padding is zero?

        // Return bytes.
        Ok(value)
    }

    /** Decodes a [`bool`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are enough bytes available, or the
     * value is not 0 nor 1. In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
     *     0x00, 0x00, 0x00, 0x02,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_bool().unwrap();
     * let b = decoder.get_bool().unwrap();
     *
     * assert_eq!(a, true);
     * assert_eq!(b, false);
     *
     * // 2 is not a valid boolean.
     * assert!(decoder.get_bool().is_err());
     *
     * // Error end of input.
     * assert!(decoder.skip(4).is_ok());
     * assert!(decoder.get_bool().is_err());
     * ```
     */
    pub fn get_bool(&self) -> Result<bool, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => {
                self.offset.set(offset);
                Err(XdrDecodeError::InvalidBoolean { offset, value })
            }
        }
    }

    /** Decodes a [`&[u8]`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00,
     *     0x00, 0x00, 0x00, 0x0c, 0x61, 0x62, 0x63, 0x64,
     *     0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_byte_array().unwrap();
     * let d = [0x61, 0x62, 0x63];
     *
     * assert_eq!(a, d);
     *
     * // Need 1 more byte for array.
     * assert!(decoder.get_byte_array().is_err());
     * assert!(decoder.skip(8).is_ok());
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_byte_array().is_err());
     *
     * // Need 1 more for length.
     * let data = &[0x00, 0x00, 0x00];
     * let decoder = XdrDecoder::from_bytes(data);
     * assert!(decoder.get_byte_array().is_err());
     * ```
     */
    pub fn get_byte_array(&self) -> Result<&[u8], XdrDecodeError> {
        let offset = self.offset.get();

        let length = self.get_usize()?;

        let res = self.get_bytes(length);
        if res.is_err() {
            self.offset.set(offset);
        }
        res
    }

    /** Decodes an [`f32`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     */
    pub fn get_f32(&self) -> Result<f32, XdrDecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(f32::from_be_bytes(bytes))
    }

    /** Decodes an [`f64`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     */
    pub fn get_f64(&self) -> Result<f64, XdrDecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(f64::from_be_bytes(bytes))
    }

    /** Decodes an [`i32`] and casts it to an [`i8`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available, or
     * casting would be out of range for [`i8`]. In case of error, offset
     * remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f,
     *     0xff, 0xff, 0xff, 0x7f,
     *     0x00, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i8().unwrap();
     * let b = decoder.get_i8().unwrap();
     *
     * assert_eq!(a, -128);
     * assert_eq!(b, 127);
     *
     * // Out of range.
     * assert!(decoder.get_i8().is_err());
     * assert!(decoder.skip(4).is_ok());
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i8().is_err());
     * ```
     */
    pub fn get_i8(&self) -> Result<i8, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_i32()?;

        match i8::try_from(value) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::I8Conversion { offset, value, err })
            }
        }
    }

    /** Decodes an [`i32`] and casts it to an [`i16`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available, or
     * casting would be out of range for [`i16`]. In case of error, offset
     * remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff,
     *     0xff, 0xff, 0x7f, 0xff,
     *     0x00, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i16().unwrap();
     * let b = decoder.get_i16().unwrap();
     *
     * assert_eq!(a, -32768);
     * assert_eq!(b, 32767);
     *
     * // Out of range.
     * assert!(decoder.get_i16().is_err());
     * assert!(decoder.skip(4).is_ok());
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i16().is_err());
     * ```
     */
    pub fn get_i16(&self) -> Result<i16, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_i32()?;

        match i16::try_from(value) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::I16Conversion { offset, value, err })
            }
        }
    }

    /** Decodes an [`i32`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0xed, 0xcb, 0xa9, 0x88,
     *     0x12, 0x34, 0x56,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i32().unwrap();
     * let b = decoder.get_i32().unwrap();
     *
     * assert_eq!(a, 0x12345678);
     * assert_eq!(b, -0x12345678);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i16().is_err());
     * ```
     */
    pub fn get_i32(&self) -> Result<i32, XdrDecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(i32::from_be_bytes(bytes))
    }

    /** Decodes an [`i64`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x10,
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i64().unwrap();
     * let b = decoder.get_i64().unwrap();
     *
     * assert_eq!(a, 0x123456789abcdef0);
     * assert_eq!(b, -0x123456789abcdef0);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i64().is_err());
     * ```
     */
    pub fn get_i64(&self) -> Result<i64, XdrDecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(i64::from_be_bytes(bytes))
    }

    /** Decodes an [`u32`] and casts it to an [`u8`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available, or
     * casting would be out of range for [`u8`]. In case of error, offset
     * remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0xff,
     *     0x00, 0x00, 0x01, 0x00,
     *     0x00, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u8().unwrap();
     *
     * assert_eq!(a, 255);
     *
     * // Out of range.
     * assert!(decoder.get_u8().is_err());
     * assert!(decoder.skip(4).is_ok());
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u8().is_err());
     * ```
     */
    pub fn get_u8(&self) -> Result<u8, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;

        match u8::try_from(value) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::U8Conversion { offset, value, err })
            }
        }
    }

    /** Decodes an [`u32`] and casts it to an [`u16`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available, or
     * casting would be out of range for [`u16`]. In case of error, offset
     * remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0xff, 0xff,
     *     0x00, 0x01, 0x00, 0x00,
     *     0x00, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u16().unwrap();
     *
     * assert_eq!(a, 65535);
     *
     * // Out of range.
     * assert!(decoder.get_u16().is_err());
     * assert!(decoder.skip(4).is_ok());
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u16().is_err());
     * ```
     */
    pub fn get_u16(&self) -> Result<u16, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;

        match u16::try_from(value) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::U16Conversion { offset, value, err })
            }
        }
    }

    /** Decodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u32().unwrap();
     *
     * assert_eq!(a, 0xf2345678);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u32().is_err());
     * ```
     */
    pub fn get_u32(&self) -> Result<u32, XdrDecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(u32::from_be_bytes(bytes))
    }

    /** Decodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u64().unwrap();
     *
     * assert_eq!(a, 0xf23456789abcdef0);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn get_u64(&self) -> Result<u64, XdrDecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(u64::from_be_bytes(bytes))
    }

    /** Decodes a [`usize`] for array or string lengths.
     *
     * XDR uses unsigned 32 bit values for array and string lengths.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available.
     * In case of error, offset remains unchanged.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0xf2, 0x34, 0x56, 0x78,
     *     0xf2, 0x34, 0x56,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_usize().unwrap();
     *
     * assert_eq!(a, 0xf2345678);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_usize().is_err());
     * ```
     */
    pub fn get_usize(&self) -> Result<usize, XdrDecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;

        match usize::try_from(value) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::UsizeConversion { offset, value, err })
            }
        }
    }

    /** Decodes a [`str`].
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] if there are not enough bytes available, or
     * the bytes are not a valid UTF8 string. In case of error, offset remains
     * unchanged.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00,
     *     0x00, 0x00, 0x00, 0x02, 0x64, 0x65, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_str().unwrap();
     * let b = decoder.get_str().unwrap();
     *
     * assert_eq!(a, "abc");
     * assert_eq!(b, "de");
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_str().is_err());
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x05, 0x61, 0x62, 0x63, 0x64];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Need 1 more byte for string.
     * assert!(decoder.get_str().is_err());
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0xff, 0x00];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Malformed UTF8.
     * assert!(decoder.get_str().is_err());
     * ```
     */
    pub fn get_str(&self) -> Result<&str, XdrDecodeError> {
        let offset = self.offset.get();
        let length = self.get_usize()?;
        let data = self.get_bytes(length)?;

        match core::str::from_utf8(data) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset.set(offset);
                Err(XdrDecodeError::InvalidStr {
                    offset,
                    length,
                    err,
                })
            }
        }
    }

    /** Decodes a value using the [`GetFromXdrDecoder`] trait for F.
     *
     * # Errors
     *
     * Returns [`XdrDecodeError`] in case of decoding errors. In case of error,
     * offset remains unchanged.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::XdrDecoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x01,                         // bool
     *     0xff, 0xff, 0xff, 0x80,                         // i8
     *     0x00, 0x00, 0x00, 0x7f,                         // u8
     *     0xff, 0xff, 0x80, 0x00,                         // i16
     *     0x00, 0x00, 0x7f, 0xff,                         // u16
     *     0xed, 0xcb, 0xa9, 0x88,                         // i32
     *     0xf2, 0x34, 0x56, 0x78,                         // u32
     *     0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x10, // i64
     *     0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // u64
     *     0xf2, 0x34, 0x56, 0x78,                         // usize
     * ];
     *
     * // Create decoder.
     * let decoder = XdrDecoder::from_bytes(data);
     *
     * // Decode values.
     * let a: bool = decoder.get().unwrap();
     * let b: i8 = decoder.get().unwrap();
     * let c: u8 = decoder.get().unwrap();
     * let d: i16 = decoder.get().unwrap();
     * let e: u16 = decoder.get().unwrap();
     * let f: i32 = decoder.get().unwrap();
     * let g: u32 = decoder.get().unwrap();
     * let h: i64 = decoder.get().unwrap();
     * let i: u64 = decoder.get().unwrap();
     * let j: usize = decoder.get().unwrap();
     *
     * assert_eq!(a, true);
     * assert_eq!(b, -128);
     * assert_eq!(c, 127);
     * assert_eq!(d, -32768);
     * assert_eq!(e, 32767);
     * assert_eq!(f, -0x12345678);
     * assert_eq!(g, 0xf2345678);
     * assert_eq!(h, -0x123456789abcdef0);
     * assert_eq!(i, 0xf23456789abcdef0);
     * assert_eq!(j, 0xf2345678);
     *
     * assert!(decoder.is_empty());
     * ```
     */
    pub fn get<F: GetFromXdrDecoder>(&self) -> Result<F, XdrDecodeError> {
        GetFromXdrDecoder::get_from_decoder(self)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`GetFromXdrDecoder`] is a trait that gets from the [`XdrDecoder`] to the type.
pub trait GetFromXdrDecoder: Sized {
    /// Get the value from the decoder.
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<Self, XdrDecodeError>;
}

impl GetFromXdrDecoder for bool {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<bool, XdrDecodeError> {
        decoder.get_bool()
    }
}

impl GetFromXdrDecoder for f32 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<f32, XdrDecodeError> {
        decoder.get_f32()
    }
}

impl GetFromXdrDecoder for f64 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<f64, XdrDecodeError> {
        decoder.get_f64()
    }
}

impl GetFromXdrDecoder for i8 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<i8, XdrDecodeError> {
        decoder.get_i8()
    }
}

impl GetFromXdrDecoder for i16 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<i16, XdrDecodeError> {
        decoder.get_i16()
    }
}

impl GetFromXdrDecoder for i32 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<i32, XdrDecodeError> {
        decoder.get_i32()
    }
}

impl GetFromXdrDecoder for i64 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<i64, XdrDecodeError> {
        decoder.get_i64()
    }
}

impl GetFromXdrDecoder for u8 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<u8, XdrDecodeError> {
        decoder.get_u8()
    }
}

impl GetFromXdrDecoder for u16 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<u16, XdrDecodeError> {
        decoder.get_u16()
    }
}

impl GetFromXdrDecoder for u32 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<u32, XdrDecodeError> {
        decoder.get_u32()
    }
}

impl GetFromXdrDecoder for u64 {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<u64, XdrDecodeError> {
        decoder.get_u64()
    }
}

impl GetFromXdrDecoder for usize {
    fn get_from_decoder(decoder: &XdrDecoder<'_>) -> Result<usize, XdrDecodeError> {
        decoder.get_usize()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`XdrDecoder`] error.
#[derive(Debug)]
pub enum XdrDecodeError {
    /// End of input data.
    EndOfInput {
        /// Byte offset of data.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
    },

    /// Invalid boolean.
    InvalidBoolean {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
    },

    /// Invalid str.
    InvalidStr {
        /// Byte offset of data.
        offset: usize,
        /// Length of string.
        length: usize,
        /// Error.
        err: core::str::Utf8Error,
    },

    /// Size conversion error from [`i32`] to [`i8`].
    I8Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: i32,
        /// Error.
        err: num::TryFromIntError,
    },

    /// Size conversion error from [`i32`] to [`i16`].
    I16Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: i32,
        /// Error.
        err: num::TryFromIntError,
    },

    /// Size conversion error from [`u32`] to [`u8`].
    U8Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
        /// Error.
        err: num::TryFromIntError,
    },

    /// Rewind count is not a multiple of 4.
    RewindAlignment {
        /// Rewind count.
        count: usize,
    },

    /// Rewind past start.
    RewindPastStart {
        /// Byte offset of data.
        offset: usize,
        /// Number of bytes needed to rewind.
        count: usize,
    },

    /// Seek offset is not a multiple of 4.
    SeekAlignment {
        /// Byte offset of data.
        offset: usize,
    },

    /// Seek past end.
    SeekPastEnd {
        /// Requested offset.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
    },

    /// Skip count is not a multiple of 4.
    SkipAlignment {
        /// Skip count.
        count: usize,
    },

    /// Size conversion error from [`u32`] to [`u16`].
    U16Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
        /// Error.
        err: num::TryFromIntError,
    },

    /// Size conversion error from [`u32`] to [`usize`].
    UsizeConversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
        /// Error.
        err: num::TryFromIntError,
    },
}

impl fmt::Display for XdrDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrDecodeError::EndOfInput {
                offset,
                capacity,
                count,
            } => {
                write!(
                    f,
                    "XDR decode error, end of input at offset {offset} capacity {capacity} count {count}"
                )
            }
            XdrDecodeError::InvalidBoolean { offset, value } => {
                write!(f, "XDR invalid boolean at offset {offset} value {value}")
            }
            XdrDecodeError::InvalidStr {
                offset,
                length,
                err,
            } => {
                write!(
                    f,
                    "XDR decode error, invalid UTF8 str of length {length} at offset {offset} | {err}"
                )
            }
            XdrDecodeError::I8Conversion { offset, value, err } => {
                write!(
                    f,
                    "XDR decode error, i8 conversion at offset {offset}, value {value} | {err}"
                )
            }
            XdrDecodeError::I16Conversion { offset, value, err } => {
                write!(
                    f,
                    "XDR decode error, i16 conversion at offset {offset}, value {value} | {err}"
                )
            }
            XdrDecodeError::SkipAlignment { count } => {
                write!(f, "XDR skip not a multiple of 4 {count}")
            }
            XdrDecodeError::RewindAlignment { count } => {
                write!(f, "XDR rewind not a multiple of 4 {count}")
            }
            XdrDecodeError::RewindPastStart { offset, count } => {
                write!(f, "XDR rewind past start at offset {offset} count {count}")
            }
            XdrDecodeError::SeekAlignment { offset } => {
                write!(f, "XDR seek not a multiple of 4 {offset}")
            }
            XdrDecodeError::SeekPastEnd { offset, capacity } => {
                write!(
                    f,
                    "XDR decode error, seek past end to offset {offset} capacity {capacity}"
                )
            }
            XdrDecodeError::U8Conversion { offset, value, err } => {
                write!(
                    f,
                    "XDR decode error, u8 conversion at offset {offset}, value {value} | {err}"
                )
            }
            XdrDecodeError::U16Conversion { offset, value, err } => {
                write!(
                    f,
                    "XDR decode error, u16 conversion at offset {offset}, value {value} | {err}"
                )
            }
            XdrDecodeError::UsizeConversion { offset, value, err } => {
                write!(
                    f,
                    "XDR decode error, usize conversion at offset {offset}, value {value} | {err}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for XdrDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            XdrDecodeError::InvalidStr {
                offset: _,
                length: _,
                err,
            } => Some(err),
            XdrDecodeError::I8Conversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            XdrDecodeError::I16Conversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            XdrDecodeError::U8Conversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            XdrDecodeError::U16Conversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            XdrDecodeError::UsizeConversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            _ => None,
        }
    }
}
