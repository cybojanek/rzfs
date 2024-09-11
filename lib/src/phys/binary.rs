use core::fmt;
use core::marker::Sized;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/// [`BinaryDecoder`] error.
#[derive(Clone, Copy, Debug)]
pub enum BinaryDecodeError {
    /// End of input data.
    EndOfInput {
        /// Byte offset of data.
        offset: usize,
        /// Maximum offset.
        max_offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
    },

    /// Size conversion error from [`i32`] to [`i8`].
    I32toI8Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: i32,
    },

    /// Size conversion error from [`i32`] to [`i16`].
    I32toI16Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: i32,
    },

    /// Invalid boolean.
    InvalidBoolean {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u64,
    },

    /// Invalid clamp.
    InvalidClamp {
        /// Total capacity of data.
        capacity: usize,
        /// Offset.
        offset: usize,
        /// Length.
        length: usize,
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

    /// NonZero data.
    NonZero {
        /// Byte offset of data.
        offset: usize,
        /// Length of zeros wanted.
        count: usize,
    },

    /// Operations is not supported for this decoder.
    NotSupported {
        /// Unsupported operation.
        operation: &'static str,
    },

    /// Missing string NULL byte.
    MissingNull {
        /// Byte offset of data.
        offset: usize,
    },

    /// Rewind is not a multiple of alignment.
    RewindAlignment {
        /// Rewind count.
        count: usize,
        /// Alignment.
        alignment: usize,
    },

    /// Rewind past start.
    RewindPastStart {
        /// Byte offset of data.
        offset: usize,
        /// Minimum offset.
        min_offset: usize,
        /// Number of bytes needed to rewind.
        count: usize,
    },

    /// Seek offset is not a multiple of alignment.
    SeekAlignment {
        /// Byte offset of data.
        offset: usize,
        /// Alignment.
        alignment: usize,
    },

    /// Seek past end.
    SeekPastEnd {
        /// Requested offset.
        offset: usize,
        /// Maximum offset.
        max_offset: usize,
        /// Total capacity of data.
        capacity: usize,
    },

    /// Seek past start.
    SeekPastStart {
        /// Requested offset.
        offset: usize,
        /// Maximum offset.
        min_offset: usize,
        /// Total capacity of data.
        capacity: usize,
    },

    /// Skip count is not a multiple of alignment.
    SkipAlignment {
        /// Skip count.
        count: usize,
        /// Alignment.
        alignment: usize,
    },

    /// Size conversion error from [`u32`] to [`u8`].
    U32toU8Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
    },

    /// Size conversion error from [`u32`] to [`u16`].
    U32toU16Conversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u32,
    },

    /// Size conversion error from [`u32`] or [`u64`] to [`usize`].
    UsizeConversion {
        /// Byte offset of data.
        offset: usize,
        /// Value.
        value: u64,
    },
}

////////////////////////////////////////////////////////////////////////////////

impl fmt::Display for BinaryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryDecodeError::EndOfInput {
                offset,
                max_offset,
                capacity,
                count,
            } => {
                write!(
                    f,
                    "BinaryDecoder error, end of input at offset {offset} max_offset {max_offset} capacity {capacity} count {count}"
                )
            }
            BinaryDecodeError::I32toI8Conversion { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, i32 to i8 conversion at offset {offset}, value {value}"
                )
            }
            BinaryDecodeError::I32toI16Conversion { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, i32 to i16 conversion at offset {offset}, value {value}"
                )
            }
            BinaryDecodeError::InvalidBoolean { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, invalid boolean at offset {offset} value {value}"
                )
            }
            BinaryDecodeError::InvalidClamp {
                capacity,
                offset,
                length,
            } => {
                write!(
                    f,
                    "BinaryDecoder error, invalid clamp offset {offset} length {length}) for capacity {capacity}"
                )
            }
            BinaryDecodeError::InvalidStr {
                offset,
                length,
                err,
            } => {
                write!(
                    f,
                    "BinaryDecoder error, invalid UTF8 str of length {length} at offset {offset} | {err}"
                )
            }
            BinaryDecodeError::NonZero { offset, count } => {
                write!(
                    f,
                    "BinaryDecoder error, found non-zero in offset {offset} length {count}"
                )
            }
            BinaryDecodeError::NotSupported { operation } => write!(
                f,
                "BinaryDecoder error, operation {operation} not supported"
            ),
            BinaryDecodeError::MissingNull { offset } => {
                write!(
                    f,
                    "BinaryDecoder error, did not find NULL byte after offset {offset}"
                )
            }
            BinaryDecodeError::RewindAlignment { count, alignment } => {
                write!(
                    f,
                    "BinaryDecoder error, rewind {count} is not a multiple of {alignment}"
                )
            }
            BinaryDecodeError::RewindPastStart {
                offset,
                min_offset,
                count,
            } => {
                write!(f, "BinaryDecoder error, rewind past start at offset {offset} min_offset {min_offset} count {count}")
            }
            BinaryDecodeError::SeekAlignment { offset, alignment } => {
                write!(
                    f,
                    "BinaryDecoder error, seek {offset} is not a multiple of {alignment}"
                )
            }
            BinaryDecodeError::SeekPastEnd {
                offset,
                max_offset,
                capacity,
            } => {
                write!(
                    f,
                    "BinaryDecoder error, seek past end to offset {offset} max_offset {max_offset} capacity {capacity}"
                )
            }
            BinaryDecodeError::SeekPastStart {
                offset,
                min_offset,
                capacity,
            } => {
                write!(
                    f,
                    "BinaryDecoder error, seek past end to offset {offset} min_offset {min_offset} capacity {capacity}"
                )
            }
            BinaryDecodeError::SkipAlignment { count, alignment } => {
                write!(
                    f,
                    "BinaryDecoder error, skip {count} is not a multiple of {alignment}"
                )
            }
            BinaryDecodeError::U32toU8Conversion { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, u32 to u8 conversion at offset {offset}, value {value}"
                )
            }
            BinaryDecodeError::U32toU16Conversion { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, u32 to u16 conversion at offset {offset}, value {value}"
                )
            }
            BinaryDecodeError::UsizeConversion { offset, value } => {
                write!(
                    f,
                    "BinaryDecoder error, usize conversion at offset {offset}, value {value}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BinaryDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BinaryDecodeError::InvalidStr {
                offset: _,
                length: _,
                err,
            } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`BinaryDecoder`] buffer.
pub struct BinaryDecoderBuffer<'a> {
    /// Data.
    data: &'a [u8],

    /// Current offset into data.
    offset: usize,

    /// Minimum offset for decoding.
    min_offset: usize,

    /// Maximum offset for decoding.
    max_offset: usize,
}

impl fmt::Debug for BinaryDecoderBuffer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("BinaryDecoderBuffer")
            .field("length", &self.data.len())
            .field("offset", &self.offset)
            .field("min_offset", &self.min_offset)
            .field("max_offset", &self.max_offset)
            .finish()
    }
}

impl BinaryDecoderBuffer<'_> {
    fn from_bytes(data: &[u8]) -> BinaryDecoderBuffer<'_> {
        BinaryDecoderBuffer {
            data,
            offset: 0,
            min_offset: 0,
            max_offset: data.len(),
        }
    }

    fn from_bytes_clamped(
        data: &[u8],
        offset: usize,
        length: usize,
    ) -> Result<BinaryDecoderBuffer<'_>, BinaryDecodeError> {
        if offset > data.len() || data.len() - offset < length {
            return Err(BinaryDecodeError::InvalidClamp {
                capacity: data.len(),
                offset,
                length,
            });
        }

        Ok(BinaryDecoderBuffer {
            data,
            offset,
            min_offset: offset,
            max_offset: offset + length,
        })
    }

    fn capacity(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        self.max_offset.saturating_sub(self.min_offset)
    }

    fn check_need(&self, count: usize) -> Result<(), BinaryDecodeError> {
        if self.len() >= count {
            Ok(())
        } else {
            Err(BinaryDecodeError::EndOfInput {
                offset: self.offset,
                max_offset: self.max_offset,
                capacity: self.capacity(),
                count,
            })
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        self.max_offset.saturating_sub(self.offset)
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn reset(&mut self) {
        self.offset = self.min_offset;
    }

    fn rewind(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        let offset = self.offset;
        let min_offset = self.min_offset;
        if count > offset || offset - count < self.min_offset {
            return Err(BinaryDecodeError::RewindPastStart {
                offset,
                min_offset,
                count,
            });
        }
        self.offset -= count;

        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<(), BinaryDecodeError> {
        let capacity = self.capacity();

        let min_offset = self.min_offset;

        if offset < min_offset {
            return Err(BinaryDecodeError::SeekPastStart {
                offset,
                min_offset,
                capacity,
            });
        }

        let max_offset = self.max_offset;
        if offset > max_offset {
            return Err(BinaryDecodeError::SeekPastEnd {
                offset,
                max_offset,
                capacity,
            });
        }

        self.offset = offset;

        Ok(())
    }

    fn skip(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.check_need(count)?;
        self.offset += count;
        Ok(())
    }

    fn skip_zeros(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        let offset = self.offset;

        let bytes = self.get_bytes(count)?;
        for b in bytes {
            if *b != 0 {
                return Err(BinaryDecodeError::NonZero { offset, count });
            }
        }

        Ok(())
    }

    fn is_skip_zeros(&mut self, count: usize) -> Result<bool, BinaryDecodeError> {
        let offset = self.offset;

        let bytes = self.get_bytes(count)?;
        for b in bytes {
            if *b != 0 {
                // Roll back the offset change.
                self.offset = offset;
                return Ok(false);
            }
        }

        Ok(true)
    }

    /** Returns 1 byte.
     *
     * # Errors
     *
     * Returns [`BinaryDecodeError`] if there are not enough bytes to decode.
     */
    fn get_1_byte(&mut self) -> Result<u8, BinaryDecodeError> {
        self.check_need(1)?;

        let offset = self.offset;
        let value = self.data[offset];
        self.offset += 1;

        Ok(value)
    }

    /** Returns 2 bytes.
     *
     * # Errors
     *
     * Returns [`BinaryDecodeError`] if there are not enough bytes to decode.
     */
    fn get_2_bytes(&mut self) -> Result<[u8; 2], BinaryDecodeError> {
        self.check_need(2)?;

        let start = self.offset;
        let end = start + 2;

        self.offset = end;

        Ok(<[u8; 2]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 4 bytes.
     *
     * # Errors
     *
     * Returns [`BinaryDecodeError`] if there are not enough bytes to decode.
     */
    fn get_4_bytes(&mut self) -> Result<[u8; 4], BinaryDecodeError> {
        self.check_need(4)?;

        let start = self.offset;
        let end = start + 4;

        self.offset = end;

        Ok(<[u8; 4]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 8 bytes.
     *
     * # Errors
     *
     * Returns [`BinaryDecodeError`] if there are not enough bytes to decode.
     */
    fn get_8_bytes(&mut self) -> Result<[u8; 8], BinaryDecodeError> {
        self.check_need(8)?;

        let start = self.offset;
        let end = start + 8;

        self.offset = end;

        Ok(<[u8; 8]>::try_from(&self.data[start..end]).unwrap())
    }
}

impl<'a> BinaryDecoderBuffer<'a> {
    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn get_bytes(&mut self, length: usize) -> Result<&'a [u8], BinaryDecodeError> {
        // Check bounds for length.
        self.check_need(length)?;

        // Start and end of bytes.
        let start = self.offset;
        let end = start + length;

        // Consume bytes.
        let value = &self.data[start..end];
        self.offset = end;

        // Return bytes.
        Ok(value)
    }

    fn get_str(&mut self, length: usize) -> Result<&'a str, BinaryDecodeError> {
        let offset = self.offset;
        let bytes = self.get_bytes(length)?;

        match core::str::from_utf8(bytes) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.offset = offset;
                Err(BinaryDecodeError::InvalidStr {
                    offset,
                    length,
                    err,
                })
            }
        }
    }

    /// Gets a string up to the next NULL byte. Consumes NULL byte.
    fn get_str_null(&mut self) -> Result<&'a str, BinaryDecodeError> {
        let null_offset = self.offset;

        while null_offset < self.max_offset {
            if self.data[null_offset] == 0 {
                // Get the string.
                let start = self.offset;
                let end = null_offset;

                let bytes = &self.data[start..end];

                let value = match core::str::from_utf8(bytes) {
                    Ok(v) => v,
                    Err(err) => {
                        return Err(BinaryDecodeError::InvalidStr {
                            offset: self.offset,
                            length: end - start,
                            err,
                        })
                    }
                };

                // Skip NULL byte.
                self.offset = null_offset + 1;

                return Ok(value);
            }
        }

        Err(BinaryDecodeError::MissingNull {
            offset: self.offset,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Decodes bytes into numbers, bytes, and strings.
pub trait BinaryDecoder<'a> {
    /** Returns the source data length.
     *
     * Remains unchanged while decoding values.
     */
    fn capacity(&self) -> usize;

    /// Returns the full underlying data bytes.
    fn data(&self) -> &'a [u8];

    /// Returns true if there are no more bytes to decode.
    fn is_empty(&self) -> bool;

    /// Returns length of bytes remaining to be processed.
    fn len(&self) -> usize;

    /// Gets the current offset in bytes.
    fn offset(&self) -> usize;

    /// Resets the decoder to the start of the data.
    fn reset(&mut self);

    /// Rewinds `count` bytes.
    fn rewind(&mut self, count: usize) -> Result<(), BinaryDecodeError>;

    /// Seeks to offset.
    fn seek(&mut self, offset: usize) -> Result<(), BinaryDecodeError>;

    /// Skips to offset.
    fn skip(&mut self, count: usize) -> Result<(), BinaryDecodeError>;

    /// Skips zeros. Errors if any of the next `count` bytes is not a zero.
    fn skip_zeros(&mut self, count: usize) -> Result<(), BinaryDecodeError>;

    /// Skips `count` zeroes and returns `true`, or returns `false`.
    fn is_skip_zeros(&mut self, count: usize) -> Result<bool, BinaryDecodeError>;

    /** Decodes a [`bool`].
     *
     * Behavior is decoder implementation specific.
     */
    fn get_bool(&mut self) -> Result<bool, BinaryDecodeError>;

    /** Decodes an array of bytes.
     *
     * Behavior is decoder implementation specific.
     */
    fn get_bytes(&mut self) -> Result<&'a [u8], BinaryDecodeError>;

    /** Decodes `length` number of bytes.
     *
     * Behavior is decoder implementation specific.
     */
    fn get_bytes_n(&mut self, length: usize) -> Result<&'a [u8], BinaryDecodeError>;

    /** Decodes a string.
     *
     * Behavior is decoder implementation specific.
     */
    fn get_str(&mut self) -> Result<&'a str, BinaryDecodeError>;

    /** Decodes string of `length` number of bytes.
     *
     * Behavior is decoder implementation specific.
     */
    fn get_str_n(&mut self, length: usize) -> Result<&'a str, BinaryDecodeError>;

    /// Decodes an [`f32`].
    fn get_f32(&mut self) -> Result<f32, BinaryDecodeError>;

    /// Decodes an [`f64`].
    fn get_f64(&mut self) -> Result<f64, BinaryDecodeError>;

    /// Decodes an [`i8`].
    fn get_i8(&mut self) -> Result<i8, BinaryDecodeError>;

    /// Decodes an [`i16`].
    fn get_i16(&mut self) -> Result<i16, BinaryDecodeError>;

    /// Decodes an [`i32`].
    fn get_i32(&mut self) -> Result<i32, BinaryDecodeError>;

    /// Decodes an [`i64`].
    fn get_i64(&mut self) -> Result<i64, BinaryDecodeError>;

    /// Decodes a [`u8`].
    fn get_u8(&mut self) -> Result<u8, BinaryDecodeError>;

    /// Decodes a [`u16`].
    fn get_u16(&mut self) -> Result<u16, BinaryDecodeError>;

    /// Decodes a [`u32`].
    fn get_u32(&mut self) -> Result<u32, BinaryDecodeError>;

    /// Decodes a [`u64`].
    fn get_u64(&mut self) -> Result<u64, BinaryDecodeError>;

    /// Decodes a [`u32`] and converts it to a [`usize`].
    fn get_usize_32(&mut self) -> Result<usize, BinaryDecodeError> {
        let offset = self.offset();
        let value = self.get_u32()?;

        match usize::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::UsizeConversion {
                offset,
                value: value.into(),
            }),
        }
    }

    /// Decodes a [`u64`] and converts it to a [`usize`].
    fn get_usize_64(&mut self) -> Result<usize, BinaryDecodeError> {
        let offset = self.offset();
        let value = self.get_u64()?;

        match usize::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::UsizeConversion { offset, value }),
        }
    }

    /// Decodes a value using the [`GetValueFromBinaryDecoder`] trait for F.
    fn get<F: GetValueFromBinaryDecoder<'a>>(&mut self) -> Result<F, BinaryDecodeError>
    where
        Self: Sized,
    {
        GetValueFromBinaryDecoder::get_from_decoder(self)
    }

    /// Decodes a value using the [`GetNValueFromBinaryDecoder`] trait for F.
    fn get_n<F: GetNValueFromBinaryDecoder<'a>>(
        &mut self,
        length: usize,
    ) -> Result<F, BinaryDecodeError>
    where
        Self: Sized,
    {
        GetNValueFromBinaryDecoder::get_from_decoder_n(self, length)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`GetValueFromBinaryDecoder`] is a trait that gets from the [`BinaryDecoder`] to the type.
pub trait GetValueFromBinaryDecoder<'a>: Sized {
    /// Get the value from the decoder.
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'a>) -> Result<Self, BinaryDecodeError>;
}

impl GetValueFromBinaryDecoder<'_> for bool {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_bool()
    }
}

impl<'a> GetValueFromBinaryDecoder<'a> for &'a [u8] {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'a>) -> Result<Self, BinaryDecodeError> {
        decoder.get_bytes()
    }
}

impl<'a> GetValueFromBinaryDecoder<'a> for &'a str {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'a>) -> Result<Self, BinaryDecodeError> {
        decoder.get_str()
    }
}

impl GetValueFromBinaryDecoder<'_> for f32 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_f32()
    }
}

impl GetValueFromBinaryDecoder<'_> for f64 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_f64()
    }
}

impl GetValueFromBinaryDecoder<'_> for i8 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_i8()
    }
}

impl GetValueFromBinaryDecoder<'_> for i16 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_i16()
    }
}

impl GetValueFromBinaryDecoder<'_> for i32 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_i32()
    }
}

impl GetValueFromBinaryDecoder<'_> for i64 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_i64()
    }
}

impl GetValueFromBinaryDecoder<'_> for u8 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_u8()
    }
}

impl GetValueFromBinaryDecoder<'_> for u16 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_u16()
    }
}

impl GetValueFromBinaryDecoder<'_> for u32 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_u32()
    }
}

impl GetValueFromBinaryDecoder<'_> for u64 {
    fn get_from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Self, BinaryDecodeError> {
        decoder.get_u64()
    }
}

/// [`GetNValueFromBinaryDecoder`] is a trait that gets from the [`BinaryDecoder`] to the type.
pub trait GetNValueFromBinaryDecoder<'a>: Sized {
    /// Get the value from the decoder.
    fn get_from_decoder_n(
        decoder: &mut dyn BinaryDecoder<'a>,
        length: usize,
    ) -> Result<Self, BinaryDecodeError>;
}

impl<'a> GetNValueFromBinaryDecoder<'a> for &'a [u8] {
    fn get_from_decoder_n(
        decoder: &mut dyn BinaryDecoder<'a>,
        length: usize,
    ) -> Result<Self, BinaryDecodeError> {
        decoder.get_bytes_n(length)
    }
}

impl<'a> GetNValueFromBinaryDecoder<'a> for &'a str {
    fn get_from_decoder_n(
        decoder: &mut dyn BinaryDecoder<'a>,
        length: usize,
    ) -> Result<Self, BinaryDecodeError> {
        decoder.get_str_n(length)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Big Endian decoder.
pub struct BigEndianDecoder<'a> {
    buffer: BinaryDecoderBuffer<'a>,
}

impl<'a> BinaryDecoder<'a> for BigEndianDecoder<'a> {
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    fn data(&self) -> &'a [u8] {
        self.buffer.data()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn offset(&self) -> usize {
        self.buffer.offset()
    }

    fn reset(&mut self) {
        self.buffer.reset()
    }

    fn rewind(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.rewind(count)
    }

    fn seek(&mut self, offset: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.seek(offset)
    }

    fn skip(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.skip(count)
    }

    fn skip_zeros(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.skip_zeros(count)
    }

    fn is_skip_zeros(&mut self, count: usize) -> Result<bool, BinaryDecodeError> {
        self.buffer.is_skip_zeros(count)
    }

    fn get_bool(&mut self) -> Result<bool, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_u8()?;

        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BinaryDecodeError::InvalidBoolean {
                offset,
                value: value.into(),
            }),
        }
    }

    fn get_bytes(&mut self) -> Result<&'a [u8], BinaryDecodeError> {
        Err(BinaryDecodeError::NotSupported {
            operation: "get_bytes",
        })
    }

    fn get_bytes_n(&mut self, length: usize) -> Result<&'a [u8], BinaryDecodeError> {
        self.buffer.get_bytes(length)
    }

    fn get_str(&mut self) -> Result<&'a str, BinaryDecodeError> {
        self.buffer.get_str_null()
    }

    fn get_str_n(&mut self, length: usize) -> Result<&'a str, BinaryDecodeError> {
        self.buffer.get_str(length)
    }

    fn get_f32(&mut self) -> Result<f32, BinaryDecodeError> {
        Ok(f32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_f64(&mut self) -> Result<f64, BinaryDecodeError> {
        Ok(f64::from_be_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_i8(&mut self) -> Result<i8, BinaryDecodeError> {
        let value = self.buffer.get_1_byte()?;
        Ok(value as i8)
    }

    fn get_i16(&mut self) -> Result<i16, BinaryDecodeError> {
        Ok(i16::from_be_bytes(self.buffer.get_2_bytes()?))
    }

    fn get_i32(&mut self) -> Result<i32, BinaryDecodeError> {
        Ok(i32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_i64(&mut self) -> Result<i64, BinaryDecodeError> {
        Ok(i64::from_be_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_u8(&mut self) -> Result<u8, BinaryDecodeError> {
        self.buffer.get_1_byte()
    }

    fn get_u16(&mut self) -> Result<u16, BinaryDecodeError> {
        Ok(u16::from_be_bytes(self.buffer.get_2_bytes()?))
    }

    fn get_u32(&mut self) -> Result<u32, BinaryDecodeError> {
        Ok(u32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_u64(&mut self) -> Result<u64, BinaryDecodeError> {
        Ok(u64::from_be_bytes(self.buffer.get_8_bytes()?))
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Little Endian decoder.
pub struct LittleEndianDecoder<'a> {
    buffer: BinaryDecoderBuffer<'a>,
}

impl<'a> BinaryDecoder<'a> for LittleEndianDecoder<'a> {
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    fn data(&self) -> &'a [u8] {
        self.buffer.data()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn offset(&self) -> usize {
        self.buffer.offset()
    }

    fn reset(&mut self) {
        self.buffer.reset()
    }

    fn rewind(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.rewind(count)
    }

    fn seek(&mut self, offset: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.seek(offset)
    }

    fn skip(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.skip(count)
    }

    fn skip_zeros(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        self.buffer.skip_zeros(count)
    }

    fn is_skip_zeros(&mut self, count: usize) -> Result<bool, BinaryDecodeError> {
        self.buffer.is_skip_zeros(count)
    }

    fn get_bool(&mut self) -> Result<bool, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_u8()?;

        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BinaryDecodeError::InvalidBoolean {
                offset,
                value: value.into(),
            }),
        }
    }

    fn get_bytes(&mut self) -> Result<&'a [u8], BinaryDecodeError> {
        Err(BinaryDecodeError::NotSupported {
            operation: "get_bytes",
        })
    }

    fn get_bytes_n(&mut self, length: usize) -> Result<&'a [u8], BinaryDecodeError> {
        self.buffer.get_bytes(length)
    }

    fn get_str(&mut self) -> Result<&'a str, BinaryDecodeError> {
        self.buffer.get_str_null()
    }

    fn get_str_n(&mut self, length: usize) -> Result<&'a str, BinaryDecodeError> {
        self.buffer.get_str(length)
    }

    fn get_f32(&mut self) -> Result<f32, BinaryDecodeError> {
        Ok(f32::from_le_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_f64(&mut self) -> Result<f64, BinaryDecodeError> {
        Ok(f64::from_le_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_i8(&mut self) -> Result<i8, BinaryDecodeError> {
        let value = self.buffer.get_1_byte()?;
        Ok(value as i8)
    }

    fn get_i16(&mut self) -> Result<i16, BinaryDecodeError> {
        Ok(i16::from_le_bytes(self.buffer.get_2_bytes()?))
    }

    fn get_i32(&mut self) -> Result<i32, BinaryDecodeError> {
        Ok(i32::from_le_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_i64(&mut self) -> Result<i64, BinaryDecodeError> {
        Ok(i64::from_le_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_u8(&mut self) -> Result<u8, BinaryDecodeError> {
        self.buffer.get_1_byte()
    }

    fn get_u16(&mut self) -> Result<u16, BinaryDecodeError> {
        Ok(u16::from_le_bytes(self.buffer.get_2_bytes()?))
    }

    fn get_u32(&mut self) -> Result<u32, BinaryDecodeError> {
        Ok(u32::from_le_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_u64(&mut self) -> Result<u64, BinaryDecodeError> {
        Ok(u64::from_le_bytes(self.buffer.get_8_bytes()?))
    }
}

////////////////////////////////////////////////////////////////////////////////

/// XDR decoder.
#[derive(Debug)]
pub struct XdrDecoder<'a> {
    buffer: BinaryDecoderBuffer<'a>,
}

impl XdrDecoder<'_> {
    const ALIGNMENT: usize = 4;
}

impl XdrDecoder<'_> {
    /// Calculate and consume padding for the given `length`.
    fn consume_padding(&mut self, length: usize) -> Result<(), BinaryDecodeError> {
        let remainder = length % Self::ALIGNMENT;
        if remainder != 0 {
            let padding = Self::ALIGNMENT - remainder;
            self.buffer.skip_zeros(padding)?;
        }

        Ok(())
    }

    /// Initializes an [`XdrDecoder`] from a slice of bytes.
    pub fn from_bytes(data: &[u8]) -> XdrDecoder<'_> {
        XdrDecoder {
            buffer: BinaryDecoderBuffer::from_bytes(data),
        }
    }

    /** Initializes an [`XdrDecoder`] from a slice of clamped bytes.
     *
     * The same as [`XdrDecoder::from_bytes`], but clamps minimum and maximum
     * offsets.
     */
    pub fn from_bytes_clamped(
        data: &[u8],
        offset: usize,
        length: usize,
    ) -> Result<XdrDecoder<'_>, BinaryDecodeError> {
        Ok(XdrDecoder {
            buffer: BinaryDecoderBuffer::from_bytes_clamped(data, offset, length)?,
        })
    }
}

impl<'a> BinaryDecoder<'a> for XdrDecoder<'a> {
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    fn data(&self) -> &'a [u8] {
        self.buffer.data()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn offset(&self) -> usize {
        self.buffer.offset()
    }

    fn reset(&mut self) {
        self.buffer.reset()
    }

    fn rewind(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        if (count % Self::ALIGNMENT) != 0 {
            return Err(BinaryDecodeError::RewindAlignment {
                count,
                alignment: Self::ALIGNMENT,
            });
        }
        self.buffer.rewind(count)
    }

    fn seek(&mut self, offset: usize) -> Result<(), BinaryDecodeError> {
        if (offset % Self::ALIGNMENT) != 0 {
            return Err(BinaryDecodeError::SeekAlignment {
                offset,
                alignment: Self::ALIGNMENT,
            });
        }
        self.buffer.seek(offset)
    }

    fn skip(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        if (count % Self::ALIGNMENT) != 0 {
            return Err(BinaryDecodeError::SkipAlignment {
                count,
                alignment: Self::ALIGNMENT,
            });
        }
        self.buffer.skip(count)
    }

    fn skip_zeros(&mut self, count: usize) -> Result<(), BinaryDecodeError> {
        if (count % Self::ALIGNMENT) != 0 {
            return Err(BinaryDecodeError::SkipAlignment {
                count,
                alignment: Self::ALIGNMENT,
            });
        }
        self.buffer.skip_zeros(count)
    }

    fn is_skip_zeros(&mut self, count: usize) -> Result<bool, BinaryDecodeError> {
        if (count % Self::ALIGNMENT) != 0 {
            return Err(BinaryDecodeError::SkipAlignment {
                count,
                alignment: Self::ALIGNMENT,
            });
        }
        self.buffer.is_skip_zeros(count)
    }

    fn get_bool(&mut self) -> Result<bool, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_u32()?;

        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BinaryDecodeError::InvalidBoolean {
                offset,
                value: value.into(),
            }),
        }
    }

    fn get_bytes(&mut self) -> Result<&'a [u8], BinaryDecodeError> {
        let length = self.get_usize_32()?;
        self.get_bytes_n(length)
    }

    fn get_bytes_n(&mut self, length: usize) -> Result<&'a [u8], BinaryDecodeError> {
        let value = self.buffer.get_bytes(length)?;
        self.consume_padding(length)?;
        Ok(value)
    }

    fn get_str(&mut self) -> Result<&'a str, BinaryDecodeError> {
        let length = self.get_usize_32()?;
        self.get_str_n(length)
    }

    fn get_str_n(&mut self, length: usize) -> Result<&'a str, BinaryDecodeError> {
        let value = self.buffer.get_str(length)?;
        self.consume_padding(length)?;
        Ok(value)
    }

    fn get_f32(&mut self) -> Result<f32, BinaryDecodeError> {
        Ok(f32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_f64(&mut self) -> Result<f64, BinaryDecodeError> {
        Ok(f64::from_be_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_i8(&mut self) -> Result<i8, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_i32()?;

        match i8::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::I32toI8Conversion { offset, value }),
        }
    }

    fn get_i16(&mut self) -> Result<i16, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_i32()?;

        match i16::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::I32toI16Conversion { offset, value }),
        }
    }

    fn get_i32(&mut self) -> Result<i32, BinaryDecodeError> {
        Ok(i32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_i64(&mut self) -> Result<i64, BinaryDecodeError> {
        Ok(i64::from_be_bytes(self.buffer.get_8_bytes()?))
    }

    fn get_u8(&mut self) -> Result<u8, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_u32()?;

        match u8::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::U32toU8Conversion { offset, value }),
        }
    }

    fn get_u16(&mut self) -> Result<u16, BinaryDecodeError> {
        let offset = self.buffer.offset;
        let value = self.get_u32()?;

        match u16::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(BinaryDecodeError::U32toU16Conversion { offset, value }),
        }
    }

    fn get_u32(&mut self) -> Result<u32, BinaryDecodeError> {
        Ok(u32::from_be_bytes(self.buffer.get_4_bytes()?))
    }

    fn get_u64(&mut self) -> Result<u64, BinaryDecodeError> {
        Ok(u64::from_be_bytes(self.buffer.get_8_bytes()?))
    }
}

////////////////////////////////////////////////////////////////////////////////
