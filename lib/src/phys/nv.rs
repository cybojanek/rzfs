// SPDX-License-Identifier: GPL-2.0 OR MIT

/*! Name Value decoder and encoder.
 *
 * A Name Value list is a sequence of Name Value [`NvPair`].
 *
 * Header
 * ======
 * The first four bytes of the parent list are:
 * - [`NvEncoding`]
 * - [`NvEndianOrder`]
 * - Two zero bytes
 *
 * [`NvEncoding`] and [`NvEndianOrder`] specify how the rest of the data is encoded.
 * Nested lists inherit [`NvEncoding`] and [`NvEndianOrder`] from the parent list.
 *
 * List
 * ====
 * A list starts with:
 * - [`u32`] version
 * - [`u32`] flags
 *
 * And is followed by a sequence of [`NvPair`].
 *
 * NvPair
 * ======
 * An [`NvPair`] starts with:
 * - [`u32`] encoded size (of entire pair, including this number)
 * - [`u32`] decoded size (in memory TODO: how is this computed?)
 *
 * If both values are zero, then this is the end of the list.
 *
 * If they are not zero, then what follows is:
 * - [`String`] name
 * - [`u32`] [`NvDataType`]
 * - [`u32`] count for number of values in this pair
 *   - 0 for [`NvDataType::Boolean`].
 *   - 1 for all non array types [`NvDataType::Uint32`] etc...
 *   - 0 to N for array types [`NvDataType::Uint32Array`] etc...
 * - [`NvDataValue`] whose encoding corresponds to [`NvDataType`] and count
 *
 * Booleans
 * ========
 * A note about the two different boolean data types:
 * - [`NvDataType::Boolean`] has a count of 0, has no value, and is used as a flag.
 *   For example, the `features_for_read` list contains a sequence of flags,
 *   such as `org.openzfs:blake3`
 * - [`NvDataType::BooleanValue`] has a count of 1, and an actual value that can
 *   be [`true`] or [`false`]
 */
use core::fmt;
use core::fmt::Display;
use core::marker::PhantomData;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::phys::{EndianOrder, GetFromXdrDecoder, XdrDecodeError, XdrDecoder};

////////////////////////////////////////////////////////////////////////////////

/// Name Value List byte order.
#[derive(Clone, Copy, Debug)]
pub enum NvEndianOrder {
    /// Big byte order.
    Big = 0,

    /// Little byte order.
    Little = 1,
}

impl From<NvEndianOrder> for EndianOrder {
    fn from(val: NvEndianOrder) -> EndianOrder {
        match val {
            NvEndianOrder::Big => EndianOrder::Big,
            NvEndianOrder::Little => EndianOrder::Little,
        }
    }
}

impl Display for NvEndianOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvEndianOrder::Big => write!(f, "Big"),
            NvEndianOrder::Little => write!(f, "Little"),
        }
    }
}

impl From<NvEndianOrder> for u8 {
    fn from(val: NvEndianOrder) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for NvEndianOrder {
    type Error = NvDecodeError;

    /** Try converting from a [`u8`] to a [`NvEndianOrder`].
     *
     * # Errors
     *
     * Returns [`NvDecodeError`] in case of an unknown [`NvEndianOrder`].
     */
    fn try_from(order: u8) -> Result<Self, Self::Error> {
        match order {
            0 => Ok(NvEndianOrder::Big),
            1 => Ok(NvEndianOrder::Little),
            _ => Err(NvDecodeError::UnknownEndian { order }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Name Value List encoding.
#[derive(Clone, Copy, Debug)]
pub enum NvEncoding {
    /// Native binary encoding.
    Native = 0,

    /// XDR encoding.
    Xdr = 1,
}

impl Display for NvEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvEncoding::Native => write!(f, "Native"),
            NvEncoding::Xdr => write!(f, "Xdr"),
        }
    }
}

impl From<NvEncoding> for u8 {
    fn from(val: NvEncoding) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for NvEncoding {
    type Error = NvDecodeError;

    /** Try converting from a [`u8`] to a [`NvEncoding`].
     *
     * # Errors
     *
     * Returns [`NvDecodeError`] in case of an unknown [`NvEncoding`].
     */
    fn try_from(encoding: u8) -> Result<Self, Self::Error> {
        match encoding {
            0 => Ok(NvEncoding::Native),
            1 => Ok(NvEncoding::Xdr),
            _ => Err(NvDecodeError::UnknownEncoding { encoding }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Name Value List Unique.
#[derive(Clone, Copy, Debug)]
pub enum NvUnique {
    /// No unique constraints.
    None = 0,

    /// Name must be unique.
    Name = 1,

    /// Namd and type must be unique.
    NameType = 2,
}

impl Display for NvUnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvUnique::None => write!(f, "None"),
            NvUnique::Name => write!(f, "Name"),
            NvUnique::NameType => write!(f, "NameType"),
        }
    }
}

impl From<NvUnique> for u8 {
    fn from(val: NvUnique) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for NvUnique {
    type Error = NvDecodeError;

    /** Try converting from a [`u8`] to a [`NvUnique`].
     *
     * # Errors
     *
     * Returns [`NvDecodeError`] in case of an unknown [`NvUnique`].
     */
    fn try_from(unique: u8) -> Result<Self, Self::Error> {
        match unique {
            0 => Ok(NvUnique::None),
            1 => Ok(NvUnique::Name),
            2 => Ok(NvUnique::NameType),
            _ => Err(NvDecodeError::UnknownUnique { unique }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Name Value Pair Data Type.
#[derive(Clone, Copy, Debug)]
pub enum NvDataType {
    /// A boolean flag (no value).
    Boolean = 1,

    /// A [u8] byte.
    Byte = 2,

    /// A [i16].
    Int16 = 3,

    /// A [u16].
    Uint16 = 4,

    /// A [i32].
    Int32 = 5,

    /// A [u32].
    Uint32 = 6,

    /// A [i64].
    Int64 = 7,

    /// A [u64].
    Uint64 = 8,

    /// A [str].
    String = 9,

    /// An array of [u8] bytes.
    ByteArray = 10,

    /// An array of [i16].
    Int16Array = 11,

    /// An array of [u16].
    Uint16Array = 12,

    /// An array of [i32].
    Int32Array = 13,

    /// An array of [u32].
    Uint32Array = 14,

    /// An array of [i64].
    Int64Array = 15,

    /// An array of [u64].
    Uint64Array = 16,

    /// An array of [str].
    StringArray = 17,

    /// High resolution time in nanoseconds.
    HrTime = 18,

    /// A [`NvList`].
    NvList = 19,

    /// An array of nested [`NvList`].
    NvListArray = 20,

    /// A [bool].
    BooleanValue = 21,

    /// A [i8].
    Int8 = 22,

    /// A [u8].
    Uint8 = 23,

    /// An array of [bool].
    BooleanArray = 24,

    /// An array of [i8].
    Int8Array = 25,

    /// An array of [u8].
    Uint8Array = 26,

    /// A [f64].
    Double = 27,
}

impl Display for NvDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvDataType::Boolean => write!(f, "Boolean"),
            NvDataType::Byte => write!(f, "Byte"),
            NvDataType::Int16 => write!(f, "Int16"),
            NvDataType::Uint16 => write!(f, "Uint16"),
            NvDataType::Int32 => write!(f, "Int32"),
            NvDataType::Uint32 => write!(f, "Uint32"),
            NvDataType::Int64 => write!(f, "Int64"),
            NvDataType::Uint64 => write!(f, "Uint64"),
            NvDataType::String => write!(f, "String"),
            NvDataType::ByteArray => write!(f, "ByteArray"),
            NvDataType::Int16Array => write!(f, "Int16Array"),
            NvDataType::Uint16Array => write!(f, "Uint16Array"),
            NvDataType::Int32Array => write!(f, "Int32Array"),
            NvDataType::Uint32Array => write!(f, "Uint32Array"),
            NvDataType::Int64Array => write!(f, "Int64Array"),
            NvDataType::Uint64Array => write!(f, "Uint64Array"),
            NvDataType::StringArray => write!(f, "StringArray"),
            NvDataType::HrTime => write!(f, "HrTime"),
            NvDataType::NvList => write!(f, "NvList"),
            NvDataType::NvListArray => write!(f, "NvListArray"),
            NvDataType::BooleanValue => write!(f, "BooleanValue"),
            NvDataType::Int8 => write!(f, "Int8"),
            NvDataType::Uint8 => write!(f, "Uint8"),
            NvDataType::BooleanArray => write!(f, "BooleanArray"),
            NvDataType::Int8Array => write!(f, "Int8Array"),
            NvDataType::Uint8Array => write!(f, "Uint8Array"),
            NvDataType::Double => write!(f, "Double"),
        }
    }
}

impl From<NvDataType> for u32 {
    fn from(val: NvDataType) -> u32 {
        val as u32
    }
}

impl TryFrom<u32> for NvDataType {
    type Error = NvDecodeError;

    /** Try converting from a [`u32`] to a [`NvDataType`].
     *
     * # Errors
     *
     * Returns [`NvDecodeError`] in case of an unknown [`NvDataType`].
     */
    fn try_from(data_type: u32) -> Result<Self, Self::Error> {
        match data_type {
            1 => Ok(NvDataType::Boolean),
            2 => Ok(NvDataType::Byte),
            3 => Ok(NvDataType::Int16),
            4 => Ok(NvDataType::Uint16),
            5 => Ok(NvDataType::Int32),
            6 => Ok(NvDataType::Uint32),
            7 => Ok(NvDataType::Int64),
            8 => Ok(NvDataType::Uint64),
            9 => Ok(NvDataType::String),
            10 => Ok(NvDataType::ByteArray),
            11 => Ok(NvDataType::Int16Array),
            12 => Ok(NvDataType::Uint16Array),
            13 => Ok(NvDataType::Int32Array),
            14 => Ok(NvDataType::Uint32Array),
            15 => Ok(NvDataType::Int64Array),
            16 => Ok(NvDataType::Uint64Array),
            17 => Ok(NvDataType::StringArray),
            18 => Ok(NvDataType::HrTime),
            19 => Ok(NvDataType::NvList),
            20 => Ok(NvDataType::NvListArray),
            21 => Ok(NvDataType::BooleanValue),
            22 => Ok(NvDataType::Int8),
            23 => Ok(NvDataType::Uint8),
            24 => Ok(NvDataType::BooleanArray),
            25 => Ok(NvDataType::Int8Array),
            26 => Ok(NvDataType::Uint8Array),
            27 => Ok(NvDataType::Double),
            _ => Err(NvDecodeError::UnknownDataType { data_type }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Checks the [`NvDataType`] and count are valid, and computes the array size.
 *
 * NOTE: The array size will be 0 for non-array types, as well as
 *       [`NvDataType::ByteArray`], [`NvDataType::StringArray`], and
 *       [`NvDataType::NvListArray`].
 *
 * # Errors
 *
 * Returns [`NvDecodeError::InvalidCount`] if count is invalid.
 */
fn check_data_type_count_and_get_array_size(
    data_type: NvDataType,
    count: usize,
) -> Result<usize, NvDecodeError> {
    let array_element_size = match data_type {
        // Boolean has no value, and it is not an array, so the array size is 0.
        NvDataType::Boolean => match count {
            0 => 0,
            _ => return Err(NvDecodeError::InvalidCount { data_type, count }),
        },

        // Non arrays have only one, and the array size is 0.
        NvDataType::Byte
        | NvDataType::Int16
        | NvDataType::Uint16
        | NvDataType::Int32
        | NvDataType::Uint32
        | NvDataType::Int64
        | NvDataType::Uint64
        | NvDataType::String
        | NvDataType::HrTime
        | NvDataType::NvList
        | NvDataType::BooleanValue
        | NvDataType::Int8
        | NvDataType::Uint8
        | NvDataType::Double => match count {
            1 => 0,
            _ => return Err(NvDecodeError::InvalidCount { data_type, count }),
        },

        // Arrays have from 0 to N values, and these types are 4 bytes per element.
        NvDataType::BooleanArray
        | NvDataType::Int16Array
        | NvDataType::Uint16Array
        | NvDataType::Int32Array
        | NvDataType::Uint32Array
        | NvDataType::Int8Array
        | NvDataType::Uint8Array => 4,

        // Arrays have from 0 to N values, and these types have 8 bytes per element.
        NvDataType::Int64Array | NvDataType::Uint64Array => 8,

        // Arrays have from 0 to N values, and the bytes per element is unknown.
        NvDataType::ByteArray | NvDataType::StringArray | NvDataType::NvListArray => 0,
    };

    // Compute array size.
    match count.checked_mul(array_element_size) {
        Some(v) => Ok(v),
        None => Err(NvDecodeError::InvalidCount { data_type, count }),
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Decoded Name Value Pair Data Value.
#[derive(Clone, Copy, Debug)]
pub enum NvDataValue<'a> {
    /// A boolean flag (no value).
    Boolean(),

    /// A byte.
    Byte(u8),

    /// A [i16].
    Int16(i16),

    /// A [u16].
    Uint16(u16),

    /// A [i32].
    Int32(i32),

    /// A [u32].
    Uint32(u32),

    /// A [i64].
    Int64(i64),

    /// A [u64].
    Uint64(u64),

    /// A [str].
    String(&'a str),

    /// An array of bytes.
    ByteArray(&'a [u8]),

    /// An array of [i16].
    Int16Array(NvArray<'a, i16>),

    /// An array of [u16].
    Uint16Array(NvArray<'a, u16>),

    /// An array of [i32].
    Int32Array(NvArray<'a, i32>),

    /// An array of [u32].
    Uint32Array(NvArray<'a, u32>),

    /// An array of [i64].
    Int64Array(NvArray<'a, i64>),

    /// An array of [u64].
    Uint64Array(NvArray<'a, u64>),

    /// An array of [str].
    StringArray(NvArray<'a, &'a str>),

    /// High resolution time in nanoseconds.
    HrTime(i64),

    /// A [`NvList`].
    NvList(NvList<'a>),

    /// An array of nested [`NvList`].
    NvListArray(NvArray<'a, NvList<'a>>),

    /// A [bool].
    BooleanValue(bool),

    /// A [i8].
    Int8(i8),

    /// A [u8].
    Uint8(u8),

    /// An array of [bool].
    BooleanArray(NvArray<'a, bool>),

    /// An array of [i8].
    Int8Array(NvArray<'a, i8>),

    /// An array of [u8].
    Uint8Array(NvArray<'a, u8>),

    /// A [f64].
    Double(f64),
}

/// A name value pair list.
#[derive(Clone, Copy, Debug)]
pub struct NvList<'a> {
    /// Full [`NvList`] data.
    data: &'a [u8],

    /// Offset into `data`.
    offset: usize,

    /// Byte length of list.
    length: usize,

    /// Encoding.
    encoding: NvEncoding,

    /// Order.
    order: EndianOrder,

    /// Unique.
    unique: NvUnique,
}

impl NvList<'_> {
    /// Returns an iterator over the [`NvList`].
    pub fn iter(&self) -> NvListIterator<'_> {
        // iter() cannot return an error, so have the Iterator return the error
        // in case byte clamp fails.
        let (decoder, clamp_err) =
            match XdrDecoder::from_bytes_clamped(self.data, self.offset, self.length) {
                Ok(decoder) => (decoder, None),
                Err(err) => {
                    // Use a decoder that cannot fail to avoid Option.
                    (XdrDecoder::from_bytes(self.data), Some(err))
                }
            };

        NvListIterator {
            list: self,
            decoder,
            clamp_err,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`NvList`] iterator.
#[derive(Debug)]
pub struct NvListIterator<'a> {
    /// List.
    list: &'a NvList<'a>,

    /// Decoder.
    decoder: XdrDecoder<'a>,

    /// Error from creating the iterator decoder.
    clamp_err: Option<XdrDecodeError>,
}

impl NvListIterator<'_> {
    /// Resets the iterator to the start of the data.
    pub fn reset(&self) {
        self.decoder.reset()
    }

    /// Gets the next pair result.
    fn next_pair_result<'a>(&self, data: &'a [u8]) -> Result<Option<NvPair<'a>>, NvDecodeError> {
        // Check for end of list.
        if self.decoder.is_empty() {
            return Ok(None);
        }

        // Keep track of starting offset, to verify encoded_size, and
        // construct nested NV List structures.
        let starting_offset = self.decoder.offset();

        // Encoded and decoded sizes.
        let encoded_size = self.decoder.get_usize()?;
        let decoded_size = self.decoder.get_usize()?;

        // Check for end of list.
        if encoded_size == 0 && decoded_size == 0 {
            return Ok(None);
        }

        // Name.
        let name = self.decoder.get_str_direct(data)?;

        // Data type.
        let data_type = self.decoder.get_u32()?;
        let data_type = NvDataType::try_from(data_type)?;

        // Number of elements.
        let element_count = self.decoder.get_usize()?;

        // Number of bytes remaining.
        let value_offset = self.decoder.offset();
        let bytes_used = value_offset - starting_offset;
        let bytes_rem = match encoded_size.checked_sub(bytes_used) {
            Some(v) => v,
            None => {
                // Consumed too many bytes.
                return Err(NvDecodeError::InvalidEncodedSize {
                    encoded_size,
                    used: bytes_used,
                });
            }
        };

        // Check count and get array size.
        let array_value_size = check_data_type_count_and_get_array_size(data_type, element_count)?;

        // Decode data value.
        let value = match data_type {
            NvDataType::Boolean => NvDataValue::Boolean(),
            NvDataType::Byte => NvDataValue::Byte(self.decoder.get_u8()?),
            NvDataType::Int16 => NvDataValue::Int16(self.decoder.get_i16()?),
            NvDataType::Uint16 => NvDataValue::Uint16(self.decoder.get_u16()?),
            NvDataType::Int32 => NvDataValue::Int32(self.decoder.get_i32()?),
            NvDataType::Uint32 => NvDataValue::Uint32(self.decoder.get_u32()?),
            NvDataType::Int64 => NvDataValue::Int64(self.decoder.get_i64()?),
            NvDataType::Uint64 => NvDataValue::Uint64(self.decoder.get_u64()?),
            NvDataType::String => NvDataValue::String(self.decoder.get_str_direct(data)?),
            NvDataType::ByteArray => {
                NvDataValue::ByteArray(self.decoder.get_byte_array_direct(data)?)
            }
            NvDataType::Int16Array => NvDataValue::Int16Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),

            NvDataType::Uint16Array => NvDataValue::Uint16Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Int32Array => NvDataValue::Int32Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Uint32Array => NvDataValue::Uint32Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Int64Array => NvDataValue::Int64Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Uint64Array => NvDataValue::Uint64Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::StringArray => NvDataValue::StringArray({
                self.decoder.skip(bytes_rem)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: bytes_rem,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::HrTime => NvDataValue::HrTime(self.decoder.get_i64()?),
            NvDataType::NvList => NvDataValue::NvList({
                self.decoder.skip(bytes_rem)?;

                NvList::from_partial(
                    data,
                    value_offset,
                    bytes_rem,
                    self.list.encoding,
                    self.list.order,
                )?
            }),
            NvDataType::NvListArray => NvDataValue::NvListArray({
                self.decoder.skip(bytes_rem)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: bytes_rem,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::BooleanValue => NvDataValue::BooleanValue(self.decoder.get_bool()?),
            NvDataType::Int8 => NvDataValue::Int8(self.decoder.get_i8()?),
            NvDataType::Uint8 => NvDataValue::Uint8(self.decoder.get_u8()?),
            NvDataType::BooleanArray => NvDataValue::BooleanArray({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Int8Array => NvDataValue::Int8Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Uint8Array => NvDataValue::Uint8Array({
                self.decoder.skip(array_value_size)?;

                NvArray {
                    data,
                    offset: value_offset,
                    length: array_value_size,
                    count: element_count,
                    order: self.list.order,
                    encoding: self.list.encoding,
                    phantom: PhantomData,
                }
            }),
            NvDataType::Double => NvDataValue::Double(self.decoder.get_f64()?),
        };

        // Number of bytes remaining.
        let bytes_used = self.decoder.offset() - starting_offset;
        let bytes_rem = match encoded_size.checked_sub(bytes_used) {
            Some(v) => v,
            None => {
                // Consumed too many bytes.
                return Err(NvDecodeError::InvalidEncodedSize {
                    encoded_size,
                    used: bytes_used,
                });
            }
        };

        // Some bytes left.
        if bytes_rem > 0 {
            return Err(NvDecodeError::InvalidEncodedSize {
                encoded_size,
                used: bytes_used,
            });
        }

        Ok(Some(NvPair { name, value }))
    }

    /** Gets the next [`NvPair`].
     *
     * The same as [`NvListIterator`] [`Iterator::next`] but returns a value,
     * whose lifetime is tied to the input `data`, which must be the same `data`
     * as was used to create the [`NvList`].
     */
    pub fn next_direct<'a>(&mut self, data: &'a [u8]) -> Option<Result<NvPair<'a>, NvDecodeError>> {
        // Check that the data is the same.
        if !core::ptr::eq(self.list.data, data) {
            return Some(Err(NvDecodeError::DataMismatch {}));
        }

        // Check for clamp error.
        if let Some(err) = self.clamp_err {
            // Finish iteration by skipping the rest of the input.
            let _ = self.decoder.skip(self.decoder.len());
            return Some(Err(NvDecodeError::Xdr { err }));
        }

        // Get the next pair result, and convert it to an option response.
        match self.next_pair_result(data) {
            Ok(v) => v.map(Ok),
            Err(err) => Some(Err(err)),
        }
    }
}

impl<'a> Iterator for NvListIterator<'a> {
    type Item = Result<NvPair<'a>, NvDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.next_direct(self.list.data)
    }
}

impl<'a> IntoIterator for &'a NvList<'_> {
    type Item = Result<NvPair<'a>, NvDecodeError>;
    type IntoIter = NvListIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A decoder of an array of [`NvPair`] entries.
#[derive(Clone, Copy, Debug)]
pub struct NvArray<'a, T> {
    /// Full [`NvList`] data.
    data: &'a [u8],

    /// Offset into `data`.
    offset: usize,

    /// Byte length of array.
    length: usize,

    /// Number of entries in the array.
    count: usize,

    /// Inherited encoding.
    encoding: NvEncoding,

    /// Inherited byte order.
    order: EndianOrder,

    /// Phantom data for type correctness.
    phantom: PhantomData<T>,
}

impl<T> NvArray<'_, T> {
    /// Is the array empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of elements in the array.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns an iterator over the [`NvArray`].
    pub fn iter(&self) -> NvArrayIterator<'_, T> {
        // iter() cannot return an error, so have the Iterator return the error
        // in case byte clamp fails.
        let (decoder, clamp_err) =
            match XdrDecoder::from_bytes_clamped(self.data, self.offset, self.length) {
                Ok(decoder) => (decoder, None),
                Err(err) => {
                    // Use a decoder that cannot fail to avoid Option.
                    (XdrDecoder::from_bytes(self.data), Some(err))
                }
            };

        NvArrayIterator::<T> {
            array: self,
            decoder,
            index: 0,
            phantom: PhantomData,
            clamp_err,
        }
    }
}

impl<'a, T: GetFromXdrDecoder> IntoIterator for &'a NvArray<'_, T> {
    type Item = Result<T, NvDecodeError>;
    type IntoIter = NvArrayIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a NvArray<'_, NvList<'_>> {
    type Item = Result<NvList<'a>, NvDecodeError>;
    type IntoIter = NvArrayIterator<'a, NvList<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`NvArray`] iterator.
#[derive(Debug)]
pub struct NvArrayIterator<'a, T> {
    /// Array.
    array: &'a NvArray<'a, T>,

    /// Decoder.
    decoder: XdrDecoder<'a>,

    /// Element index into array.
    index: usize,

    /// Phantom data for type correctness.
    phantom: PhantomData<T>,

    /// Error from creating the iterator decoder.
    clamp_err: Option<XdrDecodeError>,
}

impl<T> NvArrayIterator<'_, T> {
    /// Resets the iterator to the start of the data.
    pub fn reset(&mut self) {
        self.index = 0;
    }
}

impl<T: GetFromXdrDecoder> Iterator for NvArrayIterator<'_, T> {
    type Item = Result<T, NvDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.index < self.array.count {
            // Check for clamp error.
            if let Some(err) = self.clamp_err {
                // Finish iteration.
                self.index = self.array.count;
                return Some(Err(NvDecodeError::Xdr { err }));
            }

            self.index += 1;

            match self.decoder.get() {
                Ok(v) => Some(Ok(v)),
                Err(err) => Some(Err(NvDecodeError::Xdr { err })),
            }
        } else {
            None
        }
    }
}

impl NvArrayIterator<'_, &str> {
    /** Gets the next [str].
     *
     * The same as [`NvArrayIterator`] [`Iterator::next`] but returns a value,
     * whose lifetime is tied to the input `data`, which must be the same `data`
     * as was used to create the [`NvArray`].
     */
    pub fn next_direct<'a>(&mut self, data: &'a [u8]) -> Option<Result<&'a str, NvDecodeError>> {
        if self.index < self.array.count {
            // Check for clamp error.
            if let Some(err) = self.clamp_err {
                // Finish iteration.
                self.index = self.array.count;
                return Some(Err(NvDecodeError::Xdr { err }));
            }

            self.index += 1;

            match self.decoder.get_str_direct(data) {
                Ok(v) => Some(Ok(v)),
                Err(err) => Some(Err(NvDecodeError::Xdr { err })),
            }
        } else {
            None
        }
    }
}

impl<'a> Iterator for &'a mut NvArrayIterator<'a, &str> {
    type Item = Result<&'a str, NvDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.next_direct(self.array.data)
    }
}

impl NvArrayIterator<'_, NvList<'_>> {
    /** Gets the next [`NvList`].
     *
     * The same as [`NvArrayIterator`] [`Iterator::next`] but returns a value,
     * whose lifetime is tied to the input `data`, which must be the same `data`
     * as was used to create the [`NvArray`].
     */
    pub fn next_direct<'a>(&mut self, data: &'a [u8]) -> Option<Result<NvList<'a>, NvDecodeError>> {
        // Check that the data is the same.
        if !core::ptr::eq(self.array.data, data) {
            return Some(Err(NvDecodeError::DataMismatch {}));
        }

        // The length of the array is not actually known, so decode the array,
        // in order to increment offset of the outer decoder.
        if self.index < self.array.count {
            // Check for clamp error.
            if let Some(err) = self.clamp_err {
                // Finish iteration.
                self.index = self.array.count;
                return Some(Err(NvDecodeError::Xdr { err }));
            }

            self.index += 1;

            // Create a temporary decoder.
            let starting_offset = self.decoder.offset();
            let list = match NvList::from_partial(
                self.decoder.data(),
                self.decoder.offset(),
                self.decoder.len(),
                self.array.encoding,
                self.array.order,
            ) {
                Ok(list) => list,
                Err(err) => return Some(Err(err)),
            };

            // Decode until end of list or error.
            let mut iter = list.iter();
            for pair_res in iter.by_ref() {
                if let Err(err) = pair_res {
                    return Some(Err(err));
                }
            }

            // Compute number of bytes used for this list.
            let bytes_used = iter.decoder.offset() - starting_offset;

            // Decode bytes, but discard because data will be used.
            if let Err(err) = self.decoder.get_bytes(bytes_used) {
                return Some(Err(NvDecodeError::Xdr { err }));
            }

            // Return decoder.
            Some(NvList::from_partial(
                data,
                starting_offset,
                bytes_used,
                self.array.encoding,
                self.array.order,
            ))
        } else {
            None
        }
    }
}

impl<'a> Iterator for NvArrayIterator<'a, NvList<'_>> {
    type Item = Result<NvList<'a>, NvDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.next_direct(self.array.data)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Decoded [`NvPair`].
#[derive(Debug)]
pub struct NvPair<'a> {
    /// Name.
    pub name: &'a str,

    /// Value.
    pub value: NvDataValue<'a>,
}

impl NvPair<'_> {
    /// Gets the data type of the decoded pair.
    pub fn data_type(&self) -> NvDataType {
        match self.value {
            NvDataValue::Boolean() => NvDataType::Boolean,
            NvDataValue::Byte(_) => NvDataType::Byte,
            NvDataValue::Int16(_) => NvDataType::Int16,
            NvDataValue::Uint16(_) => NvDataType::Uint16,
            NvDataValue::Int32(_) => NvDataType::Int32,
            NvDataValue::Uint32(_) => NvDataType::Uint32,
            NvDataValue::Int64(_) => NvDataType::Int64,
            NvDataValue::Uint64(_) => NvDataType::Uint64,
            NvDataValue::String(_) => NvDataType::String,
            NvDataValue::ByteArray(_) => NvDataType::ByteArray,
            NvDataValue::Int16Array(_) => NvDataType::Int16Array,
            NvDataValue::Uint16Array(_) => NvDataType::Uint16Array,
            NvDataValue::Int32Array(_) => NvDataType::Int32Array,
            NvDataValue::Uint32Array(_) => NvDataType::Uint32Array,
            NvDataValue::Int64Array(_) => NvDataType::Int64Array,
            NvDataValue::Uint64Array(_) => NvDataType::Uint64Array,
            NvDataValue::StringArray(_) => NvDataType::StringArray,
            NvDataValue::HrTime(_) => NvDataType::HrTime,
            NvDataValue::NvList(_) => NvDataType::NvList,
            NvDataValue::NvListArray(_) => NvDataType::NvListArray,
            NvDataValue::BooleanValue(_) => NvDataType::BooleanValue,
            NvDataValue::Int8(_) => NvDataType::Int8,
            NvDataValue::Uint8(_) => NvDataType::Uint8,
            NvDataValue::BooleanArray(_) => NvDataType::BooleanArray,
            NvDataValue::Int8Array(_) => NvDataType::Int8Array,
            NvDataValue::Uint8Array(_) => NvDataType::Uint8Array,
            NvDataValue::Double(_) => NvDataType::Double,
        }
    }

    /// Gets [`bool`] value for a [`NvDataType::BooleanValue`].
    pub fn get_bool(&self) -> Result<bool, NvDecodeError> {
        match self.value {
            NvDataValue::BooleanValue(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::BooleanValue,
                actual: self.data_type(),
            }),
        }
    }

    /** Gets [`bool`] value for a [`NvDataType::Boolean`].
     *
     * If type matches, the returned value is always [`true`].
     */
    pub fn get_bool_flag(&self) -> Result<bool, NvDecodeError> {
        match self.value {
            NvDataValue::Boolean() => Ok(true),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Boolean,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`bool`] array value.
    pub fn get_bool_array(&self) -> Result<NvArray<'_, bool>, NvDecodeError> {
        match self.value {
            NvDataValue::BooleanArray(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::BooleanArray,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u8`] byte value.
    pub fn get_byte(&self) -> Result<u8, NvDecodeError> {
        match self.value {
            NvDataValue::Byte(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Byte,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u8`] byte array value.
    pub fn get_byte_array(&self) -> Result<&[u8], NvDecodeError> {
        match self.value {
            NvDataValue::ByteArray(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::ByteArray,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`f64`] byte value.
    pub fn get_f64(&self) -> Result<f64, NvDecodeError> {
        match self.value {
            NvDataValue::Double(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Double,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i64`] high resolution nanosecond time value.
    pub fn get_hr_time(&self) -> Result<i64, NvDecodeError> {
        match self.value {
            NvDataValue::HrTime(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::HrTime,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i8`] value.
    pub fn get_i8(&self) -> Result<i8, NvDecodeError> {
        match self.value {
            NvDataValue::Int8(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int8,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i8`] array value.
    pub fn get_i8_array(&self) -> Result<NvArray<'_, i8>, NvDecodeError> {
        match self.value {
            NvDataValue::Int8Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int8Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i16`] value.
    pub fn get_i16(&self) -> Result<i16, NvDecodeError> {
        match self.value {
            NvDataValue::Int16(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int16,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i16`] array value.
    pub fn get_i16_array(&self) -> Result<NvArray<'_, i16>, NvDecodeError> {
        match self.value {
            NvDataValue::Int16Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int16Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i32`] value.
    pub fn get_i32(&self) -> Result<i32, NvDecodeError> {
        match self.value {
            NvDataValue::Int32(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int32,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i32`] array value.
    pub fn get_i32_array(&self) -> Result<NvArray<'_, i32>, NvDecodeError> {
        match self.value {
            NvDataValue::Int32Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int32Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i64`] value.
    pub fn get_i64(&self) -> Result<i64, NvDecodeError> {
        match self.value {
            NvDataValue::Int64(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int64,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`i64`] array value.
    pub fn get_i64_array(&self) -> Result<NvArray<'_, i64>, NvDecodeError> {
        match self.value {
            NvDataValue::Int64Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Int64Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`NvList`] value.
    pub fn get_nv_list(&self) -> Result<NvList<'_>, NvDecodeError> {
        match self.value {
            NvDataValue::NvList(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::NvList,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`NvList`] array value.
    pub fn get_nv_list_array(&self) -> Result<NvArray<'_, NvList<'_>>, NvDecodeError> {
        match self.value {
            NvDataValue::NvListArray(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::NvListArray,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`str`] value.
    pub fn get_str(&self) -> Result<&str, NvDecodeError> {
        match self.value {
            NvDataValue::String(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::String,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`str`] array value.
    pub fn get_str_array(&self) -> Result<NvArray<'_, &str>, NvDecodeError> {
        match self.value {
            NvDataValue::StringArray(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::StringArray,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u8`] value.
    pub fn get_u8(&self) -> Result<u8, NvDecodeError> {
        match self.value {
            NvDataValue::Uint8(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint8,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u8`] array value.
    pub fn get_u8_array(&self) -> Result<NvArray<'_, u8>, NvDecodeError> {
        match self.value {
            NvDataValue::Uint8Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint8Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u16`] value.
    pub fn get_u16(&self) -> Result<u16, NvDecodeError> {
        match self.value {
            NvDataValue::Uint16(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint16,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u16`] array value.
    pub fn get_u16_array(&self) -> Result<NvArray<'_, u16>, NvDecodeError> {
        match self.value {
            NvDataValue::Uint16Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint16Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u32`] value.
    pub fn get_u32(&self) -> Result<u32, NvDecodeError> {
        match self.value {
            NvDataValue::Uint32(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint32,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u32`] array value.
    pub fn get_u32_array(&self) -> Result<NvArray<'_, u32>, NvDecodeError> {
        match self.value {
            NvDataValue::Uint32Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint32Array,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u64`] value.
    pub fn get_u64(&self) -> Result<u64, NvDecodeError> {
        match self.value {
            NvDataValue::Uint64(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint64,
                actual: self.data_type(),
            }),
        }
    }

    /// Gets [`u64`] array value.
    pub fn get_u64_array(&self) -> Result<NvArray<'_, u64>, NvDecodeError> {
        match self.value {
            NvDataValue::Uint64Array(v) => Ok(v),
            _ => Err(NvDecodeError::DataTypeMismatch {
                expected: NvDataType::Uint64Array,
                actual: self.data_type(),
            }),
        }
    }
}

impl NvList<'_> {
    /// Header byte size.
    const HEADER_SIZE: usize = 4;

    /// Gets the `data` value for this decoder.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Gets the [`NvUnique`] value for this decoder.
    pub fn unique(&self) -> NvUnique {
        self.unique
    }

    /** Create a [`NvList`] from a slice of bytes.
     *
     * # Errors.
     *
     * Returns [`NvDecodeError`] on error.
     */
    pub fn from_bytes(data: &[u8]) -> Result<NvList<'_>, NvDecodeError> {
        // Check that NvList header is not truncated.
        if data.len() < NvList::HEADER_SIZE {
            return Err(NvDecodeError::EndOfInput {
                offset: 0,
                capacity: data.len(),
                count: NvList::HEADER_SIZE,
                detail: "NV List header is truncated",
            });
        }

        // Get the first four bytes.
        let header = &data[0..NvList::HEADER_SIZE];

        let encoding = NvEncoding::try_from(header[0])?;
        let endian = EndianOrder::from(NvEndianOrder::try_from(header[1])?);
        let reserved_0 = header[2];
        let reserved_1 = header[3];

        // Check reserved bytes.
        if reserved_0 != 0 || reserved_1 != 0 {
            return Err(NvDecodeError::InvalidReservedBytes {
                reserved: [reserved_0, reserved_1],
            });
        }

        let start = header.len();
        let length = data.len() - start;

        NvList::from_partial(data, start, length, encoding, endian)
    }

    /** Instantiates a nested NV list [`NvList`] from a slice of bytes.
     *
     * - Encoding, and endian must be the same as the parent list.
     *
     * # Errors.
     *
     * Returns [`NvDecodeError`] on error.
     */
    fn from_partial(
        data: &[u8],
        start: usize,
        length: usize,
        encoding: NvEncoding,
        order: EndianOrder,
    ) -> Result<NvList<'_>, NvDecodeError> {
        // Check encoding.
        match encoding {
            NvEncoding::Native => todo!("Implement Native decoding"),
            NvEncoding::Xdr => (),
        }

        // NOTE: For XDR, it is always big endian, no matter what the endian
        //       field says.
        let decoder = XdrDecoder::from_bytes_clamped(data, start, length)?;

        // NvList version.
        let version = decoder.get_u32()?;
        if version != 0 {
            return Err(NvDecodeError::UnknownVersion { version });
        }

        // NvList flags.
        let flags = decoder.get_u32()?;
        let unique_flags = flags & 0x3;

        // Check for unknown flags.
        if unique_flags != flags {
            return Err(NvDecodeError::UnknownFlags { flags });
        }

        // Decode unique flags.
        let unique = NvUnique::try_from(unique_flags as u8)?;

        Ok(NvList {
            data,
            offset: decoder.offset(),
            length: decoder.len(),
            encoding,
            order,
            unique,
        })
    }

    /** Finds the name value pair by name.
     *
     * Returns [`None`] if the pair is not found.
     * Resets the decoder prior to searching.
     */
    pub fn find(&self, name: &str) -> Result<Option<NvPair<'_>>, NvDecodeError> {
        self.find_direct(name, self.data)
    }

    /** Finds the name value pair by name.
     *
     * The same as [`NvList::find`], but returns a value, whose lifetime is
     * tied to the input `data`, which must be the same `data` as was used to
     * create the [`NvList`].
     *
     * Returns [`None`] if the pair is not found.
     * Resets the decoder prior to searching.
     */
    pub fn find_direct<'a>(
        &self,
        name: &str,
        data: &'a [u8],
    ) -> Result<Option<NvPair<'a>>, NvDecodeError> {
        let mut iter = self.iter();
        while let Some(pair_res) = iter.next_direct(data) {
            let pair = pair_res?;

            // Return if name matches.
            if pair.name == name {
                return Ok(Some(pair));
            }
        }

        Ok(None)
    }

    /** Gets [`bool`] with the specified name for a [`NvDataType::BooleanValue`].
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_bool(&self, name: &str) -> Result<Option<bool>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_bool()?)),
            None => Ok(None),
        }
    }

    /** Gets [`bool`] with the specified name for a [`NvDataType::Boolean`].
     * If found, the returned value is always [`true`].
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_bool_flag(&self, name: &str) -> Result<Option<bool>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_bool_flag()?)),
            None => Ok(None),
        }
    }

    /** Gets [`bool`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_bool_array(&self, name: &str) -> Result<Option<NvArray<'_, bool>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::BooleanArray(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::BooleanArray,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`u8`] byte with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_byte(&self, name: &str) -> Result<Option<u8>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_byte()?)),
            None => Ok(None),
        }
    }

    /** Gets [`u8`] byte array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_byte_array(&self, name: &str) -> Result<Option<&[u8]>, NvDecodeError> {
        self.get_byte_array_direct(name, self.data)
    }

    /** Gets [`u8`] byte array with the specified name.
     *
     * The same as [`NvList::get_byte_array`], but returns a value, whose
     * lifetime is tied to the input `data`, which must be the same `data` as
     * was used to create the [`NvList`].
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_byte_array_direct<'a>(
        &self,
        name: &str,
        data: &'a [u8],
    ) -> Result<Option<&'a [u8]>, NvDecodeError> {
        let nv_pair_opt = self.find_direct(name, data)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::ByteArray(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::ByteArray,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`f64`] byte with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_f64(&self, name: &str) -> Result<Option<f64>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_f64()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i64`] high resolution nanosecond time with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_hr_time(&self, name: &str) -> Result<Option<i64>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_hr_time()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i8`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i8(&self, name: &str) -> Result<Option<i8>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_i8()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i8`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i8_array(&self, name: &str) -> Result<Option<NvArray<'_, i8>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Int8Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Int8Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`i16`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i16(&self, name: &str) -> Result<Option<i16>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_i16()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i16`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i16_array(&self, name: &str) -> Result<Option<NvArray<'_, i16>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Int16Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Int16Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`i32`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i32(&self, name: &str) -> Result<Option<i32>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_i32()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i32`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i32_array(&self, name: &str) -> Result<Option<NvArray<'_, i32>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Int32Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Int32Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`i64`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i64(&self, name: &str) -> Result<Option<i64>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_i64()?)),
            None => Ok(None),
        }
    }

    /** Gets [`i64`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_i64_array(&self, name: &str) -> Result<Option<NvArray<'_, i64>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Int64Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Int64Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`NvList`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_nv_list(&self, name: &str) -> Result<Option<NvList<'_>>, NvDecodeError> {
        self.get_nv_list_direct(name, self.data)
    }

    /** Gets [`NvList`] with the specified name.
     *
     * The same as [`NvList::get_nv_list`], but returns a value, whose lifetime
     * is tied to the input `data`, which must be the same `data` as was used to
     * create the [`NvList`].
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_nv_list_direct<'a>(
        &self,
        name: &str,
        data: &'a [u8],
    ) -> Result<Option<NvList<'a>>, NvDecodeError> {
        let nv_pair_opt = self.find_direct(name, data)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::NvList(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::NvList,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`NvList`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_nv_list_array(
        &self,
        name: &str,
    ) -> Result<Option<NvArray<'_, NvList<'_>>>, NvDecodeError> {
        self.get_nv_list_array_direct(name, self.data)
    }

    /** Gets [`NvList`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_nv_list_array_direct<'a>(
        &self,
        name: &str,
        data: &'a [u8],
    ) -> Result<Option<NvArray<'a, NvList<'a>>>, NvDecodeError> {
        let nv_pair_opt = self.find_direct(name, data)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::NvListArray(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::NvListArray,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`str`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_str(&self, name: &str) -> Result<Option<&str>, NvDecodeError> {
        self.get_str_direct(name, self.data)
    }

    /** Gets [`str`] with the specified name.
     *
     * The same as [`NvList::get_str`], but returns a value, whose lifetime
     * is tied to the input `data`, which must be the same `data` as was used to
     * create the [`NvList`].
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_str_direct<'a>(
        &self,
        name: &str,
        data: &'a [u8],
    ) -> Result<Option<&'a str>, NvDecodeError> {
        let nv_pair_opt = self.find_direct(name, data)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::String(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::String,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`str`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_str_array(&self, name: &str) -> Result<Option<NvArray<'_, &str>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::StringArray(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::StringArray,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`u8`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u8(&self, name: &str) -> Result<Option<u8>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_u8()?)),
            None => Ok(None),
        }
    }

    /** Gets [`u8`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u8_array(&self, name: &str) -> Result<Option<NvArray<'_, u8>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Uint8Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Uint8Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`u16`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u16(&self, name: &str) -> Result<Option<u16>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_u16()?)),
            None => Ok(None),
        }
    }

    /** Gets [`u16`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u16_array(&self, name: &str) -> Result<Option<NvArray<'_, u16>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Uint16Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Uint16Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`u32`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u32(&self, name: &str) -> Result<Option<u32>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_u32()?)),
            None => Ok(None),
        }
    }

    /** Gets [`u32`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u32_array(&self, name: &str) -> Result<Option<NvArray<'_, u32>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Uint32Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Uint32Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }

    /** Gets [`u64`] with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u64(&self, name: &str) -> Result<Option<u64>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => Ok(Some(nv_pair.get_u64()?)),
            None => Ok(None),
        }
    }

    /** Gets [`u64`] array with the specified name.
     *
     * Does not check for uniqueness.
     * Returns [`None`] if not found.
     */
    pub fn get_u64_array(&self, name: &str) -> Result<Option<NvArray<'_, u64>>, NvDecodeError> {
        let nv_pair_opt = self.find(name)?;
        match nv_pair_opt {
            Some(nv_pair) => match nv_pair.value {
                NvDataValue::Uint64Array(v) => Ok(Some(v)),
                _ => Err(NvDecodeError::DataTypeMismatch {
                    expected: NvDataType::Uint64Array,
                    actual: nv_pair.data_type(),
                }),
            },
            None => Ok(None),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`NvList`] decode error.
#[derive(Debug)]
pub enum NvDecodeError {
    /// Data mismatch
    DataMismatch {},

    /// [`NvDataType`] mismatch.
    DataTypeMismatch {
        /// Expected.
        expected: NvDataType,
        /// Actual.
        actual: NvDataType,
    },

    /// End of array.
    EndOfArray {},

    /// End of input data.
    EndOfInput {
        /// Byte offset of data.
        offset: usize,
        /// Total capacity of data.
        capacity: usize,
        /// Number of bytes needed.
        count: usize,
        /// Additional detail
        detail: &'static str,
    },

    /// Data type has an invalid count.
    InvalidCount {
        /// [`NvDataType`].
        data_type: NvDataType,
        /// Count.
        count: usize,
    },

    /// Invalid encoded size.
    InvalidEncodedSize {
        /// Encoded size.
        encoded_size: usize,
        /// Bytes used.
        used: usize,
    },

    /// Invalid nested size.
    InvalidNestedSize {},

    /// Invalid reserved bytes.
    InvalidReservedBytes {
        /// Invalid reserved bytes.
        reserved: [u8; 2],
    },

    /// Nested decoder mismatch.
    NestedDecoderMismatch {},

    /// Unknown [`NvDataType`].
    UnknownDataType {
        /// Unknown [`NvDataType`].
        data_type: u32,
    },

    /// Invalid [`NvEncoding`].
    UnknownEncoding {
        /// Invalid [`NvEncoding`].
        encoding: u8,
    },

    /// Invalid [`NvEndianOrder`].
    UnknownEndian {
        /// Invalid [`NvEndianOrder`].
        order: u8,
    },

    /// Invalid flags.
    UnknownFlags {
        /// Invalid flags.
        flags: u32,
    },

    /// Invalid [`NvUnique`].
    UnknownUnique {
        /// Invalid [`NvUnique`].
        unique: u8,
    },

    /// Invalid version.
    UnknownVersion {
        /// Invalid version.
        version: u32,
    },

    /// [`XdrDecoder`] error.
    Xdr {
        /// Error.
        err: XdrDecodeError,
    },
}

impl From<XdrDecodeError> for NvDecodeError {
    fn from(err: XdrDecodeError) -> Self {
        NvDecodeError::Xdr { err }
    }
}

impl fmt::Display for NvDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvDecodeError::DataMismatch {} => write!(
                f,
                "NV decode error, provided data slice does not match decoder data slice"
            ),
            NvDecodeError::DataTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "NV decode error, data type mismatch, expected {expected} actual {actual}"
                )
            }
            NvDecodeError::EndOfArray {} => {
                write!(f, "NV decode error, end of array")
            }
            NvDecodeError::EndOfInput {
                offset,
                capacity,
                count,
                detail,
            } => {
                write!(
                    f,
                    "NV decode error, end of input at offset {offset} capacity {capacity} count {count} detail {detail}"
                )
            }
            NvDecodeError::InvalidCount { data_type, count } => {
                write!(
                    f,
                    "NV decode error, invalid count {count} for data type {data_type}"
                )
            }
            NvDecodeError::InvalidEncodedSize { encoded_size, used } => {
                write!(
                    f,
                    "NV decode error, invalid encoded size {encoded_size} used {used}"
                )
            }
            NvDecodeError::InvalidNestedSize {} => {
                write!(f, "NV decode error, invalid nested size")
            }
            NvDecodeError::InvalidReservedBytes { reserved } => {
                write!(
                    f,
                    "NV decode error, invalid reserved bytes {reserved:#02x?}"
                )
            }
            NvDecodeError::NestedDecoderMismatch {} => {
                write!(f, "NV decode error, nested decoder mismatch")
            }
            NvDecodeError::UnknownDataType { data_type } => {
                write!(f, "NV decode error, unknown data type {data_type}")
            }
            NvDecodeError::UnknownEncoding { encoding } => {
                write!(f, "NV decode error, unknown encoding {encoding}")
            }
            NvDecodeError::UnknownEndian { order } => {
                write!(f, "NV decode error, unknown endian {order}")
            }
            NvDecodeError::UnknownFlags { flags } => {
                write!(f, "NV decode error, unknown flags {flags:#08x}")
            }
            NvDecodeError::UnknownUnique { unique } => {
                write!(f, "NV decode error, unknown unique {unique}")
            }
            NvDecodeError::UnknownVersion { version } => {
                write!(f, "NV decode error, unknown version {version}")
            }
            NvDecodeError::Xdr { err } => {
                write!(f, "NV decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for NvDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            NvDecodeError::Xdr { err } => Some(err),
            _ => None,
        }
    }
}
