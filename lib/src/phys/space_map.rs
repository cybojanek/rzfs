// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder};

////////////////////////////////////////////////////////////////////////////////

/** Space map header for a [`crate::phys::DmuType::SpaceMap`] [`crate::phys::Dnode`]
 * with bonus type [`crate::phys::DmuType::SpaceMapHeader`].
 *
 * ### Byte layout.
 *
 * - Bytes: 24, or 280
 *
 * ```text
 * +------------------+------+-------------+--------------------------------+
 * | Field            | Size | SPA Version | Feature                        |
 * +------------------+------+-------------+--------------------------------+
 * | object           |    8 |           1 |                                |
 * | byte length      |    8 |           1 |                                |
 * | bytes allocated  |    8 |           1 | com.delphix:zpool_checkpoint   |
 * | padding          |   40 |        5000 | com.delphix:spacemap_histogram |
 * | histogram        |  256 |        5000 | com.delphix:spacemap_histogram |
 * +------------------+------+-------------+--------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct SpaceMapHeader {
    /** Space Map object number.
     *
     * It seems like this is the object number of the [`crate::phys::Dnode`],
     * and refers to itself. Newer ZFS describes this field as deprecated,
     * and only kept for backwards compatibility.
     */
    pub obj: u64,

    /// Byte length of Space Map contents.
    pub length_bytes: u64,

    /** Bytes allocated from map.
     *
     * NOTE: This field used to be unsigned, but was changed to signed
     * when the `com.delphix:zpool_checkpoint` feature was implemented.
     *
     * TODO: Change to i64
     */
    pub allocated_bytes: u64, // com.delphix:zpool_checkpoint became signed

    /** Histogram of free regions.
     *
     * TODO: document
     */
    pub histogram: Option<[u64; SpaceMapHeader::HISTOGRAM_BUCKETS_COUNT]>,
}

impl SpaceMapHeader {
    /// Byte size of an encoded [`SpaceMapHeader`].
    pub const SIZE_EXT_NONE: usize = 24;

    /// Byte size of an encoded [`SpaceMapHeader`] with histogram.
    pub const SIZE_EXT_HISTOGRAM: usize = 280;

    /// Padding size for histogram extension.
    pub const SIZE_EXT_HISTOGRAM_PADDING: usize = 40;

    /// Number of histogram buckets.
    const HISTOGRAM_BUCKETS_COUNT: usize = 32;

    /** Decodes a [`SpaceMapHeader`].
     *
     * # Errors
     *
     * Returns [`SpaceMapHeaderDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<SpaceMapHeader, SpaceMapHeaderDecodeError> {
        ////////////////////////////////
        // Decode values.
        let obj = match decoder.get_u64()? {
            0 => return Err(SpaceMapHeaderDecodeError::MissingObject {}),
            v => v,
        };

        let length_bytes = decoder.get_u64()?;
        let allocated_bytes = decoder.get_u64()?;

        ////////////////////////////////
        // Decode histogram.
        let mut histogram = None;
        if !decoder.is_empty() {
            // Skip padding.
            decoder.skip_zero_padding(SpaceMapHeader::SIZE_EXT_HISTOGRAM_PADDING)?;

            // Decode histogram values.
            let mut counts: [u64; SpaceMapHeader::HISTOGRAM_BUCKETS_COUNT] = [0; 32];
            for v in &mut counts {
                *v = decoder.get_u64()?;
            }

            histogram = Some(counts);
        }

        ////////////////////////////////
        // Success.
        Ok(SpaceMapHeader {
            obj,
            length_bytes,
            allocated_bytes,
            histogram,
        })
    }

    /** Encodes a empty [`SpaceMapHeader`].
     *
     * # Errors
     *
     * Returns [`SpaceMapHeaderEncodeError`] on error.
     */
    pub fn to_encoder(
        &self,
        encoder: &mut EndianEncoder<'_>,
    ) -> Result<(), SpaceMapHeaderEncodeError> {
        ////////////////////////////////
        // Encode values.
        if self.obj == 0 {
            return Err(SpaceMapHeaderEncodeError::MissingObject {});
        }
        encoder.put_u64(self.obj)?;

        encoder.put_u64(self.length_bytes)?;
        encoder.put_u64(self.allocated_bytes)?;

        if let Some(histogram) = &self.histogram {
            encoder.put_zero_padding(SpaceMapHeader::SIZE_EXT_HISTOGRAM_PADDING)?;

            for v in histogram {
                encoder.put_u64(*v)?;
            }
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`SpaceMapHeader`] decode error.
#[derive(Debug)]
pub enum SpaceMapHeaderDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Object number is zero,
    MissingObject {},

    /// Non-zero padding.
    NonZeroPadding {},
}

impl From<EndianDecodeError> for SpaceMapHeaderDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        SpaceMapHeaderDecodeError::Endian { err }
    }
}

impl fmt::Display for SpaceMapHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMapHeaderDecodeError::Endian { err } => {
                write!(f, "SpaceMapHeader decode error | {err}")
            }
            SpaceMapHeaderDecodeError::MissingObject {} => {
                write!(f, "SpaceMapHeader decode error, missing object number")
            }
            SpaceMapHeaderDecodeError::NonZeroPadding {} => {
                write!(f, "SpaceMapHeader decode error, non-zero padding")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaceMapHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SpaceMapHeaderDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`SpaceMapHeader`] encode error.
#[derive(Debug)]
pub enum SpaceMapHeaderEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Object number is zero,
    MissingObject {},
}

impl From<EndianEncodeError> for SpaceMapHeaderEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        SpaceMapHeaderEncodeError::Endian { err }
    }
}

impl fmt::Display for SpaceMapHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMapHeaderEncodeError::Endian { err } => {
                write!(f, "SpaceMapHeader encode error | {err}")
            }
            SpaceMapHeaderEncodeError::MissingObject {} => {
                write!(f, "SpaceMapHeader encode error, missing object number")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaceMapHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SpaceMapHeaderEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Space map action.
#[derive(Clone, Copy, Debug)]
pub enum SpaceMapAction {
    /// Allocate.
    Allocate = 0,

    /// Free.
    Free = 1,
}

impl From<SpaceMapAction> for u8 {
    fn from(val: SpaceMapAction) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for SpaceMapAction {
    type Error = SpaceMapActionError;

    /** Try converting from a [`u8`] to a [`SpaceMapAction`].
     *
     * # Errors
     *
     * Returns [`SpaceMapActionError`] in case of an unknown [`SpaceMapAction`].
     */
    fn try_from(action: u8) -> Result<Self, Self::Error> {
        match action {
            0 => Ok(SpaceMapAction::Allocate),
            1 => Ok(SpaceMapAction::Free),
            _ => Err(SpaceMapActionError::Unknown { action }),
        }
    }
}

/// [`SpaceMapAction`] conversion error.
#[derive(Debug)]
pub enum SpaceMapActionError {
    /// Unknown [`SpaceMapAction`].
    Unknown {
        /// Action.
        action: u8,
    },
}

impl fmt::Display for SpaceMapActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMapActionError::Unknown { action } => {
                write!(f, "Unknown SpaceMapAction {action}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaceMapActionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Debug Space Map Entry.
 *
 * ```text
 * +-------------------+------+
 * | Field             | Size |
 * +-------------------+------+
 * | value             |    8 |
 * +-------------------+------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |10.|ac.|   sync pass (10)  |                                 transaction group lower bits (50)                                 |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct SpaceMapDebugEntry {
    /// Action.
    pub action: SpaceMapAction,

    /// ???
    pub sync_pass: u16,

    /// ???
    pub txg: u64,
}

impl SpaceMapDebugEntry {
    /// Maximum value for [`SpaceMapDebugEntry::sync_pass`].
    pub const SYNC_PASS_MAX: u16 = SpaceMapDebugEntry::SYNC_PASS_MASK_DOWN_SHIFTED as u16;

    /// Shift for [`SpaceMapDebugEntry`] action.
    const ACTION_SHIFT: usize = 60;

    /// Mask for down shitfted [`SpaceMapDebugEntry`] action.
    const ACTION_MASK_DOWN_SHIFTED: u64 = (1 << 2) - 1;

    /// Shift for [`SpaceMapDebugEntry`] sync pass.
    const SYNC_PASS_SHIFT: usize = 50;

    /// Mask for down shitfted [`SpaceMapDebugEntry`] sync pass.
    const SYNC_PASS_MASK_DOWN_SHIFTED: u64 = (1 << 10) - 1;

    /// Transaction group mask for [`SpaceMapDebugEntry`].
    const TXG_MASK: u64 = (1 << 50) - 1;

    /// Value of a [`SpaceMapEntry::Padding`].
    const PADDING_VALUE: u64 = (1 << 63);
}

/** V1 Space Map Entry.
 *
 * ```text
 * +-------------------+------+-------------+
 * | Field             | Size | SPA Version |
 * +-------------------+------+-------------+
 * | value             |    8 |           1 |
 * +-------------------+------+-------------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |0|                                         offset (47)                                         |t|           run (15)          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct SpaceMapEntryV1 {
    /// Action.
    pub action: SpaceMapAction,

    /// ???
    pub offset: u64,

    /// ???
    pub run: u16,
}

impl SpaceMapEntryV1 {
    /// Maximum value for [`SpaceMapEntryV1`] run.
    pub const RUN_MAX: u16 = SpaceMapEntryV1::RUN_MASK as u16;

    /// Shift for [`SpaceMapEntryV1`] action.
    const ACTION_SHIFT: usize = 15;

    /// Mask for down shitfted [`SpaceMapEntryV1`] action.
    const ACTION_MASK_DOWN_SHIFTED: u64 = 1;

    /// Shift for [`SpaceMapEntryV1`] offset.
    const OFFSET_SHIFT: usize = 16;

    /// Mask for down shitfted [`SpaceMapEntryV1`] offset.
    const OFFSET_MASK_DOWN_SHIFTED: u64 = (1 << 47) - 1;

    /// Run mask for [`SpaceMapEntryV1`].
    const RUN_MASK: u64 = (1 << 15) - 1;
}

/** V2 Space Map Entry.
 *
 * ```text
 * +-------------------+------+-------------+-------------------------+
 * | Field             | Size | SPA Version | Feature                 |
 * +-------------------+------+-------------+-------------------------+
 * | value a           |    8 |        5000 | com.delphix:spacemap_v2 |
 * | value b           |    8 |        5000 | com.delphix:spacemap_v2 |
 * +-------------------+------+-------------+-------------------------+
 * ```
 *
 * Bit layout.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |11.|pa.|                                run (36)                               |                   vdev (24)                   |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |t|                                                         offset (63)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct SpaceMapEntryV2 {
    /// Action.
    pub action: SpaceMapAction,

    /// ???
    pub offset: u64,

    /// ???
    pub run: u64,

    /// ???
    pub vdev: u32,
}

impl SpaceMapEntryV2 {
    /// Maximum value for [`SpaceMapEntryV2::vdev`].
    pub const VDEV_MAX: u32 = SpaceMapEntryV2::VDEV_MASK as u32;

    /// Shift for [`SpaceMapEntryV2`] action.
    const ACTION_SHIFT: usize = 63;

    /// Mask for down shitfted [`SpaceMapEntryV2`] action.
    const ACTION_MASK_DOWN_SHIFTED: u64 = 1;

    /// Offset mask for [`SpaceMapEntryV2`].
    const OFFSET_MASK: u64 = (1 << 63) - 1;

    /// VDev mask for [`SpaceMapEntryV2`].
    const VDEV_MASK: u64 = (1 << 24) - 1;

    /// Shift for [`SpaceMapEntryV2`] run.
    const RUN_SHIFT: usize = 24;

    /// Mask for down shitfted [`SpaceMapEntryV2`] run.
    const RUN_MASK_DOWN_SHIFTED: u64 = (1 << 36) - 1;

    /// Mask for [`SpaceMapEntryV2`] padding.
    const PADDING_MASK: u64 = (3 << 60);
}

/** An entry in a [`crate::phys::DmuType::SpaceMap`] [`crate::phys::Dnode`].
 *
 * - Bytes: 8 or 16
 */
#[derive(Debug)]
pub enum SpaceMapEntry {
    /// [`SpaceMapDebugEntry`].
    Debug(SpaceMapDebugEntry),

    /// [`SpaceMapEntryV1`].
    V1(SpaceMapEntryV1),

    /// [`SpaceMapEntryV2`].
    V2(SpaceMapEntryV2),

    /// Padding.
    Padding,
}

impl SpaceMapEntry {
    /** Decodes a [`SpaceMapEntry`].
     *
     * # Errors
     *
     * Returns [`SpaceMapEntryDecodeError`] in case of decoding error.
     */
    pub fn from_decoder(
        decoder: &EndianDecoder<'_>,
    ) -> Result<SpaceMapEntry, SpaceMapEntryDecodeError> {
        let a = decoder.get_u64()?;

        let entry_type_bits = (a >> 62) & 0x3;
        match entry_type_bits {
            0 | 1 => {
                // SpaceMapEntryV1
                // NOTE: Both 0 and 1 match, because the entry type bits mask
                //       is for the top two bits, but SpaceMapEntryV1 only uses
                //       the top most bit.

                // Decode action.
                let action = ((a >> SpaceMapEntryV1::ACTION_SHIFT)
                    & SpaceMapEntryV1::ACTION_MASK_DOWN_SHIFTED) as u8;
                let action = SpaceMapAction::try_from(action)?;

                // Decode offset.
                let offset = (a >> SpaceMapEntryV1::OFFSET_SHIFT)
                    & SpaceMapEntryV1::OFFSET_MASK_DOWN_SHIFTED;

                // Decode run.
                let run = (a & SpaceMapEntryV1::RUN_MASK) as u16;

                Ok(SpaceMapEntry::V1(SpaceMapEntryV1 {
                    action,
                    offset,
                    run,
                }))
            }
            2 => {
                // SpaceMapDebugEntry

                // Check for padding constant.
                if a == SpaceMapDebugEntry::PADDING_VALUE {
                    return Ok(SpaceMapEntry::Padding {});
                }

                // Decode action.
                let action = ((a >> SpaceMapDebugEntry::ACTION_SHIFT)
                    & SpaceMapDebugEntry::ACTION_MASK_DOWN_SHIFTED)
                    as u8;
                let action = SpaceMapAction::try_from(action)?;

                // Decode sync pass.
                let sync_pass = ((a >> SpaceMapDebugEntry::SYNC_PASS_SHIFT)
                    & SpaceMapDebugEntry::SYNC_PASS_MASK_DOWN_SHIFTED)
                    as u16;

                // Decode transaction group.
                let txg = a & SpaceMapDebugEntry::TXG_MASK;

                // Success.
                Ok(SpaceMapEntry::Debug(SpaceMapDebugEntry {
                    action,
                    sync_pass,
                    txg,
                }))
            }
            3 => {
                // SpaceMapEntryV2
                // NOTE: The second component should never span across DNode
                //       data blocks, and in case of mis-alignment, should be
                //       padded with SpaceMapEntry::Padding.
                let b = decoder.get_u64()?;

                // Check padding.
                let padding = a & SpaceMapEntryV2::PADDING_MASK;
                if padding != 0 {
                    return Err(SpaceMapEntryDecodeError::Padding { padding });
                }

                // Decode vdev.
                let vdev = (a & SpaceMapEntryV2::VDEV_MASK) as u32;

                // Decode run.
                let run =
                    (a >> SpaceMapEntryV2::RUN_SHIFT) & SpaceMapEntryV2::RUN_MASK_DOWN_SHIFTED;

                // Decode action.
                let action = ((b >> SpaceMapEntryV2::ACTION_SHIFT)
                    & SpaceMapEntryV2::ACTION_MASK_DOWN_SHIFTED) as u8;
                let action = SpaceMapAction::try_from(action)?;

                // Decode offset.
                let offset = b & SpaceMapEntryV2::OFFSET_MASK;

                Ok(SpaceMapEntry::V2(SpaceMapEntryV2 {
                    action,
                    offset,
                    run,
                    vdev,
                }))
            }
            _ => unreachable!(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`SpaceMapEntry`] decode error.
#[derive(Debug)]
pub enum SpaceMapEntryDecodeError {
    /// [`SpaceMapAction`] error.
    Action {
        /// Error.
        err: SpaceMapActionError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Non-zero padding.
    Padding {
        /// Padding.
        padding: u64,
    },
}

impl From<SpaceMapActionError> for SpaceMapEntryDecodeError {
    fn from(err: SpaceMapActionError) -> Self {
        SpaceMapEntryDecodeError::Action { err }
    }
}

impl From<EndianDecodeError> for SpaceMapEntryDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        SpaceMapEntryDecodeError::Endian { err }
    }
}

impl fmt::Display for SpaceMapEntryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMapEntryDecodeError::Action { err } => {
                write!(f, "SpaceMapEntry decode error | {err}")
            }
            SpaceMapEntryDecodeError::Endian { err } => {
                write!(f, "SpaceMapEntry decode error | {err}")
            }
            SpaceMapEntryDecodeError::Padding { padding } => {
                write!(f, "SpaceMapEntry decode error, non-zero padding {padding}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaceMapEntryDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SpaceMapEntryDecodeError::Action { err } => Some(err),
            SpaceMapEntryDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`SpaceMapEntry`] encode error.
#[derive(Debug)]
pub enum SpaceMapEntryEncodeError {
    /// [`EndianEncoder`] error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<EndianEncodeError> for SpaceMapEntryEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        SpaceMapEntryEncodeError::Endian { err }
    }
}

impl fmt::Display for SpaceMapEntryEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceMapEntryEncodeError::Endian { err } => {
                write!(f, "SpaceMapEntry encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaceMapEntryEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SpaceMapEntryEncodeError::Endian { err } => Some(err),
        }
    }
}
