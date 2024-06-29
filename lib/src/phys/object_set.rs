// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    Dnode, DnodeDecodeError, DnodeEncodeError, EndianDecodeError, EndianDecoder, EndianEncodeError,
    EndianEncoder, ZilHeader, ZilHeaderDecodeError, ZilHeaderEncodeError,
};

////////////////////////////////////////////////////////////////////////////////

/// [`ObjectSet`] type.
#[derive(Clone, Copy, Debug)]
pub enum ObjectSetType {
    /// ???
    None = 0,

    /// ???
    Meta = 1,

    /// ???
    ZFS = 2,

    /// ???
    ZVol = 3,

    /// ???
    Other = 4,

    /// ???
    Any = 5,
}

impl Display for ObjectSetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectSetType::None => write!(f, "None"),
            ObjectSetType::Meta => write!(f, "Meta"),
            ObjectSetType::ZFS => write!(f, "ZFS"),
            ObjectSetType::ZVol => write!(f, "ZVol"),
            ObjectSetType::Other => write!(f, "Other"),
            ObjectSetType::Any => write!(f, "Any"),
        }
    }
}

impl From<ObjectSetType> for u64 {
    fn from(val: ObjectSetType) -> u64 {
        val as u64
    }
}

impl TryFrom<u64> for ObjectSetType {
    type Error = ObjectSetTypeError;

    /** Try converting from a [`u64`] to a [`ObjectSetType`].
     *
     * # Errors
     *
     * Returns [`ObjectSetTypeError`] in case of an unknown [`ObjectSetType`].
     */
    fn try_from(os_type: u64) -> Result<Self, Self::Error> {
        match os_type {
            0 => Ok(ObjectSetType::None),
            1 => Ok(ObjectSetType::Meta),
            2 => Ok(ObjectSetType::ZFS),
            3 => Ok(ObjectSetType::ZVol),
            4 => Ok(ObjectSetType::Other),
            5 => Ok(ObjectSetType::Any),
            _ => Err(ObjectSetTypeError::Unknown { os_type }),
        }
    }
}

/// [`ObjectSetType`] conversion error.
#[derive(Debug)]
pub enum ObjectSetTypeError {
    /// Unknown [`ObjectSetType`].
    Unknown {
        /// Unknown object set type.
        os_type: u64,
    },
}

impl fmt::Display for ObjectSetTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectSetTypeError::Unknown { os_type } => {
                write!(f, "Unknown ObjectSetType {os_type}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ObjectSetTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// User accounting complete flag for [`ObjectSet`] flags.
const FLAG_USER_ACCOUNTING_COMPLETE: u64 = 1 << 0;

/// User object accounting complete flag for [`ObjectSet`] flags.
const FLAG_USER_OBJECT_ACCOUNTING_COMPLETE: u64 = 1 << 1;

/// Project quota complete flag for [`ObjectSet`] flags.
const FLAG_PROJECT_QUOTA_COMPLETE: u64 = 1 << 2;

/// All flags for [`ObjectSet`] flags.
const FLAG_ALL: u64 = FLAG_USER_ACCOUNTING_COMPLETE
    | FLAG_USER_OBJECT_ACCOUNTING_COMPLETE
    | FLAG_PROJECT_QUOTA_COMPLETE;

/** Object set.
 *
 * - Bytes:
 *   - V1 - V14: 1024
 *   - V15 - V28: 2048
 *   - V5000: 4096
 *
 * ```text
 * +--------------+------+-------------+------------------------------+
 * | Field        | Size | SPA Version | Feature                      |
 * +--------------+------+-------------+------------------------------+
 * | dnode        |  512 |           1 |                              |
 * | zil_header   |  192 |           1 |                              |
 * | type         |    8 |           1 |                              |
 * | flags        |    8 |          15 |                              |
 * | portable_mac |   32 |        5000 | com.datto:encryption         |
 * | local_mac    |   32 |        5000 | com.datto:encryption         |
 * | padding      |  240 |           1 |                              |
 * | user_used    |  512 |          15 |                              |
 * | group_used   |  512 |          15 |                              |
 * | project_used |  512 |        5000 | org.zfsonlinux:project_quota |
 * | padding      | 1536 |        5000 | org.zfsonlinux:project_quota |
 * +--------------+------+-------------+------------------------------+
 */
#[derive(Debug)]
pub struct ObjectSet {
    /// [`Dnode`] of [`crate::phys::DmuType::Dnode`].
    pub dnode: Dnode,

    /// ???
    pub zil_header: ZilHeader,

    /// Type of [`ObjectSet`].
    pub os_type: ObjectSetType,

    /// ???
    pub user_accounting_complete: bool,

    /// ???
    pub user_object_accounting_complete: bool,

    /// ???
    pub project_quota_complete: bool,

    /// ???
    pub portable_mac: [u8; ObjectSet::MAC_LEN],

    /// ???
    pub local_mac: [u8; ObjectSet::MAC_LEN],

    /// ???
    pub extension: ObjectSetExtension,
}

/** [`ObjectSet`] tail extensions.
 */
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ObjectSetExtension {
    /// ???
    Zero {},

    /// ???
    Two {
        /// ???
        user_used: Option<Dnode>,

        /// ???
        group_used: Option<Dnode>,
    },

    /// ???
    Three {
        /// ???
        user_used: Option<Dnode>,

        /// ???
        group_used: Option<Dnode>,

        /// ???
        project_used: Option<Dnode>,
    },
}

impl ObjectSet {
    /// Byte size of a encoded [`ObjectSet`] with [`ObjectSetExtension::Zero`].
    pub const SIZE_EXT_0: usize = (Dnode::SIZE
        + ZilHeader::SIZE
        + 16
        + ObjectSet::MAC_LEN * 2
        + ObjectSet::PADDING_SIZE_NONE);

    /// Byte size of a encoded [`ObjectSet`] [`ObjectSetExtension::Two`]
    pub const SIZE_EXT_2: usize = (ObjectSet::SIZE_EXT_0 + 2 * Dnode::SIZE);

    /// Byte size of a encoded [`ObjectSet`] with [`ObjectSetExtension::Three`].
    pub const SIZE_EXT_3: usize =
        (ObjectSet::SIZE_EXT_2 + Dnode::SIZE + ObjectSet::PADDING_SIZE_THREE);

    /// Byte size of [`ObjectSet`] MAC.
    pub const MAC_LEN: usize = 32;

    /// Padding size for [`ObjectSetExtension::Zero`].
    const PADDING_SIZE_NONE: usize = 240;

    /// Padding size for [`ObjectSetExtension::Three`].
    const PADDING_SIZE_THREE: usize = 1536;

    /** Decodes an [`ObjectSet`].
     *
     * # Errors
     *
     * Returns [`ObjectSetDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<ObjectSet, ObjectSetDecodeError> {
        ////////////////////////////////
        // Decode object set dnode.
        let dnode = match Dnode::from_decoder(decoder)? {
            Some(dnode) => dnode,
            None => return Err(ObjectSetDecodeError::EmptyDnode {}),
        };

        ////////////////////////////////
        // Decode ZIL header.
        let zil_header = ZilHeader::from_decoder(decoder)?;

        ////////////////////////////////
        // Decode object set type.
        let os_type = decoder.get_u64()?;
        let os_type = ObjectSetType::try_from(os_type)?;

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u64()?;
        if (flags & FLAG_ALL) != flags {
            return Err(ObjectSetDecodeError::Flags { flags });
        }

        ////////////////////////////////
        // Decode MACs.
        let portable_mac = decoder.get_bytes(ObjectSet::MAC_LEN)?.try_into().unwrap();
        let local_mac = decoder.get_bytes(ObjectSet::MAC_LEN)?.try_into().unwrap();

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(ObjectSet::PADDING_SIZE_NONE)?;

        ////////////////////////////////
        // Check for extensions based on length.
        let mut extension = ObjectSetExtension::Zero {};

        if !decoder.is_empty() {
            ////////////////////////////
            // Decode user used and group used.
            let user_used = Dnode::from_decoder(decoder)?;
            let group_used = Dnode::from_decoder(decoder)?;

            if decoder.is_empty() {
                extension = ObjectSetExtension::Two {
                    user_used,
                    group_used,
                };
            } else {
                ////////////////////////
                // Decode project used.
                let project_used = Dnode::from_decoder(decoder)?;

                extension = ObjectSetExtension::Three {
                    user_used,
                    group_used,
                    project_used,
                };

                decoder.skip_zero_padding(ObjectSet::PADDING_SIZE_THREE)?;
            }
        }

        ////////////////////////////////
        // Success.
        Ok(ObjectSet {
            dnode,
            zil_header,
            os_type,

            user_accounting_complete: (flags & FLAG_USER_ACCOUNTING_COMPLETE) != 0,
            user_object_accounting_complete: (flags & FLAG_USER_OBJECT_ACCOUNTING_COMPLETE) != 0,
            project_quota_complete: (flags & FLAG_PROJECT_QUOTA_COMPLETE) != 0,

            portable_mac,
            local_mac,

            extension,
        })
    }

    /** Encodes an [`ObjectSet`].
     *
     * # Errors
     *
     * Returns [`ObjectSetEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), ObjectSetEncodeError> {
        ////////////////////////////////
        // Encode object set dnode.
        self.dnode.to_encoder(encoder)?;

        ////////////////////////////////
        // Encode ZIL header.
        self.zil_header.to_encoder(encoder)?;

        ////////////////////////////////
        // Encode object set type.
        encoder.put_u64(u64::from(self.os_type))?;

        ////////////////////////////////
        // Encode flags.
        let flags = if self.user_accounting_complete {
            FLAG_USER_ACCOUNTING_COMPLETE
        } else {
            0
        } | if self.user_object_accounting_complete {
            FLAG_USER_OBJECT_ACCOUNTING_COMPLETE
        } else {
            0
        } | if self.project_quota_complete {
            FLAG_PROJECT_QUOTA_COMPLETE
        } else {
            0
        };
        encoder.put_u64(flags)?;

        ////////////////////////////////
        // Encode MACs.
        encoder.put_bytes(&self.portable_mac)?;
        encoder.put_bytes(&self.local_mac)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(ObjectSet::PADDING_SIZE_NONE)?;

        ////////////////////////////////
        // Encode extensions.
        match &self.extension {
            ObjectSetExtension::Zero {} => (),
            ObjectSetExtension::Two {
                user_used,
                group_used,
            } => {
                Dnode::option_to_encoder(user_used, encoder)?;
                Dnode::option_to_encoder(group_used, encoder)?;
            }
            ObjectSetExtension::Three {
                user_used,
                group_used,
                project_used,
            } => {
                Dnode::option_to_encoder(user_used, encoder)?;
                Dnode::option_to_encoder(group_used, encoder)?;
                Dnode::option_to_encoder(project_used, encoder)?;
                encoder.put_zero_padding(ObjectSet::PADDING_SIZE_THREE)?;
            }
        };

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ObjectSet`] decode error.
#[derive(Debug)]
pub enum ObjectSetDecodeError {
    /// [`Dnode`] decode error.
    Dnode {
        /// Error.
        err: DnodeDecodeError,
    },

    /// Empty [`Dnode`].
    EmptyDnode {},

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Invalid flags.
    Flags {
        /// Flags.
        flags: u64,
    },

    /// Invalid object set type.
    ObjectSetType {
        /// Error.
        err: ObjectSetTypeError,
    },

    /// [`ZilHeader`] decode error.
    ZilHeader {
        /// Error.
        err: ZilHeaderDecodeError,
    },
}

impl From<DnodeDecodeError> for ObjectSetDecodeError {
    fn from(err: DnodeDecodeError) -> Self {
        ObjectSetDecodeError::Dnode { err }
    }
}

impl From<EndianDecodeError> for ObjectSetDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        ObjectSetDecodeError::Endian { err }
    }
}

impl From<ObjectSetTypeError> for ObjectSetDecodeError {
    fn from(err: ObjectSetTypeError) -> Self {
        ObjectSetDecodeError::ObjectSetType { err }
    }
}

impl From<ZilHeaderDecodeError> for ObjectSetDecodeError {
    fn from(err: ZilHeaderDecodeError) -> Self {
        ObjectSetDecodeError::ZilHeader { err }
    }
}

impl fmt::Display for ObjectSetDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectSetDecodeError::Dnode { err } => {
                write!(f, "ObjectSet decode error | {err}")
            }
            ObjectSetDecodeError::EmptyDnode {} => {
                write!(f, "ObjectSet decode error, empty dnode")
            }
            ObjectSetDecodeError::Endian { err } => {
                write!(f, "ObjectSet decode error | {err}")
            }
            ObjectSetDecodeError::Flags { flags } => {
                write!(f, "ObjectSet decode error, invalid flags {flags:#016x}")
            }
            ObjectSetDecodeError::ObjectSetType { err } => {
                write!(f, "ObjectSet decode error | {err}")
            }
            ObjectSetDecodeError::ZilHeader { err } => {
                write!(f, "ObjectSet decode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ObjectSetDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ObjectSetDecodeError::Dnode { err } => Some(err),
            ObjectSetDecodeError::Endian { err } => Some(err),
            ObjectSetDecodeError::ObjectSetType { err } => Some(err),
            ObjectSetDecodeError::ZilHeader { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ObjectSet`] encode error.
#[derive(Debug)]
pub enum ObjectSetEncodeError {
    /// [`Dnode`] encode error.
    Dnode {
        /// Error.
        err: DnodeEncodeError,
    },

    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// [`ZilHeader`] encode error.
    ZilHeader {
        /// Error.
        err: ZilHeaderEncodeError,
    },
}

impl From<DnodeEncodeError> for ObjectSetEncodeError {
    fn from(err: DnodeEncodeError) -> Self {
        ObjectSetEncodeError::Dnode { err }
    }
}

impl From<EndianEncodeError> for ObjectSetEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        ObjectSetEncodeError::Endian { err }
    }
}

impl From<ZilHeaderEncodeError> for ObjectSetEncodeError {
    fn from(err: ZilHeaderEncodeError) -> Self {
        ObjectSetEncodeError::ZilHeader { err }
    }
}

impl fmt::Display for ObjectSetEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectSetEncodeError::Dnode { err } => {
                write!(f, "ObjectSet encode error | {err}")
            }
            ObjectSetEncodeError::Endian { err } => {
                write!(f, "ObjectSet encode error | {err}")
            }
            ObjectSetEncodeError::ZilHeader { err } => {
                write!(f, "ObjectSet encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ObjectSetEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ObjectSetEncodeError::Dnode { err } => Some(err),
            ObjectSetEncodeError::Endian { err } => Some(err),
            ObjectSetEncodeError::ZilHeader { err } => Some(err),
        }
    }
}
