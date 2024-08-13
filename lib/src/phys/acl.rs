// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder};

////////////////////////////////////////////////////////////////////////////////

/** [`AceV0`], [`AceV1`] permission wrapper struct.
 *
 * Some of the numerical values are the same, for example
 * [`AcePermission::READ_DATA`] and [`AcePermission::LIST_DIRECTORY`].
 */
#[derive(Debug)]
pub struct AcePermission {
    /// Permission value.
    pub value: u32,
}

impl Display for AcePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut count = 0;

        for (mask, string) in &AcePermission::STRINGS {
            if (mask & self.value) == *mask {
                let sep = match count {
                    0 => "",
                    _ => "|",
                };
                write!(f, "{sep}{string}")?;
                count += 1;
            }
        }

        let unknown = self.value - (self.value & AcePermission::MASK);
        if unknown != 0 {
            let sep = match count {
                0 => "",
                _ => "|",
            };
            write!(f, "{sep}{unknown:#08x}")?;
        }

        Ok(())
    }
}

impl AcePermission {
    /// Read a file.
    pub const READ_DATA: u32 = 0x00000001;

    /// List a directory.
    pub const LIST_DIRECTORY: u32 = 0x00000001;

    /// Write to a file.
    pub const WRITE_DATA: u32 = 0x00000002;

    /// Create a file.
    pub const ADD_FILE: u32 = 0x00000002;

    /// Append to a file.
    pub const APPEND_DATA: u32 = 0x00000004;

    /// Create a directory.
    pub const ADD_SUBDIRECTORY: u32 = 0x00000004;

    /// Read named attributes of a file or directory.
    pub const READ_NAMED_ATTRIBUTES: u32 = 0x00000008;

    /// Write named attributes of a file or directory.
    pub const WRITE_NAMED_ATTRIBUTES: u32 = 0x00000010;

    /// Execute file.
    pub const EXECUTE: u32 = 0x00000020;

    /// Change directory.
    pub const TRAVERSE: u32 = 0x00000020;

    /// Remove a file or subdirectory.
    pub const DELETE_CHILD: u32 = 0x00000040;

    /// Read attributes of a file or directory.
    pub const READ_ATTRIBUTES: u32 = 0x00000080;

    /// Write attributes of a file or directory
    pub const WRITE_ATTRIBUTES: u32 = 0x00000100;

    /// Delete file or directory.
    pub const DELETE: u32 = 0x00010000;

    /// Read the file or directory ACL.
    pub const READ_ACL: u32 = 0x00020000;

    /// Write the file or directory ACL.
    pub const WRITE_ACL: u32 = 0x00040000;

    /// Change ownership of file or directory.
    pub const WRITE_OWNER: u32 = 0x00080000;

    /// Allow synchronous I/O.
    pub const SYNCHRONIZE: u32 = 0x00100000;

    /// Mask of all the values.
    pub const MASK: u32 = (AcePermission::READ_DATA
        | AcePermission::LIST_DIRECTORY
        | AcePermission::WRITE_DATA
        | AcePermission::ADD_FILE
        | AcePermission::APPEND_DATA
        | AcePermission::ADD_SUBDIRECTORY
        | AcePermission::READ_NAMED_ATTRIBUTES
        | AcePermission::WRITE_NAMED_ATTRIBUTES
        | AcePermission::EXECUTE
        | AcePermission::TRAVERSE
        | AcePermission::DELETE_CHILD
        | AcePermission::READ_ATTRIBUTES
        | AcePermission::WRITE_ATTRIBUTES
        | AcePermission::DELETE
        | AcePermission::READ_ACL
        | AcePermission::WRITE_ACL
        | AcePermission::WRITE_OWNER
        | AcePermission::SYNCHRONIZE);

    const STRINGS: [(u32, &'static str); 18] = [
        (AcePermission::READ_DATA, "READ_DATA"),
        (AcePermission::LIST_DIRECTORY, "LIST_DIRECTORY"),
        (AcePermission::WRITE_DATA, "WRITE_DATA"),
        (AcePermission::ADD_FILE, "ADD_FILE"),
        (AcePermission::APPEND_DATA, "APPEND_DATA"),
        (AcePermission::ADD_SUBDIRECTORY, "ADD_SUBDIRECTORY"),
        (
            AcePermission::READ_NAMED_ATTRIBUTES,
            "READ_NAMED_ATTRIBUTES",
        ),
        (
            AcePermission::WRITE_NAMED_ATTRIBUTES,
            "WRITE_NAMED_ATTRIBUTES",
        ),
        (AcePermission::EXECUTE, "EXECUTE"),
        (AcePermission::TRAVERSE, "TRAVERSE"),
        (AcePermission::DELETE_CHILD, "DELETE_CHILD"),
        (AcePermission::READ_ATTRIBUTES, "READ_ATTRIBUTES"),
        (AcePermission::WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
        (AcePermission::DELETE, "DELETE"),
        (AcePermission::READ_ACL, "READ_ACL"),
        (AcePermission::WRITE_ACL, "WRITE_ACL"),
        (AcePermission::WRITE_OWNER, "WRITE_OWNER"),
        (AcePermission::SYNCHRONIZE, "SYNCHRONIZE"),
    ];
}

////////////////////////////////////////////////////////////////////////////////

/// [`AceV0`] and [`AceV1`] type.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum AceType {
    /// Allow principal to perform action requiring permission.
    Allow = 0,

    /// Deny principal to perform action requiring permission.
    Deny = 1,

    /** Log access by principal for action requiring permission.
     *
     * Requires one or both of [`AceFlag::SUCCESSFUL_ACCESS_ACE`],
     * [`AceFlag::FAILED_ACCESS_ACE`].
     */
    Audit = 2,

    /** Generate a system alarm by principal for action requiring permission.
     *
     * Requires one or both of [`AceFlag::SUCCESSFUL_ACCESS_ACE`],
     * [`AceFlag::FAILED_ACCESS_ACE`].
     */
    Alarm = 3,

    /// ???
    AccessAllowCompound = 4,

    /// ???
    AccessAllowObject = 5,

    /// ???
    AccessDenyObject = 6,

    /// ???
    SystemAuditObject = 7,

    /// ???
    SystemAlarmObject = 8,

    /// ???
    AccessAllowCallback = 9,

    /// ???
    AccessDenyCallback = 10,

    /// ???
    AccessAllowCallbackObject = 11,

    /// ???
    AccessDenyCallbackObject = 12,

    /// ???
    SystemAuditCallback = 13,

    /// ???
    SystemAlarmCallback = 14,

    /// ???
    SystemAuditCallbackObject = 15,

    /// ???
    SystemAlarmCallbackObject = 16,
}

impl Display for AceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AceType::Allow => write!(f, "Allow"),
            AceType::Deny => write!(f, "Deny"),
            AceType::Audit => write!(f, "Audit"),
            AceType::Alarm => write!(f, "Alarm"),
            AceType::AccessAllowCompound => write!(f, "AccessAllowCompound"),
            AceType::AccessAllowObject => write!(f, "AccessAllowObject"),
            AceType::AccessDenyObject => write!(f, "AccessDenyObject"),
            AceType::SystemAuditObject => write!(f, "SystemAuditObject"),
            AceType::SystemAlarmObject => write!(f, "SystemAlarmObject"),
            AceType::AccessAllowCallback => write!(f, "AccessAllowCallback"),
            AceType::AccessDenyCallback => write!(f, "AccessDenyCallback"),
            AceType::AccessAllowCallbackObject => write!(f, "AccessAllowCallbackObject"),
            AceType::AccessDenyCallbackObject => write!(f, "AccessDenyCallbackObject"),
            AceType::SystemAuditCallback => write!(f, "SystemAuditCallback"),
            AceType::SystemAlarmCallback => write!(f, "SystemAlarmCallback"),
            AceType::SystemAuditCallbackObject => write!(f, "SystemAuditCallbackObject"),
            AceType::SystemAlarmCallbackObject => write!(f, "SystemAlarmCallbackObject"),
        }
    }
}

impl From<AceType> for u16 {
    fn from(val: AceType) -> u16 {
        val as u16
    }
}

impl TryFrom<u16> for AceType {
    type Error = AceTypeError;

    /** Try converting from a [`u16`] to a [`AceType`].
     *
     * # Errors
     *
     * Returns [`AceTypeError`] in case of an invalid [`AceType`].
     */
    fn try_from(ace_type: u16) -> Result<Self, Self::Error> {
        match ace_type {
            0 => Ok(AceType::Allow),
            1 => Ok(AceType::Deny),
            2 => Ok(AceType::Audit),
            3 => Ok(AceType::Alarm),
            4 => Ok(AceType::AccessAllowCompound),
            5 => Ok(AceType::AccessAllowObject),
            6 => Ok(AceType::AccessDenyObject),
            7 => Ok(AceType::SystemAuditObject),
            8 => Ok(AceType::SystemAlarmObject),
            9 => Ok(AceType::AccessAllowCallback),
            10 => Ok(AceType::AccessDenyCallback),
            11 => Ok(AceType::AccessAllowCallbackObject),
            12 => Ok(AceType::AccessDenyCallbackObject),
            13 => Ok(AceType::SystemAuditCallback),
            14 => Ok(AceType::SystemAlarmCallback),
            15 => Ok(AceType::SystemAuditCallbackObject),
            16 => Ok(AceType::SystemAlarmCallbackObject),
            _ => Err(AceTypeError::Unknown { ace_type }),
        }
    }
}

/// [`AceType`] conversion error.
#[derive(Debug)]
pub enum AceTypeError {
    /// Unknown [`AceType`].
    Unknown {
        /// ACE type.
        ace_type: u16,
    },
}

impl fmt::Display for AceTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AceTypeError::Unknown { ace_type } => {
                write!(f, "Unknown AceType {ace_type}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AceTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`AceV0`], [`AceV1`] flag wrapper struct.
#[derive(Debug)]
pub struct AceFlag {
    /// Flags value.
    pub value: u16,
}

impl Display for AceFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut count = 0;

        for (mask, string) in &AceFlag::STRINGS {
            if (mask & self.value) == *mask {
                let sep = match count {
                    0 => "",
                    _ => "|",
                };
                write!(f, "{sep}{string}")?;
                count += 1;
            }
        }

        let unknown = self.value - (self.value & AceFlag::MASK);
        if unknown != 0 {
            let sep = match count {
                0 => "",
                _ => "|",
            };
            write!(f, "{sep}{unknown:#04x}")?;
        }

        Ok(())
    }
}

impl AceFlag {
    /// ACE to be inherited by files created in this directory.
    pub const FILE_INHERIT_ACE: u16 = 0x0001;

    /// ACE to be inherited by subdirectories created in this directory.
    pub const DIRECTORY_INHERIT_ACE: u16 = 0x0002;

    /// ACE inheritance only applies to files and directories created in this directory.
    pub const NO_PROPAGATE_INHERIT_ACE: u16 = 0x0004;

    /// ACE to be inherited by children, but does not apply to this object itself.
    pub const INHERIT_ONLY_ACE: u16 = 0x0008;

    /** Log successful access by principal for action requiring permission.
     *
     * Requires one or both of [`AceType::Audit`], [`AceType::Alarm`].
     */
    pub const SUCCESSFUL_ACCESS_ACE: u16 = 0x0010;

    /** Log denied access by principal for action requiring permission.
     *
     * Requires one or both of [`AceType::Audit`], [`AceType::Alarm`].
     */
    pub const FAILED_ACCESS_ACE: u16 = 0x0020;

    /// Principal is a group, rather than a user. GROUP ???
    pub const IDENTIFIER_GROUP: u16 = 0x0040;

    /// ACE was inherited from parent directory.
    pub const INHERITED_ACE: u16 = 0x0080;

    /// Principal is a user.
    pub const OWNER: u16 = 0x1000;

    /// Principal is a group. IDENTIFIER_GROUP ???
    pub const GROUP: u16 = 0x2000;

    /// Principal is everyone.
    pub const EVERYONE: u16 = 0x4000;

    /// Mask of types for [`AceFlag`].
    pub const TYPE: u16 =
        (AceFlag::OWNER | AceFlag::GROUP | AceFlag::EVERYONE | AceFlag::IDENTIFIER_GROUP);

    /// Owning group. ???
    pub const OWNING_GROUP: u16 = AceFlag::GROUP | AceFlag::IDENTIFIER_GROUP;

    /// Mask of all the values.
    pub const MASK: u16 = (AceFlag::FILE_INHERIT_ACE
        | AceFlag::DIRECTORY_INHERIT_ACE
        | AceFlag::NO_PROPAGATE_INHERIT_ACE
        | AceFlag::INHERIT_ONLY_ACE
        | AceFlag::SUCCESSFUL_ACCESS_ACE
        | AceFlag::FAILED_ACCESS_ACE
        | AceFlag::IDENTIFIER_GROUP
        | AceFlag::INHERITED_ACE
        | AceFlag::OWNER
        | AceFlag::GROUP
        | AceFlag::EVERYONE);

    const STRINGS: [(u16, &'static str); 11] = [
        (AceFlag::FILE_INHERIT_ACE, "FILE_INHERIT_ACE"),
        (AceFlag::DIRECTORY_INHERIT_ACE, "DIRECTORY_INHERIT_ACE"),
        (
            AceFlag::NO_PROPAGATE_INHERIT_ACE,
            "NO_PROPAGATE_INHERIT_ACE",
        ),
        (AceFlag::INHERIT_ONLY_ACE, "INHERIT_ONLY_ACE"),
        (AceFlag::SUCCESSFUL_ACCESS_ACE, "SUCCESSFUL_ACCESS_ACE"),
        (AceFlag::FAILED_ACCESS_ACE, "FAILED_ACCESS_ACE"),
        (AceFlag::IDENTIFIER_GROUP, "IDENTIFIER_GROUP"),
        (AceFlag::INHERITED_ACE, "INHERITED_ACE"),
        (AceFlag::OWNER, "OWNER"),
        (AceFlag::GROUP, "GROUP"),
        (AceFlag::EVERYONE, "EVERYONE"),
    ];
}

////////////////////////////////////////////////////////////////////////////////

/** Ace V0.
 *
 * ### Byte layout.
 *
 * - Bytes: 12
 *
 * ```text
 * +----------- +------+
 * | Field      | Size |
 * +----------- +------+
 * | id         |    4 |
 * | permission |    4 |
 * | flags      |    2 |
 * | type       |    2 |
 * +----------- +------+
 * ```
*/
#[derive(Debug)]
pub struct AceV0 {
    /// Id of user, group, etc.
    pub id: u32,

    /// [`AcePermission`] mask.
    pub permissions: u32,

    /// [`AceFlag`] mask.
    pub flags: u16,

    /// [`AceType`].
    pub ace_type: AceType,
}

impl AceV0 {
    /// Byte size of an encoded [`AceV0`].
    pub const SIZE: usize = 12;

    /** Decodes a [`AceV0`].
     *
     * # Errors
     *
     * Returns [`AceDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<AceV0, AceDecodeError> {
        ////////////////////////////////
        // Decode values.
        let id = decoder.get_u32()?;
        let permissions = decoder.get_u32()?;
        let flags = decoder.get_u16()?;
        let ace_type = AceType::try_from(decoder.get_u16()?)?;

        ////////////////////////////////
        // Check values are known.
        if (permissions & AcePermission::MASK) != permissions {
            return Err(AceDecodeError::Permissions { permissions });
        }

        if (flags & AceFlag::MASK) != flags {
            return Err(AceDecodeError::Flags { flags });
        }

        // [`AceV0`] is only valid for the following types.
        match ace_type {
            AceType::Allow | AceType::Deny | AceType::Audit | AceType::Alarm => (),
            _ => return Err(AceDecodeError::UnexpectedType { ace_type }),
        };

        ////////////////////////////////
        // Success.
        Ok(AceV0 {
            id,
            permissions,
            flags,
            ace_type,
        })
    }

    /** Encodes a [`AceV0`].
     *
     * # Errors
     *
     * Returns [`AceEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), AceEncodeError> {
        ////////////////////////////////
        // Check values are known.
        if (self.permissions & AcePermission::MASK) != self.permissions {
            return Err(AceEncodeError::Permissions {
                permissions: self.permissions,
            });
        }

        if (self.flags & AceFlag::MASK) != self.flags {
            return Err(AceEncodeError::Flags { flags: self.flags });
        }

        match self.ace_type {
            AceType::Allow | AceType::Deny | AceType::Audit | AceType::Alarm => (),
            _ => {
                return Err(AceEncodeError::UnexpectedType {
                    ace_type: self.ace_type,
                })
            }
        };

        ////////////////////////////////
        // Encode values.
        encoder.put_u32(self.id)?;
        encoder.put_u32(self.permissions)?;
        encoder.put_u16(self.flags)?;
        encoder.put_u16(u16::from(self.ace_type))?;

        Ok(())
    }
}

/** Acl V0.
 *
 * ### Byte layout.
 *
 * - Bytes: 88
 *
 * ```text
 * +----------- +------+
 * | Field      | Size |
 * +----------- +------+
 * | object id  |    8 |
 * | count      |    4 |
 * | version    |    2 |
 * | pad        |    2 |
 * | aces       |   72 |
 * +----------- +------+
 * ```
*/
#[derive(Debug)]
pub struct AclV0 {
    /// Object ID containing [`crate::phys::DmuType::AclV0`].
    pub object_id: Option<u64>,

    /// Number of [`AceV0`] entries.
    pub count: u32,

    /// [`AceV0`] entries.
    pub aces: [AceV0; 6],
}

impl AclV0 {
    /// Byte size of an encoded [`AclV0`].
    pub const SIZE: usize = 88;

    /// Version of [`AclV0`].
    pub const VERSION: u16 = 0;

    /// Padding size of [`AclV0`].
    const PADDING_SIZE: usize = 2;

    /** Decodes an [`AclV0`].
     *
     * # Errors
     *
     * Returns [`AclDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<AclV0, AclDecodeError> {
        ////////////////////////////////
        // Decode values.
        let object_id = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };
        let count = decoder.get_u32()?;
        let version = decoder.get_u16()?;
        decoder.skip_zero_padding(AclV0::PADDING_SIZE)?;

        // Check verison.
        if version != AclV0::VERSION {
            return Err(AclDecodeError::Version { version });
        }

        // Decode aces.
        Ok(AclV0 {
            object_id,
            count,
            aces: [
                AceV0::from_decoder(decoder)?,
                AceV0::from_decoder(decoder)?,
                AceV0::from_decoder(decoder)?,
                AceV0::from_decoder(decoder)?,
                AceV0::from_decoder(decoder)?,
                AceV0::from_decoder(decoder)?,
            ],
        })
    }

    /** Encodes an [`AclV0`].
     *
     * # Errors
     *
     * Returns [`AclEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), AclEncodeError> {
        ////////////////////////////////
        // Encode values.
        encoder.put_u64(self.object_id.unwrap_or(0))?;
        encoder.put_u32(self.count)?;
        encoder.put_u16(AclV0::VERSION)?;
        encoder.put_zero_padding(AclV0::PADDING_SIZE)?;

        for ace in &self.aces {
            ace.to_encoder(encoder)?;
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`AceV1`] header.
 *
 * ### Byte layout.
 *
 * - Bytes: 8
 *
 * ```text
 * +-------------+------+
 * | Field       | Size |
 * +-------------+------+
 * | type        |    2 |
 * | flags       |    2 |
 * | permissions |    4 |
 * +-------------+------+
 * ```
*/
#[derive(Debug)]
pub struct AceV1Header {
    /// [`AceType`].
    pub ace_type: AceType,

    /// [`AceFlag`] mask.
    pub flags: u16,

    /// [`AcePermission`] mask.
    pub permissions: u32,
}

impl AceV1Header {
    /// Byte size of an encoded [`AceV1Header`].
    pub const SIZE: usize = 8;

    /** Decodes an [`AceV1Header`].
     *
     * # Errors
     *
     * Returns [`AceDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<AceV1Header, AceDecodeError> {
        ////////////////////////////////
        // Decode values.
        let ace_type = AceType::try_from(decoder.get_u16()?)?;
        let flags = decoder.get_u16()?;
        let permissions = decoder.get_u32()?;

        ////////////////////////////////
        // Check values are known.
        if (permissions & AcePermission::MASK) != permissions {
            return Err(AceDecodeError::Permissions { permissions });
        }

        if (flags & AceFlag::MASK) != flags {
            return Err(AceDecodeError::Flags { flags });
        }

        ////////////////////////////////
        // Success.
        Ok(AceV1Header {
            ace_type,
            flags,
            permissions,
        })
    }

    /** Encodes an [`AceV1Header`].
     *
     * # Errors
     *
     * Returns [`AceEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), AceEncodeError> {
        ////////////////////////////////
        // Check values are known.
        if (self.permissions & AcePermission::MASK) != self.permissions {
            return Err(AceEncodeError::Permissions {
                permissions: self.permissions,
            });
        }

        if (self.flags & AceFlag::MASK) != self.flags {
            return Err(AceEncodeError::Flags { flags: self.flags });
        }

        match self.ace_type {
            AceType::Allow | AceType::Deny | AceType::Audit | AceType::Alarm => (),
            _ => {
                return Err(AceEncodeError::UnexpectedType {
                    ace_type: self.ace_type,
                })
            }
        };

        ////////////////////////////////
        // Encode values.
        encoder.put_u16(u16::from(self.ace_type))?;
        encoder.put_u16(self.flags)?;
        encoder.put_u32(self.permissions)?;

        Ok(())
    }
}

/** Simple [`AceV1`] is just the [`AceV1Header`].
 *
 * - [`AceType::Allow`], [`AceType::Deny`], when the [`AceFlag::TYPE`] mask is
 *   equal to one of: [`AceFlag::OWNER`], [`AceFlag::OWNING_GROUP`], or
 *   [`AceFlag::EVERYONE`].
 *
 * ### Byte layout.
 *
 * - Bytes: 8
 *
 * ```text
 * +--------+------+
 * | Field  | Size |
 * +--------+------+
 * | header |    8 |
 * +--------+------+
 * ```
*/
#[derive(Debug)]
pub struct AceV1Simple {
    /// Header.
    pub header: AceV1Header,
}

/** Ace V1 ID.
 *
 * - All other Ace types aside from [`AceV1Simple`] and [`AceV1Object`].
 *
 * ### Byte layout.
 *
 * - Bytes: 16
 *
 * ```text
 * +--------+------+
 * | Field  | Size |
 * +--------+------+
 * | header |    8 |
 * | id     |    8 |
 * +--------+------+
 * ```
*/
#[derive(Debug)]
pub struct AceV1Id {
    /// Header.
    pub header: AceV1Header,

    /// Subject id.
    pub id: u64,
}

/** Ace V1 for an object.
 *
 * - This is CIFS specific.
 * - [`AceType::AccessAllowObject`], [`AceType::AccessDenyObject`],
 *   [`AceType::SystemAuditObject`], or [`AceType::SystemAlarmObject`]
 *
 * ### Byte layout.
 *
 * - Bytes: 40
 *
 * ```text
 * +--------------+------+
 * | Field        | Size |
 * +--------------+------+
 * | header       |    8 |
 * | object_guid  |   16 |
 * | inherit_guid |   16 |
 * +--------------+------+
 * ```
*/
#[derive(Debug)]
pub struct AceV1Object {
    /// Header.
    pub header: AceV1Header,

    /// Object GUID.
    pub object_guid: [u8; 16],

    /// Inherit GUID.
    pub inherit_guid: [u8; 16],
}

/** Ace V1.
 *
 * ### Byte layout.
 *
 * - Bytes: 8, 16, 40
 *
 * ```text
 * +--------------+----------+
 * | Field        |     Size |
 * +--------------+----------+
 * | header       |        8 |
 * | ...          | 0, 8, 32 |
 * +--------------+----------+
 */
#[derive(Debug)]
pub enum AceV1 {
    /// Simple.
    Simple(AceV1Simple),

    /// For an ID.
    Id(AceV1Id),

    /// For a CIFS object.
    Object(AceV1Object),
}

/// [`AceV1`] iterator.
pub struct AceV1Iterator<'a> {
    /// [`AclV1`] decoder.
    decoder: EndianDecoder<'a>,
}

impl AceV1Iterator<'_> {
    /** Decodes an [`AceV1`].
     *
     * # Errors
     *
     * Returns [`AceDecodeError`] on error.
     */
    pub fn from_decoder<'a>(
        decoder: &EndianDecoder<'a>,
    ) -> Result<AceV1Iterator<'a>, AceDecodeError> {
        // Get the rest of the bytes as the entries.
        let aces = decoder.get_bytes(decoder.len())?;

        Ok(AceV1Iterator {
            decoder: EndianDecoder::from_bytes(aces, decoder.order()),
        })
    }

    /// Resets the iterator.
    pub fn reset(&mut self) {
        self.decoder.reset();
    }
}

impl<'a> Iterator for AceV1Iterator<'a> {
    type Item = Result<AceV1, AceDecodeError>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if !self.decoder.is_empty() {
            // Decode header.
            let header = match AceV1Header::from_decoder(&self.decoder) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            // Decode body based on ACE type.
            match header.ace_type {
                AceType::AccessAllowObject
                | AceType::AccessDenyObject
                | AceType::SystemAuditObject
                | AceType::SystemAlarmObject => {
                    let object_guid = match self.decoder.get_bytes(16) {
                        Ok(v) => v.try_into().unwrap(),
                        Err(e) => return Some(Err(AceDecodeError::Endian { err: e })),
                    };
                    let inherit_guid = match self.decoder.get_bytes(16) {
                        Ok(v) => v.try_into().unwrap(),
                        Err(e) => return Some(Err(AceDecodeError::Endian { err: e })),
                    };
                    let ace_object = AceV1Object {
                        header,
                        object_guid,
                        inherit_guid,
                    };
                    return Some(Ok(AceV1::Object(ace_object)));
                }
                AceType::Allow | AceType::Deny => match header.flags & AceFlag::TYPE {
                    AceFlag::OWNER | AceFlag::OWNING_GROUP | AceFlag::EVERYONE => {
                        let ace_simple = AceV1Simple { header };
                        return Some(Ok(AceV1::Simple(ace_simple)));
                    }
                    _ => (),
                },
                _ => (),
            }

            let id = match self.decoder.get_u64() {
                Ok(v) => v,
                Err(e) => return Some(Err(AceDecodeError::Endian { err: e })),
            };

            let ace_id = AceV1Id { header, id };

            return Some(Ok(AceV1::Id(ace_id)));
        }

        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Acl V1, introduced in [`crate::phys::ZplVersion::V3`], [`crate::phys::SpaVersion::V9`].
 *
 * ### Byte layout.
 *
 * - Bytes: 88
 *
 * ```text
 * +----------- +------+
 * | Field      | Size |
 * +----------- +------+
 * | object id  |    8 |
 * | size       |    4 |
 * | version    |    2 |
 * | count      |    2 |
 * | aces       |   72 |
 * +----------- +------+
 * ```
*/
#[derive(Debug)]
pub struct AclV1 {
    /// Object ID containing [`crate::phys::DmuType::AclV1`].
    pub object_id: Option<u64>,

    /// Size in bytes.
    pub size: u32,

    /// Number of [`AceV1`].
    pub count: u16,

    /// [`AceV1`] entries.
    pub aces: [u8; AceV0::SIZE * 6],
}

impl AclV1 {
    /// Byte size of an encoded [`AclV1`].
    pub const SIZE: usize = 88;

    /// Version of [`AclV1`].
    pub const VERSION: u16 = 1;

    /** Decodes an [`AclV1`].
     *
     * # Errors
     *
     * Returns [`AclDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<AclV1, AclDecodeError> {
        ////////////////////////////////
        // Decode values.
        let object_id = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };
        let size = decoder.get_u32()?;
        let version = decoder.get_u16()?;
        let count = decoder.get_u16()?;

        // Check version.
        if version != AclV1::VERSION {
            return Err(AclDecodeError::Version { version });
        }

        // Copy aces.
        let aces = decoder.get_bytes(AceV0::SIZE * 6)?;

        Ok(AclV1 {
            object_id,
            size,
            count,
            aces: aces.try_into().unwrap(),
        })
    }

    /** Encodes an [`AclV1`].
     *
     * # Errors
     *
     * Returns [`AclEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), AclEncodeError> {
        ////////////////////////////////
        // Decode values.
        encoder.put_u64(self.object_id.unwrap_or(0))?;
        encoder.put_u32(self.size)?;
        encoder.put_u16(AclV1::VERSION)?;
        encoder.put_u16(self.count)?;

        // TODO(cybojanek): Verify aces
        encoder.put_bytes(&self.aces)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Acl.
#[derive(Debug)]
pub enum Acl {
    /// Version 0.
    V0(AclV0),

    /// Version 1.
    V1(AclV1),
}

impl Acl {
    /** Decodes an [`Acl`].
     *
     * # Errors
     *
     * Returns [`AclDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &EndianDecoder<'_>) -> Result<Acl, AclDecodeError> {
        // Look ahead to get the version, and rewind back to the original position.
        let offset = decoder.offset();
        decoder.skip(12)?;
        let version = decoder.get_u16()?;
        decoder.seek(offset)?;

        match version {
            AclV0::VERSION => Ok(Acl::V0(AclV0::from_decoder(decoder)?)),
            AclV1::VERSION => Ok(Acl::V1(AclV1::from_decoder(decoder)?)),
            _ => Err(AclDecodeError::Version { version }),
        }
    }

    /** Encodes an [`Acl`].
     *
     * # Errors
     *
     * Returns [`AclEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut EndianEncoder<'_>) -> Result<(), AclEncodeError> {
        match self {
            Acl::V0(acl) => acl.to_encoder(encoder),
            Acl::V1(acl) => acl.to_encoder(encoder),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`AceV0`], [`AceV1`] decode error.
#[derive(Debug)]
pub enum AceDecodeError {
    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Unknown [`AcePermission`].
    Permissions {
        /// Permissions.
        permissions: u32,
    },

    /// Unknown flags.
    Flags {
        /// Flags.
        flags: u16,
    },

    /// Unknown [`AceType`].
    Type {
        /// Error.
        err: AceTypeError,
    },

    /// Unexpected type.
    UnexpectedType {
        /// Flags.
        ace_type: AceType,
    },
}

impl From<EndianDecodeError> for AceDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        AceDecodeError::Endian { err }
    }
}

impl From<AceTypeError> for AceDecodeError {
    fn from(err: AceTypeError) -> Self {
        AceDecodeError::Type { err }
    }
}

impl fmt::Display for AceDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AceDecodeError::Endian { err } => {
                write!(f, "Ace decode error | {err}")
            }
            AceDecodeError::Flags { flags } => {
                write!(f, "Ace decode error, unknown flags {flags}")
            }
            AceDecodeError::Permissions { permissions } => {
                write!(f, "Ace decode error, unknown permissions {permissions}")
            }
            AceDecodeError::Type { err } => {
                write!(f, "Ace decode error | {err}")
            }
            AceDecodeError::UnexpectedType { ace_type } => {
                write!(f, "Ace decode error, unexpected AceType {ace_type}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AceDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            AceDecodeError::Endian { err } => Some(err),
            AceDecodeError::Type { err } => Some(err),
            _ => None,
        }
    }
}

/// [`AceV0`], [`AceV1`] encode error.
#[derive(Debug)]
pub enum AceEncodeError {
    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },

    /// Unknown flags.
    Flags {
        /// Flags.
        flags: u16,
    },

    /// Unknown permission bits.
    Permissions {
        /// Permissions.
        permissions: u32,
    },

    /// Unexpected type.
    UnexpectedType {
        /// Flags.
        ace_type: AceType,
    },
}

impl From<EndianEncodeError> for AceEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        AceEncodeError::Endian { err }
    }
}

impl fmt::Display for AceEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AceEncodeError::Endian { err } => {
                write!(f, "Ace encode error | {err}")
            }
            AceEncodeError::Flags { flags } => {
                write!(f, "Ace encode error, unknown flags {flags}")
            }
            AceEncodeError::Permissions { permissions } => {
                write!(f, "Ace encode error, unknown permissions {permissions}")
            }
            AceEncodeError::UnexpectedType { ace_type } => {
                write!(f, "Ace encode error, unexpected AceType {ace_type}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AceEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            AceEncodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Acl`] decode error.
#[derive(Debug)]
pub enum AclDecodeError {
    /// [`AceDecodeError`].
    Ace {
        /// Error.
        err: AceDecodeError,
    },

    /// [`EndianDecoder`] error.
    Endian {
        /// Error.
        err: EndianDecodeError,
    },

    /// Incorrect version.
    Version {
        /// Version.
        version: u16,
    },
}

impl From<AceDecodeError> for AclDecodeError {
    fn from(err: AceDecodeError) -> Self {
        AclDecodeError::Ace { err }
    }
}

impl From<EndianDecodeError> for AclDecodeError {
    fn from(err: EndianDecodeError) -> Self {
        AclDecodeError::Endian { err }
    }
}

impl fmt::Display for AclDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclDecodeError::Ace { err } => {
                write!(f, "Acl decode error | {err}")
            }
            AclDecodeError::Endian { err } => {
                write!(f, "Acl decode error | {err}")
            }
            AclDecodeError::Version { version } => {
                write!(f, "Acl decode error,  unknown version {version}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AclDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            AclDecodeError::Ace { err } => Some(err),
            AclDecodeError::Endian { err } => Some(err),
            _ => None,
        }
    }
}

/// [`Acl`] encode error.
#[derive(Debug)]
pub enum AclEncodeError {
    /// [`AceEncodeError`].
    Ace {
        /// Error.
        err: AceEncodeError,
    },

    /// Endian encode error.
    Endian {
        /// Error.
        err: EndianEncodeError,
    },
}

impl From<AceEncodeError> for AclEncodeError {
    fn from(err: AceEncodeError) -> Self {
        AclEncodeError::Ace { err }
    }
}

impl From<EndianEncodeError> for AclEncodeError {
    fn from(err: EndianEncodeError) -> Self {
        AclEncodeError::Endian { err }
    }
}

impl fmt::Display for AclEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclEncodeError::Ace { err } => {
                write!(f, "Acl encode error | {err}")
            }
            AclEncodeError::Endian { err } => {
                write!(f, "Acl encode error | {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AclEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            AclEncodeError::Ace { err } => Some(err),
            AclEncodeError::Endian { err } => Some(err),
        }
    }
}
