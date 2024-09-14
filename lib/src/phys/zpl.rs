// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{
    Acl, AclDecodeError, AclEncodeError, BinaryDecodeError, BinaryDecoder, BinaryEncodeError,
    BinaryEncoder,
};

////////////////////////////////////////////////////////////////////////////////

/** ZFS Posix Layer (ZPL) Version.
 */
#[derive(Clone, Copy, Debug)]
pub enum ZplVersion {
    /// ZPL version 1.
    V1 = 1,

    /// ZPL version 2.
    V2 = 2,

    /// ZPL version 3.
    V3 = 3,

    /// ZPL version 4.
    V4 = 4,

    /// ZPL version 5.
    V5 = 5,
}

////////////////////////////////////////////////////////////////////////////////

impl From<ZplVersion> for u64 {
    fn from(val: ZplVersion) -> u64 {
        val as u64
    }
}

impl Display for ZplVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", u64::from(*self))
    }
}

impl TryFrom<u64> for ZplVersion {
    type Error = ZplVersionError;

    /** Try converting from a [`u64`] to a [`ZplVersion`].
     *
     * # Errors
     *
     * Returns [`ZplVersionError`] in case of an unknown [`ZplVersion`].
     */
    fn try_from(version: u64) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(ZplVersion::V1),
            2 => Ok(ZplVersion::V2),
            3 => Ok(ZplVersion::V3),
            4 => Ok(ZplVersion::V4),
            5 => Ok(ZplVersion::V5),
            _ => Err(ZplVersionError::Unknown { version }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`ZplVersion`] conversion error.
#[derive(Debug)]
pub enum ZplVersionError {
    /// Unknown [`ZplVersion`].
    Unknown {
        /// Version.
        version: u64,
    },
}

impl fmt::Display for ZplVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZplVersionError::Unknown { version } => {
                write!(f, "Unknown ZplVersion {version}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZplVersionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Znode`] file type.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ZnodeFileType {
    /// Fifo (first-in-first-out) pipe.
    Fifo = 1,

    /// Character device.
    Character = 2,

    /// Directory.
    Directory = 4,

    /// Block device.
    Block = 6,

    /// Regular file.
    Regular = 8,

    /// Symbolic link.
    Symlink = 10,

    /// Unix socket.
    Socket = 12,

    /// Solaris IPC door.
    Door = 13,

    /// Solaris event port.
    EventPort = 14,
}

impl Display for ZnodeFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZnodeFileType::Fifo => write!(f, "Fifo"),
            ZnodeFileType::Character => write!(f, "Character"),
            ZnodeFileType::Directory => write!(f, "Directory"),
            ZnodeFileType::Block => write!(f, "Block"),
            ZnodeFileType::Regular => write!(f, "Regular"),
            ZnodeFileType::Symlink => write!(f, "Symlink"),
            ZnodeFileType::Socket => write!(f, "Socket"),
            ZnodeFileType::Door => write!(f, "Door"),
            ZnodeFileType::EventPort => write!(f, "EventPort"),
        }
    }
}

impl From<ZnodeFileType> for u8 {
    fn from(val: ZnodeFileType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for ZnodeFileType {
    type Error = ZnodeFileTypeError;

    /** Try converting from a [`u8`] to a [`ZnodeFileType`].
     *
     * # Errors
     *
     * Returns [`ZnodeFileTypeError`] in case of an unknown [`ZnodeFileType`].
     */
    fn try_from(file_type: u8) -> Result<Self, Self::Error> {
        match file_type {
            1 => Ok(ZnodeFileType::Fifo),
            2 => Ok(ZnodeFileType::Character),
            4 => Ok(ZnodeFileType::Directory),
            6 => Ok(ZnodeFileType::Block),
            8 => Ok(ZnodeFileType::Regular),
            10 => Ok(ZnodeFileType::Symlink),
            12 => Ok(ZnodeFileType::Socket),
            13 => Ok(ZnodeFileType::Door),
            14 => Ok(ZnodeFileType::EventPort),
            _ => Err(ZnodeFileTypeError::Unknown { file_type }),
        }
    }
}

/// [`ZnodeFileType`] conversion error.
#[derive(Debug)]
pub enum ZnodeFileTypeError {
    /// Unknown [`ZnodeFileType`].
    Unknown {
        /// File type.
        file_type: u8,
    },
}

impl fmt::Display for ZnodeFileTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZnodeFileTypeError::Unknown { file_type } => {
                write!(f, "Unknown ZnodeFileType {file_type}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZnodeFileTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Znode`] time since January 1st, 1970 (GMT).
#[derive(Debug)]
pub struct ZnodeTime {
    /// Seconds.
    pub seconds: u64,

    /// Nanoseconds, fractional part of a second.
    pub nanoseconds: u64,
}

impl ZnodeTime {
    /** Decodes a [`ZnodeTime`].
     *
     * # Errors
     *
     * Returns [`BinaryDecodeError`] on error.
     */
    pub fn from_decoder(
        decoder: &mut dyn BinaryDecoder<'_>,
    ) -> Result<ZnodeTime, BinaryDecodeError> {
        Ok(ZnodeTime {
            seconds: decoder.get_u64()?,
            nanoseconds: decoder.get_u64()?,
        })
    }

    /** Encodes a [`ZnodeTime`].
     *
     * # Errors
     *
     * Returns [`BinaryEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut dyn BinaryEncoder<'_>) -> Result<(), BinaryEncodeError> {
        encoder.put_u64(self.seconds)?;
        encoder.put_u64(self.nanoseconds)?;
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Znode`] permission wrapper struct.
pub struct ZnodePermission;

impl ZnodePermission {
    /// [`Znode`] permission bits mask for S_ISUID (setuid).
    pub const SUID: u16 = 0o4000;

    /// [`Znode`] permission bits mask for S_ISGID (setgid).
    pub const SGID: u16 = 0o2000;

    /// [`Znode`] permission bits mask for S_ISVTX (sticky).
    pub const STCK: u16 = 0o1000;

    /// [`Znode`] permission bits mask for S_IRUSR (user read).
    pub const USR_R: u16 = 0o0400;

    /// [`Znode`] permission bits mask for S_IWUSR (user write).
    pub const USR_W: u16 = 0o0200;

    /// [`Znode`] permission bits mask for S_IXUSR (user execute).
    pub const USR_X: u16 = 0o0100;

    /// [`Znode`] permission bits mask for S_IRGRP (group read).
    pub const GRP_R: u16 = 0o0040;

    /// [`Znode`] permission bits mask for S_IWGRP (group write).
    pub const GRP_W: u16 = 0o0020;

    /// [`Znode`] permission bits mask for S_IXGRP (group execute).
    pub const GRP_X: u16 = 0o0010;

    /// [`Znode`] permission bits mask for S_IROTH (other read).
    pub const OTH_R: u16 = 0o0004;

    /// [`Znode`] permission bits mask for S_IWOTH (other write).
    pub const OTH_W: u16 = 0o0002;

    /// [`Znode`] permission bits mask for S_IXOTH (other execute).
    pub const OTH_X: u16 = 0o0001;

    /// [`Znode`] permission bits mask.
    pub const MASK: u16 = 0o7777;
}

////////////////////////////////////////////////////////////////////////////////

/** Znode.
 *
 * ### Byte layout.
 *
 * - Bytes: 264
 *
 * ```text
 * +-------------------------------+------+-------------+-------------+
 * | Field                         | Size | ZPL Version | SPA Version |
 * +-------------------------------+------+-------------+-------------+
 * | access time seconds           |    8 |           1 |           1 |
 * | access time nanoseconds       |    8 |           1 |           1 |
 * | modified time seconds         |    8 |           1 |           1 |
 * | modified time nanoseconds     |    8 |           1 |           1 |
 * | change time seconds           |    8 |           1 |           1 |
 * | change time nanoseconds       |    8 |           1 |           1 |
 * | creation time seconds         |    8 |           1 |           1 |
 * | creation time nanoseconds     |    8 |           1 |           1 |
 * | creation transaction group    |    8 |           1 |           1 |
 * | mode                          |    8 |           1 |           1 |
 * | size                          |    8 |           1 |           1 |
 * | parent object id              |    8 |           1 |           1 |
 * | number of links               |    8 |           1 |           1 |
 * | extended attributes object id |    8 |           1 |           1 |
 * | device number                 |    8 |           1 |           1 |
 * | flags                         |    8 |           1 |           1 |
 * | user id                       |    8 |           1 |           1 |
 * | group id                      |    8 |           1 |           1 |
 * | extra_attributes              |    8 |           3 |           9 |
 * | padding                       |   24 |             |             |
 * | acl                           |   88 |           1 |           1 |
 * +-------------------------------+------+-------------+-------------+
 *
 * bit layout of mode:
 *
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                          unused (48)                                          |typ (4)|u|g|k|r|w|x|r|w|x|r|w|x|
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct Znode {
    /// Access time.
    pub access_time: ZnodeTime,

    /// Modified time of contents.
    pub modified_time: ZnodeTime,

    /// Change time of metadata.
    pub change_time: ZnodeTime,

    /// Creation time.
    pub creation_time: ZnodeTime,

    /// Creation transaction group.
    pub creation_txg: u64,

    /// Unix-style permission bits, refer to [`ZnodePermission`] constants.
    pub permission_bits: u16,

    /// File type.
    pub file_type: ZnodeFileType,

    /// Size in bytes.
    pub size: u64,

    /// Parent object id.
    pub parent_object_id: u64,

    /// Number of hard links to this file.
    pub num_links: u64,

    /// Object id containing ZAP encoded extended attributes for this object.
    pub xattr_object_id: Option<u64>,

    /// Major minor numbers for block and character devices.
    pub device_number: u64,

    /// ???
    pub flags: u64,

    /// File user owner.
    pub user_id: u64,

    /// File group owner.
    pub group_id: u64,

    /// ???
    pub extra_attributes: u64,

    /// [`Acl`].
    pub acl: Acl,
}

impl Znode {
    /// Byte size of an encoded [`Znode`].
    pub const SIZE: usize = 512;

    /// Padding byte size.
    const PADDING_SIZE: usize = 24;

    /// Mode mask for unknown bits.
    const MODE_UNKNOWN_MASK: u64 = u64::MAX ^ ((1 << 16) - 1);

    /// Mode mask for down shifted [`ZnodeFileType`].
    const MODE_FILE_TYPE_MASK_DOWN_SHIFTED: u64 = 0xf;

    /// Mode shift for [`ZnodeFileType`].
    const MODE_FILE_TYPE_SHIFT: usize = 12;

    /** Decodes a [`Znode`].
     *
     * # Errors
     *
     * Returns [`ZnodeDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &mut dyn BinaryDecoder<'_>) -> Result<Znode, ZnodeDecodeError> {
        ////////////////////////////////
        // Decode values.
        let access_time = ZnodeTime::from_decoder(decoder)?;
        let modified_time = ZnodeTime::from_decoder(decoder)?;
        let change_time = ZnodeTime::from_decoder(decoder)?;
        let creation_time = ZnodeTime::from_decoder(decoder)?;

        let creation_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Decode mode.
        let mode = decoder.get_u64()?;
        if (mode & Znode::MODE_UNKNOWN_MASK) != 0 {
            return Err(ZnodeDecodeError::Mode { mode });
        }
        let permission_bits = (mode & u64::from(ZnodePermission::MASK)) as u16;
        let file_type =
            (mode >> Znode::MODE_FILE_TYPE_SHIFT) & Znode::MODE_FILE_TYPE_MASK_DOWN_SHIFTED;
        let file_type = ZnodeFileType::try_from(file_type as u8)?;

        ////////////////////////////////
        // Decode values.
        let size = decoder.get_u64()?;
        let parent_object_id = decoder.get_u64()?;
        if parent_object_id == 0 {
            return Err(ZnodeDecodeError::MissingParentObjectId {});
        }
        let num_links = decoder.get_u64()?;
        let xattr_object_id = match decoder.get_u64()? {
            0 => None,
            v => Some(v),
        };
        let device_number = decoder.get_u64()?;
        let flags = decoder.get_u64()?;
        let user_id = decoder.get_u64()?;
        let group_id = decoder.get_u64()?;
        let extra_attributes = decoder.get_u64()?;

        decoder.skip_zeros(Znode::PADDING_SIZE)?;

        Ok(Znode {
            access_time,
            modified_time,
            change_time,
            creation_time,
            creation_txg,
            permission_bits,
            file_type,
            size,
            parent_object_id,
            num_links,
            xattr_object_id,
            device_number,
            flags,
            user_id,
            group_id,
            extra_attributes,
            acl: Acl::from_decoder(decoder)?,
        })
    }

    /** Encodes a [`Znode`].
     *
     * # Errors
     *
     * Returns [`ZnodeEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut dyn BinaryEncoder<'_>) -> Result<(), ZnodeEncodeError> {
        ////////////////////////////////
        // Encode values.
        self.access_time.to_encoder(encoder)?;
        self.modified_time.to_encoder(encoder)?;
        self.change_time.to_encoder(encoder)?;
        self.creation_time.to_encoder(encoder)?;

        encoder.put_u64(self.creation_txg)?;

        ////////////////////////////////
        // Encode mode.
        if (self.permission_bits & ZnodePermission::MASK) != self.permission_bits {
            return Err(ZnodeEncodeError::Permissions {
                permissions: self.permission_bits,
            });
        }
        let mode = u64::from(u8::from(self.file_type)) << Znode::MODE_FILE_TYPE_SHIFT;
        let mode = mode | u64::from(self.permission_bits);
        encoder.put_u64(mode)?;

        ////////////////////////////////
        // Encode values.
        encoder.put_u64(self.size)?;

        if self.parent_object_id == 0 {
            return Err(ZnodeEncodeError::MissingParentObjectId {});
        }
        encoder.put_u64(self.parent_object_id)?;

        encoder.put_u64(self.num_links)?;
        encoder.put_u64(self.xattr_object_id.unwrap_or(0))?;
        encoder.put_u64(self.device_number)?;
        encoder.put_u64(self.flags)?;
        encoder.put_u64(self.user_id)?;
        encoder.put_u64(self.group_id)?;
        encoder.put_u64(self.extra_attributes)?;

        encoder.put_zeros(Znode::PADDING_SIZE)?;

        self.acl.to_encoder(encoder)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Znode`] decode error.
#[derive(Debug)]
pub enum ZnodeDecodeError {
    /// [`Acl`] decode error.
    Acl {
        /// Error.
        err: AclDecodeError,
    },

    /// [`BinaryDecoder`] error.
    Binary {
        /// Error.
        err: BinaryDecodeError,
    },

    /// [`ZnodeFileType`] error.
    FileType {
        /// Error.
        err: ZnodeFileTypeError,
    },

    /// Missing parent object id.
    MissingParentObjectId {},

    /// Unknown mode.
    Mode {
        /// Mode.
        mode: u64,
    },
}

impl From<AclDecodeError> for ZnodeDecodeError {
    fn from(err: AclDecodeError) -> Self {
        ZnodeDecodeError::Acl { err }
    }
}

impl From<BinaryDecodeError> for ZnodeDecodeError {
    fn from(err: BinaryDecodeError) -> Self {
        ZnodeDecodeError::Binary { err }
    }
}

impl From<ZnodeFileTypeError> for ZnodeDecodeError {
    fn from(err: ZnodeFileTypeError) -> Self {
        ZnodeDecodeError::FileType { err }
    }
}

impl fmt::Display for ZnodeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZnodeDecodeError::Acl { err } => {
                write!(f, "Znode decode error | {err}")
            }
            ZnodeDecodeError::Binary { err } => {
                write!(f, "Znode decode error | {err}")
            }
            ZnodeDecodeError::FileType { err } => {
                write!(f, "Znode decode error | {err}")
            }
            ZnodeDecodeError::MissingParentObjectId {} => {
                write!(f, "Znode decode error, missing parent object id")
            }
            ZnodeDecodeError::Mode { mode } => {
                write!(f, "Znode decode error, unknown mode {mode}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZnodeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZnodeDecodeError::Acl { err } => Some(err),
            ZnodeDecodeError::Binary { err } => Some(err),
            ZnodeDecodeError::FileType { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`Znode`] encode error.
#[derive(Debug)]
pub enum ZnodeEncodeError {
    /// [`Acl`] encode error.
    Acl {
        /// Error.
        err: AclEncodeError,
    },

    /// Binary encode error.
    Binary {
        /// Error.
        err: BinaryEncodeError,
    },

    /// Missing parent object id.
    MissingParentObjectId {},

    /// Bad permission bits.
    Permissions {
        /// Permissions.
        permissions: u16,
    },
}

impl From<AclEncodeError> for ZnodeEncodeError {
    fn from(err: AclEncodeError) -> Self {
        ZnodeEncodeError::Acl { err }
    }
}

impl From<BinaryEncodeError> for ZnodeEncodeError {
    fn from(err: BinaryEncodeError) -> Self {
        ZnodeEncodeError::Binary { err }
    }
}

impl fmt::Display for ZnodeEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZnodeEncodeError::Acl { err } => {
                write!(f, "Znode encode error | {err}")
            }
            ZnodeEncodeError::Binary { err } => {
                write!(f, "Znode encode error | {err}")
            }
            ZnodeEncodeError::MissingParentObjectId {} => {
                write!(f, "Znode encode error, missing parent object id")
            }
            ZnodeEncodeError::Permissions { permissions } => {
                write!(f, "Znode encode error, unknown permission {permissions}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZnodeEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZnodeEncodeError::Acl { err } => Some(err),
            ZnodeEncodeError::Binary { err } => Some(err),
            _ => None,
        }
    }
}
