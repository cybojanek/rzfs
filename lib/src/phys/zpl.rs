// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

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
        /// Unknown version.
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
