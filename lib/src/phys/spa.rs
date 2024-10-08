// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Storage Pool Allocator (SPA) Version.
 *
 * Historically, it was incremented when the format of data on disk changed.
 * [`SpaVersion::V28`] is the last open source version. V29+ are proprietary and
 * only available through Oracle Solaris. Since [`SpaVersion::V5000`], changes are
 * indicated using [`crate::phys::Feature`].
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaVersion {
    /// SPA version 1.
    V1 = 1,

    /// SPA version 2.
    V2 = 2,

    /// SPA version 3.
    V3 = 3,

    /// SPA version 4.
    V4 = 4,

    /// SPA version 5.
    V5 = 5,

    /// SPA version 6.
    V6 = 6,

    /// SPA version 7.
    V7 = 7,

    /// SPA version 8.
    V8 = 8,

    /// SPA version 9.
    V9 = 9,

    /// SPA version 10.
    V10 = 10,

    /// SPA version 11.
    V11 = 11,

    /// SPA version 12.
    V12 = 12,

    /// SPA version 13.
    V13 = 13,

    /// SPA version 14.
    V14 = 14,

    /// SPA version 15.
    V15 = 15,

    /// SPA version 16.
    V16 = 16,

    /// SPA version 17.
    V17 = 17,

    /// SPA version 18.
    V18 = 18,

    /// SPA version 19.
    V19 = 19,

    /// SPA version 20.
    V20 = 20,

    /// SPA version 21.
    V21 = 21,

    /// SPA version 22.
    V22 = 22,

    /// SPA version 23.
    V23 = 23,

    /// SPA version 24.
    V24 = 24,

    /// SPA version 25.
    V25 = 25,

    /// SPA version 26.
    V26 = 26,

    /// SPA version 27.
    V27 = 27,

    /** SPA version 28.
     *
     * Last open source version.
     */
    V28 = 28,

    /** SPA version 5000.
     *
     * New features are indicated using [`crate::phys::Feature`].
     */
    V5000 = 5000,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for SpaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", u64::from(*self))
    }
}

impl From<SpaVersion> for u64 {
    fn from(val: SpaVersion) -> u64 {
        val as u64
    }
}

impl TryFrom<u64> for SpaVersion {
    type Error = SpaVersionError;

    /** Try converting from a [`u64`] to a [`SpaVersion`].
     *
     * # Errors
     *
     * Returns [`SpaVersionError`] in case of an unknown [`SpaVersion`].
     */
    fn try_from(version: u64) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(SpaVersion::V1),
            2 => Ok(SpaVersion::V2),
            3 => Ok(SpaVersion::V3),
            4 => Ok(SpaVersion::V4),
            5 => Ok(SpaVersion::V5),
            6 => Ok(SpaVersion::V6),
            7 => Ok(SpaVersion::V7),
            8 => Ok(SpaVersion::V8),
            9 => Ok(SpaVersion::V9),
            10 => Ok(SpaVersion::V10),
            11 => Ok(SpaVersion::V11),
            12 => Ok(SpaVersion::V12),
            13 => Ok(SpaVersion::V13),
            14 => Ok(SpaVersion::V14),
            15 => Ok(SpaVersion::V15),
            16 => Ok(SpaVersion::V16),
            17 => Ok(SpaVersion::V17),
            18 => Ok(SpaVersion::V18),
            19 => Ok(SpaVersion::V19),
            20 => Ok(SpaVersion::V20),
            21 => Ok(SpaVersion::V21),
            22 => Ok(SpaVersion::V22),
            23 => Ok(SpaVersion::V23),
            24 => Ok(SpaVersion::V24),
            25 => Ok(SpaVersion::V25),
            26 => Ok(SpaVersion::V26),
            27 => Ok(SpaVersion::V27),
            28 => Ok(SpaVersion::V28),
            5000 => Ok(SpaVersion::V5000),
            _ => Err(SpaVersionError::Unknown { version }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`SpaVersion`] conversion error.
#[derive(Debug)]
pub enum SpaVersionError {
    /// Unknown [`SpaVersion`].
    Unknown {
        /// Version.
        version: u64,
    },
}

impl fmt::Display for SpaVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaVersionError::Unknown { version } => {
                write!(f, "Unknown SpaVersion {version}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SpaVersionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
