// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Version.
 *
 * - Historically, it was incremented when the format of data on disk changed.
 * - V28 is the last open source version, and V29+ are proprietary and only
 *   available through Oracle Solaris.
 * - Since V5000, changes are indicated using [`crate::phys::Feature`].
 */
#[derive(Clone, Copy, Debug)]
pub enum Version {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8 = 8,
    V9 = 9,
    V10 = 10,
    V11 = 11,
    V12 = 12,
    V13 = 13,
    V14 = 14,
    V15 = 15,
    V16 = 16,
    V17 = 17,
    V18 = 18,
    V19 = 19,
    V20 = 20,
    V21 = 21,
    V22 = 22,
    V23 = 23,
    V24 = 24,
    V25 = 25,
    V26 = 26,
    V27 = 27,
    V28 = 28,
    V5000 = 5000,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::V1 => write!(f, "1"),
            Version::V2 => write!(f, "2"),
            Version::V3 => write!(f, "3"),
            Version::V4 => write!(f, "4"),
            Version::V5 => write!(f, "5"),
            Version::V6 => write!(f, "6"),
            Version::V7 => write!(f, "7"),
            Version::V8 => write!(f, "8"),
            Version::V9 => write!(f, "9"),
            Version::V10 => write!(f, "10"),
            Version::V11 => write!(f, "11"),
            Version::V12 => write!(f, "12"),
            Version::V13 => write!(f, "13"),
            Version::V14 => write!(f, "14"),
            Version::V15 => write!(f, "15"),
            Version::V16 => write!(f, "16"),
            Version::V17 => write!(f, "17"),
            Version::V18 => write!(f, "18"),
            Version::V19 => write!(f, "19"),
            Version::V20 => write!(f, "20"),
            Version::V21 => write!(f, "21"),
            Version::V22 => write!(f, "22"),
            Version::V23 => write!(f, "23"),
            Version::V24 => write!(f, "24"),
            Version::V25 => write!(f, "25"),
            Version::V26 => write!(f, "26"),
            Version::V27 => write!(f, "27"),
            Version::V28 => write!(f, "28"),
            Version::V5000 => write!(f, "5000"),
        }
    }
}

impl From<Version> for u64 {
    fn from(val: Version) -> u64 {
        val as u64
    }
}

impl TryFrom<u64> for Version {
    type Error = VersionError;

    /** Try converting from a [`u64`] to a [`Version`].
     *
     * # Errors
     *
     * Returns [`VersionError`] in case of an invalid [`Version`].
     */
    fn try_from(version: u64) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(Version::V1),
            2 => Ok(Version::V2),
            3 => Ok(Version::V3),
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            6 => Ok(Version::V6),
            7 => Ok(Version::V7),
            8 => Ok(Version::V8),
            9 => Ok(Version::V9),
            10 => Ok(Version::V10),
            11 => Ok(Version::V11),
            12 => Ok(Version::V12),
            13 => Ok(Version::V13),
            14 => Ok(Version::V14),
            15 => Ok(Version::V15),
            16 => Ok(Version::V16),
            17 => Ok(Version::V17),
            18 => Ok(Version::V18),
            19 => Ok(Version::V19),
            20 => Ok(Version::V20),
            21 => Ok(Version::V21),
            22 => Ok(Version::V22),
            23 => Ok(Version::V23),
            24 => Ok(Version::V24),
            25 => Ok(Version::V25),
            26 => Ok(Version::V26),
            27 => Ok(Version::V27),
            28 => Ok(Version::V28),
            5000 => Ok(Version::V5000),
            _ => Err(VersionError::InvalidCompression { value: version }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`Version`] conversion error.
 */
#[derive(Debug)]
pub enum VersionError {
    /** Invalid [`Version`].
     *
     * - `value` - Invalid value.
     */
    InvalidCompression { value: u64 },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::InvalidCompression { value } => {
                write!(f, "Version invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for VersionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
