use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Checksum type.
 *
 * - NoParity was added at the same time as Sha512-256, Skein, and Edonr, but
 *   it does not have a feature flag.
 * - Other ZFS implementations refer to Sha512-256 as just Sha512, but here it
 *   is purposefully Sha512-256, because Sha512-256 is not the same as Sha512
 *   truncated to 256 bits.
 *
 * ```text
 * +------------+------+
 * | Zilog2     |   26 |
 * +------------+------+
 * | NoParity   | 5000 |
 * +------------+------+--------------------+
 * | Sha512-256 | 5000 | org.illumos:sha512 |
 * +------------+------+--------------------+
 * | Skein      | 5000 | org.illumos:skein  |
 * +------------+------+--------------------+
 * | Edonr      | 5000 | org.illumos:edonr  |
 * +------------+------+--------------------+
 * | Blake3     | 5000 | org.openzfs:blake3 |
 * +------------+------+--------------------+
 * ```
 */
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChecksumType {
    Inherit = 0,
    On = 1,
    Off = 2,
    Label = 3,
    GangHeader = 4,
    Zilog = 5,
    Fletcher2 = 6,
    Fletcher4 = 7,
    Sha256 = 8,
    Zilog2 = 9,
    NoParity = 10,
    Sha512_256 = 11,
    Skein = 12,
    Edonr = 13,
    Blake3 = 14,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for ChecksumType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumType::Inherit => write!(f, "Inherit"),
            ChecksumType::On => write!(f, "On"),
            ChecksumType::Off => write!(f, "Off"),
            ChecksumType::Label => write!(f, "Label"),
            ChecksumType::GangHeader => write!(f, "GangHeader"),
            ChecksumType::Zilog => write!(f, "Zilog"),
            ChecksumType::Fletcher2 => write!(f, "Fletcher2"),
            ChecksumType::Fletcher4 => write!(f, "Fletcher4"),
            ChecksumType::Sha256 => write!(f, "Sha256"),
            ChecksumType::Zilog2 => write!(f, "Zilog2"),
            ChecksumType::NoParity => write!(f, "NoParity"),
            ChecksumType::Sha512_256 => write!(f, "Sha512_256"),
            ChecksumType::Skein => write!(f, "Skein"),
            ChecksumType::Edonr => write!(f, "Edonr"),
            ChecksumType::Blake3 => write!(f, "Blake3"),
        }
    }
}

impl From<ChecksumType> for u8 {
    fn from(val: ChecksumType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for ChecksumType {
    type Error = ChecksumTypeError;

    /** Try converting from a [`u8`] to a [`ChecksumType`].
     *
     * # Errors
     *
     * Returns [`ChecksumTypeError`] in case of an invalid checksum.
     */
    fn try_from(checksum: u8) -> Result<Self, Self::Error> {
        match checksum {
            0 => Ok(ChecksumType::Inherit),
            1 => Ok(ChecksumType::On),
            2 => Ok(ChecksumType::Off),
            3 => Ok(ChecksumType::Label),
            4 => Ok(ChecksumType::GangHeader),
            5 => Ok(ChecksumType::Zilog),
            6 => Ok(ChecksumType::Fletcher2),
            7 => Ok(ChecksumType::Fletcher4),
            8 => Ok(ChecksumType::Sha256),
            9 => Ok(ChecksumType::Zilog2),
            10 => Ok(ChecksumType::NoParity),
            11 => Ok(ChecksumType::Sha512_256),
            12 => Ok(ChecksumType::Skein),
            13 => Ok(ChecksumType::Edonr),
            14 => Ok(ChecksumType::Blake3),
            _ => Err(ChecksumTypeError::InvalidValue { value: checksum }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ChecksumTypeError {
    /** Invalid checksum type value.
     *
     * - `value` - Invalid value.
     */
    InvalidValue { value: u8 },
}

impl fmt::Display for ChecksumTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumTypeError::InvalidValue { value } => {
                write!(f, "Checksum Type invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////
