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
pub enum Type {
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

impl Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Inherit => write!(f, "Inherit"),
            Type::On => write!(f, "On"),
            Type::Off => write!(f, "Off"),
            Type::Label => write!(f, "Label"),
            Type::GangHeader => write!(f, "GangHeader"),
            Type::Zilog => write!(f, "Zilog"),
            Type::Fletcher2 => write!(f, "Fletcher2"),
            Type::Fletcher4 => write!(f, "Fletcher4"),
            Type::Sha256 => write!(f, "Sha256"),
            Type::Zilog2 => write!(f, "Zilog2"),
            Type::NoParity => write!(f, "NoParity"),
            Type::Sha512_256 => write!(f, "Sha512_256"),
            Type::Skein => write!(f, "Skein"),
            Type::Edonr => write!(f, "Edonr"),
            Type::Blake3 => write!(f, "Blake3"),
        }
    }
}

impl From<Type> for u8 {
    fn from(val: Type) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for Type {
    type Error = TypeError;

    /** Try converting from a [`u8`] to a [`Type`].
     *
     * # Errors
     *
     * Returns [`TypeError`] in case of an invalid checksum.
     */
    fn try_from(checksum: u8) -> Result<Self, Self::Error> {
        match checksum {
            0 => Ok(Type::Inherit),
            1 => Ok(Type::On),
            2 => Ok(Type::Off),
            3 => Ok(Type::Label),
            4 => Ok(Type::GangHeader),
            5 => Ok(Type::Zilog),
            6 => Ok(Type::Fletcher2),
            7 => Ok(Type::Fletcher4),
            8 => Ok(Type::Sha256),
            9 => Ok(Type::Zilog2),
            10 => Ok(Type::NoParity),
            11 => Ok(Type::Sha512_256),
            12 => Ok(Type::Skein),
            13 => Ok(Type::Edonr),
            14 => Ok(Type::Blake3),
            _ => Err(TypeError::InvalidChecksum { value: checksum }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum TypeError {
    /** Invalid checksum type value.
     *
     * - `value` - Invalid value.
     */
    InvalidChecksum { value: u8 },
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeError::InvalidChecksum { value } => {
                write!(f, "Checksum Type invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for TypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////
