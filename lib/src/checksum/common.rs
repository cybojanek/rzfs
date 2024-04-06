// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::phys::{ChecksumType, EndianOrder};
use core::fmt;

#[cfg(feature = "std")]
use std::error;

/// [`Checksum`] error.
#[derive(Debug)]
pub enum ChecksumError {
    /// Unsupported [`ChecksumType`] and [`EndianOrder`] combination.
    Unsupported {
        /// Unsupported value.
        checksum: ChecksumType,
        /// Unsupported value.
        order: EndianOrder,
    },
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumError::Unsupported { checksum, order } => {
                write!(f, "Checksum unsupported {checksum} {order}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

/** Checksum for on disk data integrity.
 */
pub trait Checksum {
    /** Reset the checksum to initial state.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn reset(&mut self) -> Result<(), ChecksumError>;

    /** Update the checksum state with the given bytes.
     *
     * The state may buffer some bytes in an internal buffer, depending on
     * the checksum block size.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn update(&mut self, data: &[u8]) -> Result<(), ChecksumError>;

    /** Finalize the checksum and return the result.
     *
     * Data is returned in native byte order.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn finalize(&mut self) -> Result<[u64; 4], ChecksumError>;
}