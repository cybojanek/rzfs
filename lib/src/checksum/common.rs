// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::phys::{ChecksumType, EndianOrder};
use core::fmt;

#[cfg(feature = "std")]
use std::error;

/// [`Checksum`] error.
#[derive(Debug)]
pub enum ChecksumError {
    /// Unsupported [`ChecksumType`].
    Unsupported {
        /// Unsupported value.
        checksum: ChecksumType,
        /// Implementation.
        implementation: &'static str,
    },
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumError::Unsupported {
                checksum,
                implementation,
            } => {
                write!(f, "Checksum unsupported {checksum} {implementation}")
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
    /** Reset the checksum to initial state to update bytes in [`EndianOrder`].
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn reset(&mut self, order: EndianOrder) -> Result<(), ChecksumError>;

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
     * Checksum is returned in native byte order.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn finalize(&mut self) -> Result<[u64; 4], ChecksumError>;

    /** Hash the bytes in [`EndianOrder`] and return the result.
     *
     * Checksum is returned in native byte order.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] in case of error.
     */
    fn hash(&mut self, data: &[u8], order: EndianOrder) -> Result<[u64; 4], ChecksumError>;
}
