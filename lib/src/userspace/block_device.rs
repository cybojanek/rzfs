// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use std::error;

use std::fs;
use std::io;
use std::os::unix::fs::FileExt;

use crate::phys::{is_multiple_of_sector_size, SECTOR_SHIFT};

/// A block device interface to a file.
#[derive(Debug)]
pub struct BlockDevice {
    /// Block device file.
    pub file: fs::File,

    /// Size of file in sectors.
    pub sectors: u64,
}

impl BlockDevice {
    /** Open the path as a block device.
     *
     * # Errors
     *
     * Returns [`BlockDeviceOpenError`] in case of error.
     */
    pub fn open(path: &str) -> Result<BlockDevice, BlockDeviceOpenError> {
        ////////////////////////////////////
        // Open file.
        let file = match fs::OpenOptions::new().read(true).open(&path) {
            Ok(v) => v,
            Err(e) => return Err(BlockDeviceOpenError::OpenError { err: e }),
        };

        ////////////////////////////////////
        // Get file size.
        let metadata = match file.metadata() {
            Ok(v) => v,
            Err(e) => return Err(BlockDeviceOpenError::MetadataError { err: e }),
        };

        let size = metadata.len();
        if !is_multiple_of_sector_size(size) {
            return Err(BlockDeviceOpenError::InvalidSize { size: size });
        }

        ////////////////////////////////////
        // Success.
        Ok(BlockDevice {
            file: file,
            sectors: size >> SECTOR_SHIFT,
        })
    }

    /** Read the data starting at sector.
     *
     * # Errors
     *
     * Returns [`BlockDeviceReadError`] in case of error.
     */
    pub fn read(&self, data: &mut [u8], sector: u64) -> Result<(), BlockDeviceReadError> {
        let size = data.len();

        ////////////////////////////////
        // Check destination data is a multiple of sector.
        if !is_multiple_of_sector_size(size) {
            return Err(BlockDeviceReadError::InvalidRead {
                sector: sector,
                size: size,
            });
        }

        ////////////////////////////////
        // Compute number of sectors.
        let sector_count = match u64::try_from(size >> SECTOR_SHIFT) {
            Ok(v) => v,
            Err(_) => {
                return Err(BlockDeviceReadError::InvalidRead {
                    sector: sector,
                    size: size,
                })
            }
        };

        ////////////////////////////////
        // Check bounds.
        if sector > self.sectors || self.sectors - sector < sector_count {
            return Err(BlockDeviceReadError::InvalidRead {
                sector: sector,
                size: size,
            });
        }

        ////////////////////////////////
        // Compute offset in bytes for read_at.
        let offset = match sector.checked_shl(SECTOR_SHIFT) {
            Some(v) => v,
            None => {
                return Err(BlockDeviceReadError::InvalidRead {
                    sector: sector,
                    size: size,
                })
            }
        };

        ////////////////////////////////
        // Read bytes, while handling short reads.
        let mut offset = offset;
        let mut data: &mut [u8] = data;

        while data.len() > 0 {
            let read = match self.file.read_at(data, offset) {
                Ok(v) => v,
                Err(e) => {
                    return Err(BlockDeviceReadError::IoError {
                        err: e,
                        sector: sector,
                        size: size,
                    })
                }
            };

            let len = data.len();
            data = &mut data[read..len];
            offset += read as u64;
        }

        ////////////////////////////////
        // Success.
        Ok(())
    }
}

/// [`BlockDevice`] open error.
#[derive(Debug)]
pub enum BlockDeviceOpenError {
    /// Block device invalid size.
    InvalidSize {
        /// Size.
        size: u64,
    },

    /// Block device open error.
    OpenError {
        /// Error.
        err: io::Error,
    },

    /// Block device metadata query error.
    MetadataError {
        /// Error.
        err: io::Error,
    },
}

impl fmt::Display for BlockDeviceOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockDeviceOpenError::InvalidSize { size } => {
                write!(f, "Block Device invalid size:0x{size:016x}")
            }
            BlockDeviceOpenError::OpenError { err } => {
                write!(f, "Block Device open error: [{err}]")
            }
            BlockDeviceOpenError::MetadataError { err } => {
                write!(f, "Block Device metadata error: [{err}]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockDeviceOpenError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockDeviceOpenError::OpenError { err } => Some(err),
            BlockDeviceOpenError::MetadataError { err } => Some(err),
            _ => None,
        }
    }
}

/// [`BlockDevice`] read error.
#[derive(Debug)]
pub enum BlockDeviceReadError {
    /// Invalid read bytes offset and / or size.
    InvalidRead {
        /// Sector.
        sector: u64,
        /// Size in bytes.
        size: usize,
    },

    /// I/O error.
    IoError {
        /// Error.
        err: io::Error,
        /// Sector.
        sector: u64,
        /// Size.
        size: usize,
    },
}

impl fmt::Display for BlockDeviceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockDeviceReadError::InvalidRead { sector, size } => {
                write!(
                    f,
                    "Block Device invalid read sector:0x{sector:016x} size:0x{size:016x}"
                )
            }
            BlockDeviceReadError::IoError { err, sector, size } => {
                write!(
                    f,
                    "Block Device read IO error at sector:0x{sector:016x} size:0x{size:016x}: [{err}]"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockDeviceReadError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockDeviceReadError::IoError {
                err,
                sector: _,
                size: _,
            } => Some(err),
            _ => None,
        }
    }
}
