// SPDX-License-Identifier: GPL-2.0 OR MIT

/** ZFS sector shift.
 *
 * Power of two of a ZFS sector.
 */
pub const SECTOR_SHIFT: u32 = 9;

////////////////////////////////////////////////////////////////////////////////

/** Is the value a multiple of a sector size.
 *
 * ZFS uses sectors of size 512.
 */
pub trait IsMultipleOfSectorSize {
    /** Is the value a multiple of a sector size.
     *
     * ZFS uses sectors of size 512.
     *
     * # Examples
     *
     * ```
     * use zfs::phys::IsMultipleOfSectorSize;
     *
     * let value: u16 = 512;
     * assert_eq!(value.is_multiple_of_sector_size(), true);
     *
     * let value: u32 = 513;
     * assert_eq!(value.is_multiple_of_sector_size(), false);
     *
     * let value: u64 = 1024;
     * assert_eq!(value.is_multiple_of_sector_size(), true);
     *
     * let value: usize = 1025;
     * assert_eq!(value.is_multiple_of_sector_size(), false);
     * ```
     */
    fn is_multiple_of_sector_size(&self) -> bool;
}

impl IsMultipleOfSectorSize for u16 {
    fn is_multiple_of_sector_size(&self) -> bool {
        (self & ((1 << SECTOR_SHIFT) - 1)) == 0
    }
}

impl IsMultipleOfSectorSize for u32 {
    fn is_multiple_of_sector_size(&self) -> bool {
        (self & ((1 << SECTOR_SHIFT) - 1)) == 0
    }
}

impl IsMultipleOfSectorSize for u64 {
    fn is_multiple_of_sector_size(&self) -> bool {
        (self & ((1 << SECTOR_SHIFT) - 1)) == 0
    }
}

impl IsMultipleOfSectorSize for usize {
    fn is_multiple_of_sector_size(&self) -> bool {
        (self & ((1 << SECTOR_SHIFT) - 1)) == 0
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Is the value a multiple of a sector size.
 *
 * ZFS uses sectors of size 512.
 *
 * # Examples
 *
 * ```
 * use zfs::phys::{is_multiple_of_sector_size, IsMultipleOfSectorSize};
 *
 * let value: u16 = 512;
 * assert_eq!(is_multiple_of_sector_size(value), true);
 *
 * let value: u32 = 513;
 * assert_eq!(is_multiple_of_sector_size(value), false);
 *
 * let value: u64 = 1024;
 * assert_eq!(is_multiple_of_sector_size(value), true);
 *
 * let value: usize = 1025;
 * assert_eq!(is_multiple_of_sector_size(value), false);
 * ```
 */
pub fn is_multiple_of_sector_size<F: IsMultipleOfSectorSize>(value: F) -> bool {
    IsMultipleOfSectorSize::is_multiple_of_sector_size(&value)
}

////////////////////////////////////////////////////////////////////////////////
