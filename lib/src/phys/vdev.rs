// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::SECTOR_SHIFT;

////////////////////////////////////////////////////////////////////////////////

/** Virtual Block Device type.
 *
 * NOTE: This enum type has a lowercase string representation, and is used in
 *       NV lists. It does not have a numerical representation.
 *
 * ```text
 * +-------------+-------------+----------------------------+
 * | Vdev        | SPA Version | Feature                    |
 * +-------------+-------------+----------------------------+
 * | Root        |           1 |                            |
 * | Mirror      |           1 |                            |
 * | Replacing   |           1 |                            |
 * | RaidZ       |           1 |                            |
 * | Disk        |           1 |                            |
 * | File        |           1 |                            |
 * | Missing     |           1 |                            |
 * | Spare       |           3 |                            |
 * | Log         |           7 |                            |
 * | L2Cache     |          10 |                            |
 * | Hole        |          26 |                            |
 * | Indirect    |        5000 | com.delphix:device_removal |
 * | DRaid       |        5000 | org.openzfs:draid          |
 * | DRaid Spare |        5000 | org.openzfs:draid          |
 * +-------------+-------------+----------------------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum VdevType {
    /// A block device.
    Disk,

    /// DRAID.
    DRaid,

    /// DRAID Spare.
    DRaidSpare,

    /// A file.
    File,

    /// ???
    Hole,

    /// ???
    Indirect,

    /// ???
    L2Cache,

    /// ???
    Log,

    /// A mirror (RAID1).
    Mirror,

    /// Placeholder for missing device.
    Missing,

    /// RAID 5 / 6 / 7.
    RaidZ,

    /// ???
    Replacing,

    /// ???
    Root,

    /// ???
    Spare,
}

impl Display for VdevType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl From<VdevType> for &'static str {
    fn from(val: VdevType) -> &'static str {
        match val {
            VdevType::Root => "root",
            VdevType::Mirror => "mirror",
            VdevType::Replacing => "replacing",
            VdevType::RaidZ => "raidz",
            VdevType::Disk => "disk",
            VdevType::File => "file",
            VdevType::Missing => "missing",
            VdevType::Spare => "spare",
            VdevType::Log => "log",
            VdevType::L2Cache => "l2cache",
            VdevType::Hole => "hole",
            VdevType::Indirect => "indirect",
            VdevType::DRaid => "draid",
            VdevType::DRaidSpare => "dspare",
        }
    }
}

impl TryFrom<&str> for VdevType {
    type Error = VdevTypeDecodeError;

    /** Try converting from a [`&str`] to a [`VdevType`].
     *
     * # Errors
     *
     * Returns [`VdevTypeDecodeError`] in case of an unknown [`VdevType`].
     */
    fn try_from(vdev_type: &str) -> Result<Self, Self::Error> {
        match vdev_type {
            "root" => Ok(VdevType::Root),
            "mirror" => Ok(VdevType::Mirror),
            "replacing" => Ok(VdevType::Replacing),
            "raidz" => Ok(VdevType::RaidZ),
            "disk" => Ok(VdevType::Disk),
            "file" => Ok(VdevType::File),
            "missing" => Ok(VdevType::Missing),
            "spare" => Ok(VdevType::Spare),
            "log" => Ok(VdevType::Log),
            "l2cache" => Ok(VdevType::L2Cache),
            "hole" => Ok(VdevType::Hole),
            "indirect" => Ok(VdevType::Indirect),
            "draid" => Ok(VdevType::DRaid),
            "dspare" => Ok(VdevType::DRaidSpare),
            _ => Err(VdevTypeDecodeError::Unknown {}),
        }
    }
}

/// [`VdevType`] decode error.
#[derive(Debug)]
pub enum VdevTypeDecodeError {
    /// Unknown [`VdevType`].
    Unknown {},
}

impl fmt::Display for VdevTypeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VdevTypeDecodeError::Unknown {} => {
                write!(f, "VdevType decode error, unknown type")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for VdevTypeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** VdevTree configuration fields.
 *
 * - This enum type has a lowercase string representation, and is used in NV
 *   lists. It does not have a numerical representation.
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VdevTreeKey {
    /** Minimum allocated byte shift.
     *
     * - [`crate::phys::NvPair`] name: `ashift`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Can only be set on creation time.
     * - The shift of the number of bytes for the smallest allowed IO of
     *   [`crate::phys::Dva`] allocated value. That is:
     *   - if the value is 9, the smallest allocation will be 512 bytes (1 sector)
     *   - if the value is 10, the smallest allocation will be 1024 bytes (2 sectors)
     *   - if the value is 11, the smallest allocation will be 2048 bytes (4 sectors)
     *   - if the value is 12, the smallest allocation will be 4096 bytes (8 sectors)
     * - Must be set to at least the block device physical sector size, in order
     *   to ensure data performance, and data consistency.
     * - All IO will be a multiple of the minimum number of sectors. That is:
     *   - if the value is 9, allocated values can be 1, 2, 3, 4 sectors, etc..
     *   - if the value is 10, allocated values can be 2, 4, 6, 8, 10 sectors, etc...
     *   - if the value is 11, allocated values can be 4, 8, 12, 16, 20 sectors, etc..
     *   - if the value is 12, allocated values can be 8, 16, 24, 32 sectors, etc..
     *
     * Another way to look at it is:
     *
     * ```text
     * minimum_bytes_per_dva = (1 << ashift)
     * minimum_sectors_per_dva = (1 << ashift) >> SECTOR_SHIFT
     * ```
     *
     * - Minimum value is [`crate::phys::VdevTree::ASHIFT_MIN`].
     * - Maximum value is [`crate::phys::VdevTree::ASHIFT_MAX`].
     */
    AllocateShift,

    /** Amount of bytes of allocated for storage.
     *
     * - [`crate::phys::NvPair`] name: `asize`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - This does not include [`crate::phys::Label`] nor [`crate::phys::BootBlock`].
     * - This must be a multiple of [`SECTOR_SHIFT`].
     * - This should be total disk size minus the labels and boot block.
     * - For [`VdevType::RaidZ`], this will be the total raw storage size of all
     *   the disks. For other types, including striped storage, this will be
     *   just the size allocated for this block device.
     */
    AllocateSize,

    /** Array of children for a [`VdevType::Mirror`], or [`VdevType::RaidZ`].
     *
     * - [`crate::phys::NvPair`] name: `children`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::NvListArray`]
     */
    Children,

    /** ???
     *
     * - [`crate::phys::NvPair`] name: `create_txg`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    CreateTxg,

    /** ???
     *
     * - [`crate::phys::NvPair`] name: `devid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     */
    DevId,

    /** Device GUID.
     *
     * - [`crate::phys::NvPair`] name: `guid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - The unique ID of this device.
     * - The value is only 64 bits, so a collision is possible.
     * - Only set for [`VdevType::Disk`], [`VdevType::File`], and will match
     *   [`crate::phys::PoolConfigKey::Guid`].
     */
    Guid,

    /** Virtual Device ID.
     *
     * - [`crate::phys::NvPair`] name: `id`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - 0 for [`VdevType::Mirror`], and [`VdevType::RaidZ`].
     * - 0 for single [`VdevType::Disk`], [`VdevType::File`].
     * - 0 or more for striped [`VdevType::Disk`], [`VdevType::File`].
     */
    Id,

    /** Is this device a ZFS log.
     *
     * - [`crate::phys::NvPair`] name: `is_log`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`] (0 or 1)
     *
     * - Added in [`crate::phys::SpaVersion::V7`].
     * - Also look at [`crate::phys::PoolConfigKey::IsLog`].
     */
    IsLog,

    /** MOS object number of [`crate::phys::DmuType::ObjectArray`] metaslab array.
     *
     * - [`crate::phys::NvPair`] name: `metaslab_array`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    MetaSlabArray,

    /** Bit shift multiple of each index in metaslab array.
     *
     * - [`crate::phys::NvPair`] name: `metaslab_shift`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    MetaSlabShift,

    /** Parity for [`VdevType::RaidZ`].
     *
     * - [`crate::phys::NvPair`] name: `nparity`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Added in [`crate::phys::SpaVersion::V3`].
     * - 1 or absent is `RaidZ1` (RAID 5)
     * - 2 is `RaidZ2` (RAID 6)
     * - 3 is `RaidZ3` (RAID 7)
     */
    NParity,

    /** Path to [`VdevType::Disk`], [`VdevType::File`].
     *
     * - [`crate::phys::NvPair`] name: `path`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     */
    Path,

    /** ???
     *
     * - [`crate::phys::NvPair`] name: `phys_path`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     */
    PhysPath,

    /** [`VdevType`].
     *
     * - [`crate::phys::NvPair`] name: `type`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     */
    VdevType,

    /** If the entire disk is managed by ZFS, or only a portion of it.
     *
     * TODO: What is this used for?
     *
     * - [`crate::phys::NvPair`] name: `whole_disk`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::BooleanValue`]
     */
    WholeDisk,
}

impl VdevTreeKey {
    /// All known NV names
    const ALL: [VdevTreeKey; 14] = [
        VdevTreeKey::AllocateShift,
        VdevTreeKey::AllocateSize,
        VdevTreeKey::Children,
        VdevTreeKey::CreateTxg,
        VdevTreeKey::DevId,
        VdevTreeKey::Guid,
        VdevTreeKey::Id,
        VdevTreeKey::IsLog,
        VdevTreeKey::MetaSlabArray,
        VdevTreeKey::MetaSlabShift,
        VdevTreeKey::Path,
        VdevTreeKey::PhysPath,
        VdevTreeKey::VdevType,
        VdevTreeKey::WholeDisk,
    ];

    /// Get a slice with all of the [`VdevTreeKey`].
    pub fn all() -> &'static [VdevTreeKey] {
        &VdevTreeKey::ALL
    }
}

impl Display for VdevTreeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl From<VdevTreeKey> for &'static str {
    fn from(val: VdevTreeKey) -> &'static str {
        match val {
            VdevTreeKey::AllocateShift => "ashift",
            VdevTreeKey::AllocateSize => "asize",
            VdevTreeKey::Children => "children",
            VdevTreeKey::CreateTxg => "create_txg",
            VdevTreeKey::DevId => "devid",
            VdevTreeKey::Guid => "guid",
            VdevTreeKey::Id => "id",
            VdevTreeKey::IsLog => "is_log",
            VdevTreeKey::MetaSlabArray => "metaslab_array",
            VdevTreeKey::MetaSlabShift => "metaslab_shift",
            VdevTreeKey::NParity => "nparity",
            VdevTreeKey::Path => "path",
            VdevTreeKey::PhysPath => "phys_path",
            VdevTreeKey::VdevType => "type",
            VdevTreeKey::WholeDisk => "whole_disk",
        }
    }
}

impl TryFrom<&str> for VdevTreeKey {
    type Error = VdevTreeKeyDecodeError;

    /** Try converting from a [`&str`] to a [`VdevTreeKey`].
     *
     * # Errors
     *
     * Returns [`VdevTreeKeyDecodeError`] in case of an unknown [`VdevTreeKey`].
     */
    fn try_from(feature: &str) -> Result<Self, Self::Error> {
        match feature {
            "ashift" => Ok(VdevTreeKey::AllocateShift),
            "asize" => Ok(VdevTreeKey::AllocateSize),
            "create_txg" => Ok(VdevTreeKey::CreateTxg),
            "children" => Ok(VdevTreeKey::Children),
            "devid" => Ok(VdevTreeKey::DevId),
            "guid" => Ok(VdevTreeKey::Guid),
            "id" => Ok(VdevTreeKey::Id),
            "is_log" => Ok(VdevTreeKey::IsLog),
            "metaslab_array" => Ok(VdevTreeKey::MetaSlabArray),
            "metaslab_shift" => Ok(VdevTreeKey::MetaSlabShift),
            "nparity" => Ok(VdevTreeKey::NParity),
            "path" => Ok(VdevTreeKey::Path),
            "phys_path" => Ok(VdevTreeKey::PhysPath),
            "type" => Ok(VdevTreeKey::VdevType),
            "whole_disk" => Ok(VdevTreeKey::WholeDisk),
            _ => Err(VdevTreeKeyDecodeError::Unknown {}),
        }
    }
}

/// [`VdevTreeKey`] decode error.
#[derive(Debug)]
pub enum VdevTreeKeyDecodeError {
    /// Unknown [`VdevTreeKey`].
    Unknown {},
}

impl fmt::Display for VdevTreeKeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VdevTreeKeyDecodeError::Unknown {} => {
                write!(f, "VdevTreeKey decode error, unknown key")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for VdevTreeKeyDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Struct for [`VdevTreeKey`] fields.
#[derive(Debug)]
pub struct VdevTree {}

impl VdevTree {
    /// Minimum value for [`VdevTreeKey::AllocateShift`].
    pub const ASHIFT_MIN: u32 = SECTOR_SHIFT;

    /// Maximum value for [`VdevTreeKey::AllocateShift`].
    pub const ASHIFT_MAX: u32 = 16;
}
