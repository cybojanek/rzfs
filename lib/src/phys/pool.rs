// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Pool state.
 *
 * ```text
 * +------------+-------------+
 * | State      | SPA Version |
 * +------------+-------------+
 * | Active     |           1 |
 * | Exported   |           1 |
 * | Destroyed  |           1 |
 * | Spare      |           3 |
 * | L2Cache    |          10 |
 * +------------+-------------+
 * ```
 */
#[derive(Clone, Copy, Debug)]
pub enum PoolState {
    /// In use.
    Active = 0,

    /// Exported.
    Exported = 1,

    /// Destroyed.
    Destroyed = 2,

    /// Hot spare.
    Spare = 3,

    /// Level 2 ARC.
    L2Cache = 4,
}

impl Display for PoolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolState::Active => write!(f, "Active"),
            PoolState::Exported => write!(f, "Exported"),
            PoolState::Destroyed => write!(f, "Destroyed"),
            PoolState::Spare => write!(f, "Spare"),
            PoolState::L2Cache => write!(f, "L2Cache"),
        }
    }
}

impl From<PoolState> for u64 {
    fn from(val: PoolState) -> u64 {
        val as u64
    }
}

impl TryFrom<u64> for PoolState {
    type Error = PoolStateDecodeError;

    /** Try converting from a [`u64`] to a [`PoolState`].
     *
     * # Errors
     *
     * Returns [`PoolStateDecodeError`] in case of an unknown [`PoolState`].
     */
    fn try_from(pool_state: u64) -> Result<Self, Self::Error> {
        match pool_state {
            0 => Ok(PoolState::Active),
            1 => Ok(PoolState::Exported),
            2 => Ok(PoolState::Destroyed),
            3 => Ok(PoolState::Spare),
            4 => Ok(PoolState::L2Cache),
            _ => Err(PoolStateDecodeError::Unknown { pool_state }),
        }
    }
}

/// [`PoolState`] decode error.
#[derive(Debug)]
pub enum PoolStateDecodeError {
    /// Unknown [`PoolState`].
    Unknown {
        /// Pool state.
        pool_state: u64,
    },
}

impl fmt::Display for PoolStateDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolStateDecodeError::Unknown { pool_state } => {
                write!(f, "PoolState decode error, unknown state {pool_state}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for PoolStateDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Pool errata.
 *
 * - [`crate::phys::SpaVersion::V5000`].
 */
#[derive(Clone, Copy, Debug)]
pub enum PoolErrata {
    /// No errata.
    None = 0,

    /// ???
    Zol2094Scrub = 1,

    /// ???
    Zol2094AsyncDestroy = 2,

    /// ???
    Zol6845Encryption = 3,

    /// ???
    Zol8308Encryption = 4,
}

impl Display for PoolErrata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolErrata::None => write!(f, "None"),
            PoolErrata::Zol2094Scrub => write!(f, "Zol2094Scrub"),
            PoolErrata::Zol2094AsyncDestroy => write!(f, "Zol2094AsyncDestroy"),
            PoolErrata::Zol6845Encryption => write!(f, "Zol6845Encryption"),
            PoolErrata::Zol8308Encryption => write!(f, "Zol8308Encryption"),
        }
    }
}

impl From<PoolErrata> for u64 {
    fn from(val: PoolErrata) -> u64 {
        val as u64
    }
}

impl TryFrom<u64> for PoolErrata {
    type Error = PoolErrataDecodeError;

    /** Try converting from a [`u64`] to a [`PoolErrata`].
     *
     * # Errors
     *
     * Returns [`PoolErrataDecodeError`] in case of an unknown [`PoolErrata`].
     */
    fn try_from(pool_errata: u64) -> Result<Self, Self::Error> {
        match pool_errata {
            0 => Ok(PoolErrata::None),
            1 => Ok(PoolErrata::Zol2094Scrub),
            2 => Ok(PoolErrata::Zol2094AsyncDestroy),
            3 => Ok(PoolErrata::Zol6845Encryption),
            4 => Ok(PoolErrata::Zol8308Encryption),
            _ => Err(PoolErrataDecodeError::Unknown { pool_errata }),
        }
    }
}

/// [`PoolErrata`] decode error.
#[derive(Debug)]
pub enum PoolErrataDecodeError {
    /// Unknown [`PoolErrata`].
    Unknown {
        /// Pool errata.
        pool_errata: u64,
    },
}

impl fmt::Display for PoolErrataDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolErrataDecodeError::Unknown { pool_errata } => {
                write!(f, "PoolErrata decode error, unknown errata {pool_errata}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for PoolErrataDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Pool configuration keys.
 *
 * - This enum type has a lowercase string representation, and is used in NV
 *   lists. It does not have a numerical representation.
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolConfigKey {
    /** [`crate::phys::VdevTreeKey::AllocateShift`] stored in pool config.
     *
     * - Only present in top level pool config for [`crate::phys::VdevType::L2Cache`].
     */
    AllocateShift,

    /** Pool comment.
     *
     * - [`crate::phys::NvPair`] name: `comment`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     *
     * - Added in [`crate::phys::SpaVersion::V5000]`.
     */
    Comment,

    /** [`crate::phys::Compatibility`] restriction.
     *
     * - [`crate::phys::NvPair`] name: `compatibility`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     *
     * - Added in [`crate::phys::SpaVersion::V5000`].
     */
    Compatibility,

    /** [`PoolErrata`].
     *
     * - [`crate::phys::NvPair`] name: `errata`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Added in [`crate::phys::SpaVersion::V5000]`.
     */
    Errata,

    /** [`crate::phys::FeatureSet`] needed for reading.
     *
     * - [`crate::phys::NvPair`] name: `features_for_read`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::NvList`] of [`crate::phys::NvDataType::Boolean`] entries.
     *
     * - Added in [`crate::phys::SpaVersion::V5000`].
     */
    FeaturesForRead,

    /** Device GUID.
     *
     * - [`crate::phys::NvPair`] name: `guid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - The unique ID of this device.
     * - The value is only 64 bits, so a collision is possible.
     */
    Guid,

    /** Host ID which last exported the pool.
     *
     * The unique ID of the host, which last exported the pool.
     * The value is only 32 bits, so a collision is possible.
     *
     * The value is stored in `/etc/hostid`, and can be retrieved using the
     * `hostid` command line tool.
     *
     * - [`crate::phys::NvPair`] name: `hostid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Added between [`crate::phys::SpaVersion::V6]` and [`crate::phys::SpaVersion::V7`].
     */
    HostId,

    /** Host name which last exported the pool.
     *
     * The host name of the host, which last exported the pool.
     *
     * The value is stored in `/etc/hostname`, and can be retrieved using the
     * `hostname` command line tool.
     *
     * - [`crate::phys::NvPair`] name: `hostname`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     *
     * - Added between [`crate::phys::SpaVersion::V6]` and [`crate::phys::SpaVersion::V7`].
     */
    HostName,

    /** Is this device a ZFS log.
     *
     * - [`crate::phys::NvPair`] name: `is_log`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`] (0 or 1)
     *
     * - Added in [`crate::phys::SpaVersion::V7`].
     */
    IsLog,

    /** Is this device a spare.
     *
     * - [`crate::phys::NvPair`] name: `is_spare`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`] (0 or 1)
     *
     * - Added in [`crate::phys::SpaVersion::V3`].
     */
    IsSpare,

    /** Pool name.
     *
     * - [`crate::phys::NvPair`] name: `name`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::String`]
     */
    Name,

    /** Pool guid.
     *
     * - [`crate::phys::NvPair`] name: `pool_guid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - The unique ID of the pool.
     * - The value is only 64 bits, so a collision is possible.
     */
    PoolGuid,

    /** Pool guid before splitting mirror.
     *
     * - [`crate::phys::NvPair`] name: `split_guid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Added in [`crate::phys::SpaVersion::V26`].
     */
    SplitGuid,

    /** [`PoolState`].
     *
     * - [`crate::phys::NvPair`] name: `state`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    State,

    /** Top GUID.
     *
     * The top unique ID is used as a checksum to verify that all VDEVs are online.
     *
     * ```text
     * top_guid = vdev_a.guid + ... + vdev_z.guid + pool.guid
     * ```
     *
     * - [`crate::phys::NvPair`] name: `top_guid`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    TopGuid,

    /** Transaction group.
     *
     * - [`crate::phys::NvPair`] name: `txg`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    Txg,

    /** Number of children in Vdev tree.
     *
     * - [`crate::phys::NvPair`] name: `vdev_children`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     *
     * - Added in [`crate::phys::SpaVersion::V26]`.
     */
    VdevChildren,

    /** Vdev tree.
     *
     * - [`crate::phys::NvPair`] name: `vdev_tree`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::NvList`]
     */
    VdevTree,

    /** [`crate::phys::SpaVersion`].
     *
     * - [`crate::phys::NvPair`] name: `version`
     * - [`crate::phys::NvPair`] value: [`crate::phys::NvDataType::Uint64`]
     */
    Version,
}

impl PoolConfigKey {
    /// All known NV names
    const ALL: [PoolConfigKey; 18] = [
        PoolConfigKey::AllocateShift,
        PoolConfigKey::Comment,
        PoolConfigKey::Compatibility,
        PoolConfigKey::Errata,
        PoolConfigKey::FeaturesForRead,
        PoolConfigKey::Guid,
        PoolConfigKey::HostId,
        PoolConfigKey::HostName,
        PoolConfigKey::IsLog,
        PoolConfigKey::IsSpare,
        PoolConfigKey::Name,
        PoolConfigKey::PoolGuid,
        PoolConfigKey::State,
        PoolConfigKey::TopGuid,
        PoolConfigKey::Txg,
        PoolConfigKey::VdevChildren,
        PoolConfigKey::VdevTree,
        PoolConfigKey::Version,
    ];

    /// Get a slice with all of the [`PoolConfigKey`].
    pub fn all() -> &'static [PoolConfigKey] {
        &PoolConfigKey::ALL
    }
}

impl Display for PoolConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{s}")
    }
}

impl From<PoolConfigKey> for &'static str {
    fn from(val: PoolConfigKey) -> &'static str {
        match val {
            PoolConfigKey::AllocateShift => "ashift",
            PoolConfigKey::Comment => "comment",
            PoolConfigKey::Compatibility => "compatibility",
            PoolConfigKey::Errata => "errata",
            PoolConfigKey::FeaturesForRead => "features_for_read",
            PoolConfigKey::Guid => "guid",
            PoolConfigKey::HostId => "hostid",
            PoolConfigKey::HostName => "hostname",
            PoolConfigKey::IsLog => "is_log",
            PoolConfigKey::IsSpare => "is_spare",
            PoolConfigKey::Name => "name",
            PoolConfigKey::PoolGuid => "pool_guid",
            PoolConfigKey::SplitGuid => "split_guid",
            PoolConfigKey::State => "state",
            PoolConfigKey::TopGuid => "top_guid",
            PoolConfigKey::Txg => "txg",
            PoolConfigKey::VdevChildren => "vdev_children",
            PoolConfigKey::VdevTree => "vdev_tree",
            PoolConfigKey::Version => "version",
        }
    }
}

impl TryFrom<&str> for PoolConfigKey {
    type Error = PoolConfigKeyDecodeError;

    /** Try converting from a [`&str`] to a [`PoolConfigKey`].
     *
     * # Errors
     *
     * Returns [`PoolConfigKeyDecodeError`] in case of an unknown [`PoolConfigKey`].
     */
    fn try_from(feature: &str) -> Result<Self, Self::Error> {
        match feature {
            "comment" => Ok(PoolConfigKey::Comment),
            "compatibility" => Ok(PoolConfigKey::Compatibility),
            "errata" => Ok(PoolConfigKey::Errata),
            "features_for_read" => Ok(PoolConfigKey::FeaturesForRead),
            "guid" => Ok(PoolConfigKey::Guid),
            "hostid" => Ok(PoolConfigKey::HostId),
            "hostname" => Ok(PoolConfigKey::HostName),
            "is_log" => Ok(PoolConfigKey::IsLog),
            "is_spare" => Ok(PoolConfigKey::IsSpare),
            "name" => Ok(PoolConfigKey::Name),
            "pool_guid" => Ok(PoolConfigKey::PoolGuid),
            "split_guid" => Ok(PoolConfigKey::SplitGuid),
            "state" => Ok(PoolConfigKey::State),
            "top_guid" => Ok(PoolConfigKey::TopGuid),
            "txg" => Ok(PoolConfigKey::Txg),
            "vdev_children" => Ok(PoolConfigKey::VdevChildren),
            "vdev_tree" => Ok(PoolConfigKey::VdevTree),
            "version" => Ok(PoolConfigKey::Version),
            _ => Err(PoolConfigKeyDecodeError::Unknown {}),
        }
    }
}

/// [`PoolConfigKey`] decode error.
#[derive(Debug)]
pub enum PoolConfigKeyDecodeError {
    /// Unknown [`PoolConfigKey`].
    Unknown {},
}

impl fmt::Display for PoolConfigKeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolConfigKeyDecodeError::Unknown {} => {
                write!(f, "PoolConfigKey decode error, unknown key")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for PoolConfigKeyDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////
