// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::cmp::Ordering;
use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{NvDecodeError, NvList};
use crate::util::Fstr;

////////////////////////////////////////////////////////////////////////////////

/** Features compatibility.
 *
 * - NV Name: "compatibility"
 * - Added in [`crate::phys::SpaVersion::V5000`].
 */
#[derive(Debug, Eq, PartialEq)]
pub enum Compatibility<'a> {
    /// Compatibility is off, and all features may be enabled.
    Off,

    /// No features may be enabled.
    Legacy,

    /** Comma separated list of paths.
     *
     * - Relative or absolute.
     * - `/etc/zfs/compatibility.d` is checked first.
     * - `/usr/share/zfs/compatibility.d` is checked second.
     * - Only used by zpool create, upgrade, and status.
     * - File contents are one feature per line that may be enabled.
     */
    Files(&'a str),
}

impl Compatibility<'_> {
    /// Get the [`Compatibility`] from the string.
    pub fn from(compatibility: &str) -> Compatibility<'_> {
        match compatibility {
            "off" => Compatibility::Off {},
            "legacy" => Compatibility::Legacy {},
            _ => Compatibility::Files(compatibility),
        }
    }
}

impl<'a> Compatibility<'a> {
    /// Returns an iterator over the [`Compatibility`].
    pub fn iter(&self) -> CompatibilityIterator<'a> {
        CompatibilityIterator {
            compatibility: match self {
                Compatibility::Off => Compatibility::Off,
                Compatibility::Legacy => Compatibility::Legacy,
                Compatibility::Files(files) => Compatibility::Files(files),
            },
            index: 0,
        }
    }
}

impl<'a> From<&Compatibility<'a>> for &'a str {
    fn from(val: &Compatibility<'a>) -> &'a str {
        match val {
            Compatibility::Off => "off",
            Compatibility::Legacy => "legacy",
            Compatibility::Files(compatibility) => compatibility,
        }
    }
}

impl<'a> From<Compatibility<'a>> for &'a str {
    fn from(val: Compatibility<'a>) -> &'a str {
        (&val).into()
    }
}

impl Display for Compatibility<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self.into();
        write!(f, "{s}")
    }
}

/// [`Compatibility`] iterator.
#[derive(Debug)]
pub struct CompatibilityIterator<'a> {
    /// [`Compatibility`] set.
    compatibility: Compatibility<'a>,

    /// Current index.
    index: usize,
}

impl<'a> IntoIterator for Compatibility<'a> {
    type Item = &'a str;
    type IntoIter = CompatibilityIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Iterator for CompatibilityIterator<'a> {
    type Item = &'a str;
    /** Gets the next file from the [`Compatibility`] list.
     *
     * - Will always return [None] for [`Compatibility::Off`] and
     *   [`Compatibility::Legacy`].
     * - May return an empty string.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::Compatibility;
     *
     * // off
     * let compatibility = Compatibility::from("off");
     * assert!(matches!(compatibility, Compatibility::Off));
     *
     * let mut iter = compatibility.iter();
     * assert!(iter.next().is_none());
     *
     * // legacy
     * let compatibility = Compatibility::from("legacy");
     * assert!(matches!(compatibility, Compatibility::Legacy));
     *
     * let mut iter = compatibility.iter();
     * assert!(iter.next().is_none());
     *
     * // files (empty)
     * let compatibility = Compatibility::from("");
     * assert!(matches!(compatibility, Compatibility::Files(_)));
     *
     * let mut iter = compatibility.iter();
     * assert_eq!(iter.next().unwrap(), "");
     * assert!(iter.next().is_none());
     *
     * // files (one)
     * let compatibility = Compatibility::from("a.txt");
     * assert!(matches!(compatibility, Compatibility::Files(_)));
     *
     * let mut iter = compatibility.iter();
     * assert_eq!(iter.next().unwrap(), "a.txt");
     * assert!(iter.next().is_none());
     *
     * // files (multple, comma separated)
     * let compatibility = Compatibility::from("a,, b ,c,");
     * assert!(matches!(compatibility, Compatibility::Files(_)));
     *
     * let mut iter = compatibility.iter();
     * assert_eq!(iter.next().unwrap(), "a");
     * assert_eq!(iter.next().unwrap(), "");
     * assert_eq!(iter.next().unwrap(), " b ");
     * assert_eq!(iter.next().unwrap(), "c");
     * assert_eq!(iter.next().unwrap(), "");
     * assert!(iter.next().is_none());
     * ```
     */
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match self.compatibility {
            Compatibility::Off => None,
            Compatibility::Legacy => None,
            Compatibility::Files(comp) => {
                match (self.index).cmp(&comp.len()) {
                    Ordering::Greater => None,
                    Ordering::Equal => {
                        // Empty string.
                        self.index += 1;
                        Some("")
                    }
                    Ordering::Less => {
                        // If not yet at the end.
                        // Find the next comma.
                        let suffix = &comp[self.index..];
                        match suffix.find(',') {
                            None => {
                                // No more commas.

                                // Set index to end of string.
                                self.index = comp.len() + 1;

                                // And return the rest of the string.
                                Some(suffix)
                            }
                            Some(index) => {
                                // Increment index and skip comma.
                                self.index += index + 1;

                                // And return until the comma.
                                Some(&suffix[0..index])
                            }
                        }
                    }
                }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Features.
 *
 * - This enum type has a lowercase string representation, and is used in NV
 *   lists. It does not have a numerical representation.
 * - Added in [`crate::phys::SpaVersion::V5000`].
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feature {
    /// ???
    AllocationClasses,

    /// ???
    AsyncDestroy,

    /// ???
    Blake3,

    /// ???
    BlockCloning,

    /// ???
    BookmarkV2,

    /// ???
    BookmarkWritten,

    /// ???
    Bookmarks,

    /// ???
    DeviceRebuild,

    /// ???
    DeviceRemoval,

    /// ???
    Draid,

    /// ???
    Edonr,

    /// ???
    EmbeddedData,

    /// ???
    EmptyBlockPointerObject,

    /// ???
    EnabledTxg,

    /// ???
    Encryption,

    /// ???
    ExtensibleDataset,

    /// ???
    FilesystemLimits,

    /// ???
    HeadErrorLog,

    /// ???
    HoleBirth,

    /// ???
    LargeBlocks,

    /// ???
    LargeDnode,

    /// ???
    LiveList,

    /// ???
    LogSpaceMap,

    /// ???
    Lz4Compress,

    /// ???
    MultiVdevCrashDump,

    /// ???
    ObsoleteCounts,

    /// ???
    ProjectQuota,

    /// ???
    RaidzExpansion,

    /// ???
    RedactedDatasets,

    /// ???
    RedactionListSpill,

    /// ???
    RedactionBookmarks,

    /// ???
    ResilverDefer,

    /// ???
    Sha512,

    /// ???
    Skein,

    /// ???
    SpacemapHistogram,

    /// ???
    SpacemapV2,

    /// ???
    UserObjectAccounting,

    /// ???
    VdevZapsV2,

    /// ???
    ZilSaXattr,

    /// ???
    ZpoolCheckpoint,

    /// ???
    ZstdCompress,
}

const ALL_FEATURES: [Feature; 41] = [
    Feature::AllocationClasses,
    Feature::AsyncDestroy,
    Feature::Blake3,
    Feature::BlockCloning,
    Feature::BookmarkV2,
    Feature::BookmarkWritten,
    Feature::Bookmarks,
    Feature::DeviceRebuild,
    Feature::DeviceRemoval,
    Feature::Draid,
    Feature::Edonr,
    Feature::EmbeddedData,
    Feature::EmptyBlockPointerObject,
    Feature::EnabledTxg,
    Feature::Encryption,
    Feature::ExtensibleDataset,
    Feature::FilesystemLimits,
    Feature::HeadErrorLog,
    Feature::HoleBirth,
    Feature::LargeBlocks,
    Feature::LargeDnode,
    Feature::LiveList,
    Feature::LogSpaceMap,
    Feature::Lz4Compress,
    Feature::MultiVdevCrashDump,
    Feature::ObsoleteCounts,
    Feature::ProjectQuota,
    Feature::RaidzExpansion,
    Feature::RedactedDatasets,
    Feature::RedactionBookmarks,
    Feature::RedactionListSpill,
    Feature::ResilverDefer,
    Feature::Sha512,
    Feature::Skein,
    Feature::SpacemapHistogram,
    Feature::SpacemapV2,
    Feature::UserObjectAccounting,
    Feature::VdevZapsV2,
    Feature::ZilSaXattr,
    Feature::ZpoolCheckpoint,
    Feature::ZstdCompress,
];

impl Feature {
    /// Get a slice with all of the [`Feature`].
    pub fn all() -> &'static [Feature] {
        &ALL_FEATURES
    }
}

impl Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{s}")
    }
}

impl From<Feature> for &'static str {
    fn from(val: Feature) -> &'static str {
        match val {
            Feature::AllocationClasses => "org.zfsonlinux:allocation_classes",
            Feature::AsyncDestroy => "com.delphix:async_destroy",
            Feature::Blake3 => "org.openzfs:blake3",
            Feature::BlockCloning => "com.fudosecurity:block_cloning",
            Feature::BookmarkV2 => "com.datto:bookmark_v2",
            Feature::BookmarkWritten => "com.delphix:bookmark_written",
            Feature::Bookmarks => "com.delphix:bookmarks",
            Feature::DeviceRebuild => "org.openzfs:device_rebuild",
            Feature::DeviceRemoval => "com.delphix:device_removal",
            Feature::Draid => "org.openzfs:draid",
            Feature::Edonr => "org.illumos:edonr",
            Feature::EmbeddedData => "com.delphix:embedded_data",
            Feature::EmptyBlockPointerObject => "com.delphix:empty_bpobj",
            Feature::EnabledTxg => "com.delphix:enabled_txg",
            Feature::Encryption => "com.datto:encryption",
            Feature::ExtensibleDataset => "com.delphix:extensible_dataset",
            Feature::FilesystemLimits => "com.joyent:filesystem_limits",
            Feature::HeadErrorLog => "com.delphix:head_errlog",
            Feature::HoleBirth => "com.delphix:hole_birth",
            Feature::LargeBlocks => "org.open-zfs:large_blocks",
            Feature::LargeDnode => "org.zfsonlinux:large_dnode",
            Feature::LiveList => "com.delphix:livelist",
            Feature::LogSpaceMap => "com.delphix:log_spacemap",
            Feature::Lz4Compress => "org.illumos:lz4_compress",
            Feature::MultiVdevCrashDump => "com.joyent:multi_vdev_crash_dump",
            Feature::ObsoleteCounts => "com.delphix:obsolete_counts",
            Feature::ProjectQuota => "org.zfsonlinux:project_quota",
            Feature::RaidzExpansion => "org.openzfs:raidz_expansion",
            Feature::RedactedDatasets => "com.delphix:redacted_datasets",
            Feature::RedactionBookmarks => "com.delphix:redaction_bookmarks",
            Feature::RedactionListSpill => "com.delphix:redaction_list_spill",
            Feature::ResilverDefer => "com.datto:resilver_defer",
            Feature::Sha512 => "org.illumos:sha512",
            Feature::Skein => "org.illumos:skein",
            Feature::SpacemapHistogram => "com.delphix:spacemap_histogram",
            Feature::SpacemapV2 => "com.delphix:spacemap_v2",
            Feature::UserObjectAccounting => "org.zfsonlinux:userobj_accounting",
            Feature::VdevZapsV2 => "com.klarasystems:vdev_zaps_v2",
            Feature::ZilSaXattr => "org.openzfs:zilsaxattr",
            Feature::ZpoolCheckpoint => "com.delphix:zpool_checkpoint",
            Feature::ZstdCompress => "org.freebsd:zstd_compress",
        }
    }
}

impl TryFrom<&str> for Feature {
    type Error = FeatureDecodeError;

    /** Try converting from a [`&str`] to a [`Feature`].
     *
     * # Errors
     *
     * Returns [`FeatureDecodeError`] in case of an unknown [`Feature`].
     */
    fn try_from(feature: &str) -> Result<Self, Self::Error> {
        match feature {
            "org.zfsonlinux:allocation_classes" => Ok(Feature::AllocationClasses),
            "com.delphix:async_destroy" => Ok(Feature::AsyncDestroy),
            "org.openzfs:blake3" => Ok(Feature::Blake3),
            "com.fudosecurity:block_cloning" => Ok(Feature::BlockCloning),
            "com.datto:bookmark_v2" => Ok(Feature::BookmarkV2),
            "com.delphix:bookmark_written" => Ok(Feature::BookmarkWritten),
            "com.delphix:bookmarks" => Ok(Feature::Bookmarks),
            "org.openzfs:device_rebuild" => Ok(Feature::DeviceRebuild),
            "com.delphix:device_removal" => Ok(Feature::DeviceRemoval),
            "org.openzfs:draid" => Ok(Feature::Draid),
            "org.illumos:edonr" => Ok(Feature::Edonr),
            "com.delphix:embedded_data" => Ok(Feature::EmbeddedData),
            "com.delphix:empty_bpobj" => Ok(Feature::EmptyBlockPointerObject),
            "com.delphix:enabled_txg" => Ok(Feature::EnabledTxg),
            "com.datto:encryption" => Ok(Feature::Encryption),
            "com.delphix:extensible_dataset" => Ok(Feature::ExtensibleDataset),
            "com.joyent:filesystem_limits" => Ok(Feature::FilesystemLimits),
            "com.delphix:head_errlog" => Ok(Feature::HeadErrorLog),
            "com.delphix:hole_birth" => Ok(Feature::HoleBirth),
            "org.open-zfs:large_blocks" => Ok(Feature::LargeBlocks),
            "org.zfsonlinux:large_dnode" => Ok(Feature::LargeDnode),
            "com.delphix:livelist" => Ok(Feature::LiveList),
            "com.delphix:log_spacemap" => Ok(Feature::LogSpaceMap),
            "org.illumos:lz4_compress" => Ok(Feature::Lz4Compress),
            "com.joyent:multi_vdev_crash_dump" => Ok(Feature::MultiVdevCrashDump),
            "com.delphix:obsolete_counts" => Ok(Feature::ObsoleteCounts),
            "org.zfsonlinux:project_quota" => Ok(Feature::ProjectQuota),
            "org.openzfs:raidz_expansion" => Ok(Feature::RaidzExpansion),
            "com.delphix:redacted_datasets" => Ok(Feature::RedactedDatasets),
            "com.delphix:redaction_bookmarks" => Ok(Feature::RedactionBookmarks),
            "com.delphix:redaction_list_spill" => Ok(Feature::RedactionListSpill),
            "com.datto:resilver_defer" => Ok(Feature::ResilverDefer),
            "org.illumos:sha512" => Ok(Feature::Sha512),
            "org.illumos:skein" => Ok(Feature::Skein),
            "com.delphix:spacemap_histogram" => Ok(Feature::SpacemapHistogram),
            "com.delphix:spacemap_v2" => Ok(Feature::SpacemapV2),
            "org.zfsonlinux:userobj_accounting" => Ok(Feature::UserObjectAccounting),
            "com.klarasystems:vdev_zaps_v2" => Ok(Feature::VdevZapsV2),
            "org.openzfs:zilsaxattr" => Ok(Feature::ZilSaXattr),
            "com.delphix:zpool_checkpoint" => Ok(Feature::ZpoolCheckpoint),
            "org.freebsd:zstd_compress" => Ok(Feature::ZstdCompress),
            _ => Err(FeatureDecodeError::Unknown {}),
        }
    }
}

/// [`Feature`] decode error.
#[derive(Debug)]
pub enum FeatureDecodeError {
    /// Unknown [`Feature`].
    Unknown {},
}

impl fmt::Display for FeatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureDecodeError::Unknown {} => {
                write!(f, "Feature decode error, unknown feature")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for FeatureDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Set of [`Feature`].
 *
 * Compact, in memory representation of `features_for_read`.
 */
#[derive(Clone, Copy, Default)]
pub struct FeatureSet {
    /// Bitmap encoded [`Feature`].
    features: u64,
}

impl fmt::Debug for FeatureSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print all features.
        let mut f = f.debug_struct("FeatureSet");
        for feature in self.iter() {
            f.field("feature", &feature);
        }
        f.finish()
    }
}

impl FeatureSet {
    /// Returns number of [`Feature`] in [`FeatureSet`].
    pub fn len(&self) -> usize {
        self.features.count_ones().try_into().unwrap()
    }

    /// Returns [true] if the [`FeatureSet`] is empty.
    pub fn is_empty(&self) -> bool {
        self.features == 0
    }

    /// Returns an iterator over the [`FeatureSet`].
    pub fn iter(&self) -> FeatureSetIterator {
        FeatureSetIterator {
            feature_set: *self,
            index: 0,
        }
    }

    /** Adds a value to the set. Returns whether the value was newly inserted.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{Feature,FeatureSet};
     *
     * let mut feature_set = FeatureSet::default();
     * assert_eq!(feature_set.insert(Feature::Draid), true);
     * assert_eq!(feature_set.insert(Feature::Draid), false);
     * assert_eq!(feature_set.insert(Feature::Draid), false);
     * ```
     */
    pub fn insert(&mut self, feature: Feature) -> bool {
        let mask = 1 << FeatureSet::feature_to_bit_shift(feature);

        if (self.features & mask) == 0 {
            self.features |= mask;
            true
        } else {
            false
        }
    }

    /** Removes a value from the set. Returns whether the value was present in the set.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{Feature,FeatureSet};
     *
     * let mut feature_set = FeatureSet::default();
     * assert_eq!(feature_set.remove(Feature::Draid), false);
     *
     * feature_set.insert(Feature::Draid);
     * assert_eq!(feature_set.remove(Feature::Draid), true);
     * assert_eq!(feature_set.remove(Feature::Draid), false);
     * ```
     */
    pub fn remove(&mut self, feature: Feature) -> bool {
        let mask = 1 << FeatureSet::feature_to_bit_shift(feature);

        if (self.features & mask) == 0 {
            false
        } else {
            self.features &= u64::MAX ^ mask;
            true
        }
    }

    /** Returns `true` if the set contains a value.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{Feature,FeatureSet};
     *
     * let mut feature_set = FeatureSet::default();
     * assert_eq!(feature_set.contains(Feature::Draid), false);
     *
     * feature_set.insert(Feature::Blake3);
     * feature_set.insert(Feature::Draid);
     * assert_eq!(feature_set.contains(Feature::Blake3), true);
     * assert_eq!(feature_set.contains(Feature::Draid), true);
     *
     * feature_set.remove(Feature::Draid);
     * assert_eq!(feature_set.contains(Feature::Blake3), true);
     * assert_eq!(feature_set.contains(Feature::Draid), false);
     * ```
     */
    pub fn contains(&self, feature: Feature) -> bool {
        let mask = 1 << FeatureSet::feature_to_bit_shift(feature);

        (self.features & mask) != 0
    }

    /** Decodes a [`FeatureSet`].
     *
     * # Errors
     *
     * Returns [`FeatureSetDecodeError`] in case of decoding error.
     */
    pub fn from_nv_list(list: &NvList<'_>) -> Result<FeatureSet, FeatureSetDecodeError> {
        // Bitmap of features.
        let mut features = 0;

        // Decode the next pair.
        for pair_res in list {
            let pair = pair_res?;

            // Check the pair is a bool flag.
            pair.get_bool_flag()?;

            // Enable the bit.
            let feature = match Feature::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => {
                    return Err(FeatureSetDecodeError::Unknown {
                        feature: pair.name.into(),
                    })
                }
            };
            features |= 1 << FeatureSet::feature_to_bit_shift(feature);
        }

        Ok(FeatureSet { features })
    }

    /// Convert a [`Feature`] to a [u32].
    fn feature_to_bit_shift(feature: Feature) -> u32 {
        match feature {
            Feature::AllocationClasses => 0,
            Feature::AsyncDestroy => 1,
            Feature::Blake3 => 2,
            Feature::BlockCloning => 3,
            Feature::BookmarkV2 => 4,
            Feature::BookmarkWritten => 5,
            Feature::Bookmarks => 6,
            Feature::DeviceRebuild => 7,
            Feature::DeviceRemoval => 8,
            Feature::Draid => 9,
            Feature::Edonr => 10,
            Feature::EmbeddedData => 11,
            Feature::EmptyBlockPointerObject => 12,
            Feature::EnabledTxg => 13,
            Feature::Encryption => 14,
            Feature::ExtensibleDataset => 15,
            Feature::FilesystemLimits => 16,
            Feature::HeadErrorLog => 17,
            Feature::HoleBirth => 18,
            Feature::LargeBlocks => 19,
            Feature::LargeDnode => 20,
            Feature::LiveList => 21,
            Feature::LogSpaceMap => 22,
            Feature::Lz4Compress => 23,
            Feature::MultiVdevCrashDump => 24,
            Feature::ObsoleteCounts => 25,
            Feature::ProjectQuota => 26,
            Feature::RaidzExpansion => 27,
            Feature::RedactedDatasets => 28,
            Feature::RedactionBookmarks => 29,
            Feature::RedactionListSpill => 30,
            Feature::ResilverDefer => 31,
            Feature::Sha512 => 32,
            Feature::Skein => 33,
            Feature::SpacemapHistogram => 34,
            Feature::SpacemapV2 => 35,
            Feature::UserObjectAccounting => 36,
            Feature::VdevZapsV2 => 37,
            Feature::ZilSaXattr => 38,
            Feature::ZpoolCheckpoint => 39,
            Feature::ZstdCompress => 40,
        }
    }
}

/// [`FeatureSet`] decode error.
#[derive(Debug)]
pub enum FeatureSetDecodeError {
    /// [`Feature`] decode error.
    Feature {
        /// Error.
        err: FeatureDecodeError,
    },

    /// [`crate::phys::nv::NvList`] decode error.
    Nv {
        /// Error.
        err: NvDecodeError,
    },

    /// Unknown feature.
    Unknown {
        /// Unknown feature.
        feature: Fstr<16>,
    },
}

impl From<NvDecodeError> for FeatureSetDecodeError {
    fn from(err: NvDecodeError) -> Self {
        FeatureSetDecodeError::Nv { err }
    }
}

impl From<FeatureDecodeError> for FeatureSetDecodeError {
    fn from(err: FeatureDecodeError) -> Self {
        FeatureSetDecodeError::Feature { err }
    }
}

impl fmt::Display for FeatureSetDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureSetDecodeError::Feature { err } => {
                write!(f, "FeatureSet decode error | {err}")
            }
            FeatureSetDecodeError::Nv { err } => {
                write!(f, "FeatureSet decode error | {err}")
            }
            FeatureSetDecodeError::Unknown { feature } => {
                write!(f, "FeatureSet decode error, unknown feature '{feature}'")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for FeatureSetDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            FeatureSetDecodeError::Feature { err } => Some(err),
            FeatureSetDecodeError::Nv { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`FeatureSet`] iterator.
#[derive(Debug)]
pub struct FeatureSetIterator {
    /// [`Feature`] set.
    feature_set: FeatureSet,

    /// Current index.
    index: usize,
}

impl IntoIterator for FeatureSet {
    type Item = Feature;
    type IntoIter = FeatureSetIterator;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Iterator for FeatureSetIterator {
    type Item = Feature;

    /** Gets the next [`Feature`] in the set.
     *
     * Basic usage:
     *
     * ```
     * use rzfs::phys::{Feature,FeatureSet};
     *
     * // Empty.
     * let mut feature_set = FeatureSet::default();
     * let mut iter = feature_set.iter();
     * assert!(iter.next().is_none());
     *
     * // Insert some features.
     * feature_set.insert(Feature::SpacemapHistogram);
     * feature_set.insert(Feature::Blake3);
     * feature_set.insert(Feature::EmbeddedData);
     *
     * // Feaures are returned by enum order.
     * let mut iter = feature_set.iter();
     * assert!(matches!(iter.next(), Some(Feature::Blake3)));
     * assert!(matches!(iter.next(), Some(Feature::EmbeddedData)));
     * assert!(matches!(iter.next(), Some(Feature::SpacemapHistogram)));
     * assert!(iter.next().is_none());
     * ```
     */
    fn next(&mut self) -> Option<Self::Item> {
        // Loop through all the known features.
        while self.index < ALL_FEATURES.len() {
            // Get the feature.
            let feature = ALL_FEATURES[self.index];

            // Go to next feature after this.
            self.index += 1;

            // If the set contains the feature, return the feature.
            if self.feature_set.contains(feature) {
                return Some(feature);
            }
        }

        // No more features.
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use crate::phys::{Compatibility, Feature, FeatureSet};
    use std::error::Error;

    #[test]
    fn compatibility_off_legacy_encode_decode() {
        // String to enum.
        assert_eq!(Compatibility::from("off"), Compatibility::Off);
        assert_eq!(Compatibility::from("legacy"), Compatibility::Legacy);

        // Enum to string.
        assert_eq!(Compatibility::Off.to_string(), "off");
        assert_eq!(Compatibility::Legacy.to_string(), "legacy");

        let compatibility_str: &str = Compatibility::Off.into();
        assert_eq!(compatibility_str, Compatibility::Off.to_string());

        let compatibility_str: &str = Compatibility::Legacy.into();
        assert_eq!(compatibility_str, Compatibility::Legacy.to_string());
    }

    #[test]
    fn compatibility_files_encode_decode() {
        let s = "a,, b ,c,";
        let compatibility = Compatibility::from(s);
        assert_eq!(compatibility.to_string(), s);
    }

    #[test]
    fn compatibility_iter() {
        ////////////////////////////////
        // off
        let compatibility = Compatibility::from("off");
        assert_eq!(compatibility, Compatibility::Off);

        let mut iter = compatibility.iter();
        assert!(iter.next().is_none());

        ////////////////////////////////
        // legacy
        let compatibility = Compatibility::from("legacy");
        assert_eq!(compatibility, Compatibility::Legacy);

        let mut iter = compatibility.iter();
        assert!(iter.next().is_none());

        ////////////////////////////////
        // files (empty)
        let compatibility = Compatibility::from("");
        assert_eq!(compatibility, Compatibility::Files(""));

        let mut iter = compatibility.iter();
        assert_eq!(iter.next().unwrap(), "");
        assert!(iter.next().is_none());

        ////////////////////////////////
        // files (one)
        let compatibility = Compatibility::from("a.txt");
        assert_eq!(compatibility, Compatibility::Files("a.txt"));

        let mut iter = compatibility.iter();
        assert_eq!(iter.next().unwrap(), "a.txt");
        assert!(iter.next().is_none());

        ////////////////////////////////
        // files (multple, comma separated)
        let compatibility = Compatibility::from("a,, b ,c,");
        assert_eq!(compatibility, Compatibility::Files("a,, b ,c,"));

        let mut iter = compatibility.iter();
        assert_eq!(iter.next().unwrap(), "a");
        assert_eq!(iter.next().unwrap(), "");
        assert_eq!(iter.next().unwrap(), " b ");
        assert_eq!(iter.next().unwrap(), "c");
        assert_eq!(iter.next().unwrap(), "");
        assert!(iter.next().is_none());

        ////////////////////////////////
        // IntoIterator.
        let mut idx = 0;
        let expected = ["a", "", " b ", "c", ""];
        for entry in compatibility {
            assert_eq!(entry, expected[idx]);
            idx += 1;
        }
    }

    #[test]
    fn feature_encode_decode_all() {
        for feature in Feature::all() {
            let feature = *feature;

            // enum to str.
            let feature_str: &'static str = feature.into();

            // Check both From<Feature> for &'static str
            // and Display for Feature return the same values.
            let feature_string = feature.to_string();
            assert_eq!(feature_str, feature_string);

            // str to enum.
            let feature_enum: Feature = feature_str.try_into().unwrap();

            // enums should match.
            assert_eq!(feature, feature_enum);

            // strs should match.
            assert_eq!(format!("{}", feature_enum), feature_str);
        }
    }

    #[test]
    fn feature_enum_string() {
        assert_eq!(
            Feature::AllocationClasses.to_string(),
            "org.zfsonlinux:allocation_classes"
        );

        assert_eq!(
            Feature::AsyncDestroy.to_string(),
            "com.delphix:async_destroy"
        );
        assert_eq!(Feature::Blake3.to_string(), "org.openzfs:blake3");
        assert_eq!(
            Feature::BlockCloning.to_string(),
            "com.fudosecurity:block_cloning"
        );
        assert_eq!(Feature::BookmarkV2.to_string(), "com.datto:bookmark_v2");
        assert_eq!(
            Feature::BookmarkWritten.to_string(),
            "com.delphix:bookmark_written"
        );
        assert_eq!(Feature::Bookmarks.to_string(), "com.delphix:bookmarks");
        assert_eq!(
            Feature::DeviceRebuild.to_string(),
            "org.openzfs:device_rebuild"
        );
        assert_eq!(
            Feature::DeviceRemoval.to_string(),
            "com.delphix:device_removal"
        );
        assert_eq!(Feature::Draid.to_string(), "org.openzfs:draid");
        assert_eq!(Feature::Edonr.to_string(), "org.illumos:edonr");
        assert_eq!(
            Feature::EmbeddedData.to_string(),
            "com.delphix:embedded_data"
        );
        assert_eq!(
            Feature::EmptyBlockPointerObject.to_string(),
            "com.delphix:empty_bpobj"
        );
        assert_eq!(Feature::EnabledTxg.to_string(), "com.delphix:enabled_txg");
        assert_eq!(Feature::Encryption.to_string(), "com.datto:encryption");
        assert_eq!(
            Feature::ExtensibleDataset.to_string(),
            "com.delphix:extensible_dataset"
        );
        assert_eq!(
            Feature::FilesystemLimits.to_string(),
            "com.joyent:filesystem_limits"
        );
        assert_eq!(Feature::HeadErrorLog.to_string(), "com.delphix:head_errlog");
        assert_eq!(Feature::HoleBirth.to_string(), "com.delphix:hole_birth");
        assert_eq!(
            Feature::LargeBlocks.to_string(),
            "org.open-zfs:large_blocks"
        );
        assert_eq!(
            Feature::LargeDnode.to_string(),
            "org.zfsonlinux:large_dnode"
        );
        assert_eq!(Feature::LiveList.to_string(), "com.delphix:livelist");
        assert_eq!(Feature::LogSpaceMap.to_string(), "com.delphix:log_spacemap");
        assert_eq!(Feature::Lz4Compress.to_string(), "org.illumos:lz4_compress");
        assert_eq!(
            Feature::MultiVdevCrashDump.to_string(),
            "com.joyent:multi_vdev_crash_dump"
        );
        assert_eq!(
            Feature::ObsoleteCounts.to_string(),
            "com.delphix:obsolete_counts"
        );
        assert_eq!(
            Feature::ProjectQuota.to_string(),
            "org.zfsonlinux:project_quota"
        );
        assert_eq!(
            Feature::RaidzExpansion.to_string(),
            "org.openzfs:raidz_expansion"
        );
        assert_eq!(
            Feature::RedactedDatasets.to_string(),
            "com.delphix:redacted_datasets"
        );
        assert_eq!(
            Feature::RedactionBookmarks.to_string(),
            "com.delphix:redaction_bookmarks"
        );
        assert_eq!(
            Feature::RedactionListSpill.to_string(),
            "com.delphix:redaction_list_spill"
        );
        assert_eq!(
            Feature::ResilverDefer.to_string(),
            "com.datto:resilver_defer"
        );
        assert_eq!(Feature::Sha512.to_string(), "org.illumos:sha512");
        assert_eq!(Feature::Skein.to_string(), "org.illumos:skein");
        assert_eq!(
            Feature::SpacemapHistogram.to_string(),
            "com.delphix:spacemap_histogram"
        );
        assert_eq!(Feature::SpacemapV2.to_string(), "com.delphix:spacemap_v2");
        assert_eq!(
            Feature::UserObjectAccounting.to_string(),
            "org.zfsonlinux:userobj_accounting"
        );
        assert_eq!(
            Feature::VdevZapsV2.to_string(),
            "com.klarasystems:vdev_zaps_v2"
        );
        assert_eq!(Feature::ZilSaXattr.to_string(), "org.openzfs:zilsaxattr");
        assert_eq!(
            Feature::ZpoolCheckpoint.to_string(),
            "com.delphix:zpool_checkpoint"
        );
        assert_eq!(
            Feature::ZstdCompress.to_string(),
            "org.freebsd:zstd_compress"
        );
    }

    #[test]
    fn feature_decode_unknown() {
        let res = Feature::try_from("not.a:feature");
        let err = res.unwrap_err();
        assert_eq!(format!("{}", err), "Feature decode error, unknown feature");
        assert!(err.source().is_none());
    }

    #[test]
    fn feature_set_all() {
        let total_features = Feature::all().len();
        let mut feature_set = FeatureSet::default();

        ////////////////////////////////
        // Add all features.
        for (index, feature) in Feature::all().iter().enumerate() {
            // Check FeatureSet does not contain Feature.
            assert_eq!(feature_set.is_empty(), index == 0);
            assert_eq!(feature_set.len(), index);
            assert_eq!(feature_set.contains(*feature), false);

            // Insert Feature.
            assert_eq!(feature_set.insert(*feature), true);
            assert_eq!(feature_set.len(), index + 1);
            assert_eq!(feature_set.is_empty(), false);

            // Check FeatureSet contains expected Feature.
            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 <= index);
            }

            // Iterate over FeatureSet and insert into another FeatureSet to
            // check for correct FeatureSet iteration.
            let mut feature_set_2 = FeatureSet::default();
            for feature_2 in feature_set {
                assert!(feature_set.contains(feature_2));
                assert!(feature_set_2.insert(feature_2));
            }
            assert_eq!(feature_set_2.len(), feature_set.len());

            // Adding Feature again does nothing.
            assert_eq!(feature_set.insert(*feature), false);
            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 <= index);
            }
        }

        ////////////////////////////////
        // Remove all features.
        for (index, feature) in Feature::all().iter().enumerate() {
            // Check FeatureSet contains Feature.
            assert_eq!(feature_set.is_empty(), false);
            assert_eq!(feature_set.len(), total_features - index);
            assert_eq!(feature_set.contains(*feature), true);

            // Remove Feature.
            assert_eq!(feature_set.remove(*feature), true);
            assert_eq!(feature_set.len(), total_features - index - 1);
            assert_eq!(feature_set.is_empty(), index == total_features - 1);

            // Check FeatureSet contains expected Feature.
            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 > index);
            }

            // Iterate over FeatureSet and insert into another FeatureSet to
            // check for correct FeatureSet iteration.
            let mut feature_set_2 = FeatureSet::default();
            for feature_2 in feature_set {
                assert!(feature_set.contains(feature_2));
                assert_eq!(feature_set_2.insert(feature_2), true);
            }
            assert_eq!(feature_set_2.len(), feature_set.len());

            // Removing Feature again does nothing.
            assert_eq!(feature_set.remove(*feature), false);
            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 > index);
            }
        }
    }

    #[test]
    fn feature_set_debug() {
        let mut feature_set = FeatureSet::default();
        feature_set.insert(Feature::ZstdCompress);
        feature_set.insert(Feature::Sha512);

        assert_eq!(
            format!("{:?}", feature_set),
            "FeatureSet { feature: Sha512, feature: ZstdCompress }"
        );
    }
}
