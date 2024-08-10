// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::cmp::Ordering;
use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

use crate::phys::{NvDecodeError, NvList};

////////////////////////////////////////////////////////////////////////////////

/** Features compatibility.
 *
 * - NV Name: "compatibility"
 * - Added in [`crate::phys::SpaVersion::V5000`].
 */
#[derive(Debug)]
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

    /// Returns an iterator over the [`Compatibility`].
    pub fn iter(&self) -> CompatibilityIterator<'_> {
        CompatibilityIterator {
            compatibility: self,
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
        write!(f, "{}", s)
    }
}

/// [`Compatibility`] iterator.
#[derive(Debug)]
pub struct CompatibilityIterator<'a> {
    /// [`Compatibility`] set.
    compatibility: &'a Compatibility<'a>,

    /// Current index.
    index: usize,
}

impl<'a> IntoIterator for &'a Compatibility<'_> {
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
#[derive(Clone, Copy, Debug, PartialEq)]
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
        write!(f, "{}", s)
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
    pub fn from_list<'a>(list: &'a NvList<'_>) -> Result<FeatureSet, FeatureSetDecodeError<'a>> {
        FeatureSet::from_list_direct(list, list.data())
    }

    /** Decodes a [`FeatureSet`].
     *
     * # Errors
     *
     * Returns [`FeatureSetDecodeError`] in case of decoding error.
     */
    pub fn from_list_direct<'a>(
        list: &NvList<'_>,
        data: &'a [u8],
    ) -> Result<FeatureSet, FeatureSetDecodeError<'a>> {
        // Bitmap of features.
        let mut features = 0;

        // Decode the next pair.
        let mut iter = list.iter();
        while let Some(pair_res) = iter.next_direct(data) {
            let pair = pair_res?;

            // Check the pair is a bool flag.
            pair.get_bool_flag()?;

            // Enable the bit.
            let feature = match Feature::try_from(pair.name) {
                Ok(v) => v,
                Err(_) => return Err(FeatureSetDecodeError::Unknown { feature: pair.name }),
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
pub enum FeatureSetDecodeError<'a> {
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
        feature: &'a str,
    },
}

impl From<NvDecodeError> for FeatureSetDecodeError<'_> {
    fn from(err: NvDecodeError) -> Self {
        FeatureSetDecodeError::Nv { err }
    }
}

impl From<FeatureDecodeError> for FeatureSetDecodeError<'_> {
    fn from(err: FeatureDecodeError) -> Self {
        FeatureSetDecodeError::Feature { err }
    }
}

impl fmt::Display for FeatureSetDecodeError<'_> {
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
impl error::Error for FeatureSetDecodeError<'_> {
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
     * // empty
     * let mut feature_set = FeatureSet::default();
     * let mut iter = feature_set.iter();
     * assert!(iter.next().is_none());
     *
     * // some features
     * feature_set.insert(Feature::Blake3);
     * feature_set.insert(Feature::SpacemapHistogram);
     * feature_set.insert(Feature::EmbeddedData);
     *
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

    use crate::phys::{Feature, FeatureDecodeError, FeatureSet};

    #[test]
    /// Encode and decode all known features.
    fn feature_encode_decode_all() -> Result<(), FeatureDecodeError> {
        for feature in Feature::all() {
            let feature = *feature;
            let feature_str: &'static str = feature.into();
            let feature_enum: Feature = feature_str.try_into()?;
            assert_eq!(feature, feature_enum);
        }

        Ok(())
    }

    #[test]
    /// Decode an unknown feature.
    fn feature_decode_unknown() {
        let res = Feature::try_from("not.a:feature");
        assert!(res.is_err());
    }

    #[test]
    fn feature_set_all() {
        let total_features = Feature::all().len();
        let mut feature_set = FeatureSet::default();

        // Add all features.
        for (index, feature) in Feature::all().iter().enumerate() {
            assert_eq!(feature_set.is_empty(), index == 0);
            assert_eq!(feature_set.len(), index);
            assert_eq!(feature_set.contains(*feature), false);

            assert_eq!(feature_set.insert(*feature), true);
            assert_eq!(feature_set.len(), index + 1);
            assert_eq!(feature_set.is_empty(), false);

            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 <= index);
            }
        }

        // Remove all features.
        for (index, feature) in Feature::all().iter().enumerate() {
            assert_eq!(feature_set.is_empty(), false);
            assert_eq!(feature_set.len(), total_features - index);
            assert_eq!(feature_set.contains(*feature), true);

            assert_eq!(feature_set.remove(*feature), true);
            assert_eq!(feature_set.len(), total_features - index - 1);
            assert_eq!(feature_set.is_empty(), index == total_features - 1);

            for (index_2, feature_2) in Feature::all().iter().enumerate() {
                assert_eq!(feature_set.contains(*feature_2), index_2 > index);
            }
        }
    }
}
