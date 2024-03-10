// SPDX-License-Identifier: GPL-2.0 OR MIT

/** Feature flags.
 *
 * TODO: Document.
 */
pub struct Feature {}

#[allow(missing_docs)]
impl Feature {
    pub const ALLOCATION_CLASSES: &'static str = "org.zfsonlinux:allocation_classes";
    pub const ASYNC_DESTROY: &'static str = "com.delphix:async_destroy";
    pub const BLAKE_3: &'static str = "org.openzfs:blake3";
    pub const BLOCK_CLONING: &'static str = "com.fudosecurity:block_cloning";
    pub const BOOKMARK_V2: &'static str = "com.datto:bookmark_v2";
    pub const BOOKMARK_WRITTEN: &'static str = "com.delphix:bookmark_written";
    pub const BOOKMARKS: &'static str = "com.delphix:bookmarks";
    pub const DEVICE_REBUILD: &'static str = "org.openzfs:device_rebuild";
    pub const DEVICE_REMOVAL: &'static str = "com.delphix:device_removal";
    pub const DRAID: &'static str = "org.openzfs:draid";
    pub const EDONR: &'static str = "org.illumos:edonr";
    pub const EMBEDDED_DATA: &'static str = "com.delphix:embedded_data";
    pub const EMPTY_BLOCK_POINTER_OBJECT: &'static str = "com.delphix:empty_bpobj";
    pub const ENABLED_TXG: &'static str = "com.delphix:enabled_txg";
    pub const ENCRYPTION: &'static str = "com.datto:encryption";
    pub const EXTENSIBLE_DATASET: &'static str = "com.delphix:extensible_dataset";
    pub const FILESYSTEM_LIMITS: &'static str = "com.joyent:filesystem_limits";
    pub const HEAD_ERROR_LOG: &'static str = "com.delphix:head_errlog";
    pub const HOLE_BIRTH: &'static str = "com.delphix:hole_birth";
    pub const LARGE_BLOCKS: &'static str = "org.open-zfs:large_blocks";
    pub const LARGE_DNODE: &'static str = "org.zfsonlinux:large_dnode";
    pub const LIVE_LIST: &'static str = "com.delphix:livelist";
    pub const LOG_SPACE_MAP: &'static str = "com.delphix:log_spacemap";
    pub const LZ4_COMPRESS: &'static str = "org.illumos:lz4_compress";
    pub const MULTI_VDEV_CRASH_DUMP: &'static str = "com.joyent:multi_vdev_crash_dump";
    pub const OBSOLETE_COUNTS: &'static str = "com.delphix:obsolete_counts";
    pub const PROJECT_QUOTA: &'static str = "org.zfsonlinux:project_quota";
    pub const RAIDZ_EXPANSION: &'static str = "org.openzfs:raidz_expansion";
    pub const REDACTED_DATASETS: &'static str = "com.delphix:redacted_datasets";
    pub const REDACTION_BOOKMARKS: &'static str = "com.delphix:redaction_bookmarks";
    pub const REDACTION_LIST_SPILL: &'static str = "com.delphix:redaction_list_spill";
    pub const RESILVER_DEFER: &'static str = "com.datto:resilver_defer";
    pub const SHA_512: &'static str = "org.illumos:sha512";
    pub const SKEIN: &'static str = "org.illumos:skein";
    pub const SPACEMAP_HISTORGRAM: &'static str = "com.delphix:spacemap_histogram";
    pub const SPACEMAP_V2: &'static str = "com.delphix:spacemap_v2";
    pub const USER_OBJECT_ACCOUNTING: &'static str = "org.zfsonlinux:userobj_accounting";
    pub const VDEV_ZAPS_V2: &'static str = "com.klarasystems:vdev_zaps_v2";
    pub const ZIL_SA_XATTR: &'static str = "org.openzfs:zilsaxattr";
    pub const ZPOOL_CHECKPOINT: &'static str = "com.delphix:zpool_checkpoint";
    pub const ZSTD_COMPRESS: &'static str = "org.freebsd:zstd_compress";
}
