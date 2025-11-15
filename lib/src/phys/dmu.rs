// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Data Management Unit Generic Object Type.
 *
 * [`DmuGenericObjectType`] was added in v5000, in order to encode the underlying
 * storage type, rather than have a different [`DmuType`] for each object type.
 *
 * NOTE: Although more are defined, only the following are used:
 * [`DmuGenericObjectType::Uint8`], [`DmuGenericObjectType::Uint16`],
 * [`DmuGenericObjectType::Uint32`], [`DmuGenericObjectType::Uint64`],
 * [`DmuGenericObjectType::Zap`]
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmuGenericObjectType {
    /// [u8] DMU.
    Uint8 = 0,

    /// [u16] DMU.
    Uint16 = 1,

    /// [u32] DMU.
    Uint32 = 2,

    /// [u64] DMU.
    Uint64 = 3,

    /// ZAP DMU.
    Zap = 4,

    /// [`crate::phys::Dnode`] DMU.
    Dnode = 5,

    /// [`crate::phys::ObjectSet`] DMU.
    ObjectSet = 6,

    /// [`crate::phys::Znode`] DMU.
    Znode = 7,

    /// [`crate::phys::AclV0`] DMU.
    AclV0 = 8,

    /// [`crate::phys::AclV1`] DMU.
    AclV1 = 9,
}

impl From<DmuGenericObjectType> for u8 {
    fn from(val: DmuGenericObjectType) -> u8 {
        val as u8
    }
}

impl DmuGenericObjectType {
    /** Gets the [`DmuGenericObjectType`] from the [`DmuType`].
     *
     * Returns [None] if the type is not a generic object type.
     */
    pub fn from_dmu_type(dmu_type: DmuType) -> Option<DmuGenericObjectType> {
        match dmu_type {
            DmuType::Uint8Data => Some(DmuGenericObjectType::Uint8),
            DmuType::Uint16Data => Some(DmuGenericObjectType::Uint16),
            DmuType::Uint32Data => Some(DmuGenericObjectType::Uint32),
            DmuType::Uint64Data => Some(DmuGenericObjectType::Uint64),
            DmuType::ZapData => Some(DmuGenericObjectType::Zap),

            DmuType::Uint8DataEncrypted => Some(DmuGenericObjectType::Uint8),
            DmuType::Uint16DataEncrypted => Some(DmuGenericObjectType::Uint16),
            DmuType::Uint32DataEncrypted => Some(DmuGenericObjectType::Uint32),
            DmuType::Uint64DataEncrypted => Some(DmuGenericObjectType::Uint64),
            DmuType::ZapDataEncrypted => Some(DmuGenericObjectType::Zap),

            DmuType::Uint8Metadata => Some(DmuGenericObjectType::Uint8),
            DmuType::Uint16Metadata => Some(DmuGenericObjectType::Uint16),
            DmuType::Uint32Metadata => Some(DmuGenericObjectType::Uint32),
            DmuType::Uint64Metadata => Some(DmuGenericObjectType::Uint64),
            DmuType::ZapMetadata => Some(DmuGenericObjectType::Zap),

            DmuType::Uint8MetadataEncrypted => Some(DmuGenericObjectType::Uint8),
            DmuType::Uint16MetadataEncrypted => Some(DmuGenericObjectType::Uint16),
            DmuType::Uint32MetadataEncrypted => Some(DmuGenericObjectType::Uint32),
            DmuType::Uint64MetadataEncrypted => Some(DmuGenericObjectType::Uint64),
            DmuType::ZapMetadataEncrypted => Some(DmuGenericObjectType::Zap),

            _ => None,
        }
    }
}

/// Base value for all generic object DMU types.
macro_rules! DmuObjectTypeGeneric {
    () => {
        0x80
    };
}

/// Base value for all generic data object DMU types.
macro_rules! DmuObjectTypeGenericData {
    () => {
        DmuObjectTypeGeneric!()
    };
}

/// Base value for all generic metadata object DMU types.
macro_rules! DmuObjectTypeGenericMetadata {
    () => {
        DmuObjectTypeGeneric!() | 0x40
    };
}

/// Flag for all encrypted generic data and metadata  DMU types.
macro_rules! DmuObjectTypeEncrypted {
    () => {
        0x20
    };
}

////////////////////////////////////////////////////////////////////////////////

/** Data Management Unit type.
 *
 * The [`DmuType`] defines what type of data is stored in the [`crate::phys::Dnode`].
 *
 * ```text
 * +-----------------------------+-------------+---------------------+--------------------------+
 * | Dmu Type                    | SPA Version | Object Type         | Feature                  |
 * +-----------------------------+-------------+---------------------+--------------------------+
 * | None                        |           1 |                     |                          |
 * | ObjectDirectory             |           1 |                 Zap |                          |
 * | ObjectArray                 |           1 |                 u64 |                          |
 * | PackedNvList                |           1 |              NvList |                          |
 * | PackedNvListSize            |           1 |                 u64 |                          |
 * | BpObject                    |           1 |                 u64 |                          |
 * | BpObjectHeader              |           1 |                 u64 |                          |
 * | SpaceMapHeader              |           1 |                 u64 |                          |
 * | SpaceMap                    |           1 |                 u64 |                          |
 * | IntentLog                   |           1 |                 u64 |                          |
 * | Dnode                       |           1 |               Dnode |                          |
 * | ObjectSet                   |           1 |           ObjectSet |                          |
 * | DslDirectory                |           1 |                 u64 |                          |
 * | DslDirectoryChildMap        |           1 |                 Zap |                          |
 * | DslDsSnapshotMap            |           1 |                 Zap |                          |
 * | DslProperties               |           1 |                 Zap |                          |
 * | DslDataSet                  |           1 |                 u64 |                          |
 * | Znode                       |           1 |               Znode |                          |
 * | AclV0                       |           1 |               AclV0 |                          |
 * | PlainFileContents           |           1 |                  u8 |                          |
 * | DirectoryContents           |           1 |                 Zap |                          |
 * | MasterNode                  |           1 |                 Zap |                          |
 * | UnlinkedSet                 |           1 |                 Zap |                          |
 * | Zvol                        |           1 |                  u8 |                          |
 * | ZvolProperty                |           1 |                 Zap |                          |
 * | PlainOther                  |           1 |                  u8 |                          |
 * | Uint64Other                 |           1 |                 u64 |                          |
 * | ZapOther                    |           1 |                 Zap |                          |
 * | ErrorLog                    |           2 |                 Zap |                          |
 * | SpaHistory                  |           4 |                  u8 |                          |
 * | SpaHistoryOffsets           |           4 |          SpaHistory |                          |
 * | PoolProperties              |           6 |                 Zap |                          |
 * | DslPermissions              |           8 |                 Zap |                          |
 * | AclV1                       |           9 |               AclV1 |                          |
 * | SysAcl                      |           9 |              SysAcl |                          |
 * | Fuid                        |           9 | Fuid Table (NvList) |                          |
 * | FuidSize                    |           9 |                 u64 |                          |
 * | NextClones                  |          11 |                 Zap |                          |
 * | ScanQueue                   |          11 |                 Zap |                          |
 * | UserGroupUsed               |          15 |                 Zap |                          |
 * | UserGroupQuota              |          15 |                 Zap |                          |
 * | UserRefs                    |          18 |                 Zap |                          |
 * | DdtZap                      |          21 |                 Zap |                          |
 * | DdtStats                    |          21 |                 Zap |                          |
 * | SystemAttribute             |          26 |     SystemAttribute |                          |
 * | SystemAttributeMasterNode   |          26 |                 Zap |                          |
 * | SystemAttributeRegistration |          26 |                 Zap |                          |
 * | SystemAttributeLayouts      |          26 |                 Zap |                          |
 * | ScanXlate                   |          26 |                 Zap |                          |
 * | Dedup                       |          26 |                 ??? |                          |
 * | DeadList                    |          26 |                 Zap |                          |
 * | DeadListHeader              |          26 |                 u64 |                          |
 * | DslClones                   |          26 |                 Zap |                          |
 * | BpObjectSubObject           |          26 |                 u64 |                          |
 * | Uint8 Data                  |        5000 |                  u8 |                          |
 * | Uint16 Data                 |        5000 |                 u16 |                          |
 * | Uint32 Data                 |        5000 |                 u32 |                          |
 * | Uint64 Data                 |        5000 |                 u64 |                          |
 * | ZAP Data                    |        5000 |                 Zap |                          |
 * | Uint8 Metadata              |        5000 |                  u8 |                          |
 * | Uint16 Metadata             |        5000 |                 u16 |                          |
 * | Uint32 Metadata             |        5000 |                 u32 |                          |
 * | Uint64 Metadata             |        5000 |                 u64 |                          |
 * | ZAP Metadata                |        5000 |                 Zap |                          |
 * | Uint8 Data Encrypted        |        5000 |                  u8 | com.datto:crypto_key_obj |
 * | Uint16 Data Encrypted       |        5000 |                 u16 | com.datto:crypto_key_obj |
 * | Uint32 Data Encrypted       |        5000 |                 u32 | com.datto:crypto_key_obj |
 * | Uint64 Data Encrypted       |        5000 |                 u64 | com.datto:crypto_key_obj |
 * | ZAP Data Encrypted          |        5000 |                 Zap | com.datto:crypto_key_obj |
 * | Uint8 Metadata Encrypted    |        5000 |                  u8 | com.datto:crypto_key_obj |
 * | Uint16 Metadata Encrypted   |        5000 |                 u16 | com.datto:crypto_key_obj |
 * | Uint32 Metadata Encrypted   |        5000 |                 u32 | com.datto:crypto_key_obj |
 * | Uint64 Metadata Encrypted   |        5000 |                 u64 | com.datto:crypto_key_obj |
 * | ZAP Metadata Encrypted      |        5000 |                 Zap | com.datto:crypto_key_obj |
 * +-----------------------------+-------------+---------------------+--------------------------+
 */
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DmuType {
    None = 0,
    ObjectDirectory = 1,
    ObjectArray = 2,
    PackedNvList = 3,
    PackedNvListSize = 4,
    BpObject = 5,
    BpObjectHeader = 6,
    SpaceMapHeader = 7,
    SpaceMap = 8,
    IntentLog = 9,
    Dnode = 10,
    ObjectSet = 11,
    DslDirectory = 12,
    DslDirectoryChildMap = 13,
    DslDsSnapshotMap = 14,
    DslProperties = 15,
    DslDataSet = 16,
    Znode = 17,
    AclV0 = 18,
    PlainFileContents = 19,
    DirectoryContents = 20,
    MasterNode = 21,
    UnlinkedSet = 22,
    Zvol = 23,
    ZvolProperty = 24,
    PlainOther = 25,
    Uint64Other = 26,
    ZapOther = 27,
    ErrorLog = 28,
    SpaHistory = 29,
    SpaHistoryOffsets = 30,
    PoolProperties = 31,
    DslPermissions = 32,
    AclV1 = 33,
    SysAcl = 34,
    Fuid = 35,
    FuidSize = 36,
    NextClones = 37,
    ScanQueue = 38,
    UserGroupUsed = 39,
    UserGroupQuota = 40,
    UserRefs = 41,
    DdtZap = 42,
    DdtStats = 43,
    SystemAttribute = 44,
    SystemAttributeMasterNode = 45,
    SystemAttributeRegistration = 46,
    SystemAttributeLayouts = 47,
    ScanXlate = 48,
    Dedup = 49,
    DeadList = 50,
    DeadListHeader = 51,
    DslClones = 52,
    BpObjectSubObject = 53,

    Uint8Data = DmuObjectTypeGenericData!() | DmuGenericObjectType::Uint8 as u8,
    Uint16Data = DmuObjectTypeGenericData!() | DmuGenericObjectType::Uint16 as u8,
    Uint32Data = DmuObjectTypeGenericData!() | DmuGenericObjectType::Uint32 as u8,
    Uint64Data = DmuObjectTypeGenericData!() | DmuGenericObjectType::Uint64 as u8,
    ZapData = DmuObjectTypeGenericData!() | DmuGenericObjectType::Zap as u8,

    Uint8DataEncrypted =
        DmuObjectTypeEncrypted!() | DmuObjectTypeGenericData!() | DmuGenericObjectType::Uint8 as u8,
    Uint16DataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericData!()
        | DmuGenericObjectType::Uint16 as u8,
    Uint32DataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericData!()
        | DmuGenericObjectType::Uint32 as u8,
    Uint64DataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericData!()
        | DmuGenericObjectType::Uint64 as u8,
    ZapDataEncrypted =
        DmuObjectTypeEncrypted!() | DmuObjectTypeGenericData!() | DmuGenericObjectType::Zap as u8,

    Uint8Metadata = DmuObjectTypeGenericMetadata!() | DmuGenericObjectType::Uint8 as u8,
    Uint16Metadata = DmuObjectTypeGenericMetadata!() | DmuGenericObjectType::Uint16 as u8,
    Uint32Metadata = DmuObjectTypeGenericMetadata!() | DmuGenericObjectType::Uint32 as u8,
    Uint64Metadata = DmuObjectTypeGenericMetadata!() | DmuGenericObjectType::Uint64 as u8,
    ZapMetadata = DmuObjectTypeGenericMetadata!() | DmuGenericObjectType::Zap as u8,

    Uint8MetadataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericMetadata!()
        | DmuGenericObjectType::Uint8 as u8,
    Uint16MetadataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericMetadata!()
        | DmuGenericObjectType::Uint16 as u8,
    Uint32MetadataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericMetadata!()
        | DmuGenericObjectType::Uint32 as u8,
    Uint64MetadataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericMetadata!()
        | DmuGenericObjectType::Uint64 as u8,
    ZapMetadataEncrypted = DmuObjectTypeEncrypted!()
        | DmuObjectTypeGenericMetadata!()
        | DmuGenericObjectType::Zap as u8,
}

////////////////////////////////////////////////////////////////////////////////

impl Display for DmuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmuType::None => write!(f, "None"),
            DmuType::ObjectDirectory => write!(f, "ObjectDirectory"),
            DmuType::ObjectArray => write!(f, "ObjectArray"),
            DmuType::PackedNvList => write!(f, "PackedNvList"),
            DmuType::PackedNvListSize => write!(f, "PackedNvListSize"),
            DmuType::BpObject => write!(f, "BpObject"),
            DmuType::BpObjectHeader => write!(f, "BpObjectHeader"),
            DmuType::SpaceMapHeader => write!(f, "SpaceMapHeader"),
            DmuType::SpaceMap => write!(f, "SpaceMap"),
            DmuType::IntentLog => write!(f, "IntentLog"),
            DmuType::Dnode => write!(f, "Dnode"),
            DmuType::ObjectSet => write!(f, "ObjectSet"),
            DmuType::DslDirectory => write!(f, "DslDirectory"),
            DmuType::DslDirectoryChildMap => write!(f, "DslDirectoryChildMap"),
            DmuType::DslDsSnapshotMap => write!(f, "DslDsSnapshotMap"),
            DmuType::DslProperties => write!(f, "DslProperties"),
            DmuType::DslDataSet => write!(f, "DslDataSet"),
            DmuType::Znode => write!(f, "Znode"),
            DmuType::AclV0 => write!(f, "AclV0"),
            DmuType::PlainFileContents => write!(f, "PlainFileContents"),
            DmuType::DirectoryContents => write!(f, "DirectoryContents"),
            DmuType::MasterNode => write!(f, "MasterNode"),
            DmuType::UnlinkedSet => write!(f, "UnlinkedSet"),
            DmuType::Zvol => write!(f, "Zvol"),
            DmuType::ZvolProperty => write!(f, "ZvolProperty"),
            DmuType::PlainOther => write!(f, "PlainFileContents"),
            DmuType::Uint64Other => write!(f, "Uint64Other"),
            DmuType::ZapOther => write!(f, "ZapOther"),
            DmuType::ErrorLog => write!(f, "ErrorLog"),
            DmuType::SpaHistory => write!(f, "SpaHistory"),
            DmuType::SpaHistoryOffsets => write!(f, "SpaHistoryOffsets"),
            DmuType::PoolProperties => write!(f, "PoolProperties"),
            DmuType::DslPermissions => write!(f, "DslPermissions"),
            DmuType::AclV1 => write!(f, "AclV1"),
            DmuType::SysAcl => write!(f, "SysAcl"),
            DmuType::Fuid => write!(f, "Fuid"),
            DmuType::FuidSize => write!(f, "FuidSize"),
            DmuType::NextClones => write!(f, "NextClones"),
            DmuType::ScanQueue => write!(f, "ScanQueue"),
            DmuType::UserGroupUsed => write!(f, "UserGroupUsed"),
            DmuType::UserGroupQuota => write!(f, "UserGroupQuota"),
            DmuType::UserRefs => write!(f, "UserRefs"),
            DmuType::DdtZap => write!(f, "DdtZap"),
            DmuType::DdtStats => write!(f, "DdtStats"),
            DmuType::SystemAttribute => write!(f, "SystemAttribute"),
            DmuType::SystemAttributeMasterNode => write!(f, "SystemAttributeMasterNode"),
            DmuType::SystemAttributeRegistration => write!(f, "SystemAttributeRegistration"),
            DmuType::SystemAttributeLayouts => write!(f, "SystemAttributeLayouts"),
            DmuType::ScanXlate => write!(f, "ScanXlate"),
            DmuType::Dedup => write!(f, "Dedup"),
            DmuType::DeadList => write!(f, "DeadList"),
            DmuType::DeadListHeader => write!(f, "DeadListHeader"),
            DmuType::DslClones => write!(f, "DslClones"),
            DmuType::BpObjectSubObject => write!(f, "BpObjectSubObject"),

            DmuType::Uint8Data => write!(f, "Uint8Data"),
            DmuType::Uint16Data => write!(f, "Uint16Data"),
            DmuType::Uint32Data => write!(f, "Uint32Data"),
            DmuType::Uint64Data => write!(f, "Uint64Data"),
            DmuType::ZapData => write!(f, "ZapData"),

            DmuType::Uint8DataEncrypted => write!(f, "Uint8DataEncrypted"),
            DmuType::Uint16DataEncrypted => write!(f, "Uint16DataEncrypted"),
            DmuType::Uint32DataEncrypted => write!(f, "Uint32DataEncrypted"),
            DmuType::Uint64DataEncrypted => write!(f, "Uint64DataEncrypted"),
            DmuType::ZapDataEncrypted => write!(f, "ZapDataEncrypted"),

            DmuType::Uint8Metadata => write!(f, "Uint8Metadata"),
            DmuType::Uint16Metadata => write!(f, "Uint16Metadata"),
            DmuType::Uint32Metadata => write!(f, "Uint32Metadata"),
            DmuType::Uint64Metadata => write!(f, "Uint64Metadata"),
            DmuType::ZapMetadata => write!(f, "ZapMetadata"),

            DmuType::Uint8MetadataEncrypted => write!(f, "Uint8MetadataEncrypted"),
            DmuType::Uint16MetadataEncrypted => write!(f, "Uint16MetadataEncrypted"),
            DmuType::Uint32MetadataEncrypted => write!(f, "Uint32MetadataEncrypted"),
            DmuType::Uint64MetadataEncrypted => write!(f, "Uint64MetadataEncrypted"),
            DmuType::ZapMetadataEncrypted => write!(f, "ZapMetadataEncrypted"),
        }
    }
}

impl From<DmuType> for u8 {
    fn from(val: DmuType) -> u8 {
        val as u8
    }
}

impl TryFrom<u8> for DmuType {
    type Error = DmuTypeError;

    /** Try converting from a [`u8`] to a [`DmuType`].
     *
     * # Errors
     *
     * Returns [`DmuTypeError`] in case of an unknown [`DmuType`].
     */
    fn try_from(dmu: u8) -> Result<Self, Self::Error> {
        match dmu {
            0 => Ok(DmuType::None),
            1 => Ok(DmuType::ObjectDirectory),
            2 => Ok(DmuType::ObjectArray),
            3 => Ok(DmuType::PackedNvList),
            4 => Ok(DmuType::PackedNvListSize),
            5 => Ok(DmuType::BpObject),
            6 => Ok(DmuType::BpObjectHeader),
            7 => Ok(DmuType::SpaceMapHeader),
            8 => Ok(DmuType::SpaceMap),
            9 => Ok(DmuType::IntentLog),
            10 => Ok(DmuType::Dnode),
            11 => Ok(DmuType::ObjectSet),
            12 => Ok(DmuType::DslDirectory),
            13 => Ok(DmuType::DslDirectoryChildMap),
            14 => Ok(DmuType::DslDsSnapshotMap),
            15 => Ok(DmuType::DslProperties),
            16 => Ok(DmuType::DslDataSet),
            17 => Ok(DmuType::Znode),
            18 => Ok(DmuType::AclV0),
            19 => Ok(DmuType::PlainFileContents),
            20 => Ok(DmuType::DirectoryContents),
            21 => Ok(DmuType::MasterNode),
            22 => Ok(DmuType::UnlinkedSet),
            23 => Ok(DmuType::Zvol),
            24 => Ok(DmuType::ZvolProperty),
            25 => Ok(DmuType::PlainOther),
            26 => Ok(DmuType::Uint64Other),
            27 => Ok(DmuType::ZapOther),
            28 => Ok(DmuType::ErrorLog),
            29 => Ok(DmuType::SpaHistory),
            30 => Ok(DmuType::SpaHistoryOffsets),
            31 => Ok(DmuType::PoolProperties),
            32 => Ok(DmuType::DslPermissions),
            33 => Ok(DmuType::AclV1),
            34 => Ok(DmuType::SysAcl),
            35 => Ok(DmuType::Fuid),
            36 => Ok(DmuType::FuidSize),
            37 => Ok(DmuType::NextClones),
            38 => Ok(DmuType::ScanQueue),
            39 => Ok(DmuType::UserGroupUsed),
            40 => Ok(DmuType::UserGroupQuota),
            41 => Ok(DmuType::UserRefs),
            42 => Ok(DmuType::DdtZap),
            43 => Ok(DmuType::DdtStats),
            44 => Ok(DmuType::SystemAttribute),
            45 => Ok(DmuType::SystemAttributeMasterNode),
            46 => Ok(DmuType::SystemAttributeRegistration),
            47 => Ok(DmuType::SystemAttributeLayouts),
            48 => Ok(DmuType::ScanXlate),
            49 => Ok(DmuType::Dedup),
            50 => Ok(DmuType::DeadList),
            51 => Ok(DmuType::DeadListHeader),
            52 => Ok(DmuType::DslClones),
            53 => Ok(DmuType::BpObjectSubObject),

            0x80 => Ok(DmuType::Uint8Data),
            0x81 => Ok(DmuType::Uint16Data),
            0x82 => Ok(DmuType::Uint32Data),
            0x83 => Ok(DmuType::Uint64Data),
            0x84 => Ok(DmuType::ZapData),

            0xa0 => Ok(DmuType::Uint8DataEncrypted),
            0xa1 => Ok(DmuType::Uint16DataEncrypted),
            0xa2 => Ok(DmuType::Uint32DataEncrypted),
            0xa3 => Ok(DmuType::Uint64DataEncrypted),
            0xa4 => Ok(DmuType::ZapDataEncrypted),

            0xc0 => Ok(DmuType::Uint8Metadata),
            0xc1 => Ok(DmuType::Uint16Metadata),
            0xc2 => Ok(DmuType::Uint32Metadata),
            0xc3 => Ok(DmuType::Uint64Metadata),
            0xc4 => Ok(DmuType::ZapMetadata),

            0xe0 => Ok(DmuType::Uint8MetadataEncrypted),
            0xe1 => Ok(DmuType::Uint16MetadataEncrypted),
            0xe2 => Ok(DmuType::Uint32MetadataEncrypted),
            0xe3 => Ok(DmuType::Uint64MetadataEncrypted),
            0xe4 => Ok(DmuType::ZapMetadataEncrypted),

            _ => Err(DmuTypeError::Unknown { dmu }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// [`DmuType`] conversion error.
#[derive(Debug)]
pub enum DmuTypeError {
    /// Unknown [`DmuType`].
    Unknown {
        /// DMU type.
        dmu: u8,
    },
}

impl fmt::Display for DmuTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmuTypeError::Unknown { dmu } => {
                write!(f, "Unknown DmuType {dmu}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DmuTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
