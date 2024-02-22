// SPDX-License-Identifier: GPL-2.0 OR MIT

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** Data Management Unit type.
 *
 * ```text
 * +-----------------------------+---------+---------------------+
 * | Dmu Type                    | Version | Object Type        |
 * +-----------------------------+---------+---------------------+
 * | None                        |       1 |                     |
 * +-----------------------------+---------+---------------------+
 * | ObjectDirectory             |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | ObjectArray                 |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | PackedNvList                |       1 | NvList              |
 * +-----------------------------+---------+---------------------+
 * | PackedNvListSize            |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | BpObject                    |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | BpObjectHeader              |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | SpaceMapHeader              |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | SpaceMap                    |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | IntentLog                   |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | Dnode                       |       1 | Dnode               |
 * +-----------------------------+---------+---------------------+
 * | ObjectSet                   |       1 | ObjectSet           |
 * +-----------------------------+---------+---------------------+
 * | DslDirectory                |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | DslDirectoryChildMap        |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DslDsSnapshotMap            |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DslProperties               |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DslDataSet                  |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | Znode                       |       1 | Znode               |
 * +-----------------------------+---------+---------------------+
 * | OldAcl                      |       1 | OldAcl              |
 * +-----------------------------+---------+---------------------+
 * | PlainFileContents           |       1 | u8                  |
 * +-----------------------------+---------+---------------------+
 * | DirectoryContents           |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | MasterNode                  |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | UnlinkedSet                 |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | Zvol                        |       1 | u8                  |
 * +-----------------------------+---------+---------------------+
 * | ZvolProperty                |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | PlainOther                  |       1 | u8                  |
 * +-----------------------------+---------+---------------------+
 * | Uint64Other                 |       1 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | ZapOther                    |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | ErrorLog                    |       1 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | SpaHistory                  |       4 | u8                  |
 * +-----------------------------+---------+---------------------+
 * | SpaHistoryOffsets           |       4 | SpaHistory          |
 * +-----------------------------+---------+---------------------+
 * | PoolProperties              |       6 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DslPermissions              |       8 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | Acl                         |       9 | Acl                 |
 * +-----------------------------+---------+---------------------+
 * | SysAcl                      |       9 | SysAcl              |
 * +-----------------------------+---------+---------------------+
 * | Fuid                        |       9 | Fuid Table (NvList) |
 * +-----------------------------+---------+---------------------+
 * | FuidSize                    |       9 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | NextClones                  |      11 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | ScanQueue                   |      11 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | UserGroupUsed               |      15 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | UserGroupQuota              |      15 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | UserRefs                    |      18 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DdtZap                      |      21 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DdtStats                    |      21 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | SystemAttribute             |      26 | SystemAttribute     |
 * +-----------------------------+---------+---------------------+
 * | SystemAttributeMasterNode   |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | SystemAttributeRegistration |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | SystemAttributeLayouts      |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | ScanXlate                   |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | Dedup                       |      26 | ???                 |
 * +-----------------------------+---------+---------------------+
 * | DeadList                    |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | DeadListHeader              |      26 | u64                 |
 * +-----------------------------+---------+---------------------+
 * | DslClones                   |      26 | Zap                 |
 * +-----------------------------+---------+---------------------+
 * | BpObjectSubObject           |      26 | u64                 |
 * +-----------------------------+---------+---------------------+
 */
#[derive(Clone, Copy, Debug)]
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
    OldAcl = 18,
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
    Acl = 33,
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
            DmuType::OldAcl => write!(f, "OldAcl"),
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
            DmuType::Acl => write!(f, "Acl"),
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
     * Returns [`DmuTypeError`] in case of an invalid [`DmuType`].
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
            18 => Ok(DmuType::OldAcl),
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
            33 => Ok(DmuType::Acl),
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
            _ => Err(DmuTypeError::Unknown { value: dmu }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`DmuType`] conversion error.
 */
#[derive(Debug)]
pub enum DmuTypeError {
    /** Unknown [`DmuType`].
     *
     * - `value` - Unknown value.
     */
    Unknown { value: u8 },
}

impl fmt::Display for DmuTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmuTypeError::Unknown { value } => {
                write!(f, "DmuType unknown: {value}")
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
