// SPDX-License-Identifier: GPL-2.0 OR MIT

pub(crate) mod acl;
pub use acl::{
    AceDecodeError, AceEncodeError, AceFlag, AcePermission, AceType, AceTypeError, AceV0, AceV1,
    AceV1Header, AceV1Iterator, AceV1Object, Acl, AclDecodeError, AclEncodeError, AclV0, AclV1,
};

pub(crate) mod block_pointer;
pub use block_pointer::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEmbedded, BlockPointerEmbeddedType,
    BlockPointerEmbeddedTypeError, BlockPointerEncodeError, BlockPointerEncrypted,
    BlockPointerObjectHeader, BlockPointerObjectHeaderAccountingExtension,
    BlockPointerObjectHeaderDeadListsExtension, BlockPointerObjectHeaderDecodeError,
    BlockPointerObjectHeaderEncodeError, BlockPointerObjectHeaderExtension, BlockPointerRegular,
};

pub(crate) mod checksum;
pub use checksum::{
    ChecksumTail, ChecksumTailDecodeError, ChecksumTailEncodeError, ChecksumType,
    ChecksumTypeError, ChecksumValue, ChecksumValueDecodeError, ChecksumValueEncodeError,
};

pub(crate) mod compression;
pub use compression::{CompressionType, CompressionTypeError};

pub(crate) mod dnode;
pub use dnode::{
    Dnode, DnodeDecodeError, DnodeEncodeError, DnodeTail, DnodeTailSpill, DnodeTailThree,
    DnodeTailTwo, DnodeTailZero,
};

pub(crate) mod dsl;
pub use dsl::{
    DslDataSet, DslDataSetDecodeError, DslDataSetEncodeError, DslDirectory,
    DslDirectoryDecodeError, DslDirectoryEncodeError,
};

pub(crate) mod dmu;
pub use dmu::{DmuGenericObjectType, DmuType, DmuTypeError};

pub(crate) mod dva;
pub use dva::{Dva, DvaDecodeError, DvaEncodeError};

pub(crate) mod endian;
pub use endian::{
    EndianDecodeError, EndianDecoder, EndianEncodeError, EndianEncoder, EndianOrder,
    GetFromEndianDecoder, ENDIAN_ORDER_NATIVE, ENDIAN_ORDER_SWAP,
};

pub(crate) mod feature;
pub use feature::Feature;

pub(crate) mod label;
pub use label::{
    Blank, BlankDecodeError, BlankEncodeError, BootBlock, BootBlockDecodeError,
    BootBlockEncodeError, BootHeader, BootHeaderDecodeError, BootHeaderEncodeError, Label,
    LabelSectorsError, NvPairs, NvPairsDecodeError, NvPairsEncodeError,
};

pub(crate) mod nv;
pub use nv::{
    NvDataType, NvDataValue, NvDecodeError, NvDecodedDataValue, NvDecodedPair, NvDecoder,
    NvEncoding, NvEndianOrder, NvList, NvPair, NvUnique,
};

pub(crate) mod object_set;
pub use object_set::{
    ObjectSet, ObjectSetDecodeError, ObjectSetEncodeError, ObjectSetExtension, ObjectSetType,
    ObjectSetTypeError,
};

pub(crate) mod sector;
pub use sector::{is_multiple_of_sector_size, IsMultipleOfSectorSize, SECTOR_SHIFT};

pub(crate) mod spa;
pub use spa::{SpaVersion, SpaVersionError};

pub(crate) mod uberblock;
pub use uberblock::{
    UberBlock, UberBlockDecodeError, UberBlockEncodeError, UberBlockMmp, UberBlockMmpDecodeError,
    UberBlockMmpEncodeError,
};

pub(crate) mod xdr;
pub use xdr::{GetFromXdrDecoder, XdrDecodeError, XdrDecoder};

pub(crate) mod zap;
pub use zap::{
    ZapCaseNormalization, ZapCaseNormalizationError, ZapHeader, ZapHeaderDecodeError,
    ZapHeaderEncodeError, ZapLeafChunk, ZapLeafChunkData, ZapLeafChunkDecodeError,
    ZapLeafChunkEncodeError, ZapLeafChunkEntry, ZapLeafChunkFree, ZapLeafHeader,
    ZapLeafHeaderDecodeError, ZapLeafHeaderEncodeError, ZapMegaHeader, ZapMegaHeaderDecodeError,
    ZapMegaHeaderEncodeError, ZapMegaPointerTable, ZapMegaPointerTableDecodeError,
    ZapMegaPointerTableEncodeError, ZapMicroEntry, ZapMicroEntryDecodeError,
    ZapMicroEntryEncodeError, ZapMicroEntryRef, ZapMicroHeader, ZapMicroHeaderDecodeError,
    ZapMicroHeaderEncodeError, ZapMicroIterator, ZapMicroIteratorError, ZapUnicodeNormalization,
    ZapUnicodeNormalizationError,
};

pub(crate) mod zil;
pub use zil::{ZilHeader, ZilHeaderDecodeError, ZilHeaderEncodeError};

pub(crate) mod zpl;
pub use zpl::{
    Znode, ZnodeDecodeError, ZnodeEncodeError, ZnodeFileType, ZnodeFileTypeError, ZnodePermission,
    ZnodeTime, ZplVersion, ZplVersionError,
};
