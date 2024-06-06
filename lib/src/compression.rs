// SPDX-License-Identifier: GPL-2.0 OR MIT

pub(crate) mod common;
pub use common::{Compression, CompressionError, Decompression, DecompressionError};

pub(crate) mod lzjb;
pub use lzjb::{LzjbDecoder, LzjbEncoder};
