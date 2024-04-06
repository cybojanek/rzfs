// SPDX-License-Identifier: GPL-2.0 OR MIT

pub(crate) mod common;
pub use common::{Checksum, ChecksumError};

pub(crate) mod fletcher4;
pub use fletcher4::{Fletcher4, Fletcher4Implementation};