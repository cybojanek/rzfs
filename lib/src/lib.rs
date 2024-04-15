// SPDX-License-Identifier: GPL-2.0 OR MIT

//! ZFS library.

// Uncomment the following two lines for avx512
// #![feature(avx512_target_feature)]
// #![feature(stdarch_x86_avx512)]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// CPU architecture support.
pub(crate) mod arch;

/// Checksum calculation.
pub mod checksum;

/// On disk physical structure encoding and decoding.
pub mod phys;
