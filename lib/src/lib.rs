// SPDX-License-Identifier: GPL-2.0 OR MIT

//! ZFS library.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// On disk physical structure encoding and decoding.
pub mod phys;
