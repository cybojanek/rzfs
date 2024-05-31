// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::checksum::{Checksum, ChecksumError};
use crate::phys::{ChecksumType, EndianOrder};

use core::cmp;
use core::fmt;
use core::fmt::Display;

#[cfg(all(target_arch = "x86", any(feature = "sha256-ssse3")))]
use core::arch::x86 as arch;

#[cfg(all(target_arch = "x86_64", any(feature = "sha256-ssse3")))]
use core::arch::x86_64 as arch;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    feature = "sha256-bmi",
))]
use crate::arch::x86_any::{is_bmi1_supported, is_bmi2_supported};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-ssse3", feature = "sha256-sha"),
))]
use crate::arch::x86_any::{is_sse2_supported, is_sse3_supported, is_ssse3_supported};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-avx", feature = "sha256-avx2"),
))]
use crate::arch::x86_any::is_avx_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-avx2"),
))]
use crate::arch::x86_any::is_avx2_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-ssse3", feature = "sha256-sha"),
))]
use crate::arch::x86_any::is_sha_supported;

////////////////////////////////////////////////////////////////////////////////

/// Sha256 block size in bytes.
const SHA_256_BLOCK_SIZE: usize = 64;

/// Sha256 in u32.
const SHA_256_U32_COUNT: usize = 8;

/** Sha256 implementation.
 *
 * - [`Sha256Implementation::BMI`] uses `BMI1` and `BMI2`. AMD has released
 *   processors with just `BMI1` support, but this implementation requires both.
 *   `BMI` uses integer registers, and does not use any floating point registers.
 * - [`Sha256Implementation::SSSE3`] uses `SSE2` and `SSSE3`. It does not use
 *   `BMI`, because it was not available at the time of `SSSE3`.
 * - [`Sha256Implementation::AVX`] uses `AVX`. It does not use
 *   `BMI`, because it was not available at the time of `AVX`.
 * - [`Sha256Implementation::AVX2`] uses `AVX`, `AVX2`, `BMI1`, and `BMI2, since
 *   they were all released at the same time on Haswell. AMD has released
 *   processors with just `BMI1` support, but this implementation requires both.
 *   In order to take advantage of 256 bit SIMD, this implementation schedules
 *   two blocks at a time, and gracefully handles inputs that are not multiples
 *   of two blocks.
 * - [`Sha256Implementation::SHA`] uses `SSE2`, `SSSE3`, and Intel `SHA`.
 */
#[derive(Copy, Clone, Debug)]
pub enum Sha256Implementation {
    /// Generic.
    Generic,

    /// BMI1 and BMI2.
    BMI,

    /// SSSE3.
    SSSE3,

    /// AVX.
    AVX,

    /// AVX2 with BMI1 and BMI2.
    AVX2,

    /// SHA extensions with SSE2 and SSSE3.
    SHA,
}

/**
 * Align to 32 bytes for usage with 256 bit AVX2.
 */
#[repr(C, align(32))]
struct Sha256Constants {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(feature = "sha256-avx2"),
    ))]
    k2: [u32; 128],
    k: [u32; 64],
    h: [u32; 8],
}

/**
 * Align to 16 bytes for usage with 128 bit SSE.
 */
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-ssse3", feature = "sha256-avx"),
))]
#[repr(C, align(16))]
struct WK16 {
    wk: [u32; 64],
}

const SHA_256_CONSTANTS: Sha256Constants = Sha256Constants {
    // 256 bit k values, duplicated for 128 bit lanes of AVX2
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(feature = "sha256-avx2"),
    ))]
    k2: [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x428a2f98, 0x71374491, 0xb5c0fbcf,
        0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
        0x240ca1cc, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
        0x5cb0a9dc, 0x76f988da, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0xc6e00bf3, 0xd5a79147, 0x06ca6351,
        0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x27b70a85, 0x2e1b2138,
        0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0x650a7354,
        0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
        0x106aa070, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
        0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x748f82ee, 0x78a5636f, 0x84c87814,
        0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0x90befffa, 0xa4506ceb,
        0xbef9a3f7, 0xc67178f2,
    ],
    k: [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ],
    h: [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ],
};

const ALL_SHA_256_IMPLEMENTATIONS: [Sha256Implementation; 6] = [
    Sha256Implementation::Generic,
    Sha256Implementation::BMI,
    Sha256Implementation::SSSE3,
    Sha256Implementation::AVX,
    Sha256Implementation::AVX2,
    Sha256Implementation::SHA,
];

impl Sha256Implementation {
    /** Get a slice with all of the [`Sha256Implementation`].
     *
     * Runtime support depends on CPU. Calling [`Sha256::new`] might still
     * fail with [`ChecksumError::Unsupported`].
     */
    pub fn all() -> &'static [Sha256Implementation] {
        &ALL_SHA_256_IMPLEMENTATIONS
    }

    /// Is the implementation supported.
    pub fn is_supported(&self) -> bool {
        match self {
            Sha256Implementation::Generic => true,

            #[cfg(feature = "sha256-bmi")]
            Sha256Implementation::BMI => is_bmi1_supported() && is_bmi2_supported(),

            #[cfg(feature = "sha256-ssse3")]
            Sha256Implementation::SSSE3 => {
                is_sse2_supported() && is_sse3_supported() && is_ssse3_supported()
            }

            #[cfg(feature = "sha256-avx")]
            Sha256Implementation::AVX => is_avx_supported(),

            #[cfg(feature = "sha256-avx2")]
            Sha256Implementation::AVX2 => {
                is_avx_supported()
                    && is_avx2_supported()
                    && is_bmi1_supported()
                    && is_bmi2_supported()
            }

            #[cfg(feature = "sha256-sha")]
            Sha256Implementation::SHA => {
                is_sse2_supported()
                    && is_sse3_supported()
                    && is_ssse3_supported()
                    && is_sha_supported()
            }

            #[cfg(any(
                not(feature = "sha256-bmi"),
                not(feature = "sha256-ssse3"),
                not(feature = "sha256-avx"),
                not(feature = "sha256-avx2"),
                not(feature = "sha256-sha"),
            ))]
            _ => false,
        }
    }

    /// Get the string name of the implementation.
    pub fn to_str(&self) -> &'static str {
        match self {
            Sha256Implementation::Generic => "generic",
            Sha256Implementation::BMI => "bmi",
            Sha256Implementation::SSSE3 => "ssse3",
            Sha256Implementation::AVX => "avx",
            Sha256Implementation::AVX2 => "avx2",
            Sha256Implementation::SHA => "sha",
        }
    }
}

impl Display for Sha256Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            _ => write!(f, "{}", self.to_str()),
        }
    }
}

/// Update state. Data length is a multiple of [`SHA_256_BLOCK_SIZE`].
type Sha256UpdateBlock = fn(state: &mut [u32], data: &[u8]);

/// Sha256 implementation context.
struct Sha256ImplementationCtx {
    /// Implementation of [`Sha256UpdateBlock`].
    update_blocks: Sha256UpdateBlock,
}

/// [`crate::phys::ChecksumType::Sha256`] implementation.
pub struct Sha256 {
    /// Number of bytes processed.
    bytes_processed: u64,

    /// Number of bytes used in [`Sha256::buffer`].
    buffer_fill: usize,

    /// Partial block buffer.
    buffer: [u8; SHA_256_BLOCK_SIZE],

    /// Ongoing checksum.
    state: [u32; SHA_256_U32_COUNT],

    /// Implementation context.
    impl_ctx: Sha256ImplementationCtx,
}

impl Sha256ImplementationCtx {
    fn new(implementation: Sha256Implementation) -> Result<Sha256ImplementationCtx, ChecksumError> {
        if !implementation.is_supported() {
            return Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Sha256,
                implementation: implementation.to_str(),
            });
        }

        match implementation {
            Sha256Implementation::Generic => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_generic,
            }),

            #[cfg(feature = "sha256-bmi")]
            Sha256Implementation::BMI => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_bmi,
            }),

            #[cfg(feature = "sha256-ssse3")]
            Sha256Implementation::SSSE3 => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_ssse3,
            }),

            #[cfg(feature = "sha256-avx")]
            Sha256Implementation::AVX => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_avx,
            }),

            #[cfg(feature = "sha256-avx2")]
            Sha256Implementation::AVX2 => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_avx2,
            }),

            #[cfg(feature = "sha256-sha")]
            Sha256Implementation::SHA => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_sha,
            }),

            #[cfg(any(
                not(feature = "sha256-bmi"),
                not(feature = "sha256-ssse3"),
                not(feature = "sha256-avx"),
                not(feature = "sha256-avx2"),
                not(feature = "sha256-sha"),
            ))]
            _ => Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Sha256,
                implementation: implementation.to_str(),
            }),
        }
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-ssse3", feature = "sha256-avx"),
))]
/// Do a round of calculations. Caller must swap variables.
macro_rules! round_ssse3_or_avx {
    ($round:expr,
     $wk:expr,
     $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
    ) => {
        // Expand and re-order operations to minimize register usage,
        // dependencies, and spilling registers to stack.
        let ch_b = !$e;
        let ch = $e & $f;
        let ch_b = ch_b & $g;
        let ch = ch ^ ch_b;

        // Use Intel optimization.
        let s1 = $e.rotate_right(14);
        let s1 = $e ^ s1;
        let s1 = s1.rotate_right(5);
        let s1 = $e ^ s1;
        let s1 = s1.rotate_right(6);

        let temp1 = $h.wrapping_add(s1);
        let temp1 = temp1.wrapping_add(ch);
        let temp1 = temp1.wrapping_add($wk[$round]);
        $round = $round + 1;

        // Caller swaps variables.
        $d = $d.wrapping_add(temp1);

        let maj = $a & $b;
        let maj_b = $a & $c;
        let maj = maj ^ maj_b;
        let maj_c = $b & $c;
        let maj = maj ^ maj_c;

        // Use Intel optimization.
        let s0 = $a.rotate_right(9);
        let s0 = $a ^ s0;
        let s0 = s0.rotate_right(11);
        let s0 = $a ^ s0;
        let s0 = s0.rotate_right(2);

        let temp2 = s0.wrapping_add(maj);

        // Caller swaps variables.
        $h = temp1.wrapping_add(temp2);
    };
}

/** Schedule the next four values, and do four rounds of calculations.
 *
 * Caller must swap variables.
 */
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(feature = "sha256-ssse3", feature = "sha256-avx"),
))]
macro_rules! schedule_and_rounds_ssse3_or_avx {
    ($round:expr,
     $wk:expr,
     $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr,
     $w_00_04:expr, $w_04_08:expr, $w_08_12:expr, $w_12_16:expr
    ) => {
        ////////////////////////
        // Round 1.

            // Pre-compute SHA_256_CONSTANTS.k[i] + w[i]
            let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[$round..].as_ptr() as *const _);

        let ch_b = !$e;
        let ch = $e & $f;

            let k = arch::_mm_add_epi32(k, $w_00_04);

        let ch_b = ch_b & $g;
        let ch = ch ^ ch_b;

            arch::_mm_store_si128($wk[$round..].as_mut_ptr() as *mut _, k);

        // Use Intel optimization.
        let s1 = $e.rotate_right(14);
        let s1 = $e ^ s1;

            // s0 = w[i-15].ror(7) ^ w[i-15].ror(18) ^ (w[i-15] >> 3)
            // s0_16_20 minus 15, w_01_05 is needed
            // Compute w_01_05 by combining registers.
            let w_01_05 = arch::_mm_alignr_epi8($w_04_08, $w_00_04, 4);

        let s1 = s1.rotate_right(5);
        let s1 = $e ^ s1;
        let s1 = s1.rotate_right(6);

            let w_01_05_ror_7_a = arch::_mm_srli_epi32(w_01_05, 7);

        let temp1 = $h.wrapping_add(s1);
        let temp1 = temp1.wrapping_add(ch);
        let temp1 = temp1.wrapping_add($wk[$round]);
        $round += 1;

        // Caller swaps variables.
        $d = $d.wrapping_add(temp1);

            let w_01_05_ror_7_b = arch::_mm_slli_epi32(w_01_05, 32 - 7);

        let maj = $a & $b;
        let maj_b = $a & $c;

            let w_01_05_ror_7 = arch::_mm_or_si128(w_01_05_ror_7_a, w_01_05_ror_7_b);

        let maj = maj ^ maj_b;
        let maj_c = $b & $c;
        let maj = maj ^ maj_c;

            let w_01_05_ror_18_a = arch::_mm_srli_epi32(w_01_05, 18);

        // Use Intel optimization.
        let s0 = $a.rotate_right(9);
        let s0 = $a ^ s0;

            let w_01_05_ror_18_b = arch::_mm_slli_epi32(w_01_05, 32 - 18);

        let s0 = s0.rotate_right(11);
        let s0 = $a ^ s0;
        let s0 = s0.rotate_right(2);

            let w_01_05_ror_18 = arch::_mm_or_si128(w_01_05_ror_18_a, w_01_05_ror_18_b);

        let temp2 = s0.wrapping_add(maj);

        // Caller swaps variables.
        $h = temp1.wrapping_add(temp2);

        ////////////////////////
        // Round 2.

            let s0_16_20_a = arch::_mm_xor_si128(w_01_05_ror_7, w_01_05_ror_18);

        let ch_b = !$d;
        let ch = $d & $e;

            let s0_16_20_b = arch::_mm_srli_epi32(w_01_05, 3);

        let ch_b = ch_b & $f;
        let ch = ch ^ ch_b;

            let s0_16_20 = arch::_mm_xor_si128(s0_16_20_a, s0_16_20_b);

        // Use Intel optimization.
        let s1 = $d.rotate_right(14);
        let s1 = $d ^ s1;

            // w[i] = w[i-16] + s0 + w[i-7] + s1
            // w_16_20 minus 7, w_09_13 is needed.
            // w_16_20 minus 16, w_00_04 is available.
            // s0 is available.
            let w_16_20_minus_s1_minus_w7 = arch::_mm_add_epi32($w_00_04, s0_16_20);

        let s1 = s1.rotate_right(5);
        let s1 = $d ^ s1;
        let s1 = s1.rotate_right(6);

            let w_09_13 = arch::_mm_alignr_epi8($w_12_16, $w_08_12, 4);

        let temp1 = $g.wrapping_add(s1);
        let temp1 = temp1.wrapping_add(ch);
        let temp1 = temp1.wrapping_add($wk[$round]);
        $round += 1;

        // Caller swaps variables.
        $c = $c.wrapping_add(temp1);

            // Instead of w_16_20_minus_s1, start re-using w_00_04.
            $w_00_04 = arch::_mm_add_epi32(w_16_20_minus_s1_minus_w7, w_09_13);

        let maj = $h & $a;
        let maj_b = $h & $b;

            // s1 = w[i-2].ror(17) ^ w[i-2].ror(19) ^ (w[i-2] >> 10)
            // w_16_20 minus 2, w_14_18 is needed.
            // However, that means that w_16_18 needs to be computed, so
            // compute s1_14_18.
            // Use optimization from Intel paper, and load w[14] and w[15] as
            // [15, 15, 14, 14] in order to perform rotation by shifting
            // across a u64 created from concatenating two u32.
            let w_1414_1515 = arch::_mm_unpackhi_epi32($w_12_16, $w_12_16);

        let maj = maj ^ maj_b;
        let maj_c = $a & $b;
        let maj = maj ^ maj_c;

            let w_14gg_15gg_ror_17 = arch::_mm_srli_epi64(w_1414_1515, 17);

        // Use Intel optimization.
        let s0 = $h.rotate_right(9);
        let s0 = $h ^ s0;

            let w_14gg_15gg_ror_19 = arch::_mm_srli_epi64(w_1414_1515, 19);

        let s0 = s0.rotate_right(11);
        let s0 = $h ^ s0;
        let s0 = s0.rotate_right(2);

            let w_14gg_15gg = arch::_mm_xor_si128(w_14gg_15gg_ror_17, w_14gg_15gg_ror_19);

        let temp2 = s0.wrapping_add(maj);

        // Caller swaps variables.
        $g = temp1.wrapping_add(temp2);

        ////////////////////////
        // Round 3.

            // [x, 15', x, 14'] -> [15', 14', x, x]
            let w_gggg_1415_ror = arch::_mm_shuffle_epi32(w_14gg_15gg, 0b10000000);

        let ch_b = !$c;
        let ch = $c & $d;

            let s1_14_18_a = arch::_mm_srli_epi32($w_12_16, 10);

        let ch_b = ch_b & $e;
        let ch = ch ^ ch_b;

            // Shift s1_14_18, so that 16_18 are in the lower position to match
            // their positions in w_16_20_minus_s1.
            let s1_14_18 = arch::_mm_xor_si128(w_gggg_1415_ror, s1_14_18_a);

        // Use Intel optimization.
        let s1 = $c.rotate_right(14);
        let s1 = $c ^ s1;

            // Compute w_16_20_18, which holds the correct values for w_16_18.
            let w_16_20_18_a = arch::_mm_srli_si128(s1_14_18, 8);

        let s1 = s1.rotate_right(5);
        let s1 = $c ^ s1;
        let s1 = s1.rotate_right(6);

        let temp1 = $f.wrapping_add(s1);
        let temp1 = temp1.wrapping_add(ch);
        let temp1 = temp1.wrapping_add($wk[$round]);
        $round += 1;

        // Caller swaps variables.
        $b = $b.wrapping_add(temp1);

        let maj = $g & $h;
        let maj_b = $g & $a;

            let w_16_20_18 = arch::_mm_add_epi32($w_00_04, w_16_20_18_a);

        let maj = maj ^ maj_b;
        let maj_c = $h & $a;
        let maj = maj ^ maj_c;

            // Combine w_12_16 with w_16_20_18 to make w_14_18.
            let w_14_18 = arch::_mm_alignr_epi8(w_16_20_18, $w_12_16, 8);

        // Use Intel optimization.
        let s0 = $g.rotate_right(9);
        let s0 = $g ^ s0;

            // Use optimization from Intel paper and load w[16], w[17] as
            // [17, 17, 16, 16] in order to perform rotation by shifting
            // across a u64 created from concatenating two u32.
            let w_1616_1717 = arch::_mm_unpacklo_epi32(w_16_20_18, w_16_20_18);

        let s0 = s0.rotate_right(11);
        let s0 = $g ^ s0;
        let s0 = s0.rotate_right(2);

            let w_16gg_17gg_ror_17 = arch::_mm_srli_epi64(w_1616_1717, 17);

        let temp2 = s0.wrapping_add(maj);

        // Caller swaps variables.
        $f = temp1.wrapping_add(temp2);

        ////////////////////////
        // Round 4.

            let w_16gg_17gg_ror_19 = arch::_mm_srli_epi64(w_1616_1717, 19);

        let ch_b = !$b;
        let ch = $b & $c;

            let w_16gg_17gg = arch::_mm_xor_si128(w_16gg_17gg_ror_17, w_16gg_17gg_ror_19);

        let ch_b = ch_b & $d;
        let ch = ch ^ ch_b;

            // [x, 17', x, 16'] -> [x, x, 17', 16']
            let w_1617_gggg = arch::_mm_shuffle_epi32(w_16gg_17gg, 0b00001000);

        // Use Intel optimization.
        let s1 = $b.rotate_right(14);
        let s1 = $b ^ s1;

            let w_14_18_ror = arch::_mm_alignr_epi8(w_1617_gggg, w_gggg_1415_ror, 8);

        let s1 = s1.rotate_right(5);
        let s1 = $b ^ s1;
        let s1 = s1.rotate_right(6);

            // Compute s1_16_20.
            let s1_16_20_b = arch::_mm_srli_epi32(w_14_18, 10);

        let temp1 = $e.wrapping_add(s1);
        let temp1 = temp1.wrapping_add(ch);
        let temp1 = temp1.wrapping_add($wk[$round]);
        $round += 1;

        // Caller swaps variables.
        $a = $a.wrapping_add(temp1);

            let s1_16_20 = arch::_mm_xor_si128(w_14_18_ror, s1_16_20_b);

        let maj = $f & $g;
        let maj_b = $f & $h;

            // Add s1 to w.
            $w_00_04 = arch::_mm_add_epi32($w_00_04, s1_16_20);

        let maj = maj ^ maj_b;
        let maj_c = $g & $h;
        let maj = maj ^ maj_c;

        // Use Intel optimization.
        let s0 = $f.rotate_right(9);
        let s0 = $f ^ s0;

        let s0 = s0.rotate_right(11);
        let s0 = $f ^ s0;
        let s0 = s0.rotate_right(2);

        let temp2 = s0.wrapping_add(maj);

        // Caller swaps variables.
        $e = temp1.wrapping_add(temp2);
        ////////////////////////
    };
}

impl Sha256 {
    /** Create a new Sha256 instance.
     *
     * `order` specifies the endianness of the data to be hashed.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] if the implementation is not supported.
     */
    pub fn new(implementation: Sha256Implementation) -> Result<Sha256, ChecksumError> {
        Ok(Sha256 {
            bytes_processed: 0,
            buffer_fill: 0,
            buffer: [0; SHA_256_BLOCK_SIZE],
            state: SHA_256_CONSTANTS.h,
            impl_ctx: Sha256ImplementationCtx::new(implementation)?,
        })
    }

    fn update_blocks_generic(state: &mut [u32], data: &[u8]) {
        /// Do a round of calculations. Caller must swap variables.
        macro_rules! round {
            ($round:expr,
             $w:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
            ) => {
                // Expand and re-order operations to minimize register usage,
                // dependencies, and spilling registers to stack.
                let ch_b = !$e;
                let ch = $e & $f;
                let ch_b = ch_b & $g;
                let ch = ch ^ ch_b;

                let mut s1;
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    // Use Intel optimization.
                    s1 = $e.rotate_right(14);
                    s1 = $e ^ s1;
                    s1 = s1.rotate_right(5);
                    s1 = $e ^ s1;
                    s1 = s1.rotate_right(6);
                }
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    s1 = $e.rotate_right(6);
                    let s1_b = $e.rotate_right(11);
                    s1 = s1 ^ s1_b;
                    let s1_c = $e.rotate_right(25);
                    s1 = s1 ^ s1_c;
                }

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                let temp1 = temp1.wrapping_add(SHA_256_CONSTANTS.k[$round]);
                let temp1 = temp1.wrapping_add($w[$round]);
                $round += 1;

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                let maj = $a & $b;
                let maj_b = $a & $c;
                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                let mut s0;
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    // Use Intel optimization.
                    s0 = $a.rotate_right(9);
                    s0 = $a ^ s0;
                    s0 = s0.rotate_right(11);
                    s0 = $a ^ s0;
                    s0 = s0.rotate_right(2);
                }
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    s0 = $a.rotate_right(2);
                    let s0_b = $a.rotate_right(13);
                    s0 = s0 ^ s0_b;
                    let s0_c = $a.rotate_right(22);
                    s0 = s0 ^ s0_c;
                }

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);
            };
        }

        /** Schedule the next value, and do a round of calculations.
         *
         * Caller must swap variables.
         */
        macro_rules! schedule_and_round {
            ($round:expr,
             $w:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
            ) => {
                // Expand and re-order operations to minimize register usage,
                // dependencies, and spilling registers to stack.

                ////////////////////////
                // Round part 1.
                let ch_b = !$e;
                let ch = $e & $f;
                let ch_b = ch_b & $g;
                let ch = ch ^ ch_b;

                let mut s1;
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    // Use Intel optimization.
                    s1 = $e.rotate_right(14);
                    s1 = $e ^ s1;
                    s1 = s1.rotate_right(5);
                    s1 = $e ^ s1;
                    s1 = s1.rotate_right(6);
                }
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    s1 = $e.rotate_right(6);
                    let s1_b = $e.rotate_right(11);
                    s1 = s1 ^ s1_b;
                    let s1_c = $e.rotate_right(25);
                    s1 = s1 ^ s1_c;
                }

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);

                ////////////////////////
                // Schedule before part 2, so that the schedule result is
                // available in the local register.
                let wi = $w[$round - 16];

                let w15 = $w[$round - 15];
                let s0 = w15.rotate_right(7);
                let s0 = (w15 >> 3) ^ s0;
                let s0 = w15.rotate_right(18) ^ s0;
                let wi = wi.wrapping_add(s0);

                let w2 = $w[$round - 2];
                let s1 = w2.rotate_right(17);
                let s1 = (w2 >> 10) ^ s1;
                let s1 = w2.rotate_right(19) ^ s1;
                let wi = wi.wrapping_add(s1);

                let wi = wi.wrapping_add($w[$round - 7]);
                $w[$round] = wi;

                ////////////////////////
                // Round part 2.
                let temp1 = temp1.wrapping_add(wi);
                let temp1 = temp1.wrapping_add(SHA_256_CONSTANTS.k[$round]);
                $round += 1;

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                let maj = $a & $b;
                let maj_b = $a & $c;
                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                let mut s0;
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    // Use Intel optimization.
                    s0 = $a.rotate_right(9);
                    s0 = $a ^ s0;
                    s0 = s0.rotate_right(11);
                    s0 = $a ^ s0;
                    s0 = s0.rotate_right(2);
                }
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    s0 = $a.rotate_right(2);
                    let s0_b = $a.rotate_right(13);
                    s0 = s0 ^ s0_b;
                    let s0_c = $a.rotate_right(22);
                    s0 = s0 ^ s0_c;
                }

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);
            };
        }

        let mut w: [u32; 64] = [0; 64];

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        // Iterate one block at a time.
        for block in data.chunks_exact(SHA_256_BLOCK_SIZE).by_ref() {
            // Initialize w[0..16].
            for (i, x) in block.chunks_exact(4).by_ref().enumerate() {
                w[i] = u32::from_be_bytes(x.try_into().unwrap());
            }

            let mut round = 0;

            // Unroll the code, and instead of swapping registers,
            // swap the variables when invoking the macro.
            round!(round, w, a, b, c, d, e, f, g, h);
            round!(round, w, h, a, b, c, d, e, f, g);
            round!(round, w, g, h, a, b, c, d, e, f);
            round!(round, w, f, g, h, a, b, c, d, e);
            round!(round, w, e, f, g, h, a, b, c, d);
            round!(round, w, d, e, f, g, h, a, b, c);
            round!(round, w, c, d, e, f, g, h, a, b);
            round!(round, w, b, c, d, e, f, g, h, a);

            round!(round, w, a, b, c, d, e, f, g, h);
            round!(round, w, h, a, b, c, d, e, f, g);
            round!(round, w, g, h, a, b, c, d, e, f);
            round!(round, w, f, g, h, a, b, c, d, e);
            round!(round, w, e, f, g, h, a, b, c, d);
            round!(round, w, d, e, f, g, h, a, b, c);
            round!(round, w, c, d, e, f, g, h, a, b);
            round!(round, w, b, c, d, e, f, g, h, a);

            while round < 64 {
                // Unroll the code, and instead of swapping registers,
                // swap the variables when invoking the macro.
                schedule_and_round!(round, w, a, b, c, d, e, f, g, h);
                schedule_and_round!(round, w, h, a, b, c, d, e, f, g);
                schedule_and_round!(round, w, g, h, a, b, c, d, e, f);
                schedule_and_round!(round, w, f, g, h, a, b, c, d, e);
                schedule_and_round!(round, w, e, f, g, h, a, b, c, d);
                schedule_and_round!(round, w, d, e, f, g, h, a, b, c);
                schedule_and_round!(round, w, c, d, e, f, g, h, a, b);
                schedule_and_round!(round, w, b, c, d, e, f, g, h, a);

                schedule_and_round!(round, w, a, b, c, d, e, f, g, h);
                schedule_and_round!(round, w, h, a, b, c, d, e, f, g);
                schedule_and_round!(round, w, g, h, a, b, c, d, e, f);
                schedule_and_round!(round, w, f, g, h, a, b, c, d, e);
                schedule_and_round!(round, w, e, f, g, h, a, b, c, d);
                schedule_and_round!(round, w, d, e, f, g, h, a, b, c);
                schedule_and_round!(round, w, c, d, e, f, g, h, a, b);
                schedule_and_round!(round, w, b, c, d, e, f, g, h, a);
            }

            a = a.wrapping_add(state[0]);
            b = b.wrapping_add(state[1]);
            c = c.wrapping_add(state[2]);
            d = d.wrapping_add(state[3]);
            e = e.wrapping_add(state[4]);
            f = f.wrapping_add(state[5]);
            g = g.wrapping_add(state[6]);
            h = h.wrapping_add(state[7]);

            state[0] = a;
            state[1] = b;
            state[2] = c;
            state[3] = d;
            state[4] = e;
            state[5] = f;
            state[6] = g;
            state[7] = h;
        }
    }

    #[cfg(all(
        feature = "sha256-bmi",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_bmi(state: &mut [u32], data: &[u8]) {
        /// Do a round of calculations. Caller must swap variables.
        macro_rules! round {
            ($w:expr, $k:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
            ) => {
                // Expand and re-order operations to minimize register usage,
                // dependencies, and spilling registers to stack.

                // Combine ch expression, because BMI has ANDN.
                let ch = $e & $f;
                let ch_b = (!$e) & $g;
                let ch = ch ^ ch_b;

                // Don't use Intel optimization, because BMI has xorx.
                let s1 = $e.rotate_right(6);
                let s1_b = $e.rotate_right(11);
                let s1 = s1 ^ s1_b;
                let s1_c = $e.rotate_right(25);
                let s1 = s1 ^ s1_c;

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                let temp1 = temp1.wrapping_add(*$w);
                $w = $w.add(1);
                let temp1 = temp1.wrapping_add(*$k);
                $k = $k.add(1);

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                let maj = $a & $b;
                let maj_b = $a & $c;
                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                // Don't use Intel optimization, because BMI has xorx.
                let s0 = $a.rotate_right(2);
                let s0_b = $a.rotate_right(13);
                let s0 = s0 ^ s0_b;
                let s0_c = $a.rotate_right(22);
                let s0 = s0 ^ s0_c;

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);
            };
        }

        /** Schedule the next value, and do a round of calculations.
         *
         * Caller must swap variables.
         */
        macro_rules! schedule_and_round {
            ($w:expr, $k:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
            ) => {
                // Expand and re-order operations to minimize register usage,
                // dependencies, and spilling registers to stack.

                // Combine ch expression, because BMI has ANDN.
                let ch = $e & $f;
                let ch_b = (!$e) & $g;
                let ch = ch ^ ch_b;

                // Don't use Intel optimization, because BMI has xorx.
                let s1 = $e.rotate_right(6);
                let s1_b = $e.rotate_right(11);
                let s1 = s1 ^ s1_b;
                let s1_c = $e.rotate_right(25);
                let s1 = s1 ^ s1_c;

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);

                ////////////////////////
                // Schedule before part 2, so that the schedule result is
                // available in the local register.
                let wi = *$w.sub(16);

                let w15 = *$w.sub(15);
                let s0 = w15.rotate_right(7);
                let s0 = (w15 >> 3) ^ s0;
                let s0 = w15.rotate_right(18) ^ s0;
                let wi = wi.wrapping_add(s0);

                let w2 = *$w.sub(2);
                let s1 = w2.rotate_right(17);
                let s1 = (w2 >> 10) ^ s1;
                let s1 = w2.rotate_right(19) ^ s1;
                let wi = wi.wrapping_add(s1);

                let wi = wi.wrapping_add(*$w.sub(7));
                *$w = wi;
                $w = $w.add(1);

                ////////////////////////
                // Round part 2.
                let temp1 = temp1.wrapping_add(wi);
                let temp1 = temp1.wrapping_add(*$k);
                $k = $k.add(1);

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                let maj = $a & $b;
                let maj_b = $a & $c;
                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                // Don't use Intel optimization, because BMI has xorx.
                let s0 = $a.rotate_right(2);
                let s0_b = $a.rotate_right(13);
                let s0 = s0 ^ s0_b;
                let s0_c = $a.rotate_right(22);
                let s0 = s0 ^ s0_c;

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);
            };
        }

        #[target_feature(enable = "bmi1,bmi2")]
        unsafe fn update_blocks_bmi_impl(state: &mut [u32], data: &[u8]) {
            let mut w: [u32; 64] = [0; 64];

            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            // Iterate one block at a time.
            for block in data.chunks_exact(SHA_256_BLOCK_SIZE).by_ref() {
                // Initialize w[0..16].
                for (i, x) in block.chunks_exact(4).by_ref().enumerate() {
                    w[i] = u32::from_be_bytes(x.try_into().unwrap());
                }

                // This code is used in unsafe, so use w and k pointers.
                let mut w = w.as_mut_ptr();
                let mut k = SHA_256_CONSTANTS.k.as_ptr();

                // Unroll the code, and instead of swapping registers,
                // swap the variables when invoking the macro.
                round!(w, k, a, b, c, d, e, f, g, h);
                round!(w, k, h, a, b, c, d, e, f, g);
                round!(w, k, g, h, a, b, c, d, e, f);
                round!(w, k, f, g, h, a, b, c, d, e);
                round!(w, k, e, f, g, h, a, b, c, d);
                round!(w, k, d, e, f, g, h, a, b, c);
                round!(w, k, c, d, e, f, g, h, a, b);
                round!(w, k, b, c, d, e, f, g, h, a);

                round!(w, k, a, b, c, d, e, f, g, h);
                round!(w, k, h, a, b, c, d, e, f, g);
                round!(w, k, g, h, a, b, c, d, e, f);
                round!(w, k, f, g, h, a, b, c, d, e);
                round!(w, k, e, f, g, h, a, b, c, d);
                round!(w, k, d, e, f, g, h, a, b, c);
                round!(w, k, c, d, e, f, g, h, a, b);
                round!(w, k, b, c, d, e, f, g, h, a);

                for _ in 0..3 {
                    // Unroll the code, and instead of swapping registers,
                    // swap the variables when invoking the macro.
                    schedule_and_round!(w, k, a, b, c, d, e, f, g, h);
                    schedule_and_round!(w, k, h, a, b, c, d, e, f, g);
                    schedule_and_round!(w, k, g, h, a, b, c, d, e, f);
                    schedule_and_round!(w, k, f, g, h, a, b, c, d, e);
                    schedule_and_round!(w, k, e, f, g, h, a, b, c, d);
                    schedule_and_round!(w, k, d, e, f, g, h, a, b, c);
                    schedule_and_round!(w, k, c, d, e, f, g, h, a, b);
                    schedule_and_round!(w, k, b, c, d, e, f, g, h, a);

                    schedule_and_round!(w, k, a, b, c, d, e, f, g, h);
                    schedule_and_round!(w, k, h, a, b, c, d, e, f, g);
                    schedule_and_round!(w, k, g, h, a, b, c, d, e, f);
                    schedule_and_round!(w, k, f, g, h, a, b, c, d, e);
                    schedule_and_round!(w, k, e, f, g, h, a, b, c, d);
                    schedule_and_round!(w, k, d, e, f, g, h, a, b, c);
                    schedule_and_round!(w, k, c, d, e, f, g, h, a, b);
                    schedule_and_round!(w, k, b, c, d, e, f, g, h, a);
                }

                a = a.wrapping_add(state[0]);
                b = b.wrapping_add(state[1]);
                c = c.wrapping_add(state[2]);
                d = d.wrapping_add(state[3]);
                e = e.wrapping_add(state[4]);
                f = f.wrapping_add(state[5]);
                g = g.wrapping_add(state[6]);
                h = h.wrapping_add(state[7]);

                state[0] = a;
                state[1] = b;
                state[2] = c;
                state[3] = d;
                state[4] = e;
                state[5] = f;
                state[6] = g;
                state[7] = h;
            }
        }

        unsafe { update_blocks_bmi_impl(state, data) }
    }

    #[cfg(all(
        feature = "sha256-ssse3",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_ssse3(state: &mut [u32], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+-------+
        // | _mm_add_epi32      | SSE2  |
        // | _mm_alignr_epi8    | SSSE3 |
        // | _mm_lddqu_si128    | SSE3  |
        // | _mm_load_si128     | SSE2  |
        // | _mm_or_si128       | SSE2  |
        // | _mm_set_epi8       | SSE2  |
        // | _mm_shuffle_epi32  | SSE2  |
        // | _mm_shuffle_epi8   | SSSE3 |
        // | _mm_slli_epi32     | SSE2  |
        // | _mm_srli_epi32     | SSE2  |
        // | _mm_srli_epi64     | SSE2  |
        // | _mm_srli_si128     | SSE2  |
        // | _mm_store_si128    | SSE2  |
        // | _mm_unpacklo_epi32 | SSE2  |
        // | _mm_xor_si128      | SSE2  |
        // +--------------------+-------+

        // This function implements the SSSE3 part of the Intel paper entitled:
        // Fast SHA-256 Implementations on Intel Architecture Processors

        #[target_feature(enable = "sse2,sse3,ssse3")]
        unsafe fn update_blocks_ssse3_impl(state: &mut [u32], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                #[cfg(target_endian = "little")]
                let shuffle = arch::_mm_set_epi8(
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                );

                let mut w = WK16 { wk: [0; 64] };

                // Initialize local variables.
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(SHA_256_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Initialize w[0..16].
                    let block = block.as_ptr() as *const arch::__m128i;
                    let mut w0 = arch::_mm_lddqu_si128(block.add(0));
                    let mut w1 = arch::_mm_lddqu_si128(block.add(1));
                    let mut w2 = arch::_mm_lddqu_si128(block.add(2));
                    let mut w3 = arch::_mm_lddqu_si128(block.add(3));

                    #[cfg(target_endian = "little")]
                    {
                        w0 = arch::_mm_shuffle_epi8(w0, shuffle);
                        w1 = arch::_mm_shuffle_epi8(w1, shuffle);
                        w2 = arch::_mm_shuffle_epi8(w2, shuffle);
                        w3 = arch::_mm_shuffle_epi8(w3, shuffle);
                    }

                    let mut round = 0;

                    while round < 48 {
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, a, b, c, d, e, f, g, h, w0, w1, w2, w3
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, e, f, g, h, a, b, c, d, w1, w2, w3, w0
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, a, b, c, d, e, f, g, h, w2, w3, w0, w1
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, e, f, g, h, a, b, c, d, w3, w0, w1, w2
                        );
                    }

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w0);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, a, b, c, d, e, f, g, h);
                    round_ssse3_or_avx!(round, w.wk, h, a, b, c, d, e, f, g);
                    round_ssse3_or_avx!(round, w.wk, g, h, a, b, c, d, e, f);
                    round_ssse3_or_avx!(round, w.wk, f, g, h, a, b, c, d, e);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w1);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, e, f, g, h, a, b, c, d);
                    round_ssse3_or_avx!(round, w.wk, d, e, f, g, h, a, b, c);
                    round_ssse3_or_avx!(round, w.wk, c, d, e, f, g, h, a, b);
                    round_ssse3_or_avx!(round, w.wk, b, c, d, e, f, g, h, a);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w2);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, a, b, c, d, e, f, g, h);
                    round_ssse3_or_avx!(round, w.wk, h, a, b, c, d, e, f, g);
                    round_ssse3_or_avx!(round, w.wk, g, h, a, b, c, d, e, f);
                    round_ssse3_or_avx!(round, w.wk, f, g, h, a, b, c, d, e);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w3);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, e, f, g, h, a, b, c, d);
                    round_ssse3_or_avx!(round, w.wk, d, e, f, g, h, a, b, c);
                    round_ssse3_or_avx!(round, w.wk, c, d, e, f, g, h, a, b);
                    round_ssse3_or_avx!(round, w.wk, b, c, d, e, f, g, h, a);

                    // Prevent unused assignment warning due to loop unroll.
                    let _ = round;

                    a = a.wrapping_add(state[0]);
                    b = b.wrapping_add(state[1]);
                    c = c.wrapping_add(state[2]);
                    d = d.wrapping_add(state[3]);
                    e = e.wrapping_add(state[4]);
                    f = f.wrapping_add(state[5]);
                    g = g.wrapping_add(state[6]);
                    h = h.wrapping_add(state[7]);

                    state[0] = a;
                    state[1] = b;
                    state[2] = c;
                    state[3] = d;
                    state[4] = e;
                    state[5] = f;
                    state[6] = g;
                    state[7] = h;
                }
            }
        }

        unsafe { update_blocks_ssse3_impl(state, data) }
    }

    #[cfg(all(
        any(feature = "sha256-avx", feature = "sha256-avx2"),
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx(state: &mut [u32], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+--------+
        // | _mm_add_epi32      | SSE2*  |
        // | _mm_alignr_epi8    | SSSE3* |
        // | _mm_lddqu_si128    | SSE3*  |
        // | _mm_load_si128     | SSE2*  |
        // | _mm_or_si128       | SSE2*  |
        // | _mm_set_epi8       | SSE2*  |
        // | _mm_shuffle_epi32  | SSE2*  |
        // | _mm_shuffle_epi8   | SSSE3* |
        // | _mm_slli_epi32     | SSE2*  |
        // | _mm_srli_epi32     | SSE2*  |
        // | _mm_srli_epi64     | SSE2*  |
        // | _mm_srli_si128     | SSE2*  |
        // | _mm_store_si128    | SSE2*  |
        // | _mm_unpacklo_epi32 | SSE2*  |
        // | _mm_xor_si128      | SSE2*  |
        // +--------------------+--------+
        //
        // *Although these intrinsics are marked as SSE2 or SSSE3, they have
        // AVX encoded equivalents, and so they are supported with AVX.

        // This function implements the AVX part of the Intel paper entitled:
        // Fast SHA-256 Implementations on Intel Architecture Processors

        #[target_feature(enable = "avx")]
        unsafe fn update_blocks_avx_impl(state: &mut [u32], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                #[cfg(target_endian = "little")]
                let shuffle = arch::_mm_set_epi8(
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                );

                let mut w = WK16 { wk: [0; 64] };

                // Initialize local variables.
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(SHA_256_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Initialize w[0..16].
                    let block = block.as_ptr() as *const arch::__m128i;
                    let mut w0 = arch::_mm_lddqu_si128(block.add(0));
                    let mut w1 = arch::_mm_lddqu_si128(block.add(1));
                    let mut w2 = arch::_mm_lddqu_si128(block.add(2));
                    let mut w3 = arch::_mm_lddqu_si128(block.add(3));

                    #[cfg(target_endian = "little")]
                    {
                        w0 = arch::_mm_shuffle_epi8(w0, shuffle);
                        w1 = arch::_mm_shuffle_epi8(w1, shuffle);
                        w2 = arch::_mm_shuffle_epi8(w2, shuffle);
                        w3 = arch::_mm_shuffle_epi8(w3, shuffle);
                    }

                    let mut round = 0;

                    while round < 48 {
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, a, b, c, d, e, f, g, h, w0, w1, w2, w3
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, e, f, g, h, a, b, c, d, w1, w2, w3, w0
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, a, b, c, d, e, f, g, h, w2, w3, w0, w1
                        );
                        schedule_and_rounds_ssse3_or_avx!(
                            round, w.wk, e, f, g, h, a, b, c, d, w3, w0, w1, w2
                        );
                    }

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w0);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, a, b, c, d, e, f, g, h);
                    round_ssse3_or_avx!(round, w.wk, h, a, b, c, d, e, f, g);
                    round_ssse3_or_avx!(round, w.wk, g, h, a, b, c, d, e, f);
                    round_ssse3_or_avx!(round, w.wk, f, g, h, a, b, c, d, e);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w1);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, e, f, g, h, a, b, c, d);
                    round_ssse3_or_avx!(round, w.wk, d, e, f, g, h, a, b, c);
                    round_ssse3_or_avx!(round, w.wk, c, d, e, f, g, h, a, b);
                    round_ssse3_or_avx!(round, w.wk, b, c, d, e, f, g, h, a);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w2);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, a, b, c, d, e, f, g, h);
                    round_ssse3_or_avx!(round, w.wk, h, a, b, c, d, e, f, g);
                    round_ssse3_or_avx!(round, w.wk, g, h, a, b, c, d, e, f);
                    round_ssse3_or_avx!(round, w.wk, f, g, h, a, b, c, d, e);

                    let k = arch::_mm_load_si128(SHA_256_CONSTANTS.k[round..].as_ptr() as *const _);
                    let k = arch::_mm_add_epi32(k, w3);
                    arch::_mm_store_si128(w.wk[round..].as_mut_ptr() as *mut _, k);
                    round_ssse3_or_avx!(round, w.wk, e, f, g, h, a, b, c, d);
                    round_ssse3_or_avx!(round, w.wk, d, e, f, g, h, a, b, c);
                    round_ssse3_or_avx!(round, w.wk, c, d, e, f, g, h, a, b);
                    round_ssse3_or_avx!(round, w.wk, b, c, d, e, f, g, h, a);

                    // Prevent unused assignment warning due to loop unroll.
                    let _ = round;

                    a = a.wrapping_add(state[0]);
                    b = b.wrapping_add(state[1]);
                    c = c.wrapping_add(state[2]);
                    d = d.wrapping_add(state[3]);
                    e = e.wrapping_add(state[4]);
                    f = f.wrapping_add(state[5]);
                    g = g.wrapping_add(state[6]);
                    h = h.wrapping_add(state[7]);

                    state[0] = a;
                    state[1] = b;
                    state[2] = c;
                    state[3] = d;
                    state[4] = e;
                    state[5] = f;
                    state[6] = g;
                    state[7] = h;
                }
            }
        }

        unsafe { update_blocks_avx_impl(state, data) }
    }

    #[cfg(all(
        feature = "sha256-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2(state: &mut [u32], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+--------+
        // | _mm_add_epi32      | SSE2*  |
        // | _mm_alignr_epi8    | SSSE3* |
        // | _mm_lddqu_si128    | SSE3*  |
        // | _mm_load_si128     | SSE2*  |
        // | _mm_or_si128       | SSE2*  |
        // | _mm_set_epi8       | SSE2*  |
        // | _mm_shuffle_epi32  | SSE2*  |
        // | _mm_shuffle_epi8   | SSSE3* |
        // | _mm_slli_epi32     | SSE2*  |
        // | _mm_srli_epi32     | SSE2*  |
        // | _mm_srli_epi64     | SSE2*  |
        // | _mm_srli_si128     | SSE2*  |
        // | _mm_storeu_si128   | SSE2*  |
        // | _mm_unpacklo_epi32 | SSE2*  |
        // | _mm_xor_si128      | SSE2*  |
        // +--------------------+--------+
        //
        // *Although these intrinsics are marked as SSE2 or SSSE3, they have
        // AVX encoded equivalents, and so they are supported with AVX.

        // This function implements the AVX part of the Intel paper entitled:
        // Fast SHA-256 Implementations on Intel Architecture Processors

        /// Do a round of calculations. Caller must swap variables.
        macro_rules! round {
            ($wk:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr
            ) => {
                // Expand and re-order variables to minimize register usage, and
                // minimize dependencies.
                let ch_b = !$e;
                let ch = $e & $f;
                let ch_b = ch_b & $g;
                let ch = ch ^ ch_b;

                // Don't use Intel optimization, because BMI is available.
                let s1 = $e.rotate_right(6);
                let s1_b = $e.rotate_right(11);
                let s1 = s1 ^ s1_b;
                let s1_c = $e.rotate_right(25);
                let s1 = s1 ^ s1_c;

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add($wk);
                let temp1 = temp1.wrapping_add(ch);

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                let maj = $a & $b;
                let maj_b = $a & $c;
                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                // Don't use Intel optimization, because BMI is available.
                let s0 = $a.rotate_right(2);
                let s0_b = $a.rotate_right(13);
                let s0 = s0 ^ s0_b;
                let s0_c = $a.rotate_right(22);
                let s0 = s0 ^ s0_c;

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);
            };
        }

        /** Schedule the next four values across two blocks, and do four rounds
         * of calculations.
         *
         * Caller must swap variables.
         */
        macro_rules! schedule_and_rounds {
            ($kp:expr,
             $wk:expr,
             $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr,
             $w_00_04:expr, $w_04_08:expr, $w_08_12:expr, $w_12_16:expr
            ) => {
                ////////////////////////
                // Round 1.

                    // Pre-compute SHA_256_CONSTANTS.k2[i] + w[i]
                    let k = arch::_mm256_load_si256($kp);
                    $kp = $kp.add(1);

                let ch_b = !$e;
                let ch = $e & $f;

                    let k = arch::_mm256_add_epi32(k, $w_00_04);
                    // TODO(cybojanek): Try to add $w[$round..$round+4] + [h, g, f, e]
                    //                  Maybe _mm256_insert_epi32 as it is updated.

                let ch_b = ch_b & $g;
                let ch = ch ^ ch_b;

                    arch::_mm256_storeu_si256($wk as *mut _, k);

                // Don't use Intel optimization, because BMI is available.
                let s1 = $e.rotate_right(6);
                let s1_b = $e.rotate_right(11);

                    // s0 = w[i-15].ror(7) ^ w[i-15].ror(18) ^ (w[i-15] >> 3)
                    // s0_16_20 minus 15, w_01_05 is needed
                    // Compute w_01_05 by combining registers.
                    let w_01_05 = arch::_mm256_alignr_epi8($w_04_08, $w_00_04, 4);

                let s1 = s1 ^ s1_b;
                let s1_c = $e.rotate_right(25);
                let s1 = s1 ^ s1_c;

                    let w_01_05_ror_7_a = arch::_mm256_srli_epi32(w_01_05, 7);

                let temp1 = $h.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                let temp1 = temp1.wrapping_add(*$wk.add(0));

                // Caller swaps variables.
                $d = $d.wrapping_add(temp1);

                    let w_01_05_ror_7_b = arch::_mm256_slli_epi32(w_01_05, 32 - 7);

                let maj = $a & $b;
                let maj_b = $a & $c;

                    let w_01_05_ror_7 = arch::_mm256_or_si256(w_01_05_ror_7_a, w_01_05_ror_7_b);

                let maj = maj ^ maj_b;
                let maj_c = $b & $c;
                let maj = maj ^ maj_c;

                    let w_01_05_ror_18_a = arch::_mm256_srli_epi32(w_01_05, 18);

                // Don't use Intel optimization, because BMI is available.
                let s0 = $a.rotate_right(2);
                let s0_b = $a.rotate_right(13);

                    let w_01_05_ror_18_b = arch::_mm256_slli_epi32(w_01_05, 32 - 18);

                let s0 = s0 ^ s0_b;
                let s0_c = $a.rotate_right(22);
                let s0 = s0 ^ s0_c;

                    let w_01_05_ror_18 = arch::_mm256_or_si256(w_01_05_ror_18_a, w_01_05_ror_18_b);

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $h = temp1.wrapping_add(temp2);

                ////////////////////////
                // Round 2.

                    let s0_16_20_a = arch::_mm256_xor_si256(w_01_05_ror_7, w_01_05_ror_18);

                let ch_b = !$d;
                let ch = $d & $e;

                    let s0_16_20_b = arch::_mm256_srli_epi32(w_01_05, 3);

                let ch_b = ch_b & $f;
                let ch = ch ^ ch_b;

                    let s0_16_20 = arch::_mm256_xor_si256(s0_16_20_a, s0_16_20_b);

                // Don't use Intel optimization, because BMI is available.
                let s1 = $d.rotate_right(6);
                let s1_b = $d.rotate_right(11);

                    // w[i] = w[i-16] + s0 + w[i-7] + s1
                    // w_16_20 minus 7, w_09_13 is needed.
                    // w_16_20 minus 16, w_00_04 is available.
                    // s0 is available.
                    let w_16_20_minus_s1_minus_w7 = arch::_mm256_add_epi32($w_00_04, s0_16_20);

                let s1 = s1 ^ s1_b;
                let s1_c = $d.rotate_right(25);
                let s1 = s1 ^ s1_c;

                    let w_09_13 = arch::_mm256_alignr_epi8($w_12_16, $w_08_12, 4);

                let temp1 = $g.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                // let temp1 = temp1.wrapping_add(SHA_256_CONSTANTS.k[$round]);
                let temp1 = temp1.wrapping_add(*$wk.add(1));

                // Caller swaps variables.
                $c = $c.wrapping_add(temp1);

                    // Instead of w_16_20_minus_s1, start re-using w_00_04.
                    $w_00_04 = arch::_mm256_add_epi32(w_16_20_minus_s1_minus_w7, w_09_13);

                let maj = $h & $a;
                let maj_b = $h & $b;

                    // s1 = w[i-2].ror(17) ^ w[i-2].ror(19) ^ (w[i-2] >> 10)
                    // w_16_20 minus 2, w_14_18 is needed.
                    // However, that means that w_16_18 needs to be computed, so
                    // compute s1_14_18.
                    // Use optimization from Intel paper, and load w[14] and w[15] as
                    // [15, 15, 14, 14] in order to perform rotation by shifting
                    // across a u64 created from concatenating two u32.
                    let w_1414_1515 = arch::_mm256_unpackhi_epi32($w_12_16, $w_12_16);

                let maj = maj ^ maj_b;
                let maj_c = $a & $b;
                let maj = maj ^ maj_c;

                    let w_14gg_15gg_ror_17 = arch::_mm256_srli_epi64(w_1414_1515, 17);

                // Don't use Intel optimization, because BMI is available.
                let s0 = $h.rotate_right(2);
                let s0_b = $h.rotate_right(13);

                    let w_14gg_15gg_ror_19 = arch::_mm256_srli_epi64(w_1414_1515, 19);

                let s0 = s0 ^ s0_b;
                let s0_c = $h.rotate_right(22);
                let s0 = s0 ^ s0_c;

                    let w_14gg_15gg = arch::_mm256_xor_si256(w_14gg_15gg_ror_17, w_14gg_15gg_ror_19);

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $g = temp1.wrapping_add(temp2);

                ////////////////////////
                // Round 3.

                    // [x, 15', x, 14'] -> [15', 14', x, x]
                    let w_gggg_1415_ror = arch::_mm256_shuffle_epi32(w_14gg_15gg, 0b10000000);

                let ch_b = !$c;
                let ch = $c & $d;

                    let s1_14_18_a = arch::_mm256_srli_epi32($w_12_16, 10);

                let ch_b = ch_b & $e;
                let ch = ch ^ ch_b;

                    // Shift s1_14_18, so that 16_18 are in the lower position to match
                    // their positions in w_16_20_minus_s1.
                    let s1_14_18 = arch::_mm256_xor_si256(w_gggg_1415_ror, s1_14_18_a);

                // Don't use Intel optimization, because BMI is available.
                let s1 = $c.rotate_right(6);
                let s1_b = $c.rotate_right(11);

                    // Compute w_16_20_18, which holds the correct values for w_16_18.
                    let w_16_20_18_a = arch::_mm256_srli_si256(s1_14_18, 8);

                let s1 = s1 ^ s1_b;
                let s1_c = $c.rotate_right(25);
                let s1 = s1 ^ s1_c;

                let temp1 = $f.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                // let temp1 = temp1.wrapping_add(SHA_256_CONSTANTS.k[$round]);
                let temp1 = temp1.wrapping_add(*$wk.add(2));

                // Caller swaps variables.
                $b = $b.wrapping_add(temp1);

                let maj = $g & $h;
                let maj_b = $g & $a;

                    let w_16_20_18 = arch::_mm256_add_epi32($w_00_04, w_16_20_18_a);

                let maj = maj ^ maj_b;
                let maj_c = $h & $a;
                let maj = maj ^ maj_c;

                    // Combine w_12_16 with w_16_20_18 to make w_14_18.
                    let w_14_18 = arch::_mm256_alignr_epi8(w_16_20_18, $w_12_16, 8);

                // Don't use Intel optimization, because BMI is available.
                let s0 = $g.rotate_right(2);
                let s0_b = $g.rotate_right(13);

                    // Use optimization from Intel paper and load w[16], w[17] as
                    // [17, 17, 16, 16] in order to perform rotation by shifting
                    // across a u64 created from concatenating two u32.
                    let w_1616_1717 = arch::_mm256_unpacklo_epi32(w_16_20_18, w_16_20_18);

                let s0 = s0 ^ s0_b;
                let s0_c = $g.rotate_right(22);
                let s0 = s0 ^ s0_c;

                    let w_16gg_17gg_ror_17 = arch::_mm256_srli_epi64(w_1616_1717, 17);

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $f = temp1.wrapping_add(temp2);

                ////////////////////////
                // Round 4.

                    let w_16gg_17gg_ror_19 = arch::_mm256_srli_epi64(w_1616_1717, 19);

                let ch_b = !$b;
                let ch = $b & $c;

                    let w_16gg_17gg = arch::_mm256_xor_si256(w_16gg_17gg_ror_17, w_16gg_17gg_ror_19);

                let ch_b = ch_b & $d;
                let ch = ch ^ ch_b;

                    // [x, 17', x, 16'] -> [x, x, 17', 16']
                    let w_1617_gggg = arch::_mm256_shuffle_epi32(w_16gg_17gg, 0b00001000);

                // Don't use Intel optimization, because BMI is available.
                let s1 = $b.rotate_right(6);
                let s1_b = $b.rotate_right(11);

                    let w_14_18_ror = arch::_mm256_alignr_epi8(w_1617_gggg, w_gggg_1415_ror, 8);

                let s1 = s1 ^ s1_b;
                let s1_c = $b.rotate_right(25);
                let s1 = s1 ^ s1_c;

                    // Compute s1_16_20.
                    let s1_16_20_b = arch::_mm256_srli_epi32(w_14_18, 10);

                let temp1 = $e.wrapping_add(s1);
                let temp1 = temp1.wrapping_add(ch);
                // let temp1 = temp1.wrapping_add(SHA_256_CONSTANTS.k[$round]);
                let temp1 = temp1.wrapping_add(*$wk.add(3));

                // Caller swaps variables.
                $a = $a.wrapping_add(temp1);

                    let s1_16_20 = arch::_mm256_xor_si256(w_14_18_ror, s1_16_20_b);

                let maj = $f & $g;
                let maj_b = $f & $h;

                    // Add s1 to w.
                    $w_00_04 = arch::_mm256_add_epi32($w_00_04, s1_16_20);

                let maj = maj ^ maj_b;
                let maj_c = $g & $h;
                let maj = maj ^ maj_c;

                // Don't use Intel optimization, because BMI is available.
                let s0 = $f.rotate_right(2);
                let s0_b = $f.rotate_right(13);
                let s0 = s0 ^ s0_b;
                let s0_c = $f.rotate_right(22);
                let s0 = s0 ^ s0_c;

                let temp2 = s0.wrapping_add(maj);

                // Caller swaps variables.
                $e = temp1.wrapping_add(temp2);

                $wk = $wk.add(8);

                ////////////////////////
            };
        }

        #[target_feature(enable = "avx,avx2,bmi1,bmi2")]
        unsafe fn update_blocks_avx2_impl(state: &mut [u32], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                #[cfg(target_endian = "little")]
                let shuffle_256 = arch::_mm256_set_epi8(
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                );

                let mut w: [u32; 128] = [0; 128];

                // Initialize local variables.
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                // Iterate two blocks at a time.
                let mut iter = data.chunks_exact(2 * SHA_256_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Initialize w[0..32].
                    let block = block.as_ptr() as *const arch::__m256i;
                    let mut w01 = arch::_mm256_lddqu_si256(block.add(0));
                    let mut w23 = arch::_mm256_lddqu_si256(block.add(1));
                    let mut w45 = arch::_mm256_lddqu_si256(block.add(2));
                    let mut w67 = arch::_mm256_lddqu_si256(block.add(3));

                    #[cfg(target_endian = "little")]
                    {
                        w01 = arch::_mm256_shuffle_epi8(w01, shuffle_256);
                        w23 = arch::_mm256_shuffle_epi8(w23, shuffle_256);
                        w45 = arch::_mm256_shuffle_epi8(w45, shuffle_256);
                        w67 = arch::_mm256_shuffle_epi8(w67, shuffle_256);
                    }

                    // Permute the lanes, so that the scheduling works correctly.
                    let w04 = arch::_mm256_permute2x128_si256(w01, w45, 0b00100000);
                    let w15 = arch::_mm256_permute2x128_si256(w01, w45, 0b00110001);
                    let w26 = arch::_mm256_permute2x128_si256(w23, w67, 0b00100000);
                    let w37 = arch::_mm256_permute2x128_si256(w23, w67, 0b00110001);

                    // Rename for clarity below.
                    let mut w0 = w04;
                    let mut w1 = w15;
                    let mut w2 = w26;
                    let mut w3 = w37;

                    // Use pointer, because blocks scheduled in w are blended.
                    let mut wp = w.as_mut_ptr();
                    let mut kp = SHA_256_CONSTANTS.k2.as_ptr() as *const arch::__m256i;

                    for _ in 0..3 {
                        schedule_and_rounds!(kp, wp, a, b, c, d, e, f, g, h, w0, w1, w2, w3);
                        schedule_and_rounds!(kp, wp, e, f, g, h, a, b, c, d, w1, w2, w3, w0);
                        schedule_and_rounds!(kp, wp, a, b, c, d, e, f, g, h, w2, w3, w0, w1);
                        schedule_and_rounds!(kp, wp, e, f, g, h, a, b, c, d, w3, w0, w1, w2);
                    }

                    let k0 = arch::_mm256_load_si256(kp.add(0));
                    let k0 = arch::_mm256_add_epi32(k0, w0);
                    arch::_mm256_storeu_si256(wp as *mut _, k0);
                    round!(*wp.add(0), a, b, c, d, e, f, g, h);
                    round!(*wp.add(1), h, a, b, c, d, e, f, g);
                    round!(*wp.add(2), g, h, a, b, c, d, e, f);
                    round!(*wp.add(3), f, g, h, a, b, c, d, e);
                    wp = wp.add(8);

                    let k1 = arch::_mm256_load_si256(kp.add(1));
                    let k1 = arch::_mm256_add_epi32(k1, w1);
                    arch::_mm256_storeu_si256(wp as *mut _, k1);
                    round!(*wp.add(0), e, f, g, h, a, b, c, d);
                    round!(*wp.add(1), d, e, f, g, h, a, b, c);
                    round!(*wp.add(2), c, d, e, f, g, h, a, b);
                    round!(*wp.add(3), b, c, d, e, f, g, h, a);
                    wp = wp.add(8);

                    let k2 = arch::_mm256_load_si256(kp.add(2));
                    let k2 = arch::_mm256_add_epi32(k2, w2);
                    arch::_mm256_storeu_si256(wp as *mut _, k2);
                    round!(*wp.add(0), a, b, c, d, e, f, g, h);
                    round!(*wp.add(1), h, a, b, c, d, e, f, g);
                    round!(*wp.add(2), g, h, a, b, c, d, e, f);
                    round!(*wp.add(3), f, g, h, a, b, c, d, e);
                    wp = wp.add(8);

                    let k3 = arch::_mm256_load_si256(kp.add(3));
                    let k3 = arch::_mm256_add_epi32(k3, w3);
                    arch::_mm256_storeu_si256(wp as *mut _, k3);
                    round!(*wp.add(0), e, f, g, h, a, b, c, d);
                    round!(*wp.add(1), d, e, f, g, h, a, b, c);
                    round!(*wp.add(2), c, d, e, f, g, h, a, b);
                    round!(*wp.add(3), b, c, d, e, f, g, h, a);

                    a = a.wrapping_add(state[0]);
                    b = b.wrapping_add(state[1]);
                    c = c.wrapping_add(state[2]);
                    d = d.wrapping_add(state[3]);
                    e = e.wrapping_add(state[4]);
                    f = f.wrapping_add(state[5]);
                    g = g.wrapping_add(state[6]);
                    h = h.wrapping_add(state[7]);

                    state[0] = a;
                    state[1] = b;
                    state[2] = c;
                    state[3] = d;
                    state[4] = e;
                    state[5] = f;
                    state[6] = g;
                    state[7] = h;

                    // Skip w0 and jump to w4 from w04 result.
                    let mut wp = w.as_mut_ptr().add(4);

                    for _ in 0..8 {
                        round!(*wp.add(0), a, b, c, d, e, f, g, h);
                        round!(*wp.add(1), h, a, b, c, d, e, f, g);
                        round!(*wp.add(2), g, h, a, b, c, d, e, f);
                        round!(*wp.add(3), f, g, h, a, b, c, d, e);
                        wp = wp.add(8);
                        round!(*wp.add(0), e, f, g, h, a, b, c, d);
                        round!(*wp.add(1), d, e, f, g, h, a, b, c);
                        round!(*wp.add(2), c, d, e, f, g, h, a, b);
                        round!(*wp.add(3), b, c, d, e, f, g, h, a);
                        wp = wp.add(8);
                    }

                    a = a.wrapping_add(state[0]);
                    b = b.wrapping_add(state[1]);
                    c = c.wrapping_add(state[2]);
                    d = d.wrapping_add(state[3]);
                    e = e.wrapping_add(state[4]);
                    f = f.wrapping_add(state[5]);
                    g = g.wrapping_add(state[6]);
                    h = h.wrapping_add(state[7]);

                    state[0] = a;
                    state[1] = b;
                    state[2] = c;
                    state[3] = d;
                    state[4] = e;
                    state[5] = f;
                    state[6] = g;
                    state[7] = h;
                }

                // Gracefully handle the last block.
                let remainder = iter.remainder();
                if remainder.len() > 0 {
                    Sha256::update_blocks_avx(state, remainder);
                }
            }
        }

        unsafe { update_blocks_avx2_impl(state, data) }
    }

    #[cfg(all(
        feature = "sha256-sha",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sha(state: &mut [u32], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+-------+
        // | _mm_add_epi32         | SSE2  |
        // | _mm_alignr_epi8       | SSSE3 |
        // | _mm_lddqu_si128       | SSE3  |
        // | _mm_load_si128        | SSE2  |
        // | _mm_set_epi8          | SSE2  |
        // | _mm_sha256msg1_epu32  | SHA   |
        // | _mm_sha256msg2_epu32  | SHA   |
        // | _mm_sha256rnds2_epu32 | SHA   |
        // | _mm_shuffle_epi32     | SSE2  |
        // | _mm_shuffle_epi8      | SSSE3 |
        // | _mm_storeu_si128      | SSE2  |
        // | _mm_unpackhi_epi64    | SSE2  |
        // | _mm_unpacklo_epi64    | SSE2  |
        // +-----------------------+-------+

        macro_rules! SHA_256_K_M128I {
            () => {
                SHA_256_CONSTANTS.k.as_ptr() as *const arch::__m128i
            };
        }

        // This function implements SHA according to the Intel paper entitled:
        // Intel SHA Extensions - New Instructions Supporting the Secure Hashing
        // Algorithm on Intel Architecture Processors

        #[target_feature(enable = "sse2,sse3,ssse3,sha")]
        unsafe fn update_blocks_sha_impl(state: &mut [u32], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                #[cfg(target_endian = "little")]
                let shuffle = arch::_mm_set_epi8(
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                );

                // Load the saved state.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut abcd = arch::_mm_lddqu_si128(state.add(0));
                let mut efgh = arch::_mm_lddqu_si128(state.add(1));

                // Mix the registers for usage with _mm_sha256rnds2_epu32.
                let mut sha_abef = arch::_mm_unpacklo_epi64(abcd, efgh);
                let mut sha_cdgh = arch::_mm_unpackhi_epi64(abcd, efgh);

                // The register has values a, b, c, and, d, but they look like:
                // abef[0..32] = a, abef[32..64] = b
                // abef[64..96] = e, abef[96..128] = f
                // However, they need to be re-arranged for _mm_sha256rnds2_epu32:
                // abef[0..32] = f, abef[32..64] = e
                // abef[64..96] = b, abef[96..128] = a
                sha_abef = arch::_mm_shuffle_epi32(sha_abef, 0b00011011);
                sha_cdgh = arch::_mm_shuffle_epi32(sha_cdgh, 0b00011011);

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(SHA_256_BLOCK_SIZE);

                for block in iter.by_ref() {
                    let block = block.as_ptr() as *const arch::__m128i;

                    let mut abef = sha_abef;
                    let mut cdgh = sha_cdgh;

                    ////////////////////
                    // Rounds 0 to 4.

                    // Initialize w[0..4].
                    let mut w_00_04 = arch::_mm_lddqu_si128(block.add(0));
                    #[cfg(target_endian = "little")]
                    {
                        w_00_04 = arch::_mm_shuffle_epi8(w_00_04, shuffle);
                    }

                    // Initialize k[0..4].
                    let k_00_04 = arch::_mm_load_si128(SHA_256_K_M128I!().add(0));

                    // Initialize wk[0..4].
                    let wk_00_04 = arch::_mm_add_epi32(w_00_04, k_00_04);

                    // Do two rounds using wk[0..2].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_00_04);

                    // Move wk[2..4] down to the lower bits.
                    let wk_00_04_b = arch::_mm_shuffle_epi32(wk_00_04, 0b00001110);

                    // Do two rounds using m[2..4].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_00_04_b);

                    ////////////////////
                    // Rounds 4 to 8.

                    // Initialize w[0..4].
                    let mut w_04_08 = arch::_mm_lddqu_si128(block.add(1));
                    #[cfg(target_endian = "little")]
                    {
                        w_04_08 = arch::_mm_shuffle_epi8(w_04_08, shuffle);
                    }

                    // Initialize k[4..8].
                    let k_04_08 = arch::_mm_load_si128(SHA_256_K_M128I!().add(1));

                    // Initialize wk[4..8].
                    let wk_04_08 = arch::_mm_add_epi32(w_04_08, k_04_08);

                    // Do two rounds using wk[4..6].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_04_08);

                    // Move wk[6..8] down to the lower bits.
                    let wk_04_08_b = arch::_mm_shuffle_epi32(wk_04_08, 0b00001110);

                    // Do two rounds using wk[6..8].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_04_08_b);

                    // Compute intermediate calculation for w16 to w20.
                    // w[0..4] + w[4..] => x[0..4].
                    let x_00_04 = arch::_mm_sha256msg1_epu32(w_00_04, w_04_08);

                    ////////////////////
                    // Rounds 8 to 12.

                    // Initialize w[8..12].
                    let mut w_08_12 = arch::_mm_lddqu_si128(block.add(2));
                    #[cfg(target_endian = "little")]
                    {
                        w_08_12 = arch::_mm_shuffle_epi8(w_08_12, shuffle);
                    }

                    // Initialize k[8..12].
                    let k_08_12 = arch::_mm_load_si128(SHA_256_K_M128I!().add(2));

                    // Initialize wk[8..12].
                    let wk_08_12 = arch::_mm_add_epi32(w_08_12, k_08_12);

                    // Do two rounds using wk[8..10].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_08_12);

                    // Move wk[10..12] down to the lower bits.
                    let wk_08_12_b = arch::_mm_shuffle_epi32(wk_08_12, 0b00001110);

                    // Do two rounds using wk[10..12].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_08_12_b);

                    // Compute intermediate calculation for w20 to w24.
                    // w[4..8] + w[8..] => x[4..8].
                    let x_04_08 = arch::_mm_sha256msg1_epu32(w_04_08, w_08_12);

                    ////////////////////
                    // Rounds 12 to 16.

                    // Initialize w[12..16].
                    let mut w_12_16 = arch::_mm_lddqu_si128(block.add(3));
                    #[cfg(target_endian = "little")]
                    {
                        w_12_16 = arch::_mm_shuffle_epi8(w_12_16, shuffle);
                    }

                    // Initialize k[12..16].
                    let k_12_16 = arch::_mm_load_si128(SHA_256_K_M128I!().add(3));

                    // Initialize wk[12..16].
                    let wk_12_16 = arch::_mm_add_epi32(w_12_16, k_12_16);

                    // Do two rounds using wk[12..14].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_12_16);

                    // sha256msg2 requires that w[-7] be added by the caller.
                    // For w_16_20, w_09_13 is needed.
                    let w_09_13 = arch::_mm_alignr_epi8(w_12_16, w_08_12, 4);
                    let z_00_04 = arch::_mm_add_epi32(x_00_04, w_09_13);
                    let w_16_20 = arch::_mm_sha256msg2_epu32(z_00_04, w_12_16);

                    // Move wk[14..16] down to the lower bits.
                    let wk_12_16_b = arch::_mm_shuffle_epi32(wk_12_16, 0b00001110);

                    // Do two rounds using wk[14..16].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_12_16_b);

                    // Compute intermediate calculation for w24 to w28.
                    // w[8..12] + w[12..] => x[8..12].
                    let x_08_12 = arch::_mm_sha256msg1_epu32(w_08_12, w_12_16);

                    ////////////////////
                    // Rounds 16 to 52.
                    let mut rounds = 16;

                    let mut w_12_16 = w_12_16;
                    let mut w_16_20 = w_16_20;
                    let mut x_04_08 = x_04_08;
                    let mut x_08_12 = x_08_12;

                    while rounds < 52 {
                        // Initialize k[16..20].
                        let k_16_20 = arch::_mm_lddqu_si128(
                            SHA_256_CONSTANTS.k[rounds..].as_ptr() as *const _
                        );

                        // Initialize wk[16..20].
                        let wk_16_20 = arch::_mm_add_epi32(w_16_20, k_16_20);

                        // Do two rounds using wk[16..18].
                        cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_16_20);

                        // sha256msg2 requires that w[-7] be added by the caller.
                        // For w_20_24, w_13_17 is needed.
                        let w_13_17 = arch::_mm_alignr_epi8(w_16_20, w_12_16, 4);
                        let z_04_08 = arch::_mm_add_epi32(x_04_08, w_13_17);
                        let w_20_24 = arch::_mm_sha256msg2_epu32(z_04_08, w_16_20);

                        // Move wk[18..20] down to the lower bits.
                        let wk_16_20_b = arch::_mm_shuffle_epi32(wk_16_20, 0b00001110);

                        // Do two rounds using wk[18..20].
                        abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_16_20_b);

                        // Compute intermediate calculation for w24 to w28.
                        // w[12..16] + w[17..] => x[12..16].
                        let x_12_16 = arch::_mm_sha256msg1_epu32(w_12_16, w_16_20);

                        rounds += 4;

                        // Advance variables.
                        w_12_16 = w_16_20;
                        w_16_20 = w_20_24;
                        x_04_08 = x_08_12;
                        x_08_12 = x_12_16;
                    }

                    ////////////////////
                    // Rename for clarity.
                    let w_48_52 = w_12_16;
                    let w_52_56 = w_16_20;
                    let x_40_44 = x_04_08;
                    let x_44_48 = x_08_12;

                    ////////////////////
                    // Rounds 52 to 56.

                    // Initialize k[52..56].
                    let k_52_56 = arch::_mm_lddqu_si128(SHA_256_K_M128I!().add(13));

                    // Initialize wk[52..56].
                    let wk_52_56 = arch::_mm_add_epi32(w_52_56, k_52_56);

                    // Do two rounds using wk[52..54].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_52_56);

                    // sha256msg2 requires that w[-7] be added by the caller.
                    // For w_56_60, w_49_53 is needed.
                    let w_49_53 = arch::_mm_alignr_epi8(w_52_56, w_48_52, 4);
                    let z_40_44 = arch::_mm_add_epi32(x_40_44, w_49_53);
                    let w_56_60 = arch::_mm_sha256msg2_epu32(z_40_44, w_52_56);

                    // Move wk[54..56] down to the lower bits.
                    let wk_52_56_b = arch::_mm_shuffle_epi32(wk_52_56, 0b00001110);

                    // Do two rounds using wk[54..56].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_52_56_b);

                    ////////////////////
                    // Rounds 56 to 60.

                    // Initialize k[56..60].
                    let k_56_60 = arch::_mm_lddqu_si128(SHA_256_K_M128I!().add(14));

                    // Initialize wk[56..60].
                    let wk_56_60 = arch::_mm_add_epi32(w_56_60, k_56_60);

                    // Do two rounds using wk[56..58].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_56_60);

                    // sha256msg2 requires that w[-7] be added by the caller.
                    // For w_60_64, w_53_61 is needed.
                    let w_53_57 = arch::_mm_alignr_epi8(w_56_60, w_52_56, 4);
                    let z_44_48 = arch::_mm_add_epi32(x_44_48, w_53_57);
                    let w_60_64 = arch::_mm_sha256msg2_epu32(z_44_48, w_56_60);

                    // Move wk[58..60] down to the lower bits.
                    let wk_56_60_b = arch::_mm_shuffle_epi32(wk_56_60, 0b00001110);

                    // Do two rounds using wk[58..60].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_56_60_b);

                    ////////////////////
                    // Rounds 60 to 64.

                    // Initialize k[60..64].
                    let k_60_64 = arch::_mm_lddqu_si128(SHA_256_K_M128I!().add(15));

                    // Initialize wk[60..64].
                    let wk_60_64 = arch::_mm_add_epi32(w_60_64, k_60_64);

                    // Do two rounds using wk[60..62].
                    cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, wk_60_64);

                    // Move wk[62..64] down to the lower bits.
                    let wk_60_64_b = arch::_mm_shuffle_epi32(wk_60_64, 0b00001110);

                    // Do two rounds using wk[62..64].
                    abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, wk_60_64_b);

                    ////////////////////
                    // Done.
                    sha_abef = arch::_mm_add_epi32(sha_abef, abef);
                    sha_cdgh = arch::_mm_add_epi32(sha_cdgh, cdgh);
                }

                sha_abef = arch::_mm_shuffle_epi32(sha_abef, 0b00011011);
                sha_cdgh = arch::_mm_shuffle_epi32(sha_cdgh, 0b00011011);

                // Unpack the registers for the state.
                abcd = arch::_mm_unpacklo_epi64(sha_abef, sha_cdgh);
                efgh = arch::_mm_unpackhi_epi64(sha_abef, sha_cdgh);

                // Save the state.
                arch::_mm_storeu_si128(state.add(0), abcd);
                arch::_mm_storeu_si128(state.add(1), efgh);
            }
        }

        unsafe { update_blocks_sha_impl(state, data) }
    }
}

impl Checksum for Sha256 {
    fn reset(&mut self, _order: EndianOrder) -> Result<(), ChecksumError> {
        self.bytes_processed = 0;
        self.buffer = [0; SHA_256_BLOCK_SIZE];
        self.buffer_fill = 0;
        self.state = SHA_256_CONSTANTS.h;

        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<(), ChecksumError> {
        // Make data pointer mutable, in case of self.buffer_fill.
        let mut data = data;

        // If block has some data, fill that up first.
        if self.buffer_fill > 0 {
            // Todo is minimum of block fill needed, and input data.
            let todo = cmp::min(SHA_256_BLOCK_SIZE - self.buffer_fill, data.len());

            // Copy to block.
            self.buffer[self.buffer_fill..self.buffer_fill + todo].copy_from_slice(&data[0..todo]);
            self.buffer_fill += todo;

            // Update data to skip copied block.
            data = &data[todo..];

            // If block is full, consume it.
            if self.buffer_fill == SHA_256_BLOCK_SIZE {
                let full_blocks_data = &self.buffer[0..self.buffer_fill];
                self.bytes_processed += SHA_256_BLOCK_SIZE as u64;
                (self.impl_ctx.update_blocks)(&mut self.state, &full_blocks_data);
                self.buffer_fill = 0;
            }
        }

        // Calculate remainder.
        let remainder = data.len() % SHA_256_BLOCK_SIZE;

        // Update full blocks.
        let full_blocks_data = &data[0..data.len() - remainder];
        self.bytes_processed += full_blocks_data.len() as u64;
        (self.impl_ctx.update_blocks)(&mut self.state, &full_blocks_data);

        // Check if remainder exists, to prevent clobbering fill with 0.
        if remainder > 0 {
            self.buffer[0..remainder].copy_from_slice(&data[data.len() - remainder..]);
            self.buffer_fill = remainder;
        }

        // Success.
        Ok(())
    }

    fn finalize(&mut self) -> Result<[u64; 4], ChecksumError> {
        let byte_length = self.bytes_processed + (self.buffer_fill as u64);
        let bit_length = byte_length * 8;

        // If last block does not have enough space for 64 bits (1 bit + 64 bit length),
        // then pad it out with zeroes.
        if self.buffer_fill > SHA_256_BLOCK_SIZE - 9 {
            while self.buffer_fill < SHA_256_BLOCK_SIZE {
                self.buffer[self.buffer_fill] = 0;
                self.buffer_fill += 1;
            }
            self.buffer_fill = 0;

            let data = &self.buffer[0..SHA_256_BLOCK_SIZE];
            (self.impl_ctx.update_blocks)(&mut self.state, &data);
        }

        // Set the 1 bit.
        self.buffer[self.buffer_fill] = 0x80;
        self.buffer_fill += 1;

        // Set zero bits until 64 bits are remaining.
        while self.buffer_fill < SHA_256_BLOCK_SIZE - 8 {
            self.buffer[self.buffer_fill] = 0;
            self.buffer_fill += 1;
        }

        // Encode length in bits.
        self.buffer[SHA_256_BLOCK_SIZE - 8..SHA_256_BLOCK_SIZE]
            .copy_from_slice(&u64::to_be_bytes(bit_length));

        // Process last block.
        let data = &self.buffer[0..SHA_256_BLOCK_SIZE];
        (self.impl_ctx.update_blocks)(&mut self.state, &data);

        // Encode result to u64.
        Ok([
            (u64::from(self.state[0]) << 32) | u64::from(self.state[1]),
            (u64::from(self.state[2]) << 32) | u64::from(self.state[3]),
            (u64::from(self.state[4]) << 32) | u64::from(self.state[5]),
            (u64::from(self.state[6]) << 32) | u64::from(self.state[7]),
        ])
    }

    fn hash(&mut self, data: &[u8], order: EndianOrder) -> Result<[u64; 4], ChecksumError> {
        self.reset(order)?;
        self.update(data)?;
        self.finalize()
    }
}

#[cfg(test)]
mod tests {

    use core::cmp;

    use crate::checksum::{Checksum, ChecksumError, Sha256, Sha256Implementation};
    use crate::phys::EndianOrder;

    /** 128 byte random data.
     *
     * Refer to `docs/SHA.md` for script to generate test cases.
     */
    const TEST_VECTOR_A: [u8; 128] = [
        0xbc, 0x4b, 0x4d, 0x58, 0x43, 0xca, 0x34, 0x35, 0xe4, 0xd0, 0x59, 0xe4, 0xd0, 0x2b, 0x08,
        0xe3, 0x2f, 0xe3, 0x78, 0xe1, 0xe6, 0xf6, 0xf1, 0x34, 0x84, 0xdc, 0x1e, 0x0e, 0x12, 0x28,
        0x2e, 0xbe, 0x53, 0xbd, 0x1a, 0xf9, 0x8a, 0x97, 0x6e, 0xab, 0x7c, 0x06, 0xed, 0x50, 0xa8,
        0xc9, 0xe4, 0x1e, 0xb8, 0xaf, 0xb8, 0x8c, 0x94, 0xb5, 0x15, 0xed, 0xa8, 0x3f, 0x9d, 0x99,
        0x9c, 0x26, 0xe8, 0x1d, 0x87, 0x29, 0x1f, 0x60, 0x64, 0xca, 0xd1, 0xe8, 0x48, 0x7e, 0xe4,
        0xf2, 0x56, 0xf3, 0x59, 0x73, 0x04, 0x39, 0xb2, 0x62, 0x56, 0xea, 0xf1, 0x44, 0xf0, 0x06,
        0x28, 0x2e, 0x56, 0x16, 0xd3, 0x80, 0x0d, 0x47, 0x9e, 0x87, 0x3f, 0x52, 0x64, 0x30, 0x63,
        0x6d, 0x64, 0x58, 0xcb, 0x84, 0x4d, 0xf7, 0x1c, 0x6e, 0xc7, 0x07, 0x86, 0x3d, 0x17, 0xec,
        0x51, 0x8f, 0x51, 0x6e, 0x5a, 0x52, 0x64, 0xee,
    ];

    const TEST_VECTOR_A_CHECKSUMS: [(usize, [u64; 4]); 18] = [
        (
            0,
            [
                0xe3b0c44298fc1c14,
                0x9afbf4c8996fb924,
                0x27ae41e4649b934c,
                0xa495991b7852b855,
            ],
        ),
        (
            4,
            [
                0xda019b87bf8be659,
                0xf7fa90d87f798019,
                0x9c7bffb4d9d444c6,
                0x8a47533668a06a90,
            ],
        ),
        (
            8,
            [
                0xe99cd08bed3a67a4,
                0x5a35c1f646a3f86a,
                0x4888b4653a1736f0,
                0x40fef5f5da13ddf,
            ],
        ),
        (
            16,
            [
                0x4be87f81e1fca9da,
                0xf953ba24b2a27c5a,
                0xabbcb894af3318ca,
                0x32906d4716ae9a13,
            ],
        ),
        (
            32,
            [
                0x2f8c0e910326bb24,
                0x2290ed41ba68906a,
                0x6d10b5ff223d83df,
                0xfa1ac3a22ba58fa7,
            ],
        ),
        (
            64,
            [
                0xca2eeb504c79cb1,
                0x650ab12fc6c6edf0,
                0xbece423778da778b,
                0x175ca34ac9c24394,
            ],
        ),
        (
            128,
            [
                0xb5cf520a264dcaad,
                0xb33b2e7c4df5707d,
                0xaa9e6391019591cb,
                0x17c5c99a2e286f5e,
            ],
        ),
        (
            192,
            [
                0x664ea09482cea9f1,
                0xdc2e94d3f0ef9d51,
                0xe4030861b7a7c8b0,
                0xe9815db97948f2b7,
            ],
        ),
        (
            256,
            [
                0xbb405f88f5d22e6f,
                0x9476b31032f22587,
                0xf26c9fd634147142,
                0x5473a62267c34544,
            ],
        ),
        (
            320,
            [
                0x5cc93876edc2b41f,
                0x63dbff9c94f48fde,
                0x1012d2a836fbec7f,
                0x16f367ea91fc3586,
            ],
        ),
        (
            384,
            [
                0xdbe0128073612eed,
                0x1594bbb754c1e6f6,
                0x475152f605ff20e6,
                0xdd275962019c7142,
            ],
        ),
        (
            448,
            [
                0xd4f5cdeffa8126df,
                0x34a0ec5d0f5c382a,
                0x25ac0a260f7546ac,
                0x633516089f5dab40,
            ],
        ),
        (
            512,
            [
                0xaa06ece5c7953723,
                0xcac3295602cf526f,
                0xff7164b53ee2c05f,
                0x3c6be20ca03266cb,
            ],
        ),
        (
            8192,
            [
                0xc75a875bcb35e5f,
                0xa4fb74395c534e04,
                0x49ed5650ecf7c098,
                0x1946cc77b593a752,
            ],
        ),
        (
            16384,
            [
                0x9f76e90af5855d,
                0xa0a6dd02829f80a7,
                0x2274c050a6b0a1ef,
                0x467f72641047f79c,
            ],
        ),
        (
            32768,
            [
                0x6ea4d00ee61ef695,
                0x415750783a6491a,
                0x6b1772f2b198490,
                0xa3d770f01bc06b3d,
            ],
        ),
        (
            65536,
            [
                0x48435f04bde402d9,
                0xf0e3dce47ce5c7b3,
                0x21eef153a54ce209,
                0xd8feeaf674f5e656,
            ],
        ),
        (
            131072,
            [
                0x44ed406c57235711,
                0x26139eecf28a980d,
                0xd53ccbb3ba6b7231,
                0x7c9c728b45736992,
            ],
        ),
    ];

    fn run_test_vector(
        h: &mut Sha256,
        order: EndianOrder,
        vector: &[u8],
        checksums: &[(usize, [u64; 4])],
    ) -> Result<(), ChecksumError> {
        // Test sizes.
        for (size, checksum) in checksums {
            let size = *size;
            let checksum = *checksum;

            if size <= vector.len() {
                // Single update call.
                assert_eq!(h.hash(&vector[0..size], order)?, checksum, "size {}", size);

                // Partial update.
                h.reset(order)?;
                let mut offset = 0;

                h.update(&vector[0..size / 3])?;
                offset += size / 3;

                h.update(&vector[offset..offset + size / 3])?;
                offset += size / 3;

                h.update(&vector[offset..size])?;

                assert_eq!(h.finalize()?, checksum);
            } else {
                // Multiple calls.
                let mut todo = size;
                h.reset(order)?;

                while todo > 0 {
                    let can_do = cmp::min(todo, vector.len());
                    h.update(&vector[0..can_do])?;
                    todo -= can_do;
                }

                assert_eq!(h.finalize()?, checksum, "size {}", size);
            }
        }

        Ok(())
    }

    fn test_required_implementation(
        implementation: Sha256Implementation,
    ) -> Result<(), ChecksumError> {
        let mut h = Sha256::new(implementation)?;

        run_test_vector(
            &mut h,
            EndianOrder::Big,
            &TEST_VECTOR_A,
            &TEST_VECTOR_A_CHECKSUMS,
        )?;

        run_test_vector(
            &mut h,
            EndianOrder::Little,
            &TEST_VECTOR_A,
            &TEST_VECTOR_A_CHECKSUMS,
        )?;

        Ok(())
    }

    fn test_optional_implementation(
        implementation: Sha256Implementation,
    ) -> Result<(), ChecksumError> {
        let supported = match Sha256::new(implementation) {
            _e @ Err(ChecksumError::Unsupported {
                checksum: _,
                implementation: _,
            }) => false,
            _ => true,
        };

        match supported {
            false => Ok(()),
            true => test_required_implementation(implementation),
        }
    }

    #[test]
    fn sha256_generic() -> Result<(), ChecksumError> {
        test_required_implementation(Sha256Implementation::Generic)
    }

    #[test]
    fn sha256_bmi() -> Result<(), ChecksumError> {
        test_optional_implementation(Sha256Implementation::BMI)
    }

    #[test]
    fn sha256_ssse3() -> Result<(), ChecksumError> {
        test_optional_implementation(Sha256Implementation::SSSE3)
    }

    #[test]
    fn sha256_avx() -> Result<(), ChecksumError> {
        test_optional_implementation(Sha256Implementation::AVX)
    }

    #[test]
    fn sha256_avx2() -> Result<(), ChecksumError> {
        test_optional_implementation(Sha256Implementation::AVX2)
    }

    #[test]
    fn sha256_sha() -> Result<(), ChecksumError> {
        test_optional_implementation(Sha256Implementation::SHA)
    }
}
