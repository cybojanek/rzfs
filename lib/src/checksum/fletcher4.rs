// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::checksum::{Checksum, ChecksumError};
use crate::phys::{ChecksumType, EndianOrder};

use core::cmp;
use core::fmt;
use core::fmt::Display;

#[cfg(all(
    target_arch = "x86",
    any(
        feature = "fletcher4-sse2",
        feature = "fletcher4-ssse3",
        feature = "fletcher4-avx2",
        feature = "fletcher4-avx512f",
        feature = "fletcher4-avx512bw",
    ),
))]
use core::arch::x86 as arch;

#[cfg(all(
    target_arch = "x86_64",
    any(
        feature = "fletcher4-sse2",
        feature = "fletcher4-ssse3",
        feature = "fletcher4-avx2",
        feature = "fletcher4-avx512f",
        feature = "fletcher4-avx512bw",
    ),
))]
use core::arch::x86_64 as arch;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher4-sse2", feature = "fletcher4-ssse3",),
))]
use crate::arch::x86_any::is_sse2_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher4-ssse3",
))]
use crate::arch::x86_any::is_ssse3_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher4-avx2",
))]
use crate::arch::x86_any::{is_avx2_supported, is_avx_supported};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher4-avx512f", feature = "fletcher4-avx512bw"),
))]
use crate::arch::x86_any::is_avx512f_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher4-avx512bw",
))]
use crate::arch::x86_any::is_avx512bw_supported;

////////////////////////////////////////////////////////////////////////////////

/// Fletcher4 block size in bytes.
const FLETCHER_4_BLOCK_SIZE: usize = 4;

/// Fletcher4 in u64.
const FLETCHER_4_U64_COUNT: usize = 4;

/// Fletcher4 maximum SIMD width.
const FLETCHER_4_MAX_SIMD_WIDTH: usize = 8;

/// Fletcher4 implementation.
#[derive(Copy, Clone, Debug)]
pub enum Fletcher4Implementation {
    /// Generic.
    Generic,

    /// Superscalar using two streams.
    SuperScalar2,

    /// Superscalar using four streams.
    SuperScalar4,

    /// SSE2 128 bit SIMD.
    SSE2,

    /// SSSE3 128 bit SIMD.
    SSSE3,

    /// AVX2 256 bit SIMD.
    AVX2,

    /// AVX512F 512 bit SIMD.
    AVX512F,

    /// AVX512BW 512 bit SIMD.
    AVX512BW,
}

const ALL_FLETCHER_4_IMPLEMENTATIONS: [Fletcher4Implementation; 8] = [
    Fletcher4Implementation::Generic,
    Fletcher4Implementation::SuperScalar2,
    Fletcher4Implementation::SuperScalar4,
    Fletcher4Implementation::SSE2,
    Fletcher4Implementation::SSSE3,
    Fletcher4Implementation::AVX2,
    Fletcher4Implementation::AVX512F,
    Fletcher4Implementation::AVX512BW,
];

impl Fletcher4Implementation {
    /** Get a slice with all of the [`Fletcher4Implementation`].
     *
     * Runtime support depends on CPU. Calling [`Fletcher4::new`] might still
     * fail with [`ChecksumError::Unsupported`].
     */
    pub fn all() -> &'static [Fletcher4Implementation] {
        &ALL_FLETCHER_4_IMPLEMENTATIONS
    }

    /** Is the implementation supported.
     */
    pub fn is_supported(&self) -> bool {
        match self {
            Fletcher4Implementation::Generic => true,
            Fletcher4Implementation::SuperScalar2 => true,
            Fletcher4Implementation::SuperScalar4 => true,

            #[cfg(feature = "fletcher4-sse2")]
            Fletcher4Implementation::SSE2 => is_sse2_supported(),

            #[cfg(feature = "fletcher4-ssse3")]
            Fletcher4Implementation::SSSE3 => is_sse2_supported() && is_ssse3_supported(),

            #[cfg(feature = "fletcher4-avx2")]
            Fletcher4Implementation::AVX2 => is_avx_supported() && is_avx2_supported(),

            #[cfg(feature = "fletcher4-avx512f")]
            Fletcher4Implementation::AVX512F => is_avx512f_supported(),

            #[cfg(feature = "fletcher4-avx512bw")]
            Fletcher4Implementation::AVX512BW => is_avx512f_supported() && is_avx512bw_supported(),

            #[cfg(any(
                not(feature = "fletcher4-sse2"),
                not(feature = "fletcher4-ssse3"),
                not(feature = "fletcher4-avx2"),
                not(feature = "fletcher4-avx512f"),
                not(feature = "fletcher4-avx512bw"),
            ))]
            _ => false,
        }
    }

    /// Get the string name of the implementation.
    pub fn to_str(&self) -> &'static str {
        match self {
            Fletcher4Implementation::Generic => "generic",
            Fletcher4Implementation::SuperScalar2 => "superscalar2",
            Fletcher4Implementation::SuperScalar4 => "superscalar4",
            Fletcher4Implementation::SSE2 => "sse2",
            Fletcher4Implementation::SSSE3 => "ssse3",
            Fletcher4Implementation::AVX2 => "avx2",
            Fletcher4Implementation::AVX512F => "avx512f",
            Fletcher4Implementation::AVX512BW => "avx512bw",
        }
    }
}

impl Display for Fletcher4Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            _ => write!(f, "{}", self.to_str()),
        }
    }
}

/// Update state. Data length is a multiple of the implementation's block size.
type Fletcher4UpdateBlock = fn(state: &mut [u64], data: &[u8]);

/// Compute the final hash from multiple streams.
type Fletcher4FinishBlocks = fn(state: &[u64]) -> [u64; FLETCHER_4_U64_COUNT];

/// Fletcher4 implementation context.
struct Fletcher4ImplementationCtx {
    /// A multiple of [`FLETCHER_4_BLOCK_SIZE`].
    block_size: usize,

    /// Implementation of [`Fletcher4UpdateBlock`].
    update_blocks: Fletcher4UpdateBlock,

    /// Implementation of [`Fletcher4FinishBlocks`].
    finish_blocks: Fletcher4FinishBlocks,
}

/// [`crate::phys::ChecksumType::Fletcher4`] implementation.
pub struct Fletcher4 {
    /// Number of bytes used in [`Fletcher4::buffer`].
    buffer_fill: usize,

    /// Partial block buffer.
    buffer: [u8; FLETCHER_4_BLOCK_SIZE * FLETCHER_4_MAX_SIMD_WIDTH],

    /// Ongoing checksum.
    state: [u64; FLETCHER_4_U64_COUNT * FLETCHER_4_MAX_SIMD_WIDTH],

    /// Byte order of input data.
    order: EndianOrder,

    /// Implementation context.
    impl_ctx: Fletcher4ImplementationCtx,
}

/** Sum v and then multiply by m.
 *
 * ```text
 * (v[0] + v[1] + ...) * m
 * ```
 */
fn sum_and_mul(v: &[u64], m: u64) -> u64 {
    let mut r: u64 = 0;

    for i in v.iter() {
        r = r.wrapping_add(*i);
    }

    r.wrapping_mul(m)
}

/** Sum of each element in v multiplied by its corresponding m.
 *
 * ```text
 * (v[0] * m[0]) + (v[1] + m[1]) + ...
 * ```
 */
fn mul_and_sum(v: &[u64], m: &[u16]) -> u64 {
    let mut r: u64 = 0;

    for i in 0..v.len() {
        r = r.wrapping_add(v[i].wrapping_mul(m[i].into()));
    }

    r
}

impl Fletcher4ImplementationCtx {
    fn new(
        order: EndianOrder,
        implementation: Fletcher4Implementation,
    ) -> Result<Fletcher4ImplementationCtx, ChecksumError> {
        if !implementation.is_supported() {
            return Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Fletcher4,
                order,
                implementation: implementation.to_str(),
            });
        }

        match implementation {
            Fletcher4Implementation::Generic => Ok(Fletcher4ImplementationCtx {
                block_size: FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher4::update_blocks_generic_big,
                    EndianOrder::Little => Fletcher4::update_blocks_generic_little,
                },
                finish_blocks: Fletcher4::finish_blocks_single_stream,
            }),

            Fletcher4Implementation::SuperScalar2 => Ok(Fletcher4ImplementationCtx {
                block_size: 2 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher4::update_blocks_superscalar2_big,
                    EndianOrder::Little => Fletcher4::update_blocks_superscalar2_little,
                },
                finish_blocks: Fletcher4::finish_blocks_dual_stream,
            }),

            Fletcher4Implementation::SuperScalar4 => Ok(Fletcher4ImplementationCtx {
                block_size: 4 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher4::update_blocks_superscalar4_big,
                    EndianOrder::Little => Fletcher4::update_blocks_superscalar4_little,
                },
                finish_blocks: Fletcher4::finish_blocks_quad_stream,
            }),

            #[cfg(feature = "fletcher4-sse2")]
            Fletcher4Implementation::SSE2 => Ok(Fletcher4ImplementationCtx {
                block_size: 4 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher4::update_blocks_sse2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher4::update_blocks_sse2_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher4::update_blocks_sse2_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher4::update_blocks_sse2_native,
                },
                finish_blocks: Fletcher4::finish_blocks_dual_stream,
            }),

            #[cfg(feature = "fletcher4-ssse3")]
            Fletcher4Implementation::SSSE3 => Ok(Fletcher4ImplementationCtx {
                block_size: 4 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher4::update_blocks_sse2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher4::update_blocks_ssse3_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher4::update_blocks_ssse3_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher4::update_blocks_sse2_native,
                },
                finish_blocks: Fletcher4::finish_blocks_dual_stream,
            }),

            #[cfg(feature = "fletcher4-avx2")]
            Fletcher4Implementation::AVX2 => Ok(Fletcher4ImplementationCtx {
                block_size: 4 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx2_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx2_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx2_native,
                },
                finish_blocks: Fletcher4::finish_blocks_quad_stream,
            }),

            #[cfg(feature = "fletcher4-avx512f")]
            Fletcher4Implementation::AVX512F => Ok(Fletcher4ImplementationCtx {
                block_size: 8 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx512f_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx512f_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx512f_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx512f_native,
                },
                finish_blocks: Fletcher4::finish_blocks_octo_stream,
            }),

            #[cfg(feature = "fletcher4-avx512bw")]
            Fletcher4Implementation::AVX512BW => Ok(Fletcher4ImplementationCtx {
                block_size: 8 * FLETCHER_4_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx512f_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher4::update_blocks_avx512bw_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx512bw_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher4::update_blocks_avx512f_native,
                },
                finish_blocks: Fletcher4::finish_blocks_octo_stream,
            }),

            #[cfg(any(
                not(feature = "fletcher4-sse2"),
                not(feature = "fletcher4-ssse3"),
                not(feature = "fletcher4-avx2"),
                not(feature = "fletcher4-avx512f"),
                not(feature = "fletcher4-avx512bw"),
            ))]
            _ => Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Fletcher4,
                order,
                implementation: implementation.to_str(),
            }),
        }
    }
}

impl Fletcher4 {
    /** Create a new Fletcher4 instance.
     *
     * `order` specifies the endianness of the data to be hashed.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] if the implementation is not supported.
     */
    pub fn new(
        order: EndianOrder,
        implementation: Fletcher4Implementation,
    ) -> Result<Fletcher4, ChecksumError> {
        Ok(Fletcher4 {
            buffer_fill: 0,
            buffer: Default::default(),
            state: Default::default(),
            order: order,
            impl_ctx: Fletcher4ImplementationCtx::new(order, implementation)?,
        })
    }

    /** Finish a check that is one stream.
     *
     * For one stream, this is a NO-OP.
     */
    fn finish_blocks_single_stream(state: &[u64]) -> [u64; FLETCHER_4_U64_COUNT] {
        [state[0], state[1], state[2], state[3]]
    }

    /** Finish a checksum that is two streams wide.
     *
     * Refer to docs/FLETCHER.md for exaplanation of constants.
     */
    fn finish_blocks_dual_stream(state: &[u64]) -> [u64; FLETCHER_4_U64_COUNT] {
        let a = &state[0..2];
        let b = &state[2..4];
        let c = &state[4..6];
        let d = &state[6..8];

        let ra = a[0].wrapping_add(a[1]);

        let rb = b[0].wrapping_add(b[1]).wrapping_mul(2).wrapping_sub(a[1]);

        let rc = c[0]
            .wrapping_add(c[1])
            .wrapping_mul(4)
            .wrapping_sub(b[0].wrapping_add(b[1].wrapping_mul(3)));

        let rd = d[0]
            .wrapping_add(d[1])
            .wrapping_mul(8)
            .wrapping_sub(c[0].wrapping_mul(4).wrapping_add(c[1].wrapping_mul(8)))
            .wrapping_add(b[1]);

        [ra, rb, rc, rd]
    }

    /** Finish a checksum that is four streams wide.
     *
     * Refer to docs/FLETCHER.md for exaplanation of constants.
     */
    fn finish_blocks_quad_stream(state: &[u64]) -> [u64; FLETCHER_4_U64_COUNT] {
        let a = &state[0..4];
        let b = &state[4..8];
        let c = &state[8..12];
        let d = &state[12..16];

        let ra = sum_and_mul(a, 1);

        let rb = sum_and_mul(b, 4).wrapping_sub(
            a[1].wrapping_add(a[2].wrapping_mul(2))
                .wrapping_add(a[3].wrapping_mul(3)),
        );

        let rc_mb: [u16; 4] = [6, 10, 14, 18];
        let rc = sum_and_mul(c, 16)
            .wrapping_sub(mul_and_sum(b, &rc_mb))
            .wrapping_add(a[2])
            .wrapping_add(a[3].wrapping_mul(3));

        let rd_mc: [u16; 4] = [48, 64, 80, 96];
        let rd_mb: [u16; 4] = [4, 10, 20, 34];
        let rd = sum_and_mul(d, 64)
            .wrapping_sub(mul_and_sum(c, &rd_mc))
            .wrapping_add(mul_and_sum(b, &rd_mb))
            .wrapping_sub(a[3]);

        [ra, rb, rc, rd]
    }

    /** Finish a checksum that is eight streams wide.
     *
     * Refer to docs/FLETCHER.md for exaplanation of constants.
     */
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        any(feature = "fletcher4-avx512f", feature = "fletcher4-avx512bw"),
    ))]
    fn finish_blocks_octo_stream(state: &[u64]) -> [u64; FLETCHER_4_U64_COUNT] {
        let a = &state[0..8];
        let b = &state[8..16];
        let c = &state[16..24];
        let d = &state[24..32];

        let ra = sum_and_mul(a, 1);

        let rb_ma: [u16; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let rb = sum_and_mul(b, 8).wrapping_sub(mul_and_sum(a, &rb_ma));

        let rc_mb: [u16; 8] = [28, 36, 44, 52, 60, 68, 76, 84];
        let rc_ma: [u16; 8] = [0, 0, 1, 3, 6, 10, 15, 21];
        let rc = sum_and_mul(c, 64)
            .wrapping_sub(mul_and_sum(b, &rc_mb))
            .wrapping_add(mul_and_sum(a, &rc_ma));

        let rd_mc: [u16; 8] = [448, 512, 576, 640, 704, 768, 832, 896];
        let rd_mb: [u16; 8] = [56, 84, 120, 164, 216, 276, 344, 420];
        let rd_ma: [u16; 8] = [0, 0, 0, 1, 4, 10, 20, 35];
        let rd = sum_and_mul(d, 512)
            .wrapping_sub(mul_and_sum(c, &rd_mc))
            .wrapping_add(mul_and_sum(b, &rd_mb))
            .wrapping_sub(mul_and_sum(a, &rd_ma));

        // Result.
        [ra, rb, rc, rd]
    }

    /// Update blocks, reading one big endian [`u32`] at a time.
    fn update_blocks_generic_big(state: &mut [u64], data: &[u8]) {
        // Load state to local variables.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        // Iterate one block at a time.
        let mut iter = data.chunks_exact(FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode value.
            let value = u64::from(u32::from_be_bytes(block.try_into().unwrap()));

            // Update running checksum.
            a = a.wrapping_add(value);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        // Save state.
        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
    }

    /// Update blocks, reading one little endian [`u32`] at a time.
    fn update_blocks_generic_little(state: &mut [u64], data: &[u8]) {
        // Load state to local variables.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        // Iterate one block at a time.
        let mut iter = data.chunks_exact(FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode value.
            let value = u64::from(u32::from_le_bytes(block.try_into().unwrap()));

            // Update running checksum.
            a = a.wrapping_add(value);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        // Save state.
        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
    }

    /// Update blocks, reading two big endian [`u32`] at a time.
    fn update_blocks_superscalar2_big(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut a1 = state[1];

        let mut b0 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut c1 = state[5];

        let mut d0 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from(u32::from_be_bytes(block[0..4].try_into().unwrap()));
            let w = u64::from(u32::from_be_bytes(block[4..8].try_into().unwrap()));

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            a1 = a1.wrapping_add(w);

            b0 = b0.wrapping_add(a0);
            b1 = b1.wrapping_add(a1);

            c0 = c0.wrapping_add(b0);
            c1 = c1.wrapping_add(b1);

            d0 = d0.wrapping_add(c0);
            d1 = d1.wrapping_add(c1);
        }

        // Save state.
        state[0] = a0;
        state[1] = a1;

        state[2] = b0;
        state[3] = b1;

        state[4] = c0;
        state[5] = c1;

        state[6] = d0;
        state[7] = d1;
    }

    /// Update blocks, reading two little endian [`u32`] at a time.
    fn update_blocks_superscalar2_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut a1 = state[1];

        let mut b0 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut c1 = state[5];

        let mut d0 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from(u32::from_le_bytes(block[0..4].try_into().unwrap()));
            let w = u64::from(u32::from_le_bytes(block[4..8].try_into().unwrap()));

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            a1 = a1.wrapping_add(w);

            b0 = b0.wrapping_add(a0);
            b1 = b1.wrapping_add(a1);

            c0 = c0.wrapping_add(b0);
            c1 = c1.wrapping_add(b1);

            d0 = d0.wrapping_add(c0);
            d1 = d1.wrapping_add(c1);
        }

        // Save state.
        state[0] = a0;
        state[1] = a1;

        state[2] = b0;
        state[3] = b1;

        state[4] = c0;
        state[5] = c1;

        state[6] = d0;
        state[7] = d1;
    }

    /// Update blocks, reading four big endian [`u32`] at a time.
    fn update_blocks_superscalar4_big(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut a1 = state[1];
        let mut a2 = state[2];
        let mut a3 = state[3];

        let mut b0 = state[4];
        let mut b1 = state[5];
        let mut b2 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut c1 = state[9];
        let mut c2 = state[10];
        let mut c3 = state[11];

        let mut d0 = state[12];
        let mut d1 = state[13];
        let mut d2 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from(u32::from_be_bytes(block[0..4].try_into().unwrap()));
            let w = u64::from(u32::from_be_bytes(block[4..8].try_into().unwrap()));
            let x = u64::from(u32::from_be_bytes(block[8..12].try_into().unwrap()));
            let y = u64::from(u32::from_be_bytes(block[12..16].try_into().unwrap()));

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            a1 = a1.wrapping_add(w);
            a2 = a2.wrapping_add(x);
            a3 = a3.wrapping_add(y);

            b0 = b0.wrapping_add(a0);
            b1 = b1.wrapping_add(a1);
            b2 = b2.wrapping_add(a2);
            b3 = b3.wrapping_add(a3);

            c0 = c0.wrapping_add(b0);
            c1 = c1.wrapping_add(b1);
            c2 = c2.wrapping_add(b2);
            c3 = c3.wrapping_add(b3);

            d0 = d0.wrapping_add(c0);
            d1 = d1.wrapping_add(c1);
            d2 = d2.wrapping_add(c2);
            d3 = d3.wrapping_add(c3);
        }

        // Save state.
        state[0] = a0;
        state[1] = a1;
        state[2] = a2;
        state[3] = a3;

        state[4] = b0;
        state[5] = b1;
        state[6] = b2;
        state[7] = b3;

        state[8] = c0;
        state[9] = c1;
        state[10] = c2;
        state[11] = c3;

        state[12] = d0;
        state[13] = d1;
        state[14] = d2;
        state[15] = d3;
    }

    /// Update blocks, reading four little endian [`u32`] at a time.
    fn update_blocks_superscalar4_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut a1 = state[1];
        let mut a2 = state[2];
        let mut a3 = state[3];

        let mut b0 = state[4];
        let mut b1 = state[5];
        let mut b2 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut c1 = state[9];
        let mut c2 = state[10];
        let mut c3 = state[11];

        let mut d0 = state[12];
        let mut d1 = state[13];
        let mut d2 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from(u32::from_le_bytes(block[0..4].try_into().unwrap()));
            let w = u64::from(u32::from_le_bytes(block[4..8].try_into().unwrap()));
            let x = u64::from(u32::from_le_bytes(block[8..12].try_into().unwrap()));
            let y = u64::from(u32::from_le_bytes(block[12..16].try_into().unwrap()));

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            a1 = a1.wrapping_add(w);
            a2 = a2.wrapping_add(x);
            a3 = a3.wrapping_add(y);

            b0 = b0.wrapping_add(a0);
            b1 = b1.wrapping_add(a1);
            b2 = b2.wrapping_add(a2);
            b3 = b3.wrapping_add(a3);

            c0 = c0.wrapping_add(b0);
            c1 = c1.wrapping_add(b1);
            c2 = c2.wrapping_add(b2);
            c3 = c3.wrapping_add(b3);

            d0 = d0.wrapping_add(c0);
            d1 = d1.wrapping_add(c1);
            d2 = d2.wrapping_add(c2);
            d3 = d3.wrapping_add(c3);
        }

        // Save state.
        state[0] = a0;
        state[1] = a1;
        state[2] = a2;
        state[3] = a3;

        state[4] = b0;
        state[5] = b1;
        state[6] = b2;
        state[7] = b3;

        state[8] = c0;
        state[9] = c1;
        state[10] = c2;
        state[11] = c3;

        state[12] = d0;
        state[13] = d1;
        state[14] = d2;
        state[15] = d3;
    }

    #[cfg(all(
        feature = "fletcher4-sse2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sse2_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+------+
        // | _mm_add_epi64      | SSE2 |
        // | _mm_loadu_si128    | SSE2 |
        // | _mm_storeu_si128   | SSE2 |
        // +--------------------+------+

        #[target_feature(enable = "sse2")]
        unsafe fn update_blocks_sse2_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each dual stream into an xmm register.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut a = arch::_mm_loadu_si128(state.add(0));
                let mut b = arch::_mm_loadu_si128(state.add(1));
                let mut c = arch::_mm_loadu_si128(state.add(2));
                let mut d = arch::_mm_loadu_si128(state.add(3));

                // Iterate two blocks at a time.
                let mut iter = data.chunks_exact(2 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Decode values.
                    let v = u32::from_ne_bytes(block[0..4].try_into().unwrap()).swap_bytes();
                    let w = u32::from_ne_bytes(block[4..8].try_into().unwrap()).swap_bytes();

                    // Load v and w into an xmm register.
                    //
                    // vw[0..32]   = v[0..32] == f[n]
                    // vw[32..64]  = 0
                    // vw[64..96]  = w[0..32] == f[n+1]
                    // vw[96..128] = 0
                    let block: &[u64; 2] = &[u64::from(v), u64::from(w)];
                    let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Add the values to the lanes.
                    // a[0], a[1] += f[n], f[n+1]
                    // ...
                    a = arch::_mm_add_epi64(a, vw);
                    b = arch::_mm_add_epi64(b, a);
                    c = arch::_mm_add_epi64(c, b);
                    d = arch::_mm_add_epi64(d, c);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), a);
                arch::_mm_storeu_si128(state.add(1), b);
                arch::_mm_storeu_si128(state.add(2), c);
                arch::_mm_storeu_si128(state.add(3), d);
            }
        }

        unsafe { update_blocks_sse2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(feature = "fletcher4-sse2", feature = "fletcher4-ssse3"),
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sse2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+------+
        // | _mm_add_epi64      | SSE2 |
        // | _mm_loadu_si128    | SSE2 |
        // | _mm_setzero_si128  | SSE2 |
        // | _mm_storeu_si128   | SSE2 |
        // | _mm_unpackhi_epi32 | SSE2 |
        // | _mm_unpacklo_epi32 | SSE2 |
        // +--------------------+------+

        #[target_feature(enable = "sse2")]
        unsafe fn update_blocks_sse2_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each dual stream into an xmm register.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut a = arch::_mm_loadu_si128(state.add(0));
                let mut b = arch::_mm_loadu_si128(state.add(1));
                let mut c = arch::_mm_loadu_si128(state.add(2));
                let mut d = arch::_mm_loadu_si128(state.add(3));

                // Load zero into an xmm register.
                let zero = arch::_mm_setzero_si128();

                // Iterate four blocks at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 128 bits into an xmm register.
                    let vwxy = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Split the lower 64 bits of vwxy into two 32 bit values.
                    // Zero extend them into two 64 bit values into vw.
                    //
                    // vw[0..32]   = vwxy[0..32]  == f[n]
                    // vw[32..64]  = zero[0..32]  == 0
                    // vw[64..96]  = vwxy[32..64] == f[n+1]
                    // vw[96..128] = zero[32..64] == 0
                    //
                    // vw[0..64]   = f[n]
                    // vw[64..128] = f[n+1]
                    let vw = arch::_mm_unpacklo_epi32(vwxy, zero);

                    // Do the same, but with the high bits.
                    // xy[0..32]   = vwxy[64..96]  == f[n+2]
                    // xy[32..64]  = zero[64..96]  == 0
                    // xy[64..96]  = vwxy[96..128] == f[n+3]
                    // xy[96..128] = zero[96..128] == 0
                    //
                    // xy[0..64]   = f[n+2]
                    // xy[64..128] = f[n+3]
                    let xy = arch::_mm_unpackhi_epi32(vwxy, zero);

                    // Add the values to the lanes.
                    // a[0], a[1] += f[n], f[n+1]
                    // ...
                    a = arch::_mm_add_epi64(a, vw);
                    b = arch::_mm_add_epi64(b, a);
                    c = arch::_mm_add_epi64(c, b);
                    d = arch::_mm_add_epi64(d, c);

                    // Add the values to the lanes.
                    // a[0], a[1] += f[n+2], f[n+3]
                    // ...
                    a = arch::_mm_add_epi64(a, xy);
                    b = arch::_mm_add_epi64(b, a);
                    c = arch::_mm_add_epi64(c, b);
                    d = arch::_mm_add_epi64(d, c);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), a);
                arch::_mm_storeu_si128(state.add(1), b);
                arch::_mm_storeu_si128(state.add(2), c);
                arch::_mm_storeu_si128(state.add(3), d);
            }
        }

        unsafe { update_blocks_sse2_native_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher4-ssse3",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_ssse3_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+-------+
        // | _mm_add_epi64      | SSE2  |
        // | _mm_loadu_si128    | SSE2  |
        // | _mm_set_epi8       | SSE2  |
        // | _mm_setzero_si128  | SSE2  |
        // | _mm_shuffle_epi8   | SSSE3 |
        // | _mm_storeu_si128   | SSE2  |
        // | _mm_unpackhi_epi32 | SSE2  |
        // | _mm_unpacklo_epi32 | SSE2  |
        // +--------------------+-------+

        #[target_feature(enable = "sse2,ssse3")]
        unsafe fn update_blocks_ssse3_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each dual stream into an xmm register.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut a = arch::_mm_loadu_si128(state.add(0));
                let mut b = arch::_mm_loadu_si128(state.add(1));
                let mut c = arch::_mm_loadu_si128(state.add(2));
                let mut d = arch::_mm_loadu_si128(state.add(3));

                // Load zero into an xmm register.
                let zero = arch::_mm_setzero_si128();

                // Set the shuffle value.
                let shuffle = arch::_mm_set_epi8(
                    0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x08, 0x09, 0x0a, 0x0b, // f2
                    0x04, 0x05, 0x06, 0x07, // f1
                    0x00, 0x01, 0x02, 0x03, // f0
                );

                // Iterate four blocks at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 128 bits into an xmm register.
                    let vwxy = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Swap the order of each 4-byte part of vwxy.
                    // Each byte of shuffle indicates the byte index of vwxy.
                    //
                    // index = shuffle[0..8]
                    // vwxy[0..8] = vwxy[index * 8..(index + 1) * 8]
                    // vwxy[0..8] = vwxy[24..32]
                    //
                    // index = shuffle[8..16]
                    // vwxy[8..16] = vwxy[index * 8..(index + 1) * 8]
                    // vwxy[8..16] = vwxy[16..24]
                    // ...
                    let vwxy = arch::_mm_shuffle_epi8(vwxy, shuffle);

                    // Split the lower 64 bits of vwxy into two 32 bit values.
                    // Zero extend them into two 64 bit values into vw.
                    //
                    // vw[0..32]   = vwxy[0..32]  == f[n]
                    // vw[32..64]  = zero[0..32]  == 0
                    // vw[64..96]  = vwxy[32..64] == f[n+1]
                    // vw[96..128] = zero[32..64] == 0
                    //
                    // vw[0..64]   = f[n]
                    // vw[64..128] = f[n+1]
                    let vw = arch::_mm_unpacklo_epi32(vwxy, zero);

                    // Do the same, but with the high bits.
                    // xy[0..32]   = vwxy[64..96]  == f[n+2]
                    // xy[32..64]  = zero[64..96]  == 0
                    // xy[64..96]  = vwxy[96..128] == f[n+3]
                    // xy[96..128] = zero[96..128] == 0
                    //
                    // xy[0..64]   = f[n+2]
                    // xy[64..128] = f[n+3]
                    let xy = arch::_mm_unpackhi_epi32(vwxy, zero);

                    // Add the values to the lanes.
                    // a[0], a[1] += f[n], f[n+1]
                    // ...
                    a = arch::_mm_add_epi64(a, vw);
                    b = arch::_mm_add_epi64(b, a);
                    c = arch::_mm_add_epi64(c, b);
                    d = arch::_mm_add_epi64(d, c);

                    // Add the values to the lanes.
                    // a[0], a[1] += f[n+2], f[n+3]
                    // ...
                    a = arch::_mm_add_epi64(a, xy);
                    b = arch::_mm_add_epi64(b, a);
                    c = arch::_mm_add_epi64(c, b);
                    d = arch::_mm_add_epi64(d, c);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), a);
                arch::_mm_storeu_si128(state.add(1), b);
                arch::_mm_storeu_si128(state.add(2), c);
                arch::_mm_storeu_si128(state.add(3), d);
            }
        }

        unsafe { update_blocks_ssse3_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher4-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+-------+
        // | *_mm_loadu_si128      | SSE2  |
        // | _mm256_add_epi64      | AVX2  |
        // | _mm256_cvtepu32_epi64 | AVX2  |
        // | _mm256_lddqu_si256    | AVX   |
        // | _mm256_shuffle_epi8   | AVX2  |
        // | _mm256_storeu_si256   | AVX   |
        // +-----------------------+-------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                let shuffle = arch::_mm256_set_epi8(
                    -0x80, -0x80, -0x80, -0x80, 0x08, 0x09, 0x0a, 0x0b, // f3
                    -0x80, -0x80, -0x80, -0x80, 0x00, 0x01, 0x02, 0x03, // f2
                    -0x80, -0x80, -0x80, -0x80, 0x08, 0x09, 0x0a, 0x0b, // f1
                    -0x80, -0x80, -0x80, -0x80, 0x00, 0x01, 0x02, 0x03, // f0
                );

                // Load each quad stream into a ymm register.
                let state = state.as_ptr() as *mut arch::__m256i;
                let mut a = arch::_mm256_lddqu_si256(state.add(0));
                let mut b = arch::_mm256_lddqu_si256(state.add(1));
                let mut c = arch::_mm256_lddqu_si256(state.add(2));
                let mut d = arch::_mm256_lddqu_si256(state.add(3));

                // Iterate 128 bits at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // If you look at the intel intrinsics guide:
                    // +-----------------------+---------------------+
                    // | _mm_loadu_si128       | movdqu    xmm, m128 |
                    // | _mm256_cvtepu32_epi64 | vpmovzxdq ymm, xmm  |
                    // +-----------------------+---------------------+
                    // If you check the assembly guide, VPMOVZXDQ also supports m128.
                    // The compiler will optimize the calls, and instead just do:
                    // +-----------------------+---------------------+
                    // | _mm256_cvtepu32_epi64 | vpmovzxdq ymm, m128 |
                    // +-----------------------+---------------------+

                    // Load 128 bits into an xmm register.
                    let vwxy = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Zero extend 128 bits of 4xu32 into 256 bits of 4xu64.
                    let vwxy = arch::_mm256_cvtepu32_epi64(vwxy);

                    // Swap the order of the lower 4-byte parts of vwxy.
                    // Each byte of shuffle indicates the byte index of vwxy.
                    // The shuffle is done on each 128 bit lane, so the indices
                    // repeat for f0, f1 and f2, f3. Use -0x80 to keep the high
                    // bytes zero.
                    //
                    // index = shuffle[0..8]
                    // vwxy[0..8] = vwxy[index * 8..(index + 1) * 8]
                    // vwxy[0..8] = vwxy[24..32]
                    // ...
                    // vwxy[8..16]  = vwxy[16..24]
                    // vwxy[16..24] = vwxy[8..16]
                    // vwxy[24..32] = vwxy[0..8]
                    // vwxy[32..40] = 0
                    // vwxy[40..48] = 0
                    // vwxy[48..56] = 0
                    // vwxy[56..64] = 0
                    // ...
                    let vwxy = arch::_mm256_shuffle_epi8(vwxy, shuffle);

                    // a[0], a[1], a[2], a[3] += f[n], f[n+1], f[n+2], f[n+3]
                    // ...
                    a = arch::_mm256_add_epi64(a, vwxy);
                    b = arch::_mm256_add_epi64(b, a);
                    c = arch::_mm256_add_epi64(c, b);
                    d = arch::_mm256_add_epi64(d, c);
                }

                // Save state.
                arch::_mm256_storeu_si256(state.add(0), a);
                arch::_mm256_storeu_si256(state.add(1), b);
                arch::_mm256_storeu_si256(state.add(2), c);
                arch::_mm256_storeu_si256(state.add(3), d);
            }
        }

        unsafe { update_blocks_avx2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher4-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+------+
        // | *_mm_loadu_si128      | SSE2 |
        // | _mm256_add_epi64      | AVX2 |
        // | _mm256_cvtepu32_epi64 | AVX2 |
        // | _mm256_lddqu_si256    | AVX  |
        // | _mm256_storeu_si256   | AVX  |
        // +-----------------------+------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each quad stream into a ymm register.
                let state = state.as_ptr() as *mut arch::__m256i;
                let mut a = arch::_mm256_lddqu_si256(state.add(0));
                let mut b = arch::_mm256_lddqu_si256(state.add(1));
                let mut c = arch::_mm256_lddqu_si256(state.add(2));
                let mut d = arch::_mm256_lddqu_si256(state.add(3));

                // Iterate 128 bits at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // If you look at the intel intrinsics guide:
                    // +-----------------------+---------------------+
                    // | _mm_loadu_si128       | movdqu    xmm, m128 |
                    // | _mm256_cvtepu32_epi64 | vpmovzxdq ymm, xmm  |
                    // +-----------------------+---------------------+
                    // If you check the assembly guide, VPMOVZXDQ also supports m128.
                    // The compiler will optimize the calls, and instead just do:
                    // +-----------------------+---------------------+
                    // | _mm256_cvtepu32_epi64 | vpmovzxdq ymm, m128 |
                    // +-----------------------+---------------------+

                    // Load 128 bits into an xmm register.
                    let vwxy = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Zero extend 128 bits of 4xu32 into 256 bits of 4xu64.
                    let vwxy = arch::_mm256_cvtepu32_epi64(vwxy);

                    // a[0], a[1], a[2], a[3] += f[n], f[n+1], f[n+2], f[n+3]
                    // ...
                    a = arch::_mm256_add_epi64(a, vwxy);
                    b = arch::_mm256_add_epi64(b, a);
                    c = arch::_mm256_add_epi64(c, b);
                    d = arch::_mm256_add_epi64(d, c);
                }

                // Save state.
                arch::_mm256_storeu_si256(state.add(0), a);
                arch::_mm256_storeu_si256(state.add(1), b);
                arch::_mm256_storeu_si256(state.add(2), c);
                arch::_mm256_storeu_si256(state.add(3), d);
            }
        }

        unsafe { update_blocks_avx2_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher4-avx512f",
    ))]
    fn update_blocks_avx512f_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+---------+
        // | *_mm256_lddqu_si256   | AVX     |
        // | _mm512_add_epi64      | AVX512F |
        // | _mm512_cvtepu32_epi64 | AVX512F |
        // | _mm512_loadu_si512    | AVX512F |
        // | _mm512_storeu_si512   | AVX512F |
        // +-----------------------+---------+

        #[target_feature(enable = "avx512f")]
        unsafe fn update_blocks_avx512f_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // TODO(cybojanek): Check this ONLY uses avx512f.
            //                  At the time of this writing, the compiler
            //                  optimizes this code, and uses vpshufb, which is
            //                  an AVX512BW instruction.
            unsafe {
                // Load each octo stream into a zmm register.
                let state = state.as_ptr() as *mut arch::__m512i;
                let mut a = arch::_mm512_lddqu_si512(state.add(0));
                let mut b = arch::_mm512_lddqu_si512(state.add(1));
                let mut c = arch::_mm512_lddqu_si512(state.add(2));
                let mut d = arch::_mm512_lddqu_si512(state.add(3));

                // Iterate 256 bits at a time.
                let mut iter = data.chunks_exact(8 * FLETCHER_4_BLOCK_SIZE);

                // Use broadcast for the first, and then shift for remaining,
                // because shift is only one latency and one CPI.
                // 8xu64 [0x000000ff, ... ]
                // 8xu64 [0x0000ff00, ... ]
                // 8xu64 [0x00ff0000, ... ]
                // 8xu64 [0xff000000, ... ]
                let mask0 = arch::_mm512_maskz_set1_epi64(0xff, 0xff);
                let mask1 = arch::_mm512_slli_epi64(mask0, 8);
                let mask2 = arch::_mm512_slli_epi64(mask0, 16);
                let mask3 = arch::_mm512_slli_epi64(mask0, 24);

                for block in iter.by_ref() {
                    // If you look at the intel intrinsics guide:
                    // +-----------------------+---------------------+
                    // | _mm256_lddqu_si256    | vlddqu    ymm, m256 |
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, ymm  |
                    // +-----------------------+---------------------+
                    // If you check the assembly guide, VPMOVZXDQ also supports m256.
                    // The compiler will optimize the calls, and instead just do:
                    // +-----------------------+---------------------+
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, m256 |
                    // +-----------------------+---------------------+

                    // Load 256 bits into an ymm register.
                    let values = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                    // Zero extend 256 bits of 8xu32 into 512 bits of 8xu64.
                    let values = arch::_mm512_cvtepu32_epi64(values);

                    // Select one byte of each u64 value.
                    let s0 = arch::_mm512_and_epi64(values, mask0);
                    let s1 = arch::_mm512_and_epi64(values, mask1);
                    let s2 = arch::_mm512_and_epi64(values, mask2);
                    let s3 = arch::_mm512_and_epi64(values, mask3);

                    // Shift the selected byte of each u64, to its swapped place.
                    let s0 = arch::_mm512_slli_epi64(s0, 24);
                    let s1 = arch::_mm512_slli_epi64(s1, 8);
                    let s2 = arch::_mm512_srli_epi64(s2, 8);
                    let s3 = arch::_mm512_srli_epi64(s3, 24);

                    // Or the values to get the swapped u64 values.
                    let s01 = arch::_mm512_or_epi64(s0, s1);
                    let s23 = arch::_mm512_or_epi64(s2, s3);
                    let values = arch::_mm512_or_epi64(s01, s23);

                    // a[0], a[1], ..., a[7] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    a = arch::_mm512_add_epi64(a, values);
                    b = arch::_mm512_add_epi64(b, a);
                    c = arch::_mm512_add_epi64(c, b);
                    d = arch::_mm512_add_epi64(d, c);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), a);
                arch::_mm512_storeu_si512(state.add(1), b);
                arch::_mm512_storeu_si512(state.add(2), c);
                arch::_mm512_storeu_si512(state.add(3), d);
            }
        }

        unsafe { update_blocks_avx512f_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        any(feature = "fletcher4-avx512f", feature = "fletcher4-avx512bw"),
    ))]
    fn update_blocks_avx512f_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+---------+
        // | *_mm256_lddqu_si256   | AVX     |
        // | _mm512_add_epi64      | AVX512F |
        // | _mm512_cvtepu32_epi64 | AVX512F |
        // | _mm512_loadu_si512    | AVX512F |
        // | _mm512_storeu_si512   | AVX512F |
        // +-----------------------+---------+

        #[target_feature(enable = "avx512f")]
        unsafe fn update_blocks_avx512f_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each octo stream into a zmm register.
                let state = state.as_ptr() as *mut arch::__m512i;
                let mut a = arch::_mm512_lddqu_si512(state.add(0));
                let mut b = arch::_mm512_lddqu_si512(state.add(1));
                let mut c = arch::_mm512_lddqu_si512(state.add(2));
                let mut d = arch::_mm512_lddqu_si512(state.add(3));

                // Iterate 256 bits at a time.
                let mut iter = data.chunks_exact(8 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // If you look at the intel intrinsics guide:
                    // +-----------------------+---------------------+
                    // | _mm256_lddqu_si256    | vlddqu    ymm, m256 |
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, ymm  |
                    // +-----------------------+---------------------+
                    // If you check the assembly guide, VPMOVZXDQ also supports m256.
                    // The compiler will optimize the calls, and instead just do:
                    // +-----------------------+---------------------+
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, m256 |
                    // +-----------------------+---------------------+

                    // Load 256 bits into an ymm register.
                    let values = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                    // Zero extend 256 bits of 8xu32 into 512 bits of 8xu64.
                    let values = arch::_mm512_cvtepu32_epi64(values);

                    // a[0], a[1], ..., a[7] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    a = arch::_mm512_add_epi64(a, values);
                    b = arch::_mm512_add_epi64(b, a);
                    c = arch::_mm512_add_epi64(c, b);
                    d = arch::_mm512_add_epi64(d, c);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), a);
                arch::_mm512_storeu_si512(state.add(1), b);
                arch::_mm512_storeu_si512(state.add(2), c);
                arch::_mm512_storeu_si512(state.add(3), d);
            }
        }

        unsafe { update_blocks_avx512f_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher4-avx512bw",
    ))]
    fn update_blocks_avx512bw_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+----------+
        // | *_mm256_lddqu_si256   | AVX      |
        // | _mm512_add_epi64      | AVX512F  |
        // | _mm512_cvtepu32_epi64 | AVX512F  |
        // | _mm512_loadu_si512    | AVX512F  |
        // | _mm512_shuffle_epi8   | AVX512BW |
        // | _mm512_storeu_si512   | AVX512F  |
        // +-----------------------+----------+

        #[target_feature(enable = "avx512f,avx512bw")]
        unsafe fn update_blocks_avx512bw_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                let shuffle = arch::_mm512_set_epi8(
                    -0x80, -0x80, -0x80, -0x80, 0x18, 0x19, 0x1a, 0x1b, // f7
                    -0x80, -0x80, -0x80, -0x80, 0x10, 0x11, 0x12, 0x13, // f6
                    -0x80, -0x80, -0x80, -0x80, 0x08, 0x09, 0x0a, 0x0b, // f5
                    -0x80, -0x80, -0x80, -0x80, 0x00, 0x01, 0x02, 0x03, // f4
                    -0x80, -0x80, -0x80, -0x80, 0x18, 0x19, 0x1a, 0x1b, // f3
                    -0x80, -0x80, -0x80, -0x80, 0x10, 0x11, 0x12, 0x13, // f3
                    -0x80, -0x80, -0x80, -0x80, 0x08, 0x09, 0x0a, 0x0b, // f1
                    -0x80, -0x80, -0x80, -0x80, 0x00, 0x01, 0x02, 0x03, // f0
                );

                // Load each octo stream into a zmm register.
                let state = state.as_ptr() as *mut arch::__m512i;
                let mut a = arch::_mm512_lddqu_si512(state.add(0));
                let mut b = arch::_mm512_lddqu_si512(state.add(1));
                let mut c = arch::_mm512_lddqu_si512(state.add(2));
                let mut d = arch::_mm512_lddqu_si512(state.add(3));

                // Iterate 256 bits at a time.
                let mut iter = data.chunks_exact(8 * FLETCHER_4_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // If you look at the intel intrinsics guide:
                    // +-----------------------+---------------------+
                    // | _mm256_lddqu_si256    | vlddqu    ymm, m256 |
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, ymm  |
                    // +-----------------------+---------------------+
                    // If you check the assembly guide, VPMOVZXDQ also supports m256.
                    // The compiler will optimize the calls, and instead just do:
                    // +-----------------------+---------------------+
                    // | _mm512_cvtepu32_epi64 | vpmovzxdq zmm, m256 |
                    // +-----------------------+---------------------+

                    // Load 256 bits into an ymm register.
                    let values = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                    // Zero extend 256 bits of 8xu32 into 512 bits of 8xu64.
                    let values = arch::_mm512_cvtepu32_epi64(values);

                    // Swap the order of the lower 4-byte parts of values.
                    // Each byte of shuffle indicates the byte index of values.
                    // The shuffle is done on each 256 bit lane, so the indices
                    // repeat for f0, f1, f2, f3 and f4, f5, f6, f7. Use
                    // -0x80 to keep the high bytes zero.
                    //
                    // index = shuffle[0..8]
                    // values[0..8] = values[index * 8..(index + 1) * 8]
                    // values[0..8] = values[24..32]
                    // ...
                    // values[8..16]  = values[16..24]
                    // values[16..24] = values[8..16]
                    // values[24..32] = values[0..8]
                    // values[32..40] = 0
                    // values[40..48] = 0
                    // values[48..56] = 0
                    // values[56..64] = 0
                    // ...
                    let values = arch::_mm512_shuffle_epi8(values, shuffle);

                    // a[0], a[1], ..., a[7] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    a = arch::_mm512_add_epi64(a, values);
                    b = arch::_mm512_add_epi64(b, a);
                    c = arch::_mm512_add_epi64(c, b);
                    d = arch::_mm512_add_epi64(d, c);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), a);
                arch::_mm512_storeu_si512(state.add(1), b);
                arch::_mm512_storeu_si512(state.add(2), c);
                arch::_mm512_storeu_si512(state.add(3), d);
            }
        }

        unsafe { update_blocks_avx512bw_byteswap_impl(state, data) }
    }
}

impl Checksum for Fletcher4 {
    fn reset(&mut self) -> Result<(), ChecksumError> {
        self.buffer = Default::default();
        self.buffer_fill = 0;
        self.state = Default::default();

        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<(), ChecksumError> {
        // Make data pointer mutable, in case of self.buffer_fill.
        let mut data = data;

        // If block has some data, fill that up first.
        if self.buffer_fill > 0 {
            // Todo is minimum of block fill needed, and input data.
            let todo = cmp::min(self.impl_ctx.block_size - self.buffer_fill, data.len());

            // Copy to block.
            self.buffer[self.buffer_fill..self.buffer_fill + todo].copy_from_slice(&data[0..todo]);
            self.buffer_fill += todo;

            // Update data to skip copied block.
            data = &data[todo..];

            // If block is full, consume it.
            if self.buffer_fill == self.impl_ctx.block_size {
                let full_blocks_data = &self.buffer[0..self.buffer_fill];
                (self.impl_ctx.update_blocks)(&mut self.state, &full_blocks_data);
                self.buffer_fill = 0;
            }
        }

        // Calculate remainder.
        let remainder = data.len() % self.impl_ctx.block_size;

        // Update full blocks.
        let full_blocks_data = &data[0..data.len() - remainder];
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
        // Finish the state for parallel streams.
        let mut result = (self.impl_ctx.finish_blocks)(&self.state);

        // Calculate remainder and full blocks.
        let remainder = self.buffer_fill % FLETCHER_4_BLOCK_SIZE;
        let full_block_bytes = self.buffer_fill - remainder;

        // Update full blocks.
        if full_block_bytes > 0 {
            let generic = match self.order {
                EndianOrder::Big => Fletcher4::update_blocks_generic_big,
                EndianOrder::Little => Fletcher4::update_blocks_generic_little,
            };

            (generic)(&mut result, &self.buffer[0..full_block_bytes]);
            result = Fletcher4::finish_blocks_single_stream(&result);
        }

        // Ignore remainder bytes, because they are not included in checksum.

        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use core::cmp;

    use crate::checksum::{Checksum, ChecksumError, Fletcher4, Fletcher4Implementation};
    use crate::phys::EndianOrder;

    /** 128 byte random data.
     *
     * Refer to `docs/FLETCHER.md` for script to generate test cases.
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

    const TEST_VECTOR_A_BIG_CHECKSUMS: [(usize, [u64; 4]); 12] = [
        // Empty test case.
        (0, [0, 0, 0, 0]),
        // Small test cases.
        (
            4,
            [
                0x000000bc4b4d58,
                0x000000bc4b4d58,
                0x000000bc4b4d58,
                0x000000bc4b4d58,
            ],
        ),
        (
            8,
            [
                0x0000010015818d,
                0x000001bc60cee5,
                0x00000278ac1c3d,
                0x00000334f76995,
            ],
        ),
        (
            16,
            [
                0x000002b510e454,
                0x00000656578eaa,
                0x00000c704a553d,
                0x000015bf348565,
            ],
        ),
        (
            32,
            [
                0x00000462ef9b35,
                0x000015baee41f4,
                0x000049c5ba6417,
                0x0000cbee1ec81f,
            ],
        ),
        (
            64,
            [
                0x000008f7e04a76,
                0x00004bfc1745cd,
                0x0001d1ce6d7c23,
                0x0008d52f29a320,
            ],
        ),
        (
            128,
            [
                0x00000eeea163cc,
                0x00010e013af8bd,
                0x000c85c68f433f,
                0x00709c54f4292c,
            ],
        ),
        // Larger test cases.
        (
            8192,
            [
                0x0003bba858f300,
                0x0ef6672cfaff40,
                0x27f846f1cb5a43c0,
                0x1e53675f84390500,
            ],
        ),
        (
            16384,
            [
                0x00077750b1e600,
                0x3bca11218dfe80,
                0x3f27c10b327a8780,
                0xc8f946251150a00,
            ],
        ),
        (
            32768,
            [
                0x000eeea163cc00,
                0xef092d617bfd00,
                0xf6d4a7a7d40d0f00,
                0xf11114404b61400,
            ],
        ),
        (
            65536,
            [
                0x001ddd42c79800,
                0x3bbe6873c77fa00,
                0xad00ad2d647a1e00,
                0x4f4aa417939c2800,
            ],
        ),
        (
            131072,
            [
                0x003bba858f3000,
                0xeef1dc05eeff400,
                0x41750e91ba743c00,
                0x9ce34afd4ff85000,
            ],
        ),
    ];

    const TEST_VECTOR_A_LITTLE_CHECKSUMS: [(usize, [u64; 4]); 12] = [
        // Empty test case.
        (0, [0, 0, 0, 0]),
        // Small test cases.
        (
            4,
            [
                0x000000584d4bbc,
                0x000000584d4bbc,
                0x000000584d4bbc,
                0x000000584d4bbc,
            ],
        ),
        (
            8,
            [
                0x0000008d8215ff,
                0x000000e5cf61bb,
                0x0000013e1cad77,
                0x0000019669f933,
            ],
        ),
        (
            16,
            [
                0x00000254e412b3,
                0x000004ac8f5b51,
                0x00000842575166,
                0x00000d6e8940ae,
            ],
        ),
        (
            32,
            [
                0x000004379bf15e,
                0x000012ff44f8a5,
                0x00003d3a6ce080,
                0x0000a07ce08c36,
            ],
        ),
        (
            64,
            [
                0x0000087d4ae1ef,
                0x00004a004d2fab,
                0x0001b839b026e4,
                0x000809feab1826,
            ],
        ),
        (
            128,
            [
                0x000010db62a0df,
                0x000117affe54e5,
                0x000c8e34f31295,
                0x006e4f6d9de101,
            ],
        ),
        // Larger test cases.
        (
            8192,
            [
                0x000436d8a837c0,
                0x10dde115f0bd40,
                0x2d0623e6a0511340,
                0x2f2678bec58fce40,
            ],
        ),
        (
            16384,
            [
                0x00086db1506f80,
                0x4372876d9f7a80,
                0x67e740e65f6b2680,
                0xb37a22cd8c989c80,
            ],
        ),
        (
            32768,
            [
                0x0010db62a0df00,
                0x10dc023e236f500,
                0x3e130e68f9fa4d00,
                0x4a29d1501f153900,
            ],
        ),
        (
            65536,
            [
                0x0021b6c541be00,
                0x436ec9be04dea00,
                0xebfd9100e0849a00,
                0x5ec8691c55ba7200,
            ],
        ),
        (
            131072,
            [
                0x00436d8a837c00,
                0x10db8a88301bd400,
                0x4d8300ad73493400,
                0x6ddee96909b4e400,
            ],
        ),
    ];

    fn run_test_vector(
        h: &mut Fletcher4,
        vector: &[u8],
        checksums: &[(usize, [u64; 4])],
    ) -> Result<(), ChecksumError> {
        // Empty checksum is all zeros.
        assert_eq!(h.finalize()?, [0, 0, 0, 0]);

        // Test sizes.
        for (size, checksum) in checksums {
            let size = *size;
            let checksum = *checksum;

            if size <= vector.len() {
                // Single update call.
                h.reset()?;
                h.update(&vector[0..size])?;
                assert_eq!(h.finalize()?, checksum, "size {}", size);

                // Partial update.
                h.reset()?;
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
                h.reset()?;

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
        implementation: Fletcher4Implementation,
    ) -> Result<(), ChecksumError> {
        let mut h = Fletcher4::new(EndianOrder::Big, implementation)?;

        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_BIG_CHECKSUMS)?;

        let mut h = Fletcher4::new(EndianOrder::Little, implementation)?;
        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_LITTLE_CHECKSUMS)?;

        Ok(())
    }

    fn test_optional_implementation(
        implementation: Fletcher4Implementation,
    ) -> Result<(), ChecksumError> {
        // Assume the implementation is supported.
        let mut supported: [bool; 2] = [true, true];
        let orders: [EndianOrder; 2] = [EndianOrder::Big, EndianOrder::Little];

        for (idx, order) in orders.iter().enumerate() {
            if let Err(
                _e @ ChecksumError::Unsupported {
                    checksum: _,
                    order: _,
                    implementation: _,
                },
            ) = Fletcher4::new(*order, implementation)
            {
                supported[idx] = false;
            }
        }

        // Check Big and Little are either both support, or both not supported.
        assert_eq!(supported[0], supported[1]);

        match supported[0] {
            true => test_required_implementation(implementation),
            false => Ok(()),
        }
    }

    #[test]
    fn fletcher4_generic() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher4Implementation::Generic)
    }

    #[test]
    fn fletcher4_superscalar2() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher4Implementation::SuperScalar2)
    }

    #[test]
    fn fletcher4_superscalar4() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher4Implementation::SuperScalar4)
    }

    #[test]
    fn fletcher4_sse2() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher4Implementation::SSE2)
    }

    #[test]
    fn fletcher4_ssse3() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher4Implementation::SSSE3)
    }

    #[test]
    fn fletcher4_avx2() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher4Implementation::AVX2)
    }

    #[test]
    fn fletcher4_avx512f() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher4Implementation::AVX512F)
    }

    #[test]
    fn fletcher4_avx512bw() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher4Implementation::AVX512BW)
    }
}
