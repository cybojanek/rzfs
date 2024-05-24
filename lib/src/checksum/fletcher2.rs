// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::checksum::{Checksum, ChecksumError};
use crate::phys::{ChecksumType, EndianOrder};

use core::cmp;
use core::fmt;
use core::fmt::Display;

#[cfg(all(
    target_arch = "x86",
    any(
        feature = "fletcher2-sse2",
        feature = "fletcher2-ssse3",
        feature = "fletcher2-avx2",
        feature = "fletcher2-avx512f",
        feature = "fletcher2-avx512bw",
    ),
))]
use core::arch::x86 as arch;

#[cfg(all(
    target_arch = "x86_64",
    any(
        feature = "fletcher2-sse2",
        feature = "fletcher2-ssse3",
        feature = "fletcher2-avx2",
        feature = "fletcher2-avx512f",
        feature = "fletcher2-avx512bw",
    ),
))]
use core::arch::x86_64 as arch;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher2-sse2", feature = "fletcher2-ssse3",),
))]
use crate::arch::x86_any::is_sse2_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-ssse3",
))]
use crate::arch::x86_any::is_ssse3_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-avx2",
))]
use crate::arch::x86_any::{is_avx2_supported, is_avx_supported};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher2-avx512f", feature = "fletcher2-avx512bw"),
))]
use crate::arch::x86_any::is_avx512f_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-avx512bw",
))]
use crate::arch::x86_any::is_avx512bw_supported;

////////////////////////////////////////////////////////////////////////////////

/// Fletcher2 block size in bytes.
const FLETCHER_2_BLOCK_SIZE: usize = 16;

/// Fletcher2 in u64.
const FLETCHER_2_U64_COUNT: usize = 4;

/// Fletcher2 maximum SIMD width.
const FLETCHER_2_MAX_SIMD_WIDTH: usize = 4;

/// Fletcher2 implementation.
#[derive(Copy, Clone, Debug)]
pub enum Fletcher2Implementation {
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

const ALL_FLETCHER_2_IMPLEMENTATIONS: [Fletcher2Implementation; 8] = [
    Fletcher2Implementation::Generic,
    Fletcher2Implementation::SuperScalar2,
    Fletcher2Implementation::SuperScalar4,
    Fletcher2Implementation::SSE2,
    Fletcher2Implementation::SSSE3,
    Fletcher2Implementation::AVX2,
    Fletcher2Implementation::AVX512F,
    Fletcher2Implementation::AVX512BW,
];

impl Fletcher2Implementation {
    /** Get a slice with all of the [`Fletcher2Implementation`].
     *
     * Runtime support depends on CPU. Calling [`Fletcher2::new`] might still
     * fail with [`ChecksumError::Unsupported`].
     */
    pub fn all() -> &'static [Fletcher2Implementation] {
        &ALL_FLETCHER_2_IMPLEMENTATIONS
    }

    /** Is the implementation supported.
     */
    pub fn is_supported(&self) -> bool {
        match self {
            Fletcher2Implementation::Generic => true,
            Fletcher2Implementation::SuperScalar2 => true,
            Fletcher2Implementation::SuperScalar4 => true,

            #[cfg(feature = "fletcher2-sse2")]
            Fletcher2Implementation::SSE2 => is_sse2_supported(),

            #[cfg(feature = "fletcher2-ssse3")]
            Fletcher2Implementation::SSSE3 => is_sse2_supported() && is_ssse3_supported(),

            #[cfg(feature = "fletcher2-avx2")]
            Fletcher2Implementation::AVX2 => is_avx_supported() && is_avx2_supported(),

            #[cfg(feature = "fletcher2-avx512f")]
            Fletcher2Implementation::AVX512F => is_avx512f_supported(),

            #[cfg(feature = "fletcher2-avx512bw")]
            Fletcher2Implementation::AVX512BW => is_avx512f_supported() && is_avx512bw_supported(),

            #[cfg(any(
                not(feature = "fletcher2-sse2"),
                not(feature = "fletcher2-ssse3"),
                not(feature = "fletcher2-avx2"),
                not(feature = "fletcher2-avx512f"),
                not(feature = "fletcher2-avx512bw"),
            ))]
            _ => false,
        }
    }

    /// Get the string name of the implementation.
    pub fn to_str(&self) -> &'static str {
        match self {
            Fletcher2Implementation::Generic => "generic",
            Fletcher2Implementation::SuperScalar2 => "superscalar2",
            Fletcher2Implementation::SuperScalar4 => "superscalar4",
            Fletcher2Implementation::SSE2 => "sse2",
            Fletcher2Implementation::SSSE3 => "ssse3",
            Fletcher2Implementation::AVX2 => "avx2",
            Fletcher2Implementation::AVX512F => "avx512f",
            Fletcher2Implementation::AVX512BW => "avx512bw",
        }
    }
}

impl Display for Fletcher2Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            _ => write!(f, "{}", self.to_str()),
        }
    }
}

/// Update state. Data length is a multiple of the implementation's block size.
type Fletcher2UpdateBlock = fn(state: &mut [u64], data: &[u8]);

/// Compute the final hash from multiple streams.
type Fletcher2FinishBlocks = fn(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT];

/// Fletcher2 implementation context.
struct Fletcher2ImplementationCtx {
    /// A multiple of [`FLETCHER_2_BLOCK_SIZE`].
    block_size: usize,

    /// Implementation of [`Fletcher2UpdateBlock`].
    update_blocks: Fletcher2UpdateBlock,

    /// Implementation of [`Fletcher2FinishBlocks`].
    finish_blocks: Fletcher2FinishBlocks,
}

/// [`crate::phys::ChecksumType::Fletcher2`] implementation.
pub struct Fletcher2 {
    /// Number of bytes used in [`Fletcher2::buffer`].
    buffer_fill: usize,

    /// Partial block buffer.
    buffer: [u8; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH],

    /// Ongoing checksum.
    state: [u64; FLETCHER_2_U64_COUNT * FLETCHER_2_MAX_SIMD_WIDTH],

    /// Byte order of input data.
    order: EndianOrder,

    /// Implementation context.
    impl_ctx: Fletcher2ImplementationCtx,
}

impl Fletcher2ImplementationCtx {
    fn new(
        order: EndianOrder,
        implementation: Fletcher2Implementation,
    ) -> Result<Fletcher2ImplementationCtx, ChecksumError> {
        if !implementation.is_supported() {
            return Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Fletcher2,
                order,
                implementation: implementation.to_str(),
            });
        }

        match implementation {
            Fletcher2Implementation::Generic => Ok(Fletcher2ImplementationCtx {
                block_size: FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher2::update_blocks_generic_big,
                    EndianOrder::Little => Fletcher2::update_blocks_generic_little,
                },
                finish_blocks: Fletcher2::finish_blocks_single_stream,
            }),

            Fletcher2Implementation::SuperScalar2 => Ok(Fletcher2ImplementationCtx {
                block_size: 2 * FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher2::update_blocks_superscalar2_big,
                    EndianOrder::Little => Fletcher2::update_blocks_superscalar2_little,
                },
                finish_blocks: Fletcher2::finish_blocks_dual_stream,
            }),

            Fletcher2Implementation::SuperScalar4 => Ok(Fletcher2ImplementationCtx {
                block_size: 4 * FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    EndianOrder::Big => Fletcher2::update_blocks_superscalar4_big,
                    EndianOrder::Little => Fletcher2::update_blocks_superscalar4_little,
                },
                finish_blocks: Fletcher2::finish_blocks_quad_stream,
            }),

            #[cfg(feature = "fletcher2-sse2")]
            Fletcher2Implementation::SSE2 => Ok(Fletcher2ImplementationCtx {
                block_size: FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher2::update_blocks_sse2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher2::update_blocks_sse2_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher2::update_blocks_sse2_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher2::update_blocks_sse2_native,
                },
                finish_blocks: Fletcher2::finish_blocks_single_stream,
            }),

            #[cfg(feature = "fletcher2-ssse3")]
            Fletcher2Implementation::SSSE3 => Ok(Fletcher2ImplementationCtx {
                block_size: FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher2::update_blocks_sse2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher2::update_blocks_ssse3_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher2::update_blocks_ssse3_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher2::update_blocks_sse2_native,
                },
                finish_blocks: Fletcher2::finish_blocks_single_stream,
            }),

            #[cfg(feature = "fletcher2-avx2")]
            Fletcher2Implementation::AVX2 => Ok(Fletcher2ImplementationCtx {
                block_size: 2 * FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx2_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx2_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx2_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx2_native,
                },
                finish_blocks: Fletcher2::finish_blocks_dual_stream,
            }),

            #[cfg(feature = "fletcher2-avx512f")]
            Fletcher2Implementation::AVX512F => Ok(Fletcher2ImplementationCtx {
                block_size: 4 * FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx512f_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx512f_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx512f_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx512f_native,
                },
                finish_blocks: Fletcher2::finish_blocks_quad_stream,
            }),

            #[cfg(feature = "fletcher2-avx512bw")]
            Fletcher2Implementation::AVX512BW => Ok(Fletcher2ImplementationCtx {
                block_size: 4 * FLETCHER_2_BLOCK_SIZE,
                update_blocks: match order {
                    #[cfg(target_endian = "big")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx512f_native,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Big => Fletcher2::update_blocks_avx512bw_byteswap,
                    #[cfg(target_endian = "big")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx512bw_byteswap,
                    #[cfg(target_endian = "little")]
                    EndianOrder::Little => Fletcher2::update_blocks_avx512f_native,
                },
                finish_blocks: Fletcher2::finish_blocks_quad_stream,
            }),

            #[cfg(any(
                not(feature = "fletcher2-sse2"),
                not(feature = "fletcher2-ssse3"),
                not(feature = "fletcher2-avx2"),
                not(feature = "fletcher2-avx512f"),
                not(feature = "fletcher2-avx512bw"),
            ))]
            _ => Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Fletcher2,
                order,
                implementation: implementation.to_str(),
            }),
        }
    }
}

impl Fletcher2 {
    /** Create a new Fletcher2 instance.
     *
     * `order` specifies the endianness of the data to be hashed.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] if the implementation is not supported.
     */
    pub fn new(
        order: EndianOrder,
        implementation: Fletcher2Implementation,
    ) -> Result<Fletcher2, ChecksumError> {
        Ok(Fletcher2 {
            buffer_fill: 0,
            buffer: [0; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH],
            state: Default::default(),
            order: order,
            impl_ctx: Fletcher2ImplementationCtx::new(order, implementation)?,
        })
    }

    /** Finish a check that is one stream.
     *
     * For one stream, this is a NO-OP.
     */
    fn finish_blocks_single_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        [state[0], state[1], state[2], state[3]]
    }

    /** Finish a checksum that is two streams wide.
     *
     * - `a` and `b` correspond to `a` of [`Fletcher4::finish_blocks_dual_stream`].
     * - `c` and `d` correspond to `b` of [`Fletcher4::finish_blocks_dual_stream`].
     */
    fn finish_blocks_dual_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        // Load state.
        let a0 = state[0];
        let b0 = state[1];

        let a1 = state[2];
        let b1 = state[3];

        let c0 = state[4];
        let d0 = state[5];

        let c1 = state[6];
        let d1 = state[7];

        let ra = a0.wrapping_add(a1);
        let rb = b0.wrapping_add(b1);

        let rc = c0.wrapping_add(c1).wrapping_mul(2).wrapping_sub(a1);
        let rd = d0.wrapping_add(d1).wrapping_mul(2).wrapping_sub(b1);

        [ra, rb, rc, rd]
    }

    /** Finish a checksum that is four streams wide.
     *
     * - `a` and `b` correspond to `a` of [`Fletcher4::finish_blocks_quad_stream`].
     * - `c` and `d` correspond to `b` of [`Fletcher4::finish_blocks_quad_stream`].
     */
    fn finish_blocks_quad_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        let a0 = state[0];
        let b0 = state[1];

        let a1 = state[2];
        let b1 = state[3];

        let a2 = state[4];
        let b2 = state[5];

        let a3 = state[6];
        let b3 = state[7];

        let c0 = state[8];
        let d0 = state[9];

        let c1 = state[10];
        let d1 = state[11];

        let c2 = state[12];
        let d2 = state[13];

        let c3 = state[14];
        let d3 = state[15];

        let ra = a0.wrapping_add(a1).wrapping_add(a2).wrapping_add(a3);
        let rb = b0.wrapping_add(b1).wrapping_add(b2).wrapping_add(b3);

        let rc = c0
            .wrapping_add(c1)
            .wrapping_add(c2)
            .wrapping_add(c3)
            .wrapping_mul(4)
            .wrapping_sub(
                a1.wrapping_add(a2.wrapping_mul(2))
                    .wrapping_add(a3.wrapping_mul(3)),
            );

        let rd = d0
            .wrapping_add(d1)
            .wrapping_add(d2)
            .wrapping_add(d3)
            .wrapping_mul(4)
            .wrapping_sub(
                b1.wrapping_add(b2.wrapping_mul(2))
                    .wrapping_add(b3.wrapping_mul(3)),
            );

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
        let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());

            // Update running checksum.
            a = a.wrapping_add(v);
            b = b.wrapping_add(w);
            c = c.wrapping_add(a);
            d = d.wrapping_add(b);
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
        let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());

            // Update running checksum.
            a = a.wrapping_add(v);
            b = b.wrapping_add(w);
            c = c.wrapping_add(a);
            d = d.wrapping_add(b);
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
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut d0 = state[5];

        let mut c1 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_be_bytes(block[24..32].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = c0;
        state[5] = d0;

        state[6] = c1;
        state[7] = d1;
    }

    /// Update blocks, reading two little endian [`u32`] at a time.
    fn update_blocks_superscalar2_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut d0 = state[5];

        let mut c1 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_le_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_le_bytes(block[24..32].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = c0;
        state[5] = d0;

        state[6] = c1;
        state[7] = d1;
    }

    /// Update blocks, reading two big endian [`u32`] at a time.
    fn update_blocks_superscalar4_big(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut a2 = state[4];
        let mut b2 = state[5];

        let mut a3 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut d0 = state[9];

        let mut c1 = state[10];
        let mut d1 = state[11];

        let mut c2 = state[12];
        let mut d2 = state[13];

        let mut c3 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_be_bytes(block[24..32].try_into().unwrap());
            let vv = u64::from_be_bytes(block[32..40].try_into().unwrap());
            let ww = u64::from_be_bytes(block[40..48].try_into().unwrap());
            let xx = u64::from_be_bytes(block[48..56].try_into().unwrap());
            let yy = u64::from_be_bytes(block[56..64].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            a2 = a2.wrapping_add(vv);
            b2 = b2.wrapping_add(ww);
            a3 = a3.wrapping_add(xx);
            b3 = b3.wrapping_add(yy);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);

            c2 = c2.wrapping_add(a2);
            d2 = d2.wrapping_add(b2);
            c3 = c3.wrapping_add(a3);
            d3 = d3.wrapping_add(b3);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = a2;
        state[5] = b2;

        state[6] = a3;
        state[7] = b3;

        state[8] = c0;
        state[9] = d0;

        state[10] = c1;
        state[11] = d1;

        state[12] = c2;
        state[13] = d2;

        state[14] = c3;
        state[15] = d3;
    }

    /// Update blocks, reading two little endian [`u32`] at a time.
    fn update_blocks_superscalar4_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut a2 = state[4];
        let mut b2 = state[5];

        let mut a3 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut d0 = state[9];

        let mut c1 = state[10];
        let mut d1 = state[11];

        let mut c2 = state[12];
        let mut d2 = state[13];

        let mut c3 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_le_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_le_bytes(block[24..32].try_into().unwrap());
            let vv = u64::from_le_bytes(block[32..40].try_into().unwrap());
            let ww = u64::from_le_bytes(block[40..48].try_into().unwrap());
            let xx = u64::from_le_bytes(block[48..56].try_into().unwrap());
            let yy = u64::from_le_bytes(block[56..64].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            a2 = a2.wrapping_add(vv);
            b2 = b2.wrapping_add(ww);
            a3 = a3.wrapping_add(xx);
            b3 = b3.wrapping_add(yy);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);

            c2 = c2.wrapping_add(a2);
            d2 = d2.wrapping_add(b2);
            c3 = c3.wrapping_add(a3);
            d3 = d3.wrapping_add(b3);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = a2;
        state[5] = b2;

        state[6] = a3;
        state[7] = b3;

        state[8] = c0;
        state[9] = d0;

        state[10] = c1;
        state[11] = d1;

        state[12] = c2;
        state[13] = d2;

        state[14] = c3;
        state[15] = d3;
    }

    #[cfg(all(
        feature = "fletcher2-sse2",
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
                // Load value pairs into xmm registers.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut ab = arch::_mm_loadu_si128(state.add(0));
                let mut cd = arch::_mm_loadu_si128(state.add(1));

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Decode values.
                    let v = u64::from_ne_bytes(block[0..8].try_into().unwrap()).swap_bytes();
                    let w = u64::from_ne_bytes(block[8..16].try_into().unwrap()).swap_bytes();

                    // Load v and w into an xmm register.
                    //
                    // vw[0..64]   = f[n]
                    // vw[64..128] = f[n+1]
                    let block: &[u64; 2] = &[v, w];
                    let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Add the values to the lanes.
                    // a, b += f[n], f[n+1]
                    // ...
                    ab = arch::_mm_add_epi64(ab, vw);
                    cd = arch::_mm_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), ab);
                arch::_mm_storeu_si128(state.add(1), cd);
            }
        }

        unsafe { update_blocks_sse2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(feature = "fletcher2-sse2", feature = "fletcher2-ssse3"),
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sse2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+------+
        // | _mm_add_epi64      | SSE2 |
        // | _mm_loadu_si128    | SSE2 |
        // | _mm_storeu_si128   | SSE2 |
        // +--------------------+------+

        #[target_feature(enable = "sse2")]
        unsafe fn update_blocks_sse2_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load value pairs into xmm registers.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut ab = arch::_mm_loadu_si128(state.add(0));
                let mut cd = arch::_mm_loadu_si128(state.add(1));

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load v and w into an xmm register.
                    //
                    // vw[0..64]   = f[n]
                    // vw[64..128] = f[n+1]
                    let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Add the values to the lanes.
                    // a, b += f[n], f[n+1]
                    // ...
                    ab = arch::_mm_add_epi64(ab, vw);
                    cd = arch::_mm_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), ab);
                arch::_mm_storeu_si128(state.add(1), cd);
            }
        }

        unsafe { update_blocks_sse2_native_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-ssse3",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_ssse3_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+-------+
        // | _mm_add_epi64      | SSE2  |
        // | _mm_loadu_si128    | SSE2  |
        // | _mm_shuffle_epi8   | SSSE3 |
        // | _mm_storeu_si128   | SSE2  |
        // +--------------------+-------+

        #[target_feature(enable = "sse2,ssse3")]
        unsafe fn update_blocks_ssse3_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load value pairs into xmm registers.
                let state = state.as_ptr() as *mut arch::__m128i;
                let mut ab = arch::_mm_loadu_si128(state.add(0));
                let mut cd = arch::_mm_loadu_si128(state.add(1));

                // Set the shuffle value.
                let shuffle = arch::_mm_set_epi8(
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
                );

                // Iterate one block at a time.
                let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load block into an xmm register.
                    let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                    // Swap the order of each 8-byte part of vw.
                    // Each byte of shuffle indicates the byte index of vw.
                    //
                    // index = shuffle[0..8]
                    // vw[0..8] = vw[index * 8..(index + 1) * 8]
                    // vw[0..8] = vw[56..64]
                    //
                    // index = shuffle[8..16]
                    // vw[8..16] = vw[index * 8..(index + 1) * 8]
                    // vw[8..16] = vw[48..56]
                    // ...
                    let vw = arch::_mm_shuffle_epi8(vw, shuffle);

                    // Add the values to the lanes.
                    // a, b += f[n], f[n+1]
                    // ...
                    ab = arch::_mm_add_epi64(ab, vw);
                    cd = arch::_mm_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm_storeu_si128(state.add(0), ab);
                arch::_mm_storeu_si128(state.add(1), cd);
            }
        }

        unsafe { update_blocks_ssse3_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+-------+
        // | _mm256_add_epi64      | AVX2  |
        // | _mm256_lddqu_si256    | AVX   |
        // | _mm256_shuffle_epi8   | AVX2  |
        // | _mm256_storeu_si256   | AVX   |
        // +-----------------------+-------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                let shuffle = arch::_mm256_set_epi8(
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f3
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f2
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
                );

                // Load each dual stream into a ymm register.
                let state = state.as_ptr() as *mut arch::__m256i;
                let mut ab = arch::_mm256_lddqu_si256(state.add(0));
                let mut cd = arch::_mm256_lddqu_si256(state.add(1));

                // Iterate two blocks at a time.
                let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 256 bits into a ymm register.
                    let vwxy = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                    // Swap the order of the each 8-byte part of vwxy.
                    // Each byte of shuffle indicates the byte index of vwxy.
                    // The shuffle is done on each 128 bit lane, so the indices
                    // repeat for f0,f1 and f2,f3.
                    //
                    // index = shuffle[0..8]
                    // vwxy[0..8] = vwxy[index * 8..(index + 1) * 8]
                    // vwxy[0..8] = vwxy[56..64]
                    //
                    // index = shuffle[8..16]
                    // vwxy[8..16] = vwxy[index * 8..(index + 1) * 8]
                    // vwxy[8..16] = vwxy[48..56]
                    // ...
                    let vwxy = arch::_mm256_shuffle_epi8(vwxy, shuffle);

                    // a[0], b[0], a[1], b[1] += f[n], f[n+1], f[n+2], f[n+3]
                    // ...
                    ab = arch::_mm256_add_epi64(ab, vwxy);
                    cd = arch::_mm256_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm256_storeu_si256(state.add(0), ab);
                arch::_mm256_storeu_si256(state.add(1), cd);
            }
        }

        unsafe { update_blocks_avx2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+------+
        // | _mm256_add_epi64      | AVX2 |
        // | _mm256_lddqu_si256    | AVX  |
        // | _mm256_storeu_si256   | AVX  |
        // +-----------------------+------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each dual stream into a ymm register.
                let state = state.as_ptr() as *mut arch::__m256i;
                let mut ab = arch::_mm256_lddqu_si256(state.add(0));
                let mut cd = arch::_mm256_lddqu_si256(state.add(1));

                // Iterate two blocks at a time.
                let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 256 bits into a ymm register.
                    let vwxy = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                    // a[0], b[0], a[1], b[1] += f[n], f[n+1], f[n+2], f[n+3]
                    // ...
                    ab = arch::_mm256_add_epi64(ab, vwxy);
                    cd = arch::_mm256_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm256_storeu_si256(state.add(0), ab);
                arch::_mm256_storeu_si256(state.add(1), cd);
            }
        }

        unsafe { update_blocks_avx2_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher2-avx512f",
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
                let mut ab = arch::_mm512_loadu_epi64(state.add(0));
                let mut cd = arch::_mm512_loadu_epi64(state.add(1));

                // Iterate four blocks at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

                // Use broadcast for the first, and then shift for remaining,
                // because shift is only one latency and one CPI.
                // 8xu64 [0x00000000000000ff, ... ]
                // 8xu64 [0x000000000000ff00, ... ]
                // ...
                let mask0 = arch::_mm512_maskz_set1_epi64(0xff, 0xff);
                let mask1 = arch::_mm512_slli_epi64(mask0, 8);
                let mask2 = arch::_mm512_slli_epi64(mask0, 16);
                let mask3 = arch::_mm512_slli_epi64(mask0, 24);
                let mask4 = arch::_mm512_slli_epi64(mask0, 32);
                let mask5 = arch::_mm512_slli_epi64(mask0, 40);
                let mask6 = arch::_mm512_slli_epi64(mask0, 48);
                let mask7 = arch::_mm512_slli_epi64(mask0, 56);

                for block in iter.by_ref() {
                    // Load 512 bits into a zmm register.
                    let values = arch::_mm512_loadu_epi64(block.as_ptr() as *const _);

                    // Select one byte of each u64 value.
                    let s0 = arch::_mm512_and_epi64(values, mask0);
                    let s1 = arch::_mm512_and_epi64(values, mask1);
                    let s2 = arch::_mm512_and_epi64(values, mask2);
                    let s3 = arch::_mm512_and_epi64(values, mask3);
                    let s4 = arch::_mm512_and_epi64(values, mask4);
                    let s5 = arch::_mm512_and_epi64(values, mask5);
                    let s6 = arch::_mm512_and_epi64(values, mask6);
                    let s7 = arch::_mm512_and_epi64(values, mask7);

                    // Shift the selected byte of each u64, to its swapped place.
                    let s0 = arch::_mm512_slli_epi64(s0, 56);
                    let s1 = arch::_mm512_slli_epi64(s1, 40);
                    let s2 = arch::_mm512_slli_epi64(s2, 24);
                    let s3 = arch::_mm512_slli_epi64(s3, 8);

                    let s4 = arch::_mm512_srli_epi64(s4, 8);
                    let s5 = arch::_mm512_srli_epi64(s5, 24);
                    let s6 = arch::_mm512_srli_epi64(s6, 40);
                    let s7 = arch::_mm512_srli_epi64(s7, 56);

                    // Or the values to get the swapped u64 values.
                    let s01 = arch::_mm512_or_epi64(s0, s1);
                    let s23 = arch::_mm512_or_epi64(s2, s3);

                    let s45 = arch::_mm512_or_epi64(s4, s5);
                    let s67 = arch::_mm512_or_epi64(s6, s7);

                    let s03 = arch::_mm512_or_epi64(s01, s23);
                    let s47 = arch::_mm512_or_epi64(s45, s67);

                    let values = arch::_mm512_or_epi64(s03, s47);

                    // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    ab = arch::_mm512_add_epi64(ab, values);
                    cd = arch::_mm512_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), ab);
                arch::_mm512_storeu_si512(state.add(1), cd);
            }
        }

        unsafe { update_blocks_avx512f_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        any(feature = "fletcher2-avx512f", feature = "fletcher2-avx512bw"),
    ))]
    fn update_blocks_avx512f_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +---------------------+---------+
        // | _mm512_add_epi64    | AVX512F |
        // | _mm512_loadu_si512  | AVX512F |
        // | _mm512_storeu_si512 | AVX512F |
        // +---------------------+---------+

        #[target_feature(enable = "avx512f")]
        unsafe fn update_blocks_avx512f_native_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Load each octo stream into a zmm register.
                let state = state.as_ptr() as *mut arch::__m512i;
                let mut ab = arch::_mm512_loadu_epi64(state.add(0));
                let mut cd = arch::_mm512_loadu_epi64(state.add(1));

                // Iterate four blocks at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 512 bits into a zmm register.
                    let values = arch::_mm512_loadu_epi64(block.as_ptr() as *const _);

                    // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    ab = arch::_mm512_add_epi64(ab, values);
                    cd = arch::_mm512_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), ab);
                arch::_mm512_storeu_si512(state.add(1), cd);
            }
        }

        unsafe { update_blocks_avx512f_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher2-avx512bw",
    ))]
    fn update_blocks_avx512bw_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +---------------------+----------+
        // | _mm512_add_epi64    | AVX512F  |
        // | _mm512_loadu_si512  | AVX512F  |
        // | _mm512_shuffle_epi8 | AVX512BW |
        // | _mm512_storeu_si512 | AVX512F  |
        // +---------------------+----------+

        #[target_feature(enable = "avx512f,avx512bw")]
        unsafe fn update_blocks_avx512bw_byteswap_impl(state: &mut [u64], data: &[u8]) {
            unsafe {
                // Set the shuffle value.
                let shuffle = arch::_mm512_set_epi8(
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // f7
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // f6
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f5
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f4
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // f3
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // f2
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
                );

                // Load each octo stream into a zmm register.
                let state = state.as_ptr() as *mut arch::__m512i;
                let mut ab = arch::_mm512_loadu_epi64(state.add(0));
                let mut cd = arch::_mm512_loadu_epi64(state.add(1));

                // Iterate four blocks at a time.
                let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

                for block in iter.by_ref() {
                    // Load 512 bits into a zmm register.
                    let values = arch::_mm512_loadu_epi64(block.as_ptr() as *const _);

                    // Swap the order of the 8-byte parts of values.
                    // Each byte of shuffle indicates the byte index of values.
                    // The shuffle is done on each 256 bit lane, so the indices
                    // repeat for f0, f1, f2, f3 and f4, f5, f6, f7.
                    //
                    // index = shuffle[0..8]
                    // values[0..8] = values[index * 8..(index + 1) * 8]
                    // values[0..8] = values[56..64]
                    //
                    // index = shuffle[8..16]
                    // values[8..16] = values[index * 8..(index + 1) * 8]
                    // values[8..16] = values[48..56]
                    // ...
                    let values = arch::_mm512_shuffle_epi8(values, shuffle);

                    // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                    // ...
                    ab = arch::_mm512_add_epi64(ab, values);
                    cd = arch::_mm512_add_epi64(cd, ab);
                }

                // Save state.
                arch::_mm512_storeu_si512(state.add(0), ab);
                arch::_mm512_storeu_si512(state.add(1), cd);
            }
        }

        unsafe { update_blocks_avx512bw_byteswap_impl(state, data) }
    }
}

impl Checksum for Fletcher2 {
    fn reset(&mut self) -> Result<(), ChecksumError> {
        self.buffer = [0; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH];
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
        let remainder = self.buffer_fill % FLETCHER_2_BLOCK_SIZE;
        let full_block_bytes = self.buffer_fill - remainder;

        // Update full blocks.
        if full_block_bytes > 0 {
            let generic = match self.order {
                EndianOrder::Big => Fletcher2::update_blocks_generic_big,
                EndianOrder::Little => Fletcher2::update_blocks_generic_little,
            };

            (generic)(&mut result, &self.buffer[0..full_block_bytes]);
            result = Fletcher2::finish_blocks_single_stream(&result);
        }

        // Ignore remainder bytes, because they are not included in checksum.

        Ok(result)
    }

    fn hash(&mut self, data: &[u8]) -> Result<[u64; 4], ChecksumError> {
        self.reset()?;
        self.update(data)?;
        self.finalize()
    }
}

#[cfg(test)]
mod tests {

    use core::cmp;

    use crate::checksum::{Checksum, ChecksumError, Fletcher2, Fletcher2Implementation};
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

    const TEST_VECTOR_A_BIG_CHECKSUMS: [(usize, [u64; 4]); 10] = [
        // Empty test case.
        (0, [0, 0, 0, 0]),
        // Small test cases.
        (
            16,
            [
                0xbc4b4d5843ca3435,
                0xe4d059e4d02b08e3,
                0xbc4b4d5843ca3435,
                0xe4d059e4d02b08e3,
            ],
        ),
        (
            32,
            [
                0xec2ec63a2ac12569,
                0x69ac77f2e25337a1,
                0xa87a13926e8b599e,
                0x4e7cd1d7b27e4084,
            ],
        ),
        (
            64,
            [
                0xf89b99c04a0daa01,
                0x8df302dd274403dc,
                0xe1018e866df197b3,
                0xc22339f864df601f,
            ],
        ),
        (
            128,
            [
                0xadb4d111cb52e949,
                0x7b74c5c4fa24e3b4,
                0x23bf8e4632f63b6f,
                0x4676be1515c50b7,
            ],
        ),
        // Larger test cases.
        (
            8192,
            [
                0x6d344472d4ba5240,
                0xdd31713e8938ed00,
                0x6f56f29624f7d2c0,
                0xd68671e36b1d79c0,
            ],
        ),
        (
            16384,
            [
                0xda6888e5a974a480,
                0xba62e27d1271da00,
                0x4736cad5be942580,
                0xfef60d94814f380,
            ],
        ),
        (
            32768,
            [
                0xb4d111cb52e94900,
                0x74c5c4fa24e3b400,
                0x30912c514fba4b00,
                0xab68b5fc5791e700,
            ],
        ),
        (
            65536,
            [
                0x69a22396a5d29200,
                0xe98b89f449c76800,
                0xe9b0b339e9bc9600,
                0x84f93d1fccc3ce00,
            ],
        ),
        (
            131072,
            [
                0xd344472d4ba52400,
                0xd31713e8938ed000,
                0xf59ad0d0fc992c00,
                0xc291bedc10079c00,
            ],
        ),
    ];

    const TEST_VECTOR_A_LITTLE_CHECKSUMS: [(usize, [u64; 4]); 10] = [
        // Empty test case.
        (0, [0, 0, 0, 0]),
        // Small test cases.
        (
            16,
            [
                0x3534ca43584d4bbc,
                0xe3082bd0e459d0e4,
                0x3534ca43584d4bbc,
                0xe3082bd0e459d0e4,
            ],
        ),
        (
            32,
            [
                0x6a26c12a39c62eeb,
                0xa13653e2f278ad68,
                0x9f5b8b6d92137aa7,
                0x843e7fb3d6d27e4c,
            ],
        ),
        (
            64,
            [
                0x2ab0e49bf999bf6,
                0xde034427dd02f38c,
                0xb79bf26c848e02db,
                0x225ce166f73b25bc,
            ],
        ),
        (
            128,
            [
                0x4cea52ca11d0b3aa,
                0xb7e224fac4c57578,
                0x8144f62d428bc011,
                0xc74a5e55e06b6bf3,
            ],
        ),
        // Larger test cases.
        (
            8192,
            [
                0x3a94b284742cea80,
                0xf8893eb1315d5e00,
                0xfb9d45b2ff26da40,
                0x79b14be4b2c384c0,
            ],
        ),
        (
            16384,
            [
                0x75296508e859d500,
                0xf1127d6262babc00,
                0x209f944e5822b480,
                0x5dffa2c20430980,
            ],
        ),
        (
            32768,
            [
                0xea52ca11d0b3aa00,
                0xe224fac4c5757800,
                0xe6d34c3e17996900,
                0x55b57de32b761300,
            ],
        ),
        (
            65536,
            [
                0xd4a59423a1675400,
                0xc449f5898aeaf000,
                0x63f72701cc82d200,
                0xd34121f202ac2600,
            ],
        ),
        (
            131072,
            [
                0xa94b284742cea800,
                0x8893eb1315d5e000,
                0x2130881a0e45a400,
                0x45dadc92b4584c00,
            ],
        ),
    ];

    fn run_test_vector(
        h: &mut Fletcher2,
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
        implementation: Fletcher2Implementation,
    ) -> Result<(), ChecksumError> {
        let mut h = Fletcher2::new(EndianOrder::Big, implementation)?;

        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_BIG_CHECKSUMS)?;

        let mut h = Fletcher2::new(EndianOrder::Little, implementation)?;
        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_LITTLE_CHECKSUMS)?;

        Ok(())
    }

    fn test_optional_implementation(
        implementation: Fletcher2Implementation,
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
            ) = Fletcher2::new(*order, implementation)
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
    fn fletcher2_generic() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher2Implementation::Generic)
    }

    #[test]
    fn fletcher2_superscalar2() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher2Implementation::SuperScalar2)
    }

    #[test]
    fn fletcher2_superscalar4() -> Result<(), ChecksumError> {
        test_required_implementation(Fletcher2Implementation::SuperScalar4)
    }

    #[test]
    fn fletcher2_sse2() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher2Implementation::SSE2)
    }

    #[test]
    fn fletcher2_ssse3() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher2Implementation::SSSE3)
    }

    #[test]
    fn fletcher2_avx2() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher2Implementation::AVX2)
    }

    #[test]
    fn fletcher2_avx512f() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher2Implementation::AVX512F)
    }

    #[test]
    fn fletcher2_avx512bw() -> Result<(), ChecksumError> {
        test_optional_implementation(Fletcher2Implementation::AVX512BW)
    }
}
