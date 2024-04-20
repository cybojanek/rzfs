// SPDX-License-Identifier: GPL-2.0 OR MIT

use crate::checksum::{Checksum, ChecksumError};
use crate::phys::{ChecksumType, EndianOrder};

use core::cmp;
use core::fmt;
use core::fmt::Display;

////////////////////////////////////////////////////////////////////////////////

/// Sha256 block size in bytes.
const SHA_256_BLOCK_SIZE: usize = 64;

/// Sha256 in u32.
const SHA_256_U32_COUNT: usize = 8;

/// Sha256 implementation.
#[derive(Copy, Clone, Debug)]
pub enum Sha256Implementation {
    /// Generic.
    Generic,
}

/// Initial state H constants.
const SHA_256_H: [u32; SHA_256_U32_COUNT] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// K constants.
const SHA_256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const ALL_SHA_256_IMPLEMENTATIONS: [Sha256Implementation; 1] = [Sha256Implementation::Generic];

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
        }
    }

    /// Get the string name of the implementation.
    pub fn to_str(&self) -> &'static str {
        match self {
            Sha256Implementation::Generic => "generic",
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
    fn new(
        order: EndianOrder,
        implementation: Sha256Implementation,
    ) -> Result<Sha256ImplementationCtx, ChecksumError> {
        if !implementation.is_supported() {
            return Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Sha256,
                order,
                implementation: implementation.to_str(),
            });
        }

        match implementation {
            Sha256Implementation::Generic => Ok(Sha256ImplementationCtx {
                update_blocks: Sha256::update_blocks_generic,
            }),
        }
    }
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
    pub fn new(
        order: EndianOrder,
        implementation: Sha256Implementation,
    ) -> Result<Sha256, ChecksumError> {
        Ok(Sha256 {
            bytes_processed: 0,
            buffer_fill: 0,
            buffer: [0; SHA_256_BLOCK_SIZE],
            state: SHA_256_H,
            impl_ctx: Sha256ImplementationCtx::new(order, implementation)?,
        })
    }

    fn update_blocks_generic(state: &mut [u32], data: &[u8]) {
        // Iterate one block at a time.
        let mut iter = data.chunks_exact(SHA_256_BLOCK_SIZE);

        for block in iter.by_ref() {
            let mut w: [u32; 64] = [0; 64];

            // Initialize w[0..16].
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
            }

            // Compute w[16..64].
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // Initialize local variables.
            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            // Run compression loop.
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA_256_K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }
    }
}

impl Checksum for Sha256 {
    fn reset(&mut self) -> Result<(), ChecksumError> {
        self.bytes_processed = 0;
        self.buffer = [0; SHA_256_BLOCK_SIZE];
        self.buffer_fill = 0;
        self.state = SHA_256_H;

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
                Sha256::update_blocks_generic(&mut self.state, &full_blocks_data);
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
            Sha256::update_blocks_generic(&mut self.state, &data);
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
        Sha256::update_blocks_generic(&mut self.state, &data);

        // Encode result to u64.
        Ok([
            (u64::from(self.state[0]) << 32) | u64::from(self.state[1]),
            (u64::from(self.state[2]) << 32) | u64::from(self.state[3]),
            (u64::from(self.state[4]) << 32) | u64::from(self.state[5]),
            (u64::from(self.state[6]) << 32) | u64::from(self.state[7]),
        ])
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
        vector: &[u8],
        checksums: &[(usize, [u64; 4])],
    ) -> Result<(), ChecksumError> {
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
        implementation: Sha256Implementation,
    ) -> Result<(), ChecksumError> {
        let mut h = Sha256::new(EndianOrder::Big, implementation)?;
        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_CHECKSUMS)?;

        let mut h = Sha256::new(EndianOrder::Little, implementation)?;
        run_test_vector(&mut h, &TEST_VECTOR_A, &TEST_VECTOR_A_CHECKSUMS)?;

        Ok(())
    }

    #[test]
    fn sha256_generic() -> Result<(), ChecksumError> {
        test_required_implementation(Sha256Implementation::Generic)
    }
}
