// SPDX-License-Identifier: GPL-2.0 OR MIT
#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

////////////////////////////////////////////////////////////////////////////////

const LEAF_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 1;

const MASK_LEAF_PIAFB_EDX_SSE_2: u32 = 1 << 26;

const MASK_LEAF_PIAFB_ECX_SSSE_3: u32 = 1 << 9;

const MASK_LEAF_PIAFB_ECX_AVX: u32 = 1 << 28;

////////////////////////////////////////////////////////////////////////////////

const LEAF_EXTENDED_FEATURES: u32 = 7;

const MASK_LEAF_EXFT_EBX_AVX_2: u32 = 1 << 5;

////////////////////////////////////////////////////////////////////////////////

/// Is AVX supported by the CPU.
pub(crate) fn is_avx_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_PROCESSOR_INFO_AND_FEATURE_BITS {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_PROCESSOR_INFO_AND_FEATURE_BITS);

        (cpuid.ecx & MASK_LEAF_PIAFB_ECX_AVX) != 0
    }
}

/// Is AVX2 supported by the CPU.
pub(crate) fn is_avx2_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_AVX_2) != 0
    }
}

/// Is SSE2 supported by the CPU.
pub(crate) fn is_sse2_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_PROCESSOR_INFO_AND_FEATURE_BITS {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_PROCESSOR_INFO_AND_FEATURE_BITS);

        (cpuid.edx & MASK_LEAF_PIAFB_EDX_SSE_2) != 0
    }
}

/// Is SSSE3 supported by the CPU.
pub(crate) fn is_ssse3_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_PROCESSOR_INFO_AND_FEATURE_BITS {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_PROCESSOR_INFO_AND_FEATURE_BITS);

        (cpuid.ecx & MASK_LEAF_PIAFB_ECX_SSSE_3) != 0
    }
}
