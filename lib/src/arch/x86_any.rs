// SPDX-License-Identifier: GPL-2.0 OR MIT
#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

////////////////////////////////////////////////////////////////////////////////

const LEAF_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 1;

const MASK_LEAF_PIAFB_EDX_SSE_2: u32 = 1 << 26;

const MASK_LEAF_PIAFB_ECX_SSE_3: u32 = 1 << 0;
const MASK_LEAF_PIAFB_ECX_SSSE_3: u32 = 1 << 9;
const MASK_LEAF_PIAFB_ECX_AVX: u32 = 1 << 28;

////////////////////////////////////////////////////////////////////////////////

const LEAF_EXTENDED_FEATURES: u32 = 7;

const MASK_LEAF_EXFT_EBX_BMI1: u32 = 1 << 3;
const MASK_LEAF_EXFT_EBX_AVX_2: u32 = 1 << 5;
const MASK_LEAF_EXFT_EBX_BMI2: u32 = 1 << 8;
const MASK_LEAF_EXFT_EBX_AVX_512_F: u32 = 1 << 16;
const MASK_LEAF_EXFT_EBX_SHA: u32 = 1 << 29;
const MASK_LEAF_EXFT_EBX_AVX_512_BW: u32 = 1 << 30;

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

/// Is AVX512F supported by the CPU.
pub(crate) fn is_avx512f_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_AVX_512_F) != 0
    }
}

/// Is AVX512BW supported by the CPU.
pub(crate) fn is_avx512bw_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_AVX_512_BW) != 0
    }
}

/// Is BMI1 supported by the CPU.
pub(crate) fn is_bmi1_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_BMI1) != 0
    }
}

/// Is BMI2 supported by the CPU.
pub(crate) fn is_bmi2_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_BMI2) != 0
    }
}

/// Is SHA supported by the CPU.
pub(crate) fn is_sha_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_EXTENDED_FEATURES {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_EXTENDED_FEATURES);

        (cpuid.ebx & MASK_LEAF_EXFT_EBX_SHA) != 0
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

/// Is SSE3 supported by the CPU.
pub(crate) fn is_sse3_supported() -> bool {
    unsafe {
        // Get number of leaves.
        let (leaf_max, _) = arch::__get_cpuid_max(0);
        if leaf_max < LEAF_PROCESSOR_INFO_AND_FEATURE_BITS {
            return false;
        }

        let cpuid = arch::__cpuid(LEAF_PROCESSOR_INFO_AND_FEATURE_BITS);

        (cpuid.ecx & MASK_LEAF_PIAFB_ECX_SSE_3) != 0
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
