// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::guest_config::cpuid::KvmCpuidFlags;
use vmm::guest_config::templates::x86_64::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterValueFilter,
};
use vmm::guest_config::templates::CustomCpuTemplate;

use crate::main_branch::bit_helper::{BitHelper, BitRangeExt};

pub fn t2() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            leaf_0x1_subleaf_0x0(),
            leaf_0x7_subleaf_0x0(),
            leaf_0xd_subleaf_0x0(),
            leaf_0xd_subleaf_0x1(),
            leaf_0x80000001_subleaf_0x0(),
            leaf_0x80000008_subleaf_0x0(),
        ],
        msr_modifiers: vec![],
    }
}

pub fn leaf_0x1_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x1::*;

    // EAX
    let mut eax_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Eax,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    eax_modifier
        .bitmap
        .value
        // Extended Family ID = 0
        .write_bits_in_range(&eax::EXTENDED_FAMILY_ID_BITRANGE, 0)
        // Extended Processor Model ID = 3 (Haswell)
        .write_bits_in_range(&eax::EXTENDED_PROCESSOR_MODEL_BITRANGE, 3)
        // Processor Type = 0 (Primary processor)
        .write_bits_in_range(&eax::PROCESSOR_TYPE_BITRANGE, 0)
        // Processor Family = 6
        .write_bits_in_range(&eax::PROCESSOR_FAMILY_BITRANGE, 6)
        // Processor Model = 15
        .write_bits_in_range(&eax::PROCESSOR_MODEL_BITRANGE, 15)
        // Stepping = 2
        .write_bits_in_range(&eax::STEPPING_BITRANGE, 2);

    eax_modifier.bitmap.filter = eax::EXTENDED_FAMILY_ID_BITRANGE.get_mask()
        | eax::EXTENDED_PROCESSOR_MODEL_BITRANGE.get_mask()
        | eax::PROCESSOR_TYPE_BITRANGE.get_mask()
        | eax::PROCESSOR_FAMILY_BITRANGE.get_mask()
        | eax::PROCESSOR_MODEL_BITRANGE.get_mask()
        | eax::STEPPING_BITRANGE.get_mask();

    // ECX
    let mut ecx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ecx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ecx_modifier
        .bitmap
        .value
        .write_bit(ecx::DTES64_BITINDEX, false)
        .write_bit(ecx::MONITOR_BITINDEX, false)
        .write_bit(ecx::DS_CPL_SHIFT, false)
        .write_bit(ecx::VMX_BITINDEX, false)
        .write_bit(ecx::SMX_BITINDEX, false)
        .write_bit(ecx::EIST_BITINDEX, false)
        .write_bit(ecx::TM2_BITINDEX, false)
        .write_bit(ecx::CNXT_ID_BITINDEX, false)
        .write_bit(ecx::SDBG_BITINDEX, false)
        .write_bit(ecx::XTPR_UPDATE_BITINDEX, false)
        .write_bit(ecx::PDCM_BITINDEX, false)
        .write_bit(ecx::DCA_BITINDEX, false);

    ecx_modifier.bitmap.filter = ecx::DTES64_BITINDEX.get_mask()
        | ecx::MONITOR_BITINDEX.get_mask()
        | ecx::DS_CPL_SHIFT.get_mask()
        | ecx::VMX_BITINDEX.get_mask()
        | ecx::SMX_BITINDEX.get_mask()
        | ecx::EIST_BITINDEX.get_mask()
        | ecx::TM2_BITINDEX.get_mask()
        | ecx::CNXT_ID_BITINDEX.get_mask()
        | ecx::SDBG_BITINDEX.get_mask()
        | ecx::XTPR_UPDATE_BITINDEX.get_mask()
        | ecx::PDCM_BITINDEX.get_mask()
        | ecx::DCA_BITINDEX.get_mask();

    // EDX
    let mut edx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Edx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    edx_modifier
        .bitmap
        .value
        .write_bit(edx::MCE_BITINDEX, true)
        .write_bit(edx::MTRR_BITINDEX, true)
        .write_bit(edx::PSN_BITINDEX, false)
        .write_bit(edx::DS_BITINDEX, false)
        .write_bit(edx::ACPI_BITINDEX, false)
        .write_bit(edx::SS_BITINDEX, false)
        .write_bit(edx::TM_BITINDEX, false)
        .write_bit(edx::IA64_BITINDEX, false)
        .write_bit(edx::PBE_BITINDEX, false);

    edx_modifier.bitmap.filter = edx::MCE_BITINDEX.get_mask()
        | edx::MTRR_BITINDEX.get_mask()
        | edx::PSN_BITINDEX.get_mask()
        | edx::DS_BITINDEX.get_mask()
        | edx::ACPI_BITINDEX.get_mask()
        | edx::SS_BITINDEX.get_mask()
        | edx::TM_BITINDEX.get_mask()
        | edx::IA64_BITINDEX.get_mask()
        | edx::PBE_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(0),
        modifiers: vec![eax_modifier, ecx_modifier, edx_modifier],
    }
}

pub fn leaf_0x7_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x7::index0::*;
    use crate::main_branch::cpu_leaf::leaf_0x7::*;

    // EBX
    let mut ebx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ebx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ebx_modifier
        .bitmap
        .value
        .write_bit(ebx::SGX_BITINDEX, false)
        .write_bit(ebx::HLE_BITINDEX, false)
        .write_bit(ebx::FPDP_BITINDEX, false)
        .write_bit(ebx::ERMS_BITINDEX, true)
        .write_bit(ebx::RTM_BITINDEX, false)
        .write_bit(ebx::RDT_M_BITINDEX, false)
        .write_bit(ebx::FPU_CS_DS_DEPRECATE_BITINDEX, false)
        .write_bit(ebx::MPX_BITINDEX, false)
        .write_bit(ebx::RDT_A_BITINDEX, false)
        .write_bit(ebx::AVX512F_BITINDEX, false)
        .write_bit(ebx::AVX512DQ_BITINDEX, false)
        .write_bit(ebx::RDSEED_BITINDEX, false)
        .write_bit(ebx::ADX_BITINDEX, false)
        .write_bit(ebx::AVX512IFMA_BITINDEX, false)
        .write_bit(ebx::PCOMMIT_BITINDEX, false)
        .write_bit(ebx::CLFLUSHOPT_BITINDEX, false)
        .write_bit(ebx::CLWB_BITINDEX, false)
        .write_bit(ebx::PT_BITINDEX, false)
        .write_bit(ebx::AVX512PF_BITINDEX, false)
        .write_bit(ebx::AVX512ER_BITINDEX, false)
        .write_bit(ebx::AVX512CD_BITINDEX, false)
        .write_bit(ebx::SHA_BITINDEX, false)
        .write_bit(ebx::AVX512BW_BITINDEX, false)
        .write_bit(ebx::AVX512VL_BITINDEX, false);

    ebx_modifier.bitmap.filter = ebx::SGX_BITINDEX.get_mask()
        | ebx::HLE_BITINDEX.get_mask()
        | ebx::FPDP_BITINDEX.get_mask()
        | ebx::ERMS_BITINDEX.get_mask()
        | ebx::RTM_BITINDEX.get_mask()
        | ebx::RDT_M_BITINDEX.get_mask()
        | ebx::FPU_CS_DS_DEPRECATE_BITINDEX.get_mask()
        | ebx::MPX_BITINDEX.get_mask()
        | ebx::RDT_A_BITINDEX.get_mask()
        | ebx::AVX512F_BITINDEX.get_mask()
        | ebx::AVX512DQ_BITINDEX.get_mask()
        | ebx::RDSEED_BITINDEX.get_mask()
        | ebx::ADX_BITINDEX.get_mask()
        | ebx::AVX512IFMA_BITINDEX.get_mask()
        | ebx::PCOMMIT_BITINDEX.get_mask()
        | ebx::CLFLUSHOPT_BITINDEX.get_mask()
        | ebx::CLWB_BITINDEX.get_mask()
        | ebx::PT_BITINDEX.get_mask()
        | ebx::AVX512PF_BITINDEX.get_mask()
        | ebx::AVX512ER_BITINDEX.get_mask()
        | ebx::AVX512CD_BITINDEX.get_mask()
        | ebx::SHA_BITINDEX.get_mask()
        | ebx::AVX512BW_BITINDEX.get_mask()
        | ebx::AVX512VL_BITINDEX.get_mask();

    // ECX
    let mut ecx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ecx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ecx_modifier
        .bitmap
        .value
        .write_bit(ecx::AVX512_VBMI_BITINDEX, false)
        .write_bit(ecx::UMIP_BITINDEX, false)
        .write_bit(ecx::PKU_BITINDEX, false)
        .write_bit(ecx::OSPKE_BITINDEX, false)
        .write_bit(ecx::AVX512_VBMI2_BITINDEX, false)
        .write_bit(ecx::GFNI_BITINDEX, false)
        .write_bit(ecx::VAES_BITINDEX, false)
        .write_bit(ecx::VPCLMULQDQ_BITINDEX, false)
        .write_bit(ecx::AVX512_VNNI_BITINDEX, false)
        .write_bit(ecx::AVX512_BITALG_BITINDEX, false)
        .write_bit(ecx::AVX512_VPOPCNTDQ_BITINDEX, false)
        .write_bit(ecx::LA57_BITINDEX, false)
        .write_bit(ecx::RDPID_BITINDEX, false)
        .write_bit(ecx::SGX_LC_BITINDEX, false);

    ecx_modifier.bitmap.filter = ecx::AVX512_VBMI_BITINDEX.get_mask()
        | ecx::UMIP_BITINDEX.get_mask()
        | ecx::PKU_BITINDEX.get_mask()
        | ecx::OSPKE_BITINDEX.get_mask()
        | ecx::AVX512_VBMI2_BITINDEX.get_mask()
        | ecx::GFNI_BITINDEX.get_mask()
        | ecx::VAES_BITINDEX.get_mask()
        | ecx::VPCLMULQDQ_BITINDEX.get_mask()
        | ecx::AVX512_VNNI_BITINDEX.get_mask()
        | ecx::AVX512_BITALG_BITINDEX.get_mask()
        | ecx::AVX512_VPOPCNTDQ_BITINDEX.get_mask()
        | ecx::LA57_BITINDEX.get_mask()
        | ecx::RDPID_BITINDEX.get_mask()
        | ecx::SGX_LC_BITINDEX.get_mask();

    // EDX
    let mut edx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Edx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    edx_modifier
        .bitmap
        .value
        .write_bit(edx::AVX512_4VNNIW_BITINDEX, false)
        .write_bit(edx::AVX512_4FMAPS_BITINDEX, false)
        .write_bit(edx::FSRM_BITINDEX, false)
        .write_bit(edx::AVX512_VP2INTERSECT_BITINDEX, false);

    edx_modifier.bitmap.filter = edx::AVX512_4VNNIW_BITINDEX.get_mask()
        | edx::AVX512_4FMAPS_BITINDEX.get_mask()
        | edx::FSRM_BITINDEX.get_mask()
        | edx::AVX512_VP2INTERSECT_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(1),
        modifiers: vec![ebx_modifier, ecx_modifier, edx_modifier],
    }
}

pub fn leaf_0xd_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0xd::*;

    // EAX
    let mut eax_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Eax,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    eax_modifier
        .bitmap
        .value
        .write_bits_in_range(&index0::eax::MPX_STATE_BITRANGE, 0)
        .write_bits_in_range(&index0::eax::AVX512_STATE_BITRANGE, 0)
        .write_bit(index0::eax::PKRU_BITINDEX, false);

    eax_modifier.bitmap.filter = index0::eax::MPX_STATE_BITRANGE.get_mask()
        | index0::eax::AVX512_STATE_BITRANGE.get_mask()
        | index0::eax::PKRU_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(1),
        modifiers: vec![eax_modifier],
    }
}

pub fn leaf_0xd_subleaf_0x1() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0xd::*;

    let mut eax_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Eax,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    eax_modifier
        .bitmap
        .value
        .write_bit(index1::eax::XSAVEC_SHIFT, false)
        .write_bit(index1::eax::XGETBV_SHIFT, false)
        .write_bit(index1::eax::XSAVES_SHIFT, false);

    eax_modifier.bitmap.filter = index1::eax::XSAVEC_SHIFT.get_mask()
        | index1::eax::XGETBV_SHIFT.get_mask()
        | index1::eax::XSAVES_SHIFT.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x1,
        flags: KvmCpuidFlags(1),
        modifiers: vec![eax_modifier],
    }
}

pub fn leaf_0x80000001_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x80000001::*;

    // ECX
    let mut ecx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ecx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ecx_modifier
        .bitmap
        .value
        .write_bit(ecx::PREFETCH_BITINDEX, false)
        .write_bit(ecx::MWAIT_EXTENDED_BITINDEX, false);

    ecx_modifier.bitmap.filter =
        ecx::PREFETCH_BITINDEX.get_mask() | ecx::MWAIT_EXTENDED_BITINDEX.get_mask();

    // EDX
    let mut edx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Edx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    edx_modifier
        .bitmap
        .value
        .write_bit(edx::PDPE1GB_BITINDEX, false);

    edx_modifier.bitmap.filter = edx::PDPE1GB_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(0),
        modifiers: vec![ecx_modifier, edx_modifier],
    }
}

pub fn leaf_0x80000008_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x80000008::*;

    // EBX
    let mut ebx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ebx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ebx_modifier
        .bitmap
        .value
        .write_bit(ebx::WBNOINVD_BITINDEX, false);

    ebx_modifier.bitmap.filter = ebx::WBNOINVD_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(0),
        modifiers: vec![ebx_modifier],
    }
}
