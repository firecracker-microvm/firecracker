// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;

/// A capability the kernel's KVM interface can possibly expose.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
// We are allowing docs to be missing here because this enum is a wrapper
// over auto-generated code.
#[allow(missing_docs)]
pub enum Cap {
    Irqchip = KVM_CAP_IRQCHIP,
    Hlt = KVM_CAP_HLT,
    MmuShadowCacheControl = KVM_CAP_MMU_SHADOW_CACHE_CONTROL,
    UserMemory = KVM_CAP_USER_MEMORY,
    SetTssAddr = KVM_CAP_SET_TSS_ADDR,
    Vapic = KVM_CAP_VAPIC,
    ExtCpuid = KVM_CAP_EXT_CPUID,
    Clocksource = KVM_CAP_CLOCKSOURCE,
    NrVcpus = KVM_CAP_NR_VCPUS,
    NrMemslots = KVM_CAP_NR_MEMSLOTS,
    Pit = KVM_CAP_PIT,
    NopIoDelay = KVM_CAP_NOP_IO_DELAY,
    PvMmu = KVM_CAP_PV_MMU,
    MpState = KVM_CAP_MP_STATE,
    CoalescedMmio = KVM_CAP_COALESCED_MMIO,
    SyncMmu = KVM_CAP_SYNC_MMU,
    Iommu = KVM_CAP_IOMMU,
    DestroyMemoryRegionWorks = KVM_CAP_DESTROY_MEMORY_REGION_WORKS,
    UserNmi = KVM_CAP_USER_NMI,
    SetGuestDebug = KVM_CAP_SET_GUEST_DEBUG,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ReinjectControl = KVM_CAP_REINJECT_CONTROL,
    IrqRouting = KVM_CAP_IRQ_ROUTING,
    IrqInjectStatus = KVM_CAP_IRQ_INJECT_STATUS,
    AssignDevIrq = KVM_CAP_ASSIGN_DEV_IRQ,
    JoinMemoryRegionsWorks = KVM_CAP_JOIN_MEMORY_REGIONS_WORKS,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Mce = KVM_CAP_MCE,
    Irqfd = KVM_CAP_IRQFD,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Pit2 = KVM_CAP_PIT2,
    SetBootCpuId = KVM_CAP_SET_BOOT_CPU_ID,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    PitState2 = KVM_CAP_PIT_STATE2,
    Ioeventfd = KVM_CAP_IOEVENTFD,
    SetIdentityMapAddr = KVM_CAP_SET_IDENTITY_MAP_ADDR,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    XenHvm = KVM_CAP_XEN_HVM,
    AdjustClock = KVM_CAP_ADJUST_CLOCK,
    InternalErrorData = KVM_CAP_INTERNAL_ERROR_DATA,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    VcpuEvents = KVM_CAP_VCPU_EVENTS,
    S390Psw = KVM_CAP_S390_PSW,
    PpcSegstate = KVM_CAP_PPC_SEGSTATE,
    Hyperv = KVM_CAP_HYPERV,
    HypervVapic = KVM_CAP_HYPERV_VAPIC,
    HypervSpin = KVM_CAP_HYPERV_SPIN,
    PciSegment = KVM_CAP_PCI_SEGMENT,
    PpcPairedSingles = KVM_CAP_PPC_PAIRED_SINGLES,
    IntrShadow = KVM_CAP_INTR_SHADOW,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Debugregs = KVM_CAP_DEBUGREGS,
    X86RobustSinglestep = KVM_CAP_X86_ROBUST_SINGLESTEP,
    PpcOsi = KVM_CAP_PPC_OSI,
    PpcUnsetIrq = KVM_CAP_PPC_UNSET_IRQ,
    EnableCap = KVM_CAP_ENABLE_CAP,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Xsave = KVM_CAP_XSAVE,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Xcrs = KVM_CAP_XCRS,
    PpcGetPvinfo = KVM_CAP_PPC_GET_PVINFO,
    PpcIrqLevel = KVM_CAP_PPC_IRQ_LEVEL,
    AsyncPf = KVM_CAP_ASYNC_PF,
    TscControl = KVM_CAP_TSC_CONTROL,
    GetTscKhz = KVM_CAP_GET_TSC_KHZ,
    PpcBookeSregs = KVM_CAP_PPC_BOOKE_SREGS,
    SpaprTce = KVM_CAP_SPAPR_TCE,
    PpcSmt = KVM_CAP_PPC_SMT,
    PpcRma = KVM_CAP_PPC_RMA,
    MaxVcpus = KVM_CAP_MAX_VCPUS,
    PpcHior = KVM_CAP_PPC_HIOR,
    PpcPapr = KVM_CAP_PPC_PAPR,
    SwTlb = KVM_CAP_SW_TLB,
    OneReg = KVM_CAP_ONE_REG,
    S390Gmap = KVM_CAP_S390_GMAP,
    TscDeadlineTimer = KVM_CAP_TSC_DEADLINE_TIMER,
    S390Ucontrol = KVM_CAP_S390_UCONTROL,
    SyncRegs = KVM_CAP_SYNC_REGS,
    Pci23 = KVM_CAP_PCI_2_3,
    KvmclockCtrl = KVM_CAP_KVMCLOCK_CTRL,
    SignalMsi = KVM_CAP_SIGNAL_MSI,
    PpcGetSmmuInfo = KVM_CAP_PPC_GET_SMMU_INFO,
    S390Cow = KVM_CAP_S390_COW,
    PpcAllocHtab = KVM_CAP_PPC_ALLOC_HTAB,
    ReadonlyMem = KVM_CAP_READONLY_MEM,
    IrqfdResample = KVM_CAP_IRQFD_RESAMPLE,
    PpcBookeWatchdog = KVM_CAP_PPC_BOOKE_WATCHDOG,
    PpcHtabFd = KVM_CAP_PPC_HTAB_FD,
    S390CssSupport = KVM_CAP_S390_CSS_SUPPORT,
    PpcEpr = KVM_CAP_PPC_EPR,
    ArmPsci = KVM_CAP_ARM_PSCI,
    ArmSetDeviceAddr = KVM_CAP_ARM_SET_DEVICE_ADDR,
    DeviceCtrl = KVM_CAP_DEVICE_CTRL,
    IrqMpic = KVM_CAP_IRQ_MPIC,
    PpcRtas = KVM_CAP_PPC_RTAS,
    IrqXics = KVM_CAP_IRQ_XICS,
    ArmEl132bit = KVM_CAP_ARM_EL1_32BIT,
    SpaprMultitce = KVM_CAP_SPAPR_MULTITCE,
    ExtEmulCpuid = KVM_CAP_EXT_EMUL_CPUID,
    HypervTime = KVM_CAP_HYPERV_TIME,
    IoapicPolarityIgnored = KVM_CAP_IOAPIC_POLARITY_IGNORED,
    EnableCapVm = KVM_CAP_ENABLE_CAP_VM,
    S390Irqchip = KVM_CAP_S390_IRQCHIP,
    IoeventfdNoLength = KVM_CAP_IOEVENTFD_NO_LENGTH,
    VmAttributes = KVM_CAP_VM_ATTRIBUTES,
    ArmPsci02 = KVM_CAP_ARM_PSCI_0_2,
    PpcFixupHcall = KVM_CAP_PPC_FIXUP_HCALL,
    PpcEnableHcall = KVM_CAP_PPC_ENABLE_HCALL,
    CheckExtensionVm = KVM_CAP_CHECK_EXTENSION_VM,
    S390UserSigp = KVM_CAP_S390_USER_SIGP,
    ImmediateExit = KVM_CAP_IMMEDIATE_EXIT,
}
