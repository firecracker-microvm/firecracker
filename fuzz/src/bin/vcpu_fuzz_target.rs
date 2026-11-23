// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

/// Fuzzer for vCPU restore functionality
///
/// This fuzzer loads a randomized vcpu state and tries to execute KVM_RUN. It can catch the
/// following issues:
/// - Crashes during deserialization of vcpu states
/// - Inability to restore a vcpu state that was retrieved from a microvm
/// - crashes in KVM due to invalid vcpu states
mod fuzzing {
    use bincode::Options;
    use fuzzer::check_hugepages_available;
    use serde::{Deserialize, Serialize};
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::kvm::Kvm;
    use vmm::vstate::memory::{GuestMemoryState, anonymous};
    use vmm::vstate::vcpu::VcpuState;
    use vmm::vstate::vm::KvmVm;
    use vmm::vstate::vm::VmError;

    /// KVM allocates an internal memslot of size of page at this address for the APIC access page.
    /// If the fuzzer happens to construct a guest memory map that puts ordinary guest memory that
    /// overlaps with this page, KVM_CREATE_VCPU will fail with `EEXIST`.
    pub const APIC_DEFAULT_PHYS_BASE: usize = 0xfee00000;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct FuzzData {
        /// Decision variable for whether 2M hugetlbfs should be used
        pub huge_pages: bool,
        /// Decision variables used to perform a sequence of save/restore operations
        pub bools: [bool; 8],
        pub memory_state: GuestMemoryState,
        pub vcpu_state: VcpuState,
    }

    pub const MAX_MEMORY: usize = 8 * 1024 * 1024; // 8MB

    pub fn target(input: &[u8]) {
        let Ok(mut data) = bincode::DefaultOptions::new()
            .allow_trailing_bytes()
            .with_limit(MAX_MEMORY as u64)
            .with_fixint_encoding()
            .deserialize::<FuzzData>(input)
        else {
            return;
        };

        let page_size = vmm::arch::host_page_size();

        let huge_page_config = match data.huge_pages {
            true => {
                // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
                // would fail with SIGBUS.
                if !check_hugepages_available(MAX_MEMORY) {
                    return;
                }
                HugePageConfig::Hugetlbfs2M
            }
            false => HugePageConfig::None,
        };

        let mut budget = MAX_MEMORY;
        for region in &mut data.memory_state.regions {
            region.size = region.size.clamp(0, budget);
            budget -= region.size;

            // Check this memory region does not overlap with the APIC access page
            if !(region.base_address as usize >= APIC_DEFAULT_PHYS_BASE + page_size
                || region.base_address as usize + region.size <= APIC_DEFAULT_PHYS_BASE)
            {
                return;
            }
        }

        let kvm = Kvm::new(vec![]).unwrap();
        let mut vm = KvmVm::new(kvm).unwrap();

        let Ok(memory) = anonymous(&data.memory_state.regions(), false, huge_page_config) else {
            return;
        };

        match vm.register_dram_memory_regions(memory) {
            Ok(_) => {}
            // When loading a randomized guest memory state, we can get something that KVM rejects
            // (e.g. offset of some region larger than backing mmap region).
            Err(VmError::SetUserMemoryRegion(err))
                if err.errno() == libc::EINVAL || err.errno() == libc::EFAULT =>
            {
                return;
            }
            // If we got overlapping memory regions in the randomized state, registration will
            // (deterministically) fail.
            Err(VmError::InsertRegion(
                vm_memory::GuestRegionCollectionError::MemoryRegionOverlap,
            )) => {
                return;
            }
            Err(err) => panic!("{:?}", err),
        }

        // We are going to restore state once below and then up to len(bools) times in a loop,
        // so we create len(bools) + 1 vcpus.
        let mut vcpus = vm.create_vcpus((data.bools.len() + 1) as u8).unwrap();

        let mut vcpu = vcpus.pop().unwrap();

        if vcpu.kvm_vcpu.restore_state(&data.vcpu_state).is_err() {
            return;
        }

        // On kernel 4.14, KVM_SET_SREGS has some validation checks against EFER, CR0 and
        // CR4 in kvm_valid_sregs() before actually setting a given sregs to vcpu. When this
        // validation fails, KVM_SET_SREGS also exits with error 22.
        // https://elixir.bootlin.com/linux/latest/source/arch/x86/kvm/x86.c#L11383
        // https://elixir.bootlin.com/linux/v4.14.313/source/arch/x86/kvm/x86.c#L7738
        //
        // Besides that, it has another validation check against CR4 in vmx_set_cr4() on
        // Intel and svm_set_cr4() on AMD just before assigning the given value to
        // vcpu->arch.cr4, and returns an error when it is invalid.
        // https://elixir.bootlin.com/linux/v5.10/source/arch/x86/kvm/vmx/vmx.c#L3098
        // https://elixir.bootlin.com/linux/v5.10/source/arch/x86/kvm/svm/svm.c#L1687
        // However the caller kvm_arch_vcpu_ioctl_set_sregs() ignores the return value, and
        // KVM_SET_SREGS exits successfully without setting the CR4 value.
        // https://elixir.bootlin.com/linux/v4.14.313/source/arch/x86/kvm/x86.c#L7806
        //
        // Based on the above facts, suppose a randomly-mutated CR4 has partially-invalid
        // value that passes kvm_valid_sregs()'s validation but doesn't pass vmx_set_cr4() /
        // svm_set_cr4()'s validation. The first KvmVcpu::restore_state() succeeds, since we
        // only use a restorable state that passes kvm_valid_sregs()'s validation. But under
        // the ground, the CR4 value is not set silently when it doesn't pass
        // vmx_set_cr4()'s validation. Against such a vcpu, this fuzzer tries to save and
        // restore the state with CR4=0. Thus, a successive restoration fails to pass the
        // first validation and KVM_SET_SREGS exits with an error.
        //
        // This issue has been fixed in kernel 5.11 and was backported to kernel 5.10 but
        // not to kernel 4.14.
        // https://github.com/torvalds/linux/commit/c2fe3cd4604ac87c587db05d41843d667dc43815
        // https://lore.kernel.org/all/20201007014417.29276-5-sean.j.christopherson@intel.com/
        // https://lore.kernel.org/all/1669810906116@kroah.com/
        //
        // To mitigate the above issue, we verify that the given CR4 is correctly restored
        // as a temporary mitigation.
        //
        // On kernel 5.10 KVM_SET_SREGS has an unexpected behaviour that resets the EFER_LME
        // bit in the EFER register. This happens because the EFER is being reset
        // with host EFER value here:
        // https://elixir.bootlin.com/linux/v5.10.206/source/arch/x86/kvm/vmx/vmx.c#L1136
        // to mitigate this we additionally check that EFER in the restored state is the
        // same as in the original state otherwise the check in KVM returns EINVAL from
        // here https://elixir.bootlin.com/linux/v5.10.206/source/arch/x86/kvm/x86.c#L9902.
        #[cfg(target_arch = "x86_64")]
        let restored = {
            let restored_state = vcpu.kvm_vcpu.save_state().unwrap();
            restored_state.sregs.cr4 == data.vcpu_state.sregs.cr4
                && restored_state.sregs.efer == data.vcpu_state.sregs.efer
        };

        // TODO: Remove `restored` variable by using `impl Drop`.
        // More details can be found in the following link.
        // https://github.com/firecracker-microvm/fuzzer/pull/117#discussion_r1210030899
        #[cfg(target_arch = "aarch64")]
        let restored = true;

        if restored {
            let mut state = None;

            // Go through some cycles of save and restore vcpu state.
            for b in data.bools {
                if b {
                    state = Some(vcpu.kvm_vcpu.save_state().unwrap());
                } else {
                    if let Some(state) = state.take() {
                        // Use another vcpu to avoid restoring again on an already existing one
                        vcpu = vcpus.pop().unwrap();
                        vcpu.kvm_vcpu
                            .restore_state(&state)
                            .expect(&format!("{:?}", state));
                    }
                }
            }

            // We set kvm_immediate_exit to 1 to make sure the KVM_RUN invoked by
            // run_emulation() immediately exits. This means that we ensure that KVM finds
            // a "proper" environment (as otherwise it would exit KVM_RUN with some error
            // instead of the Interrupted flag), without needing to (potentially
            // nondeterministically) wait for the vcpu to hit some instruction that
            // causes it to trap.
            vcpu.kvm_vcpu.fd.set_kvm_immediate_exit(1);

            // VcpuEmulation is not public in firecracker
            assert_eq!(vcpu.kvm_vcpu.fd.run().unwrap_err().errno(), libc::EINTR);
        }
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module containing "unit tests" that do not test things but rather generate input seeds for
    //! AFL

    use std::fs::OpenOptions;

    #[cfg(target_arch = "aarch64")]
    use vmm::VcpuConfig;
    use vmm::arch::{BootProtocol, EntryPoint};
    use vmm::cpu_config::templates::CpuConfiguration;
    use vmm::test_utils::arch_mem_raw;
    use vmm::vstate::kvm::Kvm;
    use vmm::vstate::memory::{GuestAddress, GuestMemoryExtension};
    use vmm::vstate::vm::KvmVm;

    use crate::fuzzing::{FuzzData, MAX_MEMORY};

    #[test]
    fn generate_valid_state() {
        let capabilities = Vec::new();
        let kvm = Kvm::new(capabilities).unwrap();

        let mut vm = KvmVm::new(kvm).unwrap();

        let memory = arch_mem_raw(MAX_MEMORY);
        vm.register_dram_memory_regions(memory).unwrap();

        let mut vcpu = vm.create_vcpus(1).unwrap().remove(0);

        #[cfg(target_arch = "aarch64")]
        vcpu.kvm_vcpu.init(&[]).unwrap();

        // On x86_64, load a template to give the fuzzer some data to work fuzz in the VCpuState's
        // CPUID/MSR fields. Note that it does not matter what template we use here, or whether
        // this template is compatible with the instance/CPU that the fuzzer runs on, since the
        // fuzz engine will randomly mutate it anyway.
        #[cfg(target_arch = "x86_64")]
        let cpu_config = {
            use std::convert::TryFrom;

            use vmm::cpu_config::x86_64::cpuid::Cpuid;

            let cpu_template = vmm::cpu_config::x86_64::static_cpu_templates::t2cl::t2cl();
            let cpuid = Cpuid::try_from(vm.common.kvm.supported_cpuid.clone()).unwrap();
            let msr_index_iter = cpu_template.msr_index_iter();
            let msrs = vcpu.kvm_vcpu.get_msrs(msr_index_iter).unwrap();
            CpuConfiguration { cpuid, msrs }
        };

        // On ARM, we do not have templates yet.
        #[cfg(target_arch = "aarch64")]
        let cpu_config = CpuConfiguration::default();

        let entry_point = EntryPoint {
            entry_addr: GuestAddress(0),
            protocol: BootProtocol::LinuxBoot,
            // `setup_header` is only a field of `EntryPoint` on x86_64.
            #[cfg(target_arch = "x86_64")]
            setup_header: None,
        };

        #[cfg(target_arch = "x86_64")]
        {
            let configured_cpuid = vcpu
                .kvm_vcpu
                .configure_cpuid(&cpu_config.cpuid, 1, false)
                .unwrap();
            vcpu.kvm_vcpu
                .configure_msrs_for_boot(&cpu_config.msrs, &configured_cpuid)
                .unwrap();
            vcpu.kvm_vcpu
                .configure_boot_state(vm.guest_memory(), entry_point)
                .unwrap();
        }

        #[cfg(target_arch = "aarch64")]
        vcpu.kvm_vcpu
            .configure(
                vm.guest_memory(),
                entry_point,
                &VcpuConfig {
                    vcpu_count: 1,
                    smt: false,
                    cpu_config,
                },
                &vm.common.kvm.optional_capabilities(),
            )
            .unwrap();

        let state = vcpu.kvm_vcpu.save_state().unwrap();

        let _ = std::fs::create_dir_all("in/vcpu");
        let seed_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(if cfg!(target_arch = "x86_64") {
                "in/vcpu/valid_state_x86_64.in"
            } else {
                "in/vcpu/valid_state_aarch64.in"
            })
            .unwrap();

        bincode::serialize_into(
            seed_file,
            &FuzzData {
                huge_pages: true,
                bools: [true, false, true, false, true, false, true, false],
                memory_state: vm.guest_memory().describe(),
                vcpu_state: state,
            },
        )
        .expect("Failed to serialize initial seed data");
    }
}
