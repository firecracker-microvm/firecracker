// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

// Generate main functions for supported features
#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target); // main function used by afl.rs

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target); // main function used when replaying corpus items to collect backtraces/coverage

pub mod fuzzing {
    use fuzzer::virtio::{FuzzData, InsufficientData};
    use vmm::builder::build_microvm_for_boot;
    use vmm::resources::VmResources;
    use vmm::seccomp::get_empty_filters;
    use vmm::test_utils::mock_resources::{MockBootSourceConfig, MockVmResources};
    use vmm::vmm_config::entropy::{EntropyDeviceBuilder, EntropyDeviceConfig};
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::{EventManager, Vmm};

    // Inject a guest read/write access on either the MMIO or the Port IO bus
    fn inject_access(
        vmm: &Vmm,
        is_mmio: bool,
        is_write: bool,
        mut input: &[u8],
    ) -> Result<(), InsufficientData> {
        let kvm_vm = vmm.vm.as_kvm().unwrap();
        let bus = if is_mmio {
            &kvm_vm.common.mmio_bus
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                &kvm_vm.pio_bus
            }

            // On Aarch64 we don't have a port IO bus, so always return the MMIO bus.
            // Use the boolean from the input anyways so that we can reuse the same seed file
            #[cfg(target_arch = "aarch64")]
            {
                &kvm_vm.common.mmio_bus
            }
        };

        // MMIO and Port IO accesses can really be up to 64 bits long on ARM64 and x86_64
        // architectures. Moreover, we really can only have accesses of 1, 2, 4 or 8 bytes.
        let len = 1usize << (input.take_u8()? % 4);
        let addr = input.take_u64()?;

        if is_write {
            let data = input.take_slice(len)?.to_vec();
            let _ = bus.write(addr, &data);
        } else {
            let mut data = vec![0u8; len];
            let _ = bus.read(addr, &mut data);
        }

        Ok(())
    }

    pub fn target(mut input: &[u8]) -> Result<(), InsufficientData> {
        // We fuzz the presence of PCI and one entropy device so that we can test accesses in the
        // VirtIO configuration space both in the MMIO and PCI cases. This will also test for rogue
        // accesses when no device is present.
        let [entropy_present, pci_enabled, mut is_mmio, mut is_write, ..] = input.take_bools()?;

        // This uses the dummy kernel file from
        // `firecracker/src/vmm/src/test_utils/mock_resources/test_elf.bin`
        // as a mock kernel. We won't actually boot the kernel, but if we don't pass a kinda
        // truthful binary the builder will complain when trying to create the Vmm object.
        let mut vm_resources: VmResources = MockVmResources::new()
            .with_boot_source(MockBootSourceConfig::new().with_default_boot_args().into())
            .into();
        let mut entropy = EntropyDeviceBuilder::default();
        if entropy_present {
            entropy
                .build(EntropyDeviceConfig { rate_limiter: None })
                .unwrap();
        }
        let instance_info = InstanceInfo::default();
        vm_resources.pci_enabled = pci_enabled;
        vm_resources.entropy = entropy;
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filters = get_empty_filters();

        let vmm = build_microvm_for_boot(
            &instance_info,
            &vm_resources,
            &mut event_manager,
            &empty_seccomp_filters,
        )
        .unwrap();

        let locked_vmm = vmm.lock().unwrap();

        // Inject Bus accesses for as long as we have input data
        while inject_access(&locked_vmm, is_mmio, is_write, input).is_ok() {
            let config = input.take_bools()?;
            is_mmio = config[0];
            is_write = config[1];
        }

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module used for generating the binary input seeds
    //!
    //! Each test contains a seed as a u8 array, which is written to a file in fuzzer/in/bus_access
    //! at the end.
    use std::fs::OpenOptions;
    use std::io::Write;

    use vmm::arch::{MEM_32BIT_DEVICES_START, MEM_64BIT_DEVICES_START, PCI_MMCONFIG_START};

    fn write_seed(seed: &[u8], seed_fname: &str) {
        let _ = std::fs::create_dir_all("in/bus_access");
        let path = format!("in/bus_access/{seed_fname}");
        let mut seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();

        seed_file.write_all(seed).unwrap();
    }

    #[test]
    fn generate_mmio_read_pci_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: true
            // * write access: false
            0b00000111, 
            // A 4 bytes access
            0x2,
        ];
        // address to read: PCI_MMCONFIG_START (0x0000_0000_EEC0_0000)
        seed.extend_from_slice(&u64::to_le_bytes(PCI_MMCONFIG_START));

        write_seed(&seed, "mmio_read_pci.in");
    }

    #[test]
    fn generate_mmio_write_pci_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: true
            // * write access: false
            0b00001111,
            // A 4 bytes access
            0x2,
        ];
        // address to read: PCI_MMCONFIG_START (0x0000_0000_EEC0_0000)
        seed.extend_from_slice(&u64::to_le_bytes(PCI_MMCONFIG_START));

        write_seed(&seed, "mmio_write_pci.in");
    }

    #[test]
    fn generate_pio_read_pci_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: false
            // * write access: false
            0b00000011, 
            // A 4 bytes access
            0x2,
        ];
        // address to read: Port IO PCI configuration space address
        seed.extend_from_slice(&u64::to_le_bytes(0xcf8));

        write_seed(&seed, "pio_read_pci.in");
    }

    #[test]
    fn generate_pio_write_pci_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: false
            // * write access: true
            0b00001011,
            // A 4 bytes access
            0x2,
        ];
        // Port to write: Port IO PCI configuration space address
        seed.extend_from_slice(&u64::to_le_bytes(0xcf8));
        // Write the address of the root port:
        // |   Bit 31   |  Bits 30-24  |  Bits 23-16  |  Bits 15-11   |    Bits 10-8    |     Bits 7-0    |
        // | Enable Bit |   Reserved   |  Bus Number  | Device Number | Function Number | Register Offset |
        //
        // Register Offset has to point to consecutive DWORDs, ie. bits 1:0 are always 0b00 (they
        // are still part of the register offset).
        seed.extend_from_slice(&u64::to_le_bytes(0x8000_0000));

        write_seed(&seed, "pio_write_pci.in");
    }

    #[test]
    fn generate_pci_virtio_read_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: true 
            // * write access: false
            0b00000111,
            // A 4 bytes access
            0x2,
        ];
        // address to read: MEM_64BIT_DEVICES_START (0x4000_0000_0000_0000)
        seed.extend_from_slice(&u64::to_le_bytes(MEM_64BIT_DEVICES_START));

        write_seed(&seed, "pci_virtio_read.in");
    }

    #[test]
    fn generate_pci_virtio_write_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: true
            // * MMIO access: true
            // * write access: true
            0b00001111,
            // A 4 bytes access
            0x2,
        ];
        // address to read: MEM_64BIT_DEVICES_START (0x4000_0000_0000_0000)
        seed.extend_from_slice(&u64::to_le_bytes(MEM_64BIT_DEVICES_START));

        write_seed(&seed, "pci_virtio_write.in");
    }

    #[test]
    fn generate_mmio_virtio_read_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: false
            // * MMIO access: true
            // * write access: false
            0b00000101,
            // A 4 bytes access
            0x2,
        ];
        // address to read: MEM_32BIT_DEVICES_START (0xC000_1000)
        seed.extend_from_slice(&u64::to_le_bytes(MEM_32BIT_DEVICES_START));

        write_seed(&seed, "mmio_virtio_read.in");
    }

    #[test]
    fn generate_mmio_virtio_write_seed() {
        #[rustfmt::skip]
        let mut seed = vec![
            // Bools for configuration:
            // * Entropy device: true
            // * PCI enabled: false
            // * MMIO access: true
            // * write access: true
            0b00001101,
            // A 4 bytes access
            0x2,
        ];
        // address to read: MEM_32BIT_DEVICES_START (0xC000_1000)
        seed.extend_from_slice(&u64::to_le_bytes(MEM_32BIT_DEVICES_START));

        write_seed(&seed, "mmio_virtio_write.in");
    }
}
