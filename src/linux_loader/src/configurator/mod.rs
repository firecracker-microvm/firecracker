// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Traits and structs for configuring and loading boot parameters.
//! - [BootConfigurator](trait.BootConfigurator.html): configure boot parameters.
//! - [LinuxBootConfigurator](linux/struct.LinuxBootConfigurator.html): Linux boot protocol
//!   parameters configurator.
//! - [PvhBootConfigurator](pvh/struct.PvhBootConfigurator.html): PVH boot protocol parameters
//!   configurator.

#![cfg(any(feature = "elf", feature = "pe", feature = "bzimage"))]

use vm_memory::{Address, ByteValued, GuestAddress, GuestMemory};

use std::fmt;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
use std::cmp::max;
use std::mem::size_of;

/// Errors specific to boot protocol configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Errors specific to the Linux boot protocol configuration.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Linux(linux::Error),
    /// Errors specific to the PVH boot protocol configuration.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Pvh(pvh::Error),
    /// Errors specific to device tree boot configuration.
    #[cfg(target_arch = "aarch64")]
    Fdt(fdt::Error),

    /// Boot parameter was specified without its starting address in guest memory.
    MissingStartAddress,
    /// Boot parameter address overflows.
    Overflow,
    /// Boot parameter address precedes the starting address.
    InvalidAddress,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        let desc = match self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Linux(ref _e) => "failed to configure boot parameter by Linux Boot protocol.",
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Pvh(ref _e) => "failed to configure boot parameter by PVH.",
            #[cfg(target_arch = "aarch64")]
            Fdt(ref _e) => "failed to configure boot parameter by FDT.",

            MissingStartAddress => {
                "boot parameter was specified without its starting address in guest memory."
            }
            Overflow => "boot parameter address overflows.",
            InvalidAddress => "boot parameter address precedes the starting address.",
        };

        write!(f, "Boot Configurator: {}", desc)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Linux(ref e) => Some(e),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Pvh(ref e) => Some(e),
            #[cfg(target_arch = "aarch64")]
            Fdt(ref e) => Some(e),

            MissingStartAddress => None,
            Overflow => None,
            InvalidAddress => None,
        }
    }
}

/// Specialized [`Result`] type for the boot configurator.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// Trait that defines interfaces for building (TBD) and configuring boot parameters.
///
/// Currently, this trait exposes a single function which writes user-provided boot parameters into
/// guest memory at the user-specified addresses. It's meant to be called after the kernel is
/// loaded and after the boot parameters are built externally (in the VMM).
///
/// This trait will be extended with additional functionality to build boot parameters.
pub trait BootConfigurator {
    /// Writes the boot parameters (configured elsewhere) into guest memory.
    ///
    /// The arguments are split into `header` and `sections` to accommodate different boot
    /// protocols like Linux boot and PVH. In Linux boot, the e820 map could be considered as
    /// `sections`, but it's already encapsulated in the `boot_params` and thus all the boot
    /// parameters are passed through a single struct. In PVH, the memory map table is separated
    /// from the `hvm_start_info` struct, therefore it's passed separately.
    ///
    /// # Arguments
    ///
    /// * `params` - struct containing the header section of the boot parameters, additional
    ///              sections and modules, and their associated addresses in guest memory. These
    ///              vary with the boot protocol used.
    /// * `guest_memory` - guest's physical memory.
    fn write_bootparams<M>(params: &BootParams, guest_memory: &M) -> Result<()>
    where
        M: GuestMemory;
}

/// Boot parameters to be written in guest memory.
#[derive(Clone)]
pub struct BootParams {
    /// "Header section", always written in guest memory irrespective of boot protocol.
    pub header: Vec<u8>,
    /// Header section address.
    pub header_start: GuestAddress,
    /// Optional sections containing boot configurations (e.g. E820 map).
    pub sections: Option<Vec<u8>>,
    /// Sections starting address.
    pub sections_start: Option<GuestAddress>,
    /// Optional modules specified at boot configuration time.
    pub modules: Option<Vec<u8>>,
    /// Modules starting address.
    pub modules_start: Option<GuestAddress>,
}

impl BootParams {
    /// Creates a new [`BootParams`](struct.BootParams.html) struct with the specified header.
    ///
    /// # Arguments
    ///
    /// * `header` - [`ByteValued`] representation of mandatory boot parameters.
    /// * `header_addr` - address in guest memory where `header` will be written.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::configurator::BootParams;
    /// # use vm_memory::{GuestAddress, ByteValued};
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Header;
    /// # unsafe impl ByteValued for Header {}
    /// let boot_params = BootParams::new(&Header::default(), GuestAddress(0x1000));
    /// ```
    ///
    /// [`ByteValued`]: https://docs.rs/vm-memory/latest/vm_memory/bytes/trait.ByteValued.html
    pub fn new<T: ByteValued>(header: &T, header_addr: GuestAddress) -> Self {
        BootParams {
            header: header.as_slice().to_vec(),
            header_start: header_addr,
            sections: None,
            sections_start: None,
            modules: None,
            modules_start: None,
        }
    }

    /// Sets or overwrites the boot sections and associated memory address.
    ///
    /// Unused on `aarch64` and for the Linux boot protocol.
    /// For the PVH boot protocol, the sections specify the memory map table in
    /// [`hvm_memmap_table_entry`] structs.
    ///
    /// # Arguments
    ///
    /// * `sections` - vector of [`ByteValued`] boot configurations.
    /// * `sections_addr` - address where the sections will be written in guest memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::configurator::BootParams;
    /// # use vm_memory::{ByteValued, GuestAddress};
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Header;
    /// # unsafe impl ByteValued for Header {}
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Section;
    /// # unsafe impl ByteValued for Section {}
    /// let mut boot_params = BootParams::new(&Header::default(), GuestAddress(0x1000));
    /// let mut sections: Vec<Section> = vec![Section::default()];
    /// boot_params.set_sections(sections.as_slice(), GuestAddress(0x2000));
    /// // Another call overwrites the sections.
    /// sections.clear();
    /// boot_params.set_sections(sections.as_slice(), GuestAddress(0x3000));
    /// assert_eq!(boot_params.sections.unwrap().len(), 0);
    /// assert_eq!(boot_params.sections_start.unwrap(), GuestAddress(0x3000));
    /// ```
    ///
    /// [`ByteValued`]: https://docs.rs/vm-memory/latest/vm_memory/bytes/trait.ByteValued.html
    /// [`hvm_memmap_table_entry`]: ../loader/elf/start_info/struct.hvm_memmap_table_entry.html
    pub fn set_sections<T: ByteValued>(&mut self, sections: &[T], sections_addr: GuestAddress) {
        self.sections = Some(
            sections
                .iter()
                .flat_map(|section| section.as_slice().to_vec())
                .collect(),
        );
        self.sections_start = Some(sections_addr);
    }

    /// Adds a boot section at the specified address (if specified and valid), or appends it.
    ///
    /// It's up to the caller to ensure that the section will not overlap with existing content
    /// or leave a gap past the current sections in the list.
    ///
    /// # Arguments
    ///
    /// * `section` - [`ByteValued`] boot section element.
    /// * `section_addr` - optional address for the section in guest memory.
    ///
    /// # Returns
    ///
    /// Starting address of the section in guest memory, or an error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::configurator::BootParams;
    /// # use vm_memory::{Address, GuestAddress, ByteValued};
    /// # use std::mem::size_of;
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Header;
    /// # unsafe impl ByteValued for Header {}
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Section;
    /// # unsafe impl ByteValued for Section {}
    /// let mut boot_params = BootParams::new(&Header::default(), GuestAddress(0x1000));
    /// let section = Section::default();
    /// // Sections start address needs to be configured first.
    /// assert!(boot_params.add_section::<Section>(&section, None).is_err());
    /// let sections_start = GuestAddress(0x2000);
    /// assert!(boot_params
    ///     .add_section::<Section>(&section, Some(sections_start))
    ///     .is_ok());
    /// // It can be overwritten...
    /// assert_eq!(
    ///     boot_params
    ///         .add_section::<Section>(&section, Some(sections_start))
    ///         .unwrap(),
    ///     sections_start
    /// );
    /// // But only if the address is valid.
    /// assert!(boot_params
    ///     .add_section::<Section>(&section, Some(sections_start.unchecked_sub(0x100)))
    ///     .is_err());
    /// // Or appended...
    /// assert_eq!(
    ///     boot_params.add_section::<Section>(&section, None).unwrap(),
    ///     sections_start.unchecked_add(size_of::<Section>() as u64)
    /// );
    /// ```
    ///
    /// [`ByteValued`]: https://docs.rs/vm-memory/latest/vm_memory/bytes/trait.ByteValued.html
    pub fn add_section<T: ByteValued>(
        &mut self,
        section: &T,
        section_addr: Option<GuestAddress>,
    ) -> Result<GuestAddress> {
        Self::add_boot_parameter_to_list(
            section,
            section_addr,
            self.sections.get_or_insert(vec![]),
            &mut self.sections_start,
        )
    }

    /// Sets or overwrites the boot modules and associated memory address.
    ///
    /// Unused on `aarch64` and for the Linux boot protocol.
    /// For the PVH boot protocol, the modules are specified in [`hvm_modlist_entry`] structs.
    ///
    /// # Arguments
    ///
    /// * `modules` - vector of [`ByteValued`] boot configurations.
    /// * `modules_addr` - address where the modules will be written in guest memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::configurator::BootParams;
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Header;
    /// # unsafe impl ByteValued for Header {}
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Module;
    /// # unsafe impl ByteValued for Module {}
    /// # use vm_memory::{GuestAddress, ByteValued};
    /// let mut boot_params = BootParams::new(&Header::default(), GuestAddress(0x1000));
    /// let mut modules: Vec<Module> = vec![Module::default()];
    /// boot_params.set_modules(modules.as_slice(), GuestAddress(0x2000));
    /// // Another call overwrites the sections.
    /// modules.clear();
    /// boot_params.set_modules(modules.as_slice(), GuestAddress(0x3000));
    /// assert_eq!(boot_params.modules.unwrap().len(), 0);
    /// assert_eq!(boot_params.modules_start.unwrap(), GuestAddress(0x3000));
    /// ```
    ///
    /// [`ByteValued`]: https://docs.rs/vm-memory/latest/vm_memory/bytes/trait.ByteValued.html
    /// [`hvm_modlist_entry`]: ../loader/elf/start_info/struct.hvm_modlist_entry.html
    pub fn set_modules<T: ByteValued>(&mut self, modules: &[T], modules_addr: GuestAddress) {
        self.modules = Some(
            modules
                .iter()
                .flat_map(|module| module.as_slice().to_vec())
                .collect(),
        );
        self.modules_start = Some(modules_addr);
    }

    /// Adds a boot module at the specified address (if specified and valid), or appends it.
    ///
    /// It's up to the caller to ensure that the module will not overlap with existing content
    /// or leave a gap past the current modules in the list.
    ///
    /// # Arguments
    ///
    /// * `module` - [`ByteValued`] boot module element.
    /// * `module_addr` - optional address for the module in guest memory.
    ///
    /// # Returns
    ///
    /// Starting address of the module in guest memory, or an error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::configurator::BootParams;
    /// # use vm_memory::{Address, GuestAddress, ByteValued};
    /// # use std::mem::size_of;
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Header;
    /// # unsafe impl ByteValued for Header {}
    /// # #[derive(Clone, Copy, Default)]
    /// # struct Module;
    /// # unsafe impl ByteValued for Module {}
    /// let mut boot_params = BootParams::new(&Header::default(), GuestAddress(0x1000));
    /// let module = Module::default();
    /// // Modules start address needs to be configured first.
    /// assert!(boot_params.add_module::<Module>(&module, None).is_err());
    /// let modules_start = GuestAddress(0x2000);
    /// assert!(boot_params
    ///     .add_module::<Module>(&module, Some(modules_start))
    ///     .is_ok());
    /// // It can be overwritten...
    /// assert_eq!(
    ///     boot_params
    ///         .add_module::<Module>(&module, Some(modules_start))
    ///         .unwrap(),
    ///     modules_start
    /// );
    /// // But only if the address is valid.
    /// assert!(boot_params
    ///     .add_module::<Module>(&module, Some(modules_start.unchecked_sub(0x100)))
    ///     .is_err());
    /// // Or appended...
    /// assert_eq!(
    ///     boot_params.add_module::<Module>(&module, None).unwrap(),
    ///     modules_start.unchecked_add(size_of::<Module>() as u64)
    /// );
    /// ```
    ///
    /// [`ByteValued`]: https://docs.rs/vm-memory/latest/vm_memory/bytes/trait.ByteValued.html
    pub fn add_module<T: ByteValued>(
        &mut self,
        module: &T,
        module_addr: Option<GuestAddress>,
    ) -> Result<GuestAddress> {
        Self::add_boot_parameter_to_list(
            module,
            module_addr,
            self.modules.get_or_insert(vec![]),
            &mut self.modules_start,
        )
    }

    /// Adds a boot parameter (section or module) to a byte buffer.
    ///
    /// Initializes the buffer and corresponding starting address, if necessary.
    fn add_boot_parameter_to_list<T: ByteValued>(
        elem: &T,
        elem_start_opt: Option<GuestAddress>,
        bytes_acc: &mut Vec<u8>,
        list_start_opt: &mut Option<GuestAddress>,
    ) -> Result<GuestAddress> {
        if list_start_opt.is_none() {
            *list_start_opt = elem_start_opt;
        }
        let list_start = list_start_opt.ok_or(Error::MissingStartAddress)?;
        let elem_start = elem_start_opt.unwrap_or(
            list_start
                .checked_add(bytes_acc.len() as u64)
                .ok_or(Error::Overflow)?,
        );
        let elem_off = elem_start
            .checked_offset_from(list_start)
            .ok_or(Error::InvalidAddress)? as usize;
        let elem_end = elem_off + size_of::<T>();
        bytes_acc.resize(max(elem_end, bytes_acc.len()), 0);
        bytes_acc.splice(elem_off..elem_end, elem.as_slice().iter().cloned());
        Ok(elem_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Default)]
    struct Foobar {
        _foo: [u8; 5],
    }

    unsafe impl ByteValued for Foobar {}

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct DummyHeader {
        _dummy: u64,
    }

    unsafe impl ByteValued for DummyHeader {}

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct DummySection {
        _dummy: u64,
    }

    unsafe impl ByteValued for DummySection {}

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct DummyModule {
        _dummy: u64,
    }

    unsafe impl ByteValued for DummyModule {}

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct OtherDummyModule {
        _dummy: u64,
    }

    unsafe impl ByteValued for OtherDummyModule {}

    #[test]
    fn test_error_messages() {
        #[cfg(target_arch = "x86_64")]
        {
            // Linux
            assert_eq!(
                format!("{}", Error::Linux(linux::Error::ZeroPagePastRamEnd)),
                "Boot Configurator: failed to configure boot parameter by Linux Boot protocol."
            );
            assert_eq!(
                format!("{}", Error::Linux(linux::Error::ZeroPageSetup)),
                "Boot Configurator: failed to configure boot parameter by Linux Boot protocol."
            );

            // PVH
            assert_eq!(
                format!("{}", Error::Pvh(pvh::Error::MemmapTableMissing)),
                "Boot Configurator: failed to configure boot parameter by PVH."
            );
            assert_eq!(
                format!("{}", Error::Pvh(pvh::Error::MemmapTablePastRamEnd)),
                "Boot Configurator: failed to configure boot parameter by PVH."
            );
            assert_eq!(
                format!("{}", Error::Pvh(pvh::Error::MemmapTableSetup)),
                "Boot Configurator: failed to configure boot parameter by PVH."
            );
            assert_eq!(
                format!("{}", Error::Pvh(pvh::Error::StartInfoPastRamEnd)),
                "Boot Configurator: failed to configure boot parameter by PVH."
            );
            assert_eq!(
                format!("{}", Error::Pvh(pvh::Error::StartInfoSetup)),
                "Boot Configurator: failed to configure boot parameter by PVH."
            );
        }

        #[cfg(target_arch = "aarch64")]
        // FDT
        assert_eq!(
            format!("{}", Error::Fdt(fdt::Error::WriteFDTToMemory)),
            "Boot Configurator: failed to configure boot parameter by FDT."
        );

        assert_eq!(
            format!("{}", Error::MissingStartAddress),
            "Boot Configurator: \
             boot parameter was specified without its starting address in guest memory."
        );
        assert_eq!(
            format!("{}", Error::Overflow),
            "Boot Configurator: boot parameter address overflows."
        );
        assert_eq!(
            format!("{}", Error::InvalidAddress),
            "Boot Configurator: boot parameter address precedes the starting address."
        );
    }

    #[test]
    fn test_bootparam_list_addition() {
        let mut accumulator: Vec<u8> = vec![];
        let start = GuestAddress(0x1000);
        let element = Foobar::default();

        // Error case: start address not specified.
        assert_eq!(
            format!(
                "{:?}",
                BootParams::add_boot_parameter_to_list(&element, None, &mut accumulator, &mut None)
                    .err()
            ),
            "Some(MissingStartAddress)"
        );

        // Success case: start address is set, element address not specified - will be appended.
        assert_eq!(
            BootParams::add_boot_parameter_to_list(
                &element,
                None,
                &mut accumulator,
                &mut Some(start)
            )
            .unwrap(),
            start
        );
        assert_eq!(accumulator, element.as_slice().to_vec());

        // Success case: start address is unset, element address is specified.
        let mut list_start_opt: Option<GuestAddress> = None;
        assert_eq!(
            BootParams::add_boot_parameter_to_list(
                &element,
                Some(start),
                &mut accumulator,
                &mut list_start_opt
            )
            .unwrap(),
            start
        );
        assert_eq!(list_start_opt, Some(start));
        assert_eq!(accumulator, element.as_slice().to_vec());

        // Error case: start address is set, element address is specified, but precedes start.
        assert_eq!(
            format!(
                "{:?}",
                BootParams::add_boot_parameter_to_list(
                    &element,
                    Some(start.unchecked_sub(0x100)),
                    &mut accumulator,
                    &mut list_start_opt
                )
                .err()
            ),
            "Some(InvalidAddress)"
        );

        // Success case: start address is set, element address is specified and valid.

        // Case 1: element falls in the middle of the accumulator.
        accumulator.clear();
        // Start by adding 2 elements.
        assert!(BootParams::add_boot_parameter_to_list(
            &element,
            None,
            &mut accumulator,
            &mut list_start_opt
        )
        .is_ok());
        assert!(BootParams::add_boot_parameter_to_list(
            &Foobar {
                _foo: [2, 2, 2, 3, 3]
            },
            None,
            &mut accumulator,
            &mut list_start_opt
        )
        .is_ok());
        // Sanity check.
        #[rustfmt::skip]
        assert_eq!(
            accumulator,
            &[
                0, 0, 0, 0, 0,  // elem 0
                2, 2, 2, 3, 3,  // elem 1
            ]
        );

        // Add a 3rd one that overlaps with the middle of element 1.
        assert!(BootParams::add_boot_parameter_to_list(
            &Foobar { _foo: [1u8; 5] },
            Some(start.unchecked_add(size_of::<Foobar>() as u64 + 3)),
            &mut accumulator,
            &mut list_start_opt
        )
        .is_ok());
        #[rustfmt::skip]
        assert_eq!(
            accumulator,
            &[
                0, 0, 0, 0, 0,              // elem 0
                2, 2, 2,                    // elem 1 cut short
                1, 1, 1, 1, 1,              // elem 2
            ]
        );
        assert_eq!(accumulator.len(), 13)
    }

    #[test]
    fn test_bootparams() {
        // Test building bootparams from header.
        let hdr = DummyHeader::default();
        let hdr_addr = GuestAddress(0x1000);
        let mut bootparams = BootParams::new(&hdr, hdr_addr);
        assert_eq!(bootparams.header, hdr.as_slice());
        assert_eq!(bootparams.header_start, hdr_addr);

        // Test setting sections.
        let sections = vec![DummySection::default(); 2];
        let sections_addr = GuestAddress(0x2000);
        bootparams.set_sections::<DummySection>(sections.as_slice(), sections_addr);
        assert_eq!(
            bootparams.sections,
            Some(vec![0u8; 2 * size_of::<DummySection>()])
        );
        assert_eq!(bootparams.sections_start, Some(sections_addr));

        // Test overwriting sections.
        let sections = vec![DummySection::default(); 3];
        let sections_addr = GuestAddress(0x3000);
        bootparams.set_sections::<DummySection>(sections.as_slice(), sections_addr);
        assert_eq!(
            bootparams.sections,
            Some(vec![0u8; 3 * size_of::<DummySection>()])
        );
        assert_eq!(bootparams.sections_start, Some(sections_addr));

        // Test appending a new section.
        assert_eq!(
            bootparams.add_section::<DummySection>(&DummySection::default(), None),
            Ok(sections_addr.unchecked_add(3 * size_of::<DummySection>() as u64))
        );
        assert_eq!(
            bootparams.sections,
            Some(vec![0u8; 4 * size_of::<DummySection>()])
        );
        assert_eq!(bootparams.sections_start, Some(sections_addr));

        // Test setting modules.
        let modules = vec![DummyModule::default(); 2];
        let modules_addr = GuestAddress(0x4000);
        bootparams.set_modules::<DummyModule>(modules.as_slice(), modules_addr);
        assert_eq!(
            bootparams.modules,
            Some(vec![0u8; 2 * size_of::<DummyModule>()])
        );
        assert_eq!(bootparams.modules_start, Some(modules_addr));

        // Test overwriting modules.
        let modules = vec![DummyModule::default(); 3];
        let modules_addr = GuestAddress(0x5000);
        bootparams.set_modules::<DummyModule>(modules.as_slice(), modules_addr);
        assert_eq!(
            bootparams.modules,
            Some(vec![0u8; 3 * size_of::<DummyModule>()])
        );
        assert_eq!(bootparams.modules_start, Some(modules_addr));

        // Test appending a new module.
        assert_eq!(
            bootparams.add_module::<DummyModule>(&DummyModule::default(), None),
            Ok(modules_addr.unchecked_add(3 * size_of::<DummyModule>() as u64))
        );

        // Test appending a new module of a different type.
        assert_eq!(
            bootparams.add_module::<OtherDummyModule>(&OtherDummyModule::default(), None),
            Ok(modules_addr.unchecked_add(
                3 * size_of::<DummyModule>() as u64 + size_of::<OtherDummyModule>() as u64
            ))
        );
    }
}
