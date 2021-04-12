// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#[cfg(target_arch = "x86_64")]
use std::collections::btree_map::BTreeMap;
use std::result;

#[derive(Debug)]
pub enum Error {
    Overflow,
}

pub type Result<T> = result::Result<T, Error>;

/// GsiApic
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
pub struct GsiApic {
    base: u32,
    irqs: u32,
}

#[cfg(target_arch = "x86_64")]
impl GsiApic {
    /// New GSI APIC
    pub fn new(base: u32, irqs: u32) -> Self {
        GsiApic { base, irqs }
    }
}

/// GsiAllocator
pub struct GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    apics: BTreeMap<u32, u32>,
    next_irq: u32,
    next_gsi: u32,
}

impl GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    /// New GSI allocator
    pub fn new(apics: Vec<GsiApic>) -> Self {
        let mut allocator = GsiAllocator {
            apics: BTreeMap::new(),
            next_irq: 0xffff_ffff,
            next_gsi: 0,
        };

        for apic in &apics {
            if apic.base < allocator.next_irq {
                allocator.next_irq = apic.base;
            }

            if apic.base + apic.irqs > allocator.next_gsi {
                allocator.next_gsi = apic.base + apic.irqs;
            }

            allocator.apics.insert(apic.base, apic.irqs);
        }

        allocator
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::new_without_default)]
    /// New GSI allocator
    pub fn new() -> Self {
        GsiAllocator {
            next_irq: arch::IRQ_BASE,
            next_gsi: arch::IRQ_BASE,
        }
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        let gsi = self.next_gsi;
        self.next_gsi = self.next_gsi.checked_add(1).ok_or(Error::Overflow)?;
        Ok(gsi)
    }

    #[cfg(target_arch = "x86_64")]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        let mut irq: u32 = 0;
        for (base, irqs) in self.apics.iter() {
            // HACKHACK - This only works with 1 single IOAPIC...
            if self.next_irq >= *base && self.next_irq < *base + *irqs {
                irq = self.next_irq;
                self.next_irq += 1;
            }
        }

        if irq == 0 {
            return Err(Error::Overflow);
        }

        Ok(irq)
    }

    #[cfg(target_arch = "aarch64")]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        let irq = self.next_irq;
        self.next_irq = self.next_irq.checked_add(1).ok_or(Error::Overflow)?;
        Ok(irq)
    }
}
