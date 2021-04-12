// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

// use devices::interrupt_controller::InterruptController;
// use hypervisor::IrqRoutingEntry;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup, MsiIrqGroupConfig,
};
use kvm_ioctls::{VmFd};

/// Reuse std::io::Result to simplify interoperability among crates.
pub type Result<T> = std::io::Result<T>;

struct InterruptRoute {
    gsi: u32,
    irq_fd: EventFd,
    registered: AtomicBool,
}

impl InterruptRoute {
    pub fn new(allocator: &mut SystemAllocator) -> Result<Self> {
        let irq_fd = EventFd::new(libc::EFD_NONBLOCK)?;
        let gsi = allocator
            .allocate_gsi()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed allocating new GSI"))?;

        Ok(InterruptRoute {
            gsi,
            irq_fd,
            registered: AtomicBool::new(false),
        })
    }

    pub fn enable(&self, vm: &VmFd) -> Result<()> {
        if !self.registered.load(Ordering::Acquire) {
            vm.register_irqfd(&self.irq_fd, self.gsi).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed registering irq_fd: {}", e),
                )
            })?;

            // Update internals to track the irq_fd as "registered".
            self.registered.store(true, Ordering::Release);
        }

        Ok(())
    }

    pub fn disable(&self, vm: &VmFd) -> Result<()> {
        if self.registered.load(Ordering::Acquire) {
            vm.unregister_irqfd(&self.irq_fd, self.gsi).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed unregistering irq_fd: {}", e),
                )
            })?;

            // Update internals to track the irq_fd as "unregistered".
            self.registered.store(false, Ordering::Release);
        }

        Ok(())
    }

    pub fn trigger(&self) -> Result<()> {
        self.irq_fd.write(1)
    }

    pub fn notifier(&self) -> Option<EventFd> {
        Some(
            self.irq_fd
                .try_clone()
                .expect("Failed cloning interrupt's EventFd"),
        )
    }
}

pub struct RoutingEntry<IrqRoutingEntry> {
    route: IrqRoutingEntry,
    masked: bool,
}

pub struct MsiInterruptGroup<IrqRoutingEntry> {
    vm: Arc<Mutex<VmFd>>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<IrqRoutingEntry>>>>,
    irq_routes: HashMap<InterruptIndex, InterruptRoute>,
}

use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use vm_system_allocator::SystemAllocator;

impl MsiInterruptGroup<IrqRoutingEntry> {
    fn set_gsi_routes(&self, routes: &HashMap<u32, RoutingEntry<IrqRoutingEntry>>) -> Result<()> {
        let mut entry_vec: Vec<IrqRoutingEntry> = Vec::new();
        
        for i in 0..24 {
            let mut kvm_route = kvm_irq_routing_entry {
                gsi: i,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                ..Default::default()
            };

            kvm_route.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
            kvm_route.u.irqchip.pin = i;
            
            entry_vec.push(kvm_route);
        }

        for (_, entry) in routes.iter() {
            if entry.masked {
                continue;
            }
            entry_vec.push(entry.route);
        }


        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(entry_vec.len());
        irq_routing[0].nr = entry_vec.len() as u32;
        irq_routing[0].flags = 0;

        unsafe {
            let entries_slice: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(entry_vec.len());
            entries_slice.copy_from_slice(&entry_vec);
        }

        self.vm.lock().expect("Poisoned VmFd lock").set_gsi_routing(&irq_routing[0]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed setting GSI routing: {}", e),
            )
        })
    }
}

impl<IrqRoutingEntry> MsiInterruptGroup<IrqRoutingEntry> {
    fn new(
        vm: Arc<Mutex<VmFd>>,
        gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<IrqRoutingEntry>>>>,
        irq_routes: HashMap<InterruptIndex, InterruptRoute>,
    ) -> Self {
        MsiInterruptGroup {
            vm,
            gsi_msi_routes,
            irq_routes,
        }
    }
}

impl InterruptSourceGroup for MsiInterruptGroup<IrqRoutingEntry> {
    fn enable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.enable(&self.vm.lock().expect("Poisoned lock"))?;
        }

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.disable(&self.vm.lock().expect("Poisoned lock"))?;
        }

        Ok(())
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.trigger();
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("trigger: Invalid interrupt index {}", index),
        ))
    }

    fn notifier(&self, index: InterruptIndex) -> Option<EventFd> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.notifier();
        }

        None
    }

    fn update(&self, index: InterruptIndex, config: InterruptSourceConfig) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let entry = RoutingEntry::<_>::make_entry(route.gsi, &config)?;
            let mut routes = self.gsi_msi_routes.lock().unwrap();
            routes.insert(route.gsi, *entry);
            return self.set_gsi_routes(&routes);
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("update: Invalid interrupt index {}", index),
        ))
    }

    fn mask(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let mut routes = self.gsi_msi_routes.lock().unwrap();
            if let Some(entry) = routes.get_mut(&route.gsi) {
                entry.masked = true;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("mask: No existing route for interrupt index {}", index),
                ));
            }
            self.set_gsi_routes(&routes)?;
            return route.disable(&self.vm.lock().expect("Poisoned lock"));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("mask: Invalid interrupt index {}", index),
        ))
    }

    fn unmask(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let mut routes = self.gsi_msi_routes.lock().unwrap();
            if let Some(entry) = routes.get_mut(&route.gsi) {
                entry.masked = false;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("mask: No existing route for interrupt index {}", index),
                ));
            }
            self.set_gsi_routes(&routes)?;
            return route.enable(&&self.vm.lock().expect("Poisoned lock"));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unmask: Invalid interrupt index {}", index),
        ))
    }
}

pub struct MsiInterruptManager<IrqRoutingEntry> {
    allocator: Arc<Mutex<SystemAllocator>>,
    vm: Arc<Mutex<VmFd>>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<IrqRoutingEntry>>>>,
}

impl MsiInterruptManager<IrqRoutingEntry> {
    pub fn new(allocator: Arc<Mutex<SystemAllocator>>, vm: Arc<Mutex<VmFd>>) -> Self {
        // Create a shared list of GSI that can be shared through all PCI
        // devices. This way, we can maintain the full list of used GSI,
        // preventing one device from overriding interrupts setting from
        // another one.
        let gsi_msi_routes = Arc::new(Mutex::new(HashMap::new()));

        MsiInterruptManager {
            allocator,
            vm,
            gsi_msi_routes,
        }
    }
}

impl InterruptManager for MsiInterruptManager<IrqRoutingEntry> {
    type GroupConfig = MsiIrqGroupConfig;

    fn create_group(
        &self,
        config: Self::GroupConfig,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        let mut allocator = self.allocator.lock().unwrap();
        let mut irq_routes: HashMap<InterruptIndex, InterruptRoute> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, InterruptRoute::new(&mut allocator)?);
        }

        Ok(Arc::new(Box::new(MsiInterruptGroup::new(
            self.vm.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        ))))
    }

    fn destroy_group(&self, _group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        Ok(())
    }
}

use super::*;
use kvm_bindings::KVM_MSI_VALID_DEVID;
use kvm_bindings::{kvm_irq_routing_entry, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI};

type KvmRoutingEntry = RoutingEntry<kvm_irq_routing_entry>;
pub type KvmMsiInterruptManager = MsiInterruptManager<kvm_irq_routing_entry>;

impl KvmRoutingEntry {
    pub fn make_entry(
        gsi: u32,
        config: &InterruptSourceConfig,
    ) -> Result<Box<Self>> {
        if let InterruptSourceConfig::MsiIrq(cfg) = &config {
            let mut kvm_route = kvm_irq_routing_entry {
                gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                ..Default::default()
            };

            kvm_route.u.msi.address_lo = cfg.low_addr;
            kvm_route.u.msi.address_hi = cfg.high_addr;
            kvm_route.u.msi.data = cfg.data;

            kvm_route.flags = KVM_MSI_VALID_DEVID;
            kvm_route.u.msi.__bindgen_anon_1.devid = cfg.devid;

            let kvm_entry = KvmRoutingEntry {
                route: kvm_route,
                masked: false,
            };

            return Ok(Box::new(kvm_entry));
        } else if let InterruptSourceConfig::LegacyIrq(cfg) = &config {
            let mut kvm_route = kvm_irq_routing_entry {
                gsi,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                ..Default::default()
            };
            kvm_route.u.irqchip.irqchip = cfg.irqchip;
            kvm_route.u.irqchip.pin = cfg.pin;
            let kvm_entry = KvmRoutingEntry {
                route: kvm_route,
                masked: false,
            };

            return Ok(Box::new(kvm_entry));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Interrupt config type not supported",
        ))
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use arch::aarch64::gic::kvm::{create_gic, save_pending_tables};
    use arch::aarch64::gic::{
        get_dist_regs, get_icc_regs, get_redist_regs, set_dist_regs, set_icc_regs, set_redist_regs,
    };

    #[test]
    fn test_create_gic() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();

        assert!(create_gic(&vm, 1).is_ok());
    }

    #[test]
    fn test_get_set_dist_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");

        let res = get_dist_regs(gic.device());
        assert!(res.is_ok());
        let state = res.unwrap();
        assert_eq!(state.len(), 649);

        let res = set_dist_regs(gic.device(), &state);
        assert!(res.is_ok());
    }

    #[test]
    fn test_get_set_redist_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");

        let mut gicr_typer = Vec::new();
        gicr_typer.push(123);
        let res = get_redist_regs(gic.device(), &gicr_typer);
        assert!(res.is_ok());
        let state = res.unwrap();
        println!("{}", state.len());
        assert!(state.len() == 24);

        assert!(set_redist_regs(gic.device(), &gicr_typer, &state).is_ok());
    }

    #[test]
    fn test_get_set_icc_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");

        let mut gicr_typer = Vec::new();
        gicr_typer.push(123);
        let res = get_icc_regs(gic.device(), &gicr_typer);
        assert!(res.is_ok());
        let state = res.unwrap();
        println!("{}", state.len());
        assert!(state.len() == 9);

        assert!(set_icc_regs(gic.device(), &gicr_typer, &state).is_ok());
    }

    #[test]
    fn test_save_pending_tables() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");

        assert!(save_pending_tables(gic.device()).is_ok());
    }
}
