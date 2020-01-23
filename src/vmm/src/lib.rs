// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![deny(missing_docs)]
extern crate epoll;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;
extern crate polly;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate arch;
#[cfg(target_arch = "x86_64")]
extern crate cpuid;
extern crate devices;
extern crate kernel;
#[macro_use]
extern crate logger;
extern crate dumbo;
extern crate rate_limiter;
extern crate seccomp;
extern crate utils;
extern crate vm_memory;

/// Handles setup and initialization a `Vmm` object.
pub mod builder;
/// Handles runtime configuration of a `Vmm` object.
pub mod controller;
/// Syscalls allowed through the seccomp filter.
pub mod default_syscalls;
pub(crate) mod device_manager;
/// Resource store for configured microVM resources.
pub mod resources;
/// microVM RPC API adapters.
pub mod rpc_interface;
/// Signal handling utilities.
pub mod signal_handler;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
mod vstate;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use arch::DeviceType;
use arch::InitrdConfig;
#[cfg(target_arch = "x86_64")]
use device_manager::legacy::PortIODeviceManager;
#[cfg(target_arch = "aarch64")]
use device_manager::mmio::MMIODeviceInfo;
use device_manager::mmio::MMIODeviceManager;
use devices::virtio::EpollConfigConstructor;
use devices::{BusDevice, DeviceEventT, EpollHandler};
use kernel::cmdline::Cmdline as KernelCmdline;
use logger::error::LoggerError;
use logger::{Metric, LOGGER, METRICS};
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::{self, EventManager, Subscriber};
use seccomp::{BpfProgram, BpfProgramRef, SeccompFilter};
use utils::eventfd::EventFd;
use utils::time::TimestampUs;
use vm_memory::GuestMemoryMmap;
use vstate::{Vcpu, VcpuEvent, VcpuHandle, VcpuResponse, Vm};

/// Success exit code.
pub const FC_EXIT_CODE_OK: u8 = 0;
/// Generic error exit code.
pub const FC_EXIT_CODE_GENERIC_ERROR: u8 = 1;
/// Generic exit code for an error considered not possible to occur if the program logic is sound.
pub const FC_EXIT_CODE_UNEXPECTED_ERROR: u8 = 2;
/// Firecracker was shut down after intercepting a restricted system call.
pub const FC_EXIT_CODE_BAD_SYSCALL: u8 = 148;
/// Firecracker was shut down after intercepting `SIGBUS`.
pub const FC_EXIT_CODE_SIGBUS: u8 = 149;
/// Firecracker was shut down after intercepting `SIGSEGV`.
pub const FC_EXIT_CODE_SIGSEGV: u8 = 150;
/// Bad configuration for microvm's resources, when using a single json.
pub const FC_EXIT_CODE_BAD_CONFIGURATION: u8 = 151;
/// Command line arguments parsing error.
pub const FC_EXIT_CODE_ARG_PARSING: u8 = 152;

/// Dispatch categories for epoll events.
pub enum EpollDispatch {
    /// Event has to be dispatch to an EpollHandler.
    DeviceHandler(usize, DeviceEventT),
}

struct MaybeHandler {
    handler: Option<Box<dyn EpollHandler>>,
    receiver: Receiver<Box<dyn EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<dyn EpollHandler>>) -> Self {
        MaybeHandler {
            handler: None,
            receiver,
        }
    }
}

/// Handles epoll related business.
// A glaring shortcoming of the current design is the liberal passing around of raw_fds,
// and duping of file descriptors. This issue will be solved when we also implement device removal.
pub struct EpollContext {
    epoll_raw_fd: RawFd,
    // FIXME: find a different design as this does not scale. This Vec can only grow.
    dispatch_table: Vec<Option<EpollDispatch>>,
    device_handlers: Vec<MaybeHandler>,
    device_id_to_handler_id: HashMap<(u32, String), usize>,

    // This part of the class relates to incoming epoll events. The incoming events are held in
    // `events[event_index..num_events)`, followed by the events not yet read from `epoll_raw_fd`.
    events: Vec<epoll::Event>,
    num_events: usize,
    event_index: usize,
}

impl EpollContext {
    /// Creates a new `EpollContext` object.
    pub fn new() -> Result<Self> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 2 queue events for virtio block
        // * 4 for virtio net
        // The total is 8 elements; allowing spare capacity to avoid reallocations.
        let mut dispatch_table = Vec::with_capacity(20);
        dispatch_table.push(None);
        Ok(EpollContext {
            epoll_raw_fd,
            dispatch_table,
            device_handlers: Vec::with_capacity(6),
            device_id_to_handler_id: HashMap::new(),
            events: vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN],
            num_events: 0,
            event_index: 0,
        })
    }

    /// Given a file descriptor `fd`, and an EpollDispatch token `token`,
    /// associate `token` with an `EPOLLIN` event for `fd`, through the
    /// `dispatch_table`.
    pub fn add_epollin_event<T: AsRawFd + ?Sized>(
        &mut self,
        fd: &T,
        token: EpollDispatch,
    ) -> Result<()> {
        // The index in the dispatch where the new token will be added.
        let dispatch_index = self.dispatch_table.len() as u64;

        // Add a new epoll event on `fd`, associated with index
        // `dispatch_index`.
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )
        .map_err(Error::EpollFd)?;

        // Add the associated token at index `dispatch_index`
        self.dispatch_table.push(Some(token));

        Ok(())
    }

    /// Allocates `count` dispatch tokens, simultaneously registering them in
    /// `dispatch_table`. The tokens will be associated with a device.
    /// This device's handler will be added to the end of `device_handlers`.
    /// This returns the index of the first token, and a channel on which to
    /// send an epoll handler for the relevant device.
    pub fn allocate_tokens_for_device(
        &mut self,
        count: usize,
    ) -> (u64, Sender<Box<dyn EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        self.dispatch_table.extend((0..count).map(|index| {
            Some(EpollDispatch::DeviceHandler(
                device_idx,
                index as DeviceEventT,
            ))
        }));
        self.device_handlers.push(MaybeHandler::new(receiver));

        (dispatch_base, sender)
    }

    /// Allocate tokens for a virtio device, as with `allocate_tokens_for_device`,
    /// but also call T::new to create a device handler for the device. This handler
    /// will then be associated to a given `device_id` through the `device_id_to_handler_id`
    /// table. Finally, return the handler.
    pub fn allocate_tokens_for_virtio_device<T: EpollConfigConstructor>(
        &mut self,
        type_id: u32,
        device_id: &str,
        count: usize,
    ) -> T {
        let (dispatch_base, sender) = self.allocate_tokens_for_device(count);

        self.device_id_to_handler_id.insert(
            (type_id, device_id.to_string()),
            self.device_handlers.len() - 1,
        );

        T::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    /// Obtains the `EpollHandler` trait object associated with the provided handler id.
    pub fn get_device_handler_by_handler_id(&mut self, id: usize) -> Result<&mut dyn EpollHandler> {
        let maybe = &mut self.device_handlers[id];
        match maybe.handler {
            Some(ref mut v) => Ok(v.as_mut()),
            None => {
                // This should only be called in response to an epoll trigger.
                // Moreover, this branch of the match should only be active on the first call
                // (the first epoll event for this device), therefore the channel is guaranteed
                // to contain a message for the first epoll event since both epoll event
                // registration and channel send() happen in the device activate() function.
                let received = maybe
                    .receiver
                    .try_recv()
                    .map_err(|_| Error::DeviceEventHandlerNotFound)?;
                Ok(maybe.handler.get_or_insert(received).as_mut())
            }
        }
    }

    /// Obtains a mut reference to an object implementing `EpollHandler` for the given device
    /// type and identifier.
    pub fn get_device_handler_by_device_id<T: EpollHandler + 'static>(
        &mut self,
        type_id: u32,
        device_id: &str,
    ) -> Result<&mut T> {
        let handler_id = *self
            .device_id_to_handler_id
            .get(&(type_id, device_id.to_string()))
            .ok_or(Error::DeviceEventHandlerNotFound)?;
        let device_handler = self.get_device_handler_by_handler_id(handler_id)?;
        device_handler
            .as_mut_any()
            .downcast_mut::<T>()
            .ok_or(Error::DeviceEventHandlerInvalidDowncast)
    }

    /// Gets the next event from `epoll_raw_fd`.
    pub fn get_event(&mut self) -> Result<epoll::Event> {
        // Check if no events are left in `events`:
        while self.num_events == self.event_index {
            // If so, get more events.
            // Note that if there is an error, we propagate it.
            self.num_events =
                epoll::wait(self.epoll_raw_fd, -1, &mut self.events[..]).map_err(Error::Poll)?;
            // And reset the event_index.
            self.event_index = 0;
        }

        // Now, move our position in the stream.
        self.event_index += 1;

        // And return the appropriate event.
        Ok(self.events[self.event_index - 1])
    }

    /// Wait for and dispatch events.
    pub fn run_event_loop(&mut self) {
        let event = self.get_event().unwrap();
        let evset = match epoll::Events::from_bits(event.events) {
            Some(evset) => evset,
            None => {
                let evbits = event.events;
                warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                return;
            }
        };

        match self.dispatch_table[event.data as usize] {
            Some(EpollDispatch::DeviceHandler(device_idx, device_token)) => {
                METRICS.vmm.device_events.inc();
                match self.get_device_handler_by_handler_id(device_idx) {
                    Ok(handler) => match handler.handle_event(device_token, evset) {
                        Err(devices::Error::PayloadExpected) => {
                            panic!("Received update disk image event with empty payload.")
                        }
                        Err(devices::Error::UnknownEvent { device, event }) => {
                            panic!("Unknown event: {:?} {:?}", device, event)
                        }
                        _ => (),
                    },
                    Err(e) => warn!("invalid handler for device {}: {:?}", device_idx, e),
                }
            }
            None => {
                panic!("what do you mean nothing?!");
                // Do nothing.
            }
        };
        // Currently, we never get to return with Ok(EventLoopExitReason::Break) because
        // we just invoke stop() whenever that would happen.
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_raw_fd
    }
}

impl Subscriber for EpollContext {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: EpollEvent, _: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.epoll_raw_fd && event_set == EventSet::IN {
            self.run_event_loop();
        } else {
            error!("Spurious EventManager event for handler: EpollContext");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(EventSet::IN, self.as_raw_fd() as u64)]
    }
}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll.");
        }
    }
}

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
#[derive(Debug)]
pub enum Error {
    /// This error is thrown by the minimal boot loader implementation.
    ConfigureSystem(arch::Error),
    /// Legacy devices work with Event file descriptors and the creation can fail because
    /// of resource exhaustion.
    #[cfg(target_arch = "x86_64")]
    CreateLegacyDevice(device_manager::legacy::Error),
    /// An operation on the epoll instance failed due to resource exhaustion or bad configuration.
    EpollFd(io::Error),
    /// Cannot read from an Event file descriptor.
    EventFd(io::Error),
    /// Polly error wrapper.
    EventManager(event_manager::Error),
    /// An event arrived for a device, but the dispatcher can't find the event (epoll) handler.
    DeviceEventHandlerNotFound,
    /// An epoll handler can't be downcasted to the desired type.
    DeviceEventHandlerInvalidDowncast,
    /// I8042 Error.
    I8042Error(devices::legacy::I8042DeviceError),
    /// Cannot access kernel file.
    KernelFile(io::Error),
    /// Cannot open /dev/kvm. Either the host does not have KVM or Firecracker does not have
    /// permission to open the file descriptor.
    KvmContext(vstate::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot add devices to the Legacy I/O Bus.
    LegacyIOBus(device_manager::legacy::Error),
    /// Cannot load command line.
    LoadCommandline(kernel::cmdline::Error),
    /// Internal logger error.
    Logger(LoggerError),
    /// Epoll wait failed.
    Poll(io::Error),
    /// Cannot add a device to the MMIO Bus.
    RegisterMMIODevice(device_manager::mmio::Error),
    /// Cannot build seccomp filters.
    SeccompFilters(seccomp::Error),
    /// Write to the serial console failed.
    Serial(io::Error),
    /// Cannot create Timer file descriptor.
    TimerFd(io::Error),
    /// Vcpu error.
    Vcpu(vstate::Error),
    /// Cannot send event to vCPU.
    VcpuEvent(vstate::Error),
    /// Cannot create a vCPU handle.
    VcpuHandle(vstate::Error),
    /// vCPU resume failed.
    VcpuResume,
    /// Cannot spawn a new Vcpu thread.
    VcpuSpawn(std::io::Error),
    /// Vm error.
    Vm(vstate::Error),
    /// Error thrown by observer object on Vmm initialization.
    VmmObserverInit(utils::errno::Error),
    /// Error thrown by observer object on Vmm teardown.
    VmmObserverTeardown(utils::errno::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            ConfigureSystem(e) => write!(f, "System configuration error: {:?}", e),
            #[cfg(target_arch = "x86_64")]
            CreateLegacyDevice(e) => write!(f, "Error creating legacy device: {:?}", e),
            EpollFd(e) => write!(f, "Epoll fd error: {}", e),
            EventFd(e) => write!(f, "Event fd error: {}", e),
            EventManager(e) => write!(f, "Event manager error: {:?}", e),
            DeviceEventHandlerNotFound => write!(
                f,
                "Device event handler not found. This might point to a guest device driver issue."
            ),
            DeviceEventHandlerInvalidDowncast => write!(
                f,
                "Device event handler couldn't be downcasted to expected type."
            ),
            I8042Error(e) => write!(f, "I8042 error: {}", e),
            KernelFile(e) => write!(f, "Cannot access kernel file: {}", e),
            KvmContext(e) => write!(f, "Failed to validate KVM support: {:?}", e),
            #[cfg(target_arch = "x86_64")]
            LegacyIOBus(e) => write!(f, "Cannot add devices to the legacy I/O Bus. {}", e),
            LoadCommandline(e) => write!(f, "Cannot load command line: {}", e),
            Logger(e) => write!(f, "Logger error: {}", e),
            Poll(e) => write!(f, "Epoll wait failed: {}", e),
            RegisterMMIODevice(e) => write!(f, "Cannot add a device to the MMIO Bus. {}", e),
            SeccompFilters(e) => write!(f, "Cannot build seccomp filters: {}", e),
            Serial(e) => write!(f, "Error writing to the serial console: {:?}", e),
            TimerFd(e) => write!(f, "Error creating timer fd: {}", e),
            Vcpu(e) => write!(f, "Vcpu error: {}", e),
            VcpuEvent(e) => write!(f, "Cannot send event to vCPU. {:?}", e),
            VcpuHandle(e) => write!(f, "Cannot create a vCPU handle. {}", e),
            VcpuResume => write!(f, "vCPUs resume failed."),
            VcpuSpawn(e) => write!(f, "Cannot spawn Vcpu thread: {}", e),
            Vm(e) => write!(f, "Vm error: {}", e),
            VmmObserverInit(e) => write!(
                f,
                "Error thrown by observer object on Vmm initialization: {}",
                e
            ),
            VmmObserverTeardown(e) => {
                write!(f, "Error thrown by observer object on Vmm teardown: {}", e)
            }
        }
    }
}

/// Trait for objects that need custom initialization and teardown during the Vmm lifetime.
pub trait VmmEventsObserver {
    /// This function will be called during microVm boot.
    fn on_vmm_boot(&mut self) -> std::result::Result<(), utils::errno::Error> {
        Ok(())
    }
    /// This function will be called on microVm teardown.
    fn on_vmm_stop(&mut self) -> std::result::Result<(), utils::errno::Error> {
        Ok(())
    }
}

/// Shorthand result type for internal VMM commands.
pub type Result<T> = std::result::Result<T, Error>;

/// Contains the state and associated methods required for the Firecracker VMM.
pub struct Vmm {
    events_observer: Option<Box<dyn VmmEventsObserver>>,

    // Guest VM core resources.
    guest_memory: GuestMemoryMmap,

    kernel_cmdline: KernelCmdline,

    vcpus_handles: Vec<VcpuHandle>,
    exit_evt: EventFd,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    pio_device_manager: PortIODeviceManager,
}

impl Vmm {
    /// Gets the the specified bus device.
    pub fn get_bus_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        self.mmio_device_manager.get_device(device_type, device_id)
    }

    #[cfg(target_arch = "aarch64")]
    fn get_mmio_device_info(&self) -> Option<&HashMap<(DeviceType, String), MMIODeviceInfo>> {
        Some(self.mmio_device_manager.get_device_info())
    }

    fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vmm_seccomp_filter: BpfProgram,
        vcpu_seccomp_filter: BpfProgramRef,
    ) -> Result<()> {
        let vcpu_count = vcpus.len();

        if let Some(observer) = self.events_observer.as_mut() {
            observer.on_vmm_boot().map_err(Error::VmmObserverInit)?;
        }

        Vcpu::register_kick_signal_handler();

        self.vcpus_handles.reserve(vcpu_count as usize);

        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.mmio_device_manager.bus.clone());

            self.vcpus_handles.push(
                vcpu.start_threaded(vcpu_seccomp_filter.to_vec())
                    .map_err(Error::VcpuHandle)?,
            );
        }

        // Load seccomp filters for the VMM thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        SeccompFilter::apply(vmm_seccomp_filter).map_err(Error::SeccompFilters)?;

        // The vcpus start off in the `Paused` state, let them run.
        self.resume_vcpus()?;

        Ok(())
    }

    fn resume_vcpus(&mut self) -> Result<()> {
        for handle in self.vcpus_handles.iter() {
            handle
                .send_event(VcpuEvent::Resume)
                .map_err(Error::VcpuEvent)?;
        }
        for handle in self.vcpus_handles.iter() {
            match handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(1000))
            {
                Ok(VcpuResponse::Resumed) => (),
                _ => return Err(Error::VcpuResume),
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    fn configure_system(&self, vcpus: &[Vcpu], initrd: &Option<InitrdConfig>) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        arch::x86_64::configure_system(
            &self.guest_memory,
            vm_memory::GuestAddress(arch::x86_64::layout::CMDLINE_START),
            self.kernel_cmdline.len() + 1,
            initrd,
            vcpus.len() as u8,
        )
        .map_err(Error::ConfigureSystem)?;

        #[cfg(target_arch = "aarch64")]
        {
            let vcpu_mpidr = vcpus.into_iter().map(|cpu| cpu.get_mpidr()).collect();
            arch::aarch64::configure_system(
                &self.guest_memory,
                &self
                    .kernel_cmdline
                    .as_cstring()
                    .map_err(Error::LoadCommandline)?,
                vcpu_mpidr,
                self.get_mmio_device_info(),
                self.vm.get_irqchip(),
                initrd,
            )
            .map_err(Error::ConfigureSystem)?;
        }
        Ok(())
    }

    /// Returns a reference to the inner `GuestMemoryMmap` object if present, or `None` otherwise.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }

    /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> Result<()> {
        self.pio_device_manager
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(Error::I8042Error)
    }

    /// Waits for all vCPUs to exit and terminates the Firecracker process.
    pub fn stop(&mut self, exit_code: i32) {
        info!("Vmm is stopping.");

        if let Some(observer) = self.events_observer.as_mut() {
            if let Err(e) = observer.on_vmm_stop() {
                warn!("{}", Error::VmmObserverTeardown(e));
            }
        }

        // Log the metrics before exiting.
        if let Err(e) = LOGGER.log_metrics() {
            error!("Failed to log metrics while stopping: {}", e);
        }

        // Exit from Firecracker using the provided exit code. Safe because we're terminating
        // the process anyway.
        unsafe {
            libc::_exit(exit_code);
        }
    }

    fn log_boot_time(t0_ts: &TimestampUs) {
        let now_tm_us = TimestampUs::default();

        let boot_time_us = now_tm_us.time_us - t0_ts.time_us;
        let boot_time_cpu_us = now_tm_us.cputime_us - t0_ts.cputime_us;
        info!(
            "Guest-boot-time = {:>6} us {} ms, {:>6} CPU us {} CPU ms",
            boot_time_us,
            boot_time_us / 1000,
            boot_time_cpu_us,
            boot_time_cpu_us / 1000
        );
    }

    /// Returns a reference to the inner KVM Vm object.
    pub fn kvm_vm(&self) -> &Vm {
        &self.vm
    }
}

impl Subscriber for Vmm {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: EpollEvent, _: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.exit_evt.as_raw_fd() && event_set == EventSet::IN {
            let _ = self.exit_evt.read();
            // Query each vcpu for the exit_code.
            // If the exit_code can't be found on any vcpu, it means that the exit signal
            // has been issued by the i8042 controller in which case we exit with
            // FC_EXIT_CODE_OK.
            let exit_code = self
                .vcpus_handles
                .iter()
                .find_map(|handle| match handle.response_receiver().try_recv() {
                    Ok(VcpuResponse::Exited(exit_code)) => Some(exit_code),
                    _ => None,
                })
                .unwrap_or(FC_EXIT_CODE_OK);
            self.stop(i32::from(exit_code));
        } else {
            error!("Spurious EventManager event for handler: Vmm");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.exit_evt.as_raw_fd() as u64,
        )]
    }
}

#[cfg(test)]
mod tests {}
