// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std;
use std::fmt::{Display, Formatter, Result};

use device_manager;
use devices;
use kernel::loader as kernel_loader;
use memory_model::GuestMemoryError;
use seccomp;
use sys_util;
use vstate;

/// The microvm state. When Firecracker starts, the instance state is Uninitialized.
/// Once start_microvm method is called, the state goes from Uninitialized to Starting.
/// The state is changed to Running before ending the start_microvm method.
/// Halting and Halted are currently unsupported.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum InstanceState {
    /// Microvm is not initialized.
    Uninitialized,
    /// Microvm is starting.
    Starting,
    /// Microvm is running.
    Running,
    /// Microvm received a halt instruction.
    Halting,
    /// Microvm is halted.
    Halted,
}

/// The strongly typed that contains general information about the microVM.
#[derive(Debug, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// The state of the microVM.
    pub state: InstanceState,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
}

/// Errors associated with starting the instance.
// TODO: add error kind to these variants because not all these errors are user or internal.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// This error is thrown by the minimal boot loader implementation.
    /// It is related to a faulty memory configuration.
    ConfigureSystem(arch::Error),
    /// Cannot configure the VM.
    ConfigureVm(vstate::Error),
    /// Unable to seek the block device backing file due to invalid permissions or
    /// the file was deleted/corrupted.
    CreateBlockDevice(sys_util::Error),
    /// Split this at some point.
    /// Internal errors are due to resource exhaustion.
    /// Users errors are due to invalid permissions.
    CreateNetDevice(devices::virtio::Error),
    #[cfg(feature = "vsock")]
    /// Creating a vsock device can only fail if the /dev/vhost-vsock device cannot be open.
    CreateVsockDevice(devices::virtio::vhost::Error),
    /// The device manager was not configured.
    DeviceManager,
    /// Executing a VM request failed.
    DeviceVmRequest(sys_util::Error),
    /// Cannot read from an Event file descriptor.
    EventFd,
    /// Memory regions are overlapping or mmap fails.
    GuestMemory(GuestMemoryError),
    /// The kernel command line is invalid.
    KernelCmdline(String),
    /// Cannot add devices to the Legacy I/O Bus.
    LegacyIOBus(device_manager::legacy::Error),
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image.
    Loader(kernel_loader::Error),
    /// The start command was issued more than once.
    MicroVMAlreadyRunning,
    /// Cannot start the VM because the kernel was not configured.
    MissingKernelConfig,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(std::io::Error),
    /// Cannot initialize a MMIO Block Device or add a device to the MMIO Bus.
    RegisterBlockDevice(device_manager::mmio::Error),
    /// Cannot add event to Epoll.
    RegisterEvent,
    /// Cannot initialize a MMIO Network Device or add a device to the MMIO Bus.
    RegisterNetDevice(device_manager::mmio::Error),
    #[cfg(feature = "vsock")]
    /// Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus.
    RegisterVsockDevice(device_manager::mmio::Error),
    /// Cannot build seccomp filters.
    SeccompFilters(seccomp::Error),
    /// Cannot create a new vCPU file descriptor.
    Vcpu(vstate::Error),
    /// vCPU configuration failed.
    VcpuConfigure(vstate::Error),
    /// vCPUs were not configured.
    VcpusNotConfigured,
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(std::io::Error),
}

impl Display for StartMicrovmError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::StartMicrovmError::*;
        match *self {
            ConfigureSystem(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Faulty memory configuration. {}", err_msg)
            }
            ConfigureVm(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot configure virtual machine. {}", err_msg)
            }
            CreateBlockDevice(ref err) => write!(
                f,
                "Unable to seek the block device backing file due to invalid permissions or \
                 the file was deleted/corrupted. Error number: {}",
                err.errno().to_string()
            ),
            #[cfg(feature = "vsock")]
            CreateVsockDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot create vsock device. {}", err_msg)
            }
            CreateNetDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot create network device. {}", err_msg)
            }
            DeviceVmRequest(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Executing a VM request failed. {}", err_msg)
            }
            DeviceManager => write!(f, "The device manager was not configured."),
            EventFd => write!(f, "Cannot read from an Event file descriptor."),
            GuestMemory(ref err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");
                write!(f, "Invalid Memory Configuration: {}", err_msg)
            }
            KernelCmdline(ref err) => write!(f, "Invalid kernel command line: {}", err),
            LegacyIOBus(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot add devices to the legacy I/O Bus. {}", err_msg)
            }
            Loader(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(
                    f,
                    "Cannot load kernel due to invalid memory configuration or invalid kernel \
                     image. {}",
                    err_msg
                )
            }
            MicroVMAlreadyRunning => write!(f, "Microvm already running."),
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot open the block device backing file. {}", err_msg)
            }
            RegisterBlockDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");
                write!(
                    f,
                    "Cannot initialize a MMIO Block Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
            RegisterEvent => write!(f, "Cannot add event to Epoll."),
            RegisterNetDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(
                    f,
                    "Cannot initialize a MMIO Network Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
            #[cfg(feature = "vsock")]
            RegisterVsockDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(
                    f,
                    "Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
            SeccompFilters(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot build seccomp filters. {}", err_msg)
            }
            Vcpu(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot create a new vCPU file descriptor. {}", err_msg)
            }
            VcpuConfigure(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "vCPU configuration failed. {}", err_msg)
            }
            VcpusNotConfigured => write!(f, "vCPUs were not configured."),
            VcpuSpawn(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot spawn vCPU thread. {}", err_msg)
            }
        }
    }
}
