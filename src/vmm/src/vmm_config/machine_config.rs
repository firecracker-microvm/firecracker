// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Debug;
use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};
use crate::pci::bus::MAX_PCI_BUSES;
use crate::vmm_config::snapshot::{MemBackendConfig, MemBackendType};

/// The default memory size of the VM, in MiB.
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;
/// The maximum number of PCIe hot-plug ports. Each port starts a secondary bus,
/// and the root bus takes one of the bus numbers.
pub const MAX_PCIE_HOTPLUG_PORTS: u8 = MAX_PCI_BUSES - 1;

/// Errors associated with configuring the microVM.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum MachineConfigError {
    /// The memory size (MiB) is smaller than the previously set balloon device target size.
    IncompatibleBalloonSize,
    /// The memory size (MiB) is either 0, or not a multiple of the configured page size.
    InvalidMemorySize,
    /// The number of vCPUs must be greater than 0, less than {MAX_SUPPORTED_VCPUS:} and must be 1 or an even number if SMT is enabled.
    InvalidVcpuCount,
    /// Could not get the configuration of the previously installed balloon device to validate the memory size.
    InvalidVmState,
    /// Invalid queue count {1} for device {0}; cannot exceed the configured vCPU count {2}.
    InvalidQueueCount(String, u16, u8),
    /// Enabling simultaneous multithreading is not supported on aarch64.
    #[cfg(target_arch = "aarch64")]
    SmtNotSupported,
    /// Could not determine host kernel version when checking hugetlbfs compatibility
    KernelVersion,
    /// The number of PCIe hot-plug ports must be at most {MAX_PCIE_HOTPLUG_PORTS:}.
    InvalidPcieHotplugPorts,
    /// PCIe hot-plug ports require `--enable-pci`.
    PcieHotplugPortsRequirePci,
    /// Only the `SharedMemfd` backend type is valid for `mem_backend` in the machine configuration.
    InvalidMemBackend,
}

/// Describes the possible (huge)page configurations for a microVM's memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HugePageConfig {
    /// Back guest memory by 4K pages, no hugepage behavior
    #[default]
    None,
    /// Use madvise(MADV_HUGEPAGE) for transparent huge pages
    Transparent,
    /// Back guest memory by 2MB hugetlbfs pages
    #[serde(rename = "2M")]
    Hugetlbfs2M,
}

impl HugePageConfig {
    /// Checks whether the given memory size (in MiB) is valid for this [`HugePageConfig`], e.g.
    /// whether it is a multiple of the page size
    fn is_valid_mem_size(&self, mem_size_mib: usize) -> bool {
        let divisor = match self {
            // Any integer memory size expressed in MiB will be a multiple of 4096KiB.
            HugePageConfig::None => 1,
            // Note: THP technically supports memory not multiple of 2MB, however that disables some optimizations done
            // by the kernel (e.g. automatic memory alignment on Linux 6.4+).
            // To avoid performance/fragmentation surprises, having a memory multiple of 2MB is wiser.
            HugePageConfig::Transparent => 2,
            HugePageConfig::Hugetlbfs2M => 2,
        };

        mem_size_mib.is_multiple_of(divisor)
    }

    /// Returns the flags required to pass to `mmap`, in addition to `MAP_ANONYMOUS`, to
    /// create a mapping backed by huge pages as described by this [`HugePageConfig`].
    pub fn mmap_flags(&self) -> libc::c_int {
        match self {
            HugePageConfig::None | HugePageConfig::Transparent => 0,
            HugePageConfig::Hugetlbfs2M => libc::MAP_HUGETLB | libc::MAP_HUGE_2MB,
        }
    }

    /// Returns the flags required to pass to [libc::madvise], after allocating anonymous guest memory.
    /// Note: returning [libc::MADV_NORMAL] might skip the call to `madvise` entirely.
    pub fn madvise_flags(&self) -> libc::c_int {
        match self {
            HugePageConfig::Transparent => libc::MADV_HUGEPAGE,
            HugePageConfig::None | HugePageConfig::Hugetlbfs2M => libc::MADV_NORMAL,
        }
    }

    /// Returns `true` iff this [`HugePageConfig`] describes a hugetlbfs-based configuration.
    pub fn is_hugetlbfs(&self) -> bool {
        matches!(self, HugePageConfig::Hugetlbfs2M)
    }

    /// Gets the page size in bytes of this [`HugePageConfig`].
    pub fn page_size(&self) -> usize {
        match self {
            HugePageConfig::None | HugePageConfig::Transparent => 4096,
            HugePageConfig::Hugetlbfs2M => 2 * 1024 * 1024,
        }
    }
}

impl From<HugePageConfig> for Option<memfd::HugetlbSize> {
    fn from(value: HugePageConfig) -> Self {
        match value {
            HugePageConfig::None | HugePageConfig::Transparent => None,
            HugePageConfig::Hugetlbfs2M => Some(memfd::HugetlbSize::Huge2MB),
        }
    }
}

/// Struct used in PUT `/machine-config` API call.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// Number of vcpu to start.
    pub vcpu_count: u8,
    /// The memory size in MiB.
    pub mem_size_mib: usize,
    /// Enables or disabled SMT.
    #[serde(default)]
    pub smt: bool,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    // FIXME: once support for static CPU templates is removed, this field can be dropped altogether
    #[serde(
        default,
        skip_serializing_if = "is_none_or_custom_template",
        deserialize_with = "deserialize_static_template",
        serialize_with = "serialize_static_template"
    )]
    pub cpu_template: Option<CpuTemplateType>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: bool,
    /// Configures what page size Firecracker should use to back guest memory.
    #[serde(default)]
    pub huge_pages: HugePageConfig,
    /// Number of PCIe root ports to create.
    #[serde(default)]
    pub pcie_hotplug_ports: u8,
    /// Memory backend to share guest memory with at boot. Only `SharedMemfd` is accepted here:
    /// guest memory is then backed by a single memfd, handed to the process listening on
    /// `backend_path` before the microVM starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_backend: Option<MemBackendConfig>,
    /// GDB socket address.
    #[cfg(feature = "gdb")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gdb_socket_path: Option<String>,
}

fn is_none_or_custom_template(template: &Option<CpuTemplateType>) -> bool {
    matches!(template, None | Some(CpuTemplateType::Custom(_)))
}

fn deserialize_static_template<'de, D>(deserializer: D) -> Result<Option<CpuTemplateType>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StaticCpuTemplate>::deserialize(deserializer)
        .map(|maybe_template| maybe_template.map(CpuTemplateType::Static))
}

fn serialize_static_template<S>(
    template: &Option<CpuTemplateType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let Some(CpuTemplateType::Static(template)) = template else {
        // We have a skip_serializing_if on the field
        unreachable!()
    };

    template.serialize(serializer)
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
            smt: false,
            cpu_template: None,
            track_dirty_pages: false,
            huge_pages: HugePageConfig::None,
            pcie_hotplug_ports: 0,
            mem_backend: None,
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        }
    }
}

/// Struct used in PATCH `/machine-config` API call.
/// Used to update `MachineConfig` in `VmResources`.
/// This struct mirrors all the fields in `MachineConfig`.
/// All fields are optional, but at least one needs to be specified.
/// If a field is `Some(value)` then we assume an update is requested
/// for that field.
#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfigUpdate {
    /// Number of vcpu to start.
    #[serde(default)]
    pub vcpu_count: Option<u8>,
    /// The memory size in MiB.
    #[serde(default)]
    pub mem_size_mib: Option<usize>,
    /// Enables or disabled SMT.
    #[serde(default)]
    pub smt: Option<bool>,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(default)]
    pub cpu_template: Option<StaticCpuTemplate>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: Option<bool>,
    /// Configures what page size Firecracker should use to back guest memory.
    #[serde(default)]
    pub huge_pages: Option<HugePageConfig>,
    /// Number of PCIe root ports to create.
    #[serde(default)]
    pub pcie_hotplug_ports: Option<u8>,
    /// Memory backend to share guest memory with at boot. `None` leaves the current value;
    /// `Some(None)`, which a `PUT` without the field converts to, removes the backend.
    #[serde(default)]
    pub mem_backend: Option<Option<MemBackendConfig>>,
    /// GDB socket address.
    #[cfg(feature = "gdb")]
    #[serde(default)]
    pub gdb_socket_path: Option<String>,
}

impl MachineConfigUpdate {
    /// Checks if the update request contains any data.
    /// Returns `true` if all fields are set to `None` which means that there is nothing
    /// to be updated.
    pub fn is_empty(&self) -> bool {
        self == &Default::default()
    }
}

impl From<MachineConfig> for MachineConfigUpdate {
    fn from(cfg: MachineConfig) -> Self {
        MachineConfigUpdate {
            vcpu_count: Some(cfg.vcpu_count),
            mem_size_mib: Some(cfg.mem_size_mib),
            smt: Some(cfg.smt),
            cpu_template: cfg.static_template(),
            track_dirty_pages: Some(cfg.track_dirty_pages),
            huge_pages: Some(cfg.huge_pages),
            pcie_hotplug_ports: Some(cfg.pcie_hotplug_ports),
            mem_backend: Some(cfg.mem_backend),
            #[cfg(feature = "gdb")]
            gdb_socket_path: cfg.gdb_socket_path,
        }
    }
}

impl MachineConfig {
    /// Sets cpu tempalte field to `CpuTemplateType::Custom(cpu_template)`.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.cpu_template = Some(CpuTemplateType::Custom(cpu_template));
    }

    fn static_template(&self) -> Option<StaticCpuTemplate> {
        match self.cpu_template {
            Some(CpuTemplateType::Static(template)) => Some(template),
            _ => None,
        }
    }

    /// Updates [`MachineConfig`] with [`MachineConfigUpdate`].
    /// Mapping for cpu template update:
    /// StaticCpuTemplate::None -> None
    /// StaticCpuTemplate::Other -> Some(CustomCpuTemplate::Static(Other)),
    /// Returns the updated `MachineConfig` object.
    pub fn update(
        &self,
        update: &MachineConfigUpdate,
    ) -> Result<MachineConfig, MachineConfigError> {
        let vcpu_count = update.vcpu_count.unwrap_or(self.vcpu_count);

        let smt = update.smt.unwrap_or(self.smt);

        #[cfg(target_arch = "aarch64")]
        if smt {
            return Err(MachineConfigError::SmtNotSupported);
        }

        if vcpu_count == 0 || vcpu_count > MAX_SUPPORTED_VCPUS {
            return Err(MachineConfigError::InvalidVcpuCount);
        }

        // If SMT is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if smt && vcpu_count > 1 && vcpu_count % 2 == 1 {
            return Err(MachineConfigError::InvalidVcpuCount);
        }

        let mem_size_mib = update.mem_size_mib.unwrap_or(self.mem_size_mib);
        let page_config = update.huge_pages.unwrap_or(self.huge_pages);

        if mem_size_mib == 0 || !page_config.is_valid_mem_size(mem_size_mib) {
            return Err(MachineConfigError::InvalidMemorySize);
        }

        let pcie_hotplug_ports = update.pcie_hotplug_ports.unwrap_or(self.pcie_hotplug_ports);
        if pcie_hotplug_ports > MAX_PCIE_HOTPLUG_PORTS {
            return Err(MachineConfigError::InvalidPcieHotplugPorts);
        }

        let cpu_template = match update.cpu_template {
            None => self.cpu_template.clone(),
            Some(StaticCpuTemplate::None) => None,
            Some(other) => Some(CpuTemplateType::Static(other)),
        };

        let mem_backend = match &update.mem_backend {
            None => self.mem_backend.clone(),
            Some(mem_backend) => mem_backend.clone(),
        };
        if let Some(backend) = &mem_backend
            && backend.backend_type != MemBackendType::SharedMemfd
        {
            return Err(MachineConfigError::InvalidMemBackend);
        }

        Ok(MachineConfig {
            vcpu_count,
            mem_size_mib,
            smt,
            cpu_template,
            track_dirty_pages: update.track_dirty_pages.unwrap_or(self.track_dirty_pages),
            huge_pages: page_config,
            pcie_hotplug_ports,
            mem_backend,
            #[cfg(feature = "gdb")]
            gdb_socket_path: update.gdb_socket_path.clone(),
        })
    }

    pub(crate) fn validate_num_queues(
        &self,
        id: &str,
        num_queues: Option<NonZeroU16>,
    ) -> Result<(), MachineConfigError> {
        let Some(num_queues) = num_queues else {
            return Ok(());
        };
        if num_queues.get() > u16::from(self.vcpu_count) {
            return Err(MachineConfigError::InvalidQueueCount(
                id.to_owned(),
                num_queues.get(),
                self.vcpu_count,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::path::PathBuf;

    use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};
    use crate::vmm_config::machine_config::{
        MachineConfig, MachineConfigError, MachineConfigUpdate,
    };
    use crate::vmm_config::snapshot::{MemBackendConfig, MemBackendType};

    // Ensure the special (de)serialization logic for the cpu_template field works:
    // only static cpu templates can be specified via the machine-config endpoint, but
    // we still cram custom cpu templates into the MachineConfig struct if they're set otherwise
    // Ensure that during (de)serialization we preserve static templates, but we set custom
    // templates to None
    #[test]
    fn test_serialize_machine_config() {
        #[cfg(target_arch = "aarch64")]
        const TEMPLATE: StaticCpuTemplate = StaticCpuTemplate::V1N1;
        #[cfg(target_arch = "x86_64")]
        const TEMPLATE: StaticCpuTemplate = StaticCpuTemplate::T2S;

        let mconfig = MachineConfig {
            cpu_template: None,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert!(deserialized.cpu_template.is_none());

        let mconfig = MachineConfig {
            cpu_template: Some(CpuTemplateType::Static(TEMPLATE)),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert_eq!(
            deserialized.cpu_template,
            Some(CpuTemplateType::Static(TEMPLATE))
        );

        let mconfig = MachineConfig {
            cpu_template: Some(CpuTemplateType::Custom(CustomCpuTemplate::default())),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert!(deserialized.cpu_template.is_none());
    }

    #[test]
    fn test_validate_num_queues() {
        let mconfig = MachineConfig {
            vcpu_count: 4,
            ..Default::default()
        };

        mconfig.validate_num_queues("dev", None).unwrap();
        mconfig
            .validate_num_queues("dev", NonZeroU16::new(1))
            .unwrap();
        mconfig
            .validate_num_queues("dev", NonZeroU16::new(4))
            .unwrap();
        assert_eq!(
            mconfig.validate_num_queues("dev", NonZeroU16::new(5)),
            Err(MachineConfigError::InvalidQueueCount(
                "dev".to_string(),
                5,
                4
            ))
        );
    }

    #[test]
    fn test_mem_backend() {
        let backend = |backend_type| MemBackendConfig {
            backend_path: PathBuf::from("/backend.sock"),
            backend_type,
        };

        // Only `SharedMemfd` makes sense at boot: `File` and `Uffd` describe how memory is
        // populated on restore.
        let base = MachineConfig::default();
        for backend_type in [MemBackendType::File, MemBackendType::Uffd] {
            let update = MachineConfigUpdate {
                mem_backend: Some(Some(backend(backend_type))),
                ..Default::default()
            };
            assert_eq!(
                base.update(&update).unwrap_err(),
                MachineConfigError::InvalidMemBackend
            );
        }

        let update = MachineConfigUpdate {
            mem_backend: Some(Some(backend(MemBackendType::SharedMemfd))),
            ..Default::default()
        };
        let with_backend = base.update(&update).unwrap();
        assert_eq!(
            with_backend.mem_backend,
            Some(backend(MemBackendType::SharedMemfd))
        );

        // An update that does not mention the backend leaves it in place; a `PUT` without it (a
        // full `MachineConfig`, converted) removes it.
        let update = serde_json::from_str::<MachineConfigUpdate>(r#"{"vcpu_count": 2}"#).unwrap();
        assert_eq!(update.mem_backend, None);
        let updated = with_backend.update(&update).unwrap();
        assert_eq!(updated.mem_backend, with_backend.mem_backend);
        let put = MachineConfigUpdate::from(MachineConfig::default());
        assert_eq!(put.mem_backend, Some(None));
        assert_eq!(with_backend.update(&put).unwrap().mem_backend, None);

        // The field round-trips through JSON (configuration file, `GET /machine-config`) and is
        // left out when unset.
        let serialized = serde_json::to_string(&with_backend).unwrap();
        assert!(serialized.contains("\"backend_type\":\"SharedMemfd\""));
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();
        assert_eq!(deserialized.mem_backend, with_backend.mem_backend);
        assert!(
            !serde_json::to_string(&MachineConfig::default())
                .unwrap()
                .contains("mem_backend")
        );
    }
}
