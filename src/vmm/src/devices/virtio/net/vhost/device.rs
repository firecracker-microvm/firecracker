use std::cmp;
use std::io::Write;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use log::error;
use utils::eventfd::EventFd;
use utils::net::mac::MacAddr;
use utils::u64_to_usize;
use vm_memory::GuestMemory;

use crate::devices::virtio::device::{DeviceState, IrqTrigger, VirtioDevice};
use crate::devices::virtio::gen::virtio_net::{
    VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_MAC,
    VIRTIO_NET_F_MRG_RXBUF,
};
use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::net::device::ConfigSpace;
use crate::devices::virtio::net::{gen, NetError, Tap, NET_QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{ActivateError, TYPE_NET};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

pub const VIRTIO_NET_F_GUEST_USO4: u32 = 54;
pub const VIRTIO_NET_F_GUEST_USO6: u32 = 55;
pub const VIRTIO_NET_F_HOST_USO: u32 = 56;
pub const TUN_F_USO4: u32 = 0x20;
pub const TUN_F_USO6: u32 = 0x40;
pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 28;

use vhost::net::VhostNet as vhost_VhostNet;
use vhost::{vhost_kern, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, GuestAddress, GuestMemoryRegion};

impl core::fmt::Debug for VhostNet {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "VhostNet {{ id: {:?}, tap: {:?}, avail_features: {:?}, acked_features: {:?}, \
             config_space: {:?}, guest_mac: {:?}, device_state: {:?}, activate_evt: {:?}, \
             features: {:?} }}",
            self.id,
            self.tap,
            self.avail_features,
            self.acked_features,
            self.config_space,
            self.guest_mac,
            self.device_state,
            self.activate_evt,
            self.features,
        )
    }
}

pub struct VhostNet {
    pub(crate) id: String,

    /// The backend for this device: a tap.
    pub tap: Tap,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    pub(crate) irq_trigger: IrqTrigger,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    pub(crate) vhost: Option<vhost::vhost_kern::net::Net<Arc<GuestMemoryMmap>>>,

    pub(crate) features: u64,
}

impl VhostNet {
    /// Provides the host IFACE name of this net device.
    pub fn iface_name(&self) -> String {
        self.tap.if_name_as_str().to_string()
    }

    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap: Tap,
        guest_mac: Option<MacAddr>,
    ) -> Result<Self, NetError> {
        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_EVENT_IDX;
        let xdp = true;
        let uso = false;

        avail_features |= if !xdp {
            1 << VIRTIO_NET_F_GUEST_TSO4
                | 1 << VIRTIO_NET_F_HOST_TSO4
                | 1 << VIRTIO_NET_F_GUEST_TSO6
                | 1 << VIRTIO_NET_F_HOST_TSO6
                | 1 << VIRTIO_NET_F_HOST_USO
        } else {
            0
        };

        avail_features |= if !xdp && uso {
            1 << VIRTIO_NET_F_GUEST_USO4 | 1 << VIRTIO_NET_F_GUEST_USO6
        } else {
            0
        };

        // We could announce VIRTIO_RING_F_INDIRECT_DESC and
        // VIRTIO_NET_F_MRG_RXBUF but this is not needed at this
        // point.

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac = mac;
            // Enabling feature for MAC address configuration
            // If not set, the driver will generates a random MAC address
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        let mut queues = Vec::new();
        for size in NET_QUEUE_SIZES {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?);
            queues.push(Queue::new(size));
        }

        let features: u64 = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_NET_F_MRG_RXBUF;

        Ok(VhostNet {
            id: id.clone(),
            tap,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            irq_trigger: IrqTrigger::new().map_err(NetError::EventFd)?,
            config_space,
            guest_mac,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?,
            vhost: None,
            features,
        })
    }

    /// Create a new virtio network device given the interface name.
    pub fn new(
        id: String,
        tap_if_name: &str,
        guest_mac: Option<MacAddr>,
    ) -> Result<Self, NetError> {
        let tap = Tap::open_named(tap_if_name).map_err(NetError::TapOpen)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(gen::TUN_F_CSUM | gen::TUN_F_UFO | gen::TUN_F_TSO4 | gen::TUN_F_TSO6)
            .map_err(NetError::TapSetOffload)?;

        let vnet_hdr_size = i32::try_from(super::super::device::vnet_hdr_len()).unwrap();
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(NetError::TapSetVnetHdrSize)?;

        Self::new_with_tap(id, tap, guest_mac)
    }

    fn setup_vhost_handle(&mut self, mem: &GuestMemoryMmap) -> Result<(), ::vhost::Error> {
        let vhost = vhost_kern::net::Net::new(Arc::new(mem.clone()))?;

        vhost.set_owner()?;
        vhost.set_features(self.features)?;

        let regions: Vec<_> = mem
            .iter()
            .map(|region| VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.size() as u64,
                userspace_addr: mem.get_host_address(GuestAddress(0x0)).unwrap() as u64,
                mmap_offset: 0,
                mmap_handle: -1,
            })
            .collect();
        vhost.set_mem_table(&regions)?;
        vhost.set_vring_call(RX_INDEX, &self.irq_trigger.irq_evt)?;
        vhost.set_vring_call(TX_INDEX, &self.irq_trigger.irq_evt)?;

        vhost.set_vring_kick(RX_INDEX, &self.queue_evts[RX_INDEX])?;
        vhost.set_vring_kick(TX_INDEX, &self.queue_evts[TX_INDEX])?;

        for (queue_index, queue) in self.queues().iter().enumerate() {
            let qsize = queue.actual_size();
            vhost.set_vring_num(queue_index, qsize)?;

            let vring = VringConfigData {
                flags: 0,
                queue_max_size: qsize,
                queue_size: qsize,
                desc_table_addr: queue.desc_table.raw_value(),
                used_ring_addr: queue.used_ring.raw_value(),
                avail_ring_addr: queue.avail_ring.raw_value(),
                log_addr: None,
            };

            vhost.set_vring_addr(queue_index, &vring)?;
            vhost.set_backend(queue_index, Some(&self.tap.tap_file))?;
        }
        self.vhost = Some(vhost);
        Ok(())
    }
}

impl VirtioDevice for VhostNet {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        if self.acked_features & (1 << VIRTIO_NET_F_GUEST_USO4) == 0 {
            error!("please use a guest kernel with USO support (patched 6.1 or 6.2)");
        }
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.irq_trigger.irq_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicU32> {
        self.irq_trigger.irq_status.clone()
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[u64_to_usize(offset)..u64_to_usize(cmp::min(end, config_len))],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_space_bytes = self.config_space.as_mut_slice();
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| config_space_bytes.get_mut(start..end))
        else {
            error!("Failed to write config space");
            return;
        };

        dst.copy_from_slice(data);
        self.guest_mac = Some(self.config_space.guest_mac);
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        self.setup_vhost_handle(&mem)
            .map_err(ActivateError::Vhost)?;

        if self.activate_evt.write(1).is_err() {
            error!("Net: Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
