// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

use std::fs::File;
use std::mem;
use std::os::raw::c_ulong;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use utils::net::mac::MacAddr;

#[cfg(test)]
use crate::devices::virtio::net::device::vnet_hdr_len;
use crate::devices::virtio::net::tap::{IfReqBuilder, Tap};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::queue::{Queue, QueueError};
use crate::devices::virtio::test_utils::VirtQueue;
use crate::devices::DeviceError;
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::rate_limiter::RateLimiter;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

pub fn default_net() -> Net {
    let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
    // Id is the firecracker-facing identifier, e.g. local to the FC process. We thus do not need to
    // make sure it is globally unique
    let tap_device_id = format!("net-device{}", next_tap);
    // This is the device name on the host, and thus needs to be unique between all firecracker
    // processes. We cannot use the above counter to ensure this uniqueness (as it is
    // per-process). Thus, ask the kernel to assign us a number.
    let tap_if_name = "net-device%d";

    let guest_mac = default_guest_mac();

    let mut net = Net::new(
        tap_device_id,
        tap_if_name,
        Some(guest_mac),
        RateLimiter::default(),
        RateLimiter::default(),
    )
    .unwrap();
    net.configure_mmds_network_stack(
        MmdsNetworkStack::default_ipv4_addr(),
        Arc::new(Mutex::new(Mmds::default())),
    );
    enable(&net.tap);

    net
}

pub fn default_net_no_mmds() -> Net {
    let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
    let tap_device_id = format!("net-device{}", next_tap);

    let guest_mac = default_guest_mac();

    let net = Net::new(
        tap_device_id,
        "net-device%d",
        Some(guest_mac),
        RateLimiter::default(),
        RateLimiter::default(),
    )
    .unwrap();
    enable(&net.tap);

    net
}

#[derive(Debug)]
pub enum ReadTapMock {
    Failure,
    MockFrame(Vec<u8>),
    TapFrame,
}

impl ReadTapMock {
    pub fn mock_frame(&self) -> Vec<u8> {
        if let ReadTapMock::MockFrame(frame) = self {
            return frame.clone();
        }
        panic!("Can't get last mock frame");
    }
}

#[derive(Debug)]
pub enum WriteTapMock {
    Failure,
    Success,
}

// Used to simulate tap read and write fails in tests.
#[derive(Debug)]
pub struct Mocks {
    pub(crate) read_tap: ReadTapMock,
    pub(crate) write_tap: WriteTapMock,
}

impl Mocks {
    pub fn set_read_tap(&mut self, read_tap: ReadTapMock) {
        self.read_tap = read_tap;
    }

    pub fn set_write_tap(&mut self, write_tap: WriteTapMock) {
        self.write_tap = write_tap;
    }
}

impl Default for Mocks {
    fn default() -> Mocks {
        Mocks {
            read_tap: ReadTapMock::MockFrame(
                utils::rand::rand_alphanumerics(1234).as_bytes().to_vec(),
            ),
            write_tap: WriteTapMock::Success,
        }
    }
}

#[derive(Debug)]
pub enum NetQueue {
    Rx,
    Tx,
}

#[derive(Debug)]
pub enum NetEvent {
    RxQueue,
    RxRateLimiter,
    Tap,
    TxQueue,
    TxRateLimiter,
}

#[derive(Debug)]
pub struct TapTrafficSimulator {
    socket: File,
    send_addr: libc::sockaddr_ll,
}

impl TapTrafficSimulator {
    pub fn new(tap_index: i32) -> Self {
        // Create sockaddr_ll struct.
        // SAFETY: sockaddr_storage has no invariants and can be safely zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };

        let send_addr_ptr = &mut storage as *mut libc::sockaddr_storage;

        // SAFETY: `sock_addr` is a valid pointer and safe to derference.
        unsafe {
            let sock_addr: *mut libc::sockaddr_ll = send_addr_ptr.cast::<libc::sockaddr_ll>();
            (*sock_addr).sll_family = libc::sa_family_t::try_from(libc::AF_PACKET).unwrap();
            (*sock_addr).sll_protocol = u16::try_from(libc::ETH_P_ALL).unwrap().to_be();
            (*sock_addr).sll_halen = u8::try_from(libc::ETH_ALEN).unwrap();
            (*sock_addr).sll_ifindex = tap_index;
        }

        // Bind socket to tap interface.
        let socket = create_socket();
        // SAFETY: Call is safe because parameters are valid.
        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                send_addr_ptr.cast(),
                libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap(),
            )
        };
        if ret == -1 {
            panic!("Can't create TapChannel");
        }

        // Enable nonblocking
        // SAFETY: Call is safe because parameters are valid.
        let ret = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if ret == -1 {
            panic!("Couldn't make TapChannel non-blocking");
        }

        Self {
            socket,
            // SAFETY: size_of::<libc::sockaddr_storage>() is greater than
            // sizeof::<libc::sockaddr_ll>(), so to return an owned value of sockaddr_ll
            // from the stack-local libc::sockaddr_storage that we have, we need to
            // 1. Create a zeroed out libc::sockaddr_ll,
            // 2. Copy over the first size_of::<libc::sockaddr_ll>() bytes into the struct we want
            //    to return
            // We cannot simply return "*(send_addr_ptr as *const libc::sockaddr_ll)", as this
            // would return a reference to a variable that lives in the stack frame of the current
            // function, and which will no longer be valid after returning.
            // transmute_copy does all this for us.
            // Note that this is how these structures are intended to be used in C.
            send_addr: unsafe { mem::transmute_copy(&storage) },
        }
    }

    pub fn push_tx_packet(&self, buf: &[u8]) {
        // SAFETY: The call is safe since the parameters are valid.
        let res = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                (&self.send_addr as *const libc::sockaddr_ll).cast(),
                libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap(),
            )
        };
        if res == -1 {
            panic!("Can't inject tx_packet");
        }
    }

    pub fn pop_rx_packet(&self, buf: &mut [u8]) -> bool {
        // SAFETY: The call is safe since the parameters are valid.
        let ret = unsafe {
            libc::recvfrom(
                self.socket.as_raw_fd(),
                buf.as_ptr() as *mut _,
                buf.len(),
                0,
                (&mut mem::zeroed() as *mut libc::sockaddr_storage).cast(),
                &mut libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_storage>()).unwrap(),
            )
        };
        if ret == -1 {
            return false;
        }
        true
    }
}

pub fn create_socket() -> File {
    // SAFETY: This is safe since we check the return value.
    let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) };
    if socket < 0 {
        panic!("Unable to create tap socket");
    }

    // SAFETY: This is safe; nothing else will use or hold onto the raw socket fd.
    unsafe { File::from_raw_fd(socket) }
}

// Returns handles to virtio queues creation/activation and manipulation.
pub fn virtqueues(mem: &GuestMemoryMmap) -> (VirtQueue, VirtQueue) {
    let rxq = VirtQueue::new(GuestAddress(0), mem, 16);
    let txq = VirtQueue::new(GuestAddress(0x1000), mem, 16);
    assert!(rxq.end().0 < txq.start().0);

    (rxq, txq)
}

pub fn if_index(tap: &Tap) -> i32 {
    let sock = create_socket();
    let ifreq = IfReqBuilder::new()
        .if_name(&tap.if_name)
        .execute(&sock, c_ulong::from(super::gen::sockios::SIOCGIFINDEX))
        .unwrap();

    // SAFETY: Using this union variant is safe since `SIOCGIFINDEX` returns an integer.
    unsafe { ifreq.ifr_ifru.ifru_ivalue }
}

/// Enable the tap interface.
pub fn enable(tap: &Tap) {
    // Disable IPv6 router advertisment requests
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra",
            tap.if_name_as_str()
        ))
        .output()
        .unwrap();

    let sock = create_socket();
    IfReqBuilder::new()
        .if_name(&tap.if_name)
        .flags(
            (crate::devices::virtio::net::gen::net_device_flags_IFF_UP
                | crate::devices::virtio::net::gen::net_device_flags_IFF_RUNNING
                | crate::devices::virtio::net::gen::net_device_flags_IFF_NOARP)
                .try_into()
                .unwrap(),
        )
        .execute(&sock, c_ulong::from(super::gen::sockios::SIOCSIFFLAGS))
        .unwrap();
}

#[cfg(test)]
pub(crate) fn inject_tap_tx_frame(net: &Net, len: usize) -> Vec<u8> {
    assert!(len >= vnet_hdr_len());
    let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&net.tap));
    let mut frame = utils::rand::rand_alphanumerics(len - vnet_hdr_len())
        .as_bytes()
        .to_vec();
    tap_traffic_simulator.push_tx_packet(&frame);
    frame.splice(0..0, vec![b'\0'; vnet_hdr_len()]);

    frame
}

pub fn write_element_in_queue(net: &Net, idx: u16, val: u64) -> Result<(), DeviceError> {
    if idx as usize > net.queue_evts.len() {
        return Err(DeviceError::QueueError(QueueError::DescIndexOutOfBounds(
            u32::from(idx),
        )));
    }
    net.queue_evts[idx as usize].write(val).unwrap();
    Ok(())
}

pub fn get_element_from_queue(net: &Net, idx: u16) -> Result<u64, DeviceError> {
    if idx as usize > net.queue_evts.len() {
        return Err(DeviceError::QueueError(QueueError::DescIndexOutOfBounds(
            u32::from(idx),
        )));
    }
    Ok(u64::try_from(net.queue_evts[idx as usize].as_raw_fd()).unwrap())
}

pub fn default_guest_mac() -> MacAddr {
    MacAddr::from_str("11:22:33:44:55:66").unwrap()
}

pub fn set_mac(net: &mut Net, mac: MacAddr) {
    net.guest_mac = Some(mac);
    net.config_space.guest_mac = mac;
}

// Assigns "guest virtio driver" activated queues to the net device.
pub fn assign_queues(net: &mut Net, rxq: Queue, txq: Queue) {
    net.queues.clear();
    net.queues.push(rxq);
    net.queues.push(txq);
}

#[cfg(test)]
pub mod test {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::{cmp, fmt, mem};

    use event_manager::{EventManager, SubscriberId, SubscriberOps};

    use crate::check_metric_after_block;
    use crate::devices::virtio::device::{IrqType, VirtioDevice};
    use crate::devices::virtio::net::device::vnet_hdr_len;
    use crate::devices::virtio::net::gen::ETH_HLEN;
    use crate::devices::virtio::net::test_utils::{
        assign_queues, default_net, inject_tap_tx_frame, NetEvent, NetQueue, ReadTapMock,
    };
    use crate::devices::virtio::net::{Net, MAX_BUFFER_SIZE, RX_INDEX, TX_INDEX};
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, VirtqDesc};
    use crate::logger::IncMetric;
    use crate::utilities::test_utils::single_region_mem;
    use crate::vstate::memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

    pub struct TestHelper<'a> {
        pub event_manager: EventManager<Arc<Mutex<Net>>>,
        pub subscriber_id: SubscriberId,
        pub net: Arc<Mutex<Net>>,
        pub mem: GuestMemoryMmap,
        pub rxq: VirtQueue<'a>,
        pub txq: VirtQueue<'a>,
    }

    impl fmt::Debug for TestHelper<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestHelper")
                .field("event_manager", &"?")
                .field("subscriber_id", &self.subscriber_id)
                .field("net", &self.net)
                .field("mem", &self.mem)
                .field("rxq", &self.rxq)
                .field("txq", &self.txq)
                .finish()
        }
    }

    impl<'a> TestHelper<'a> {
        const QUEUE_SIZE: u16 = 16;

        pub fn get_default() -> TestHelper<'a> {
            let mut event_manager = EventManager::new().unwrap();
            let mut net = default_net();
            let mem = single_region_mem(2 * MAX_BUFFER_SIZE);

            // transmute mem_ref lifetime to 'a
            let mem_ref = unsafe { mem::transmute::<&GuestMemoryMmap, &'a GuestMemoryMmap>(&mem) };

            let rxq = VirtQueue::new(GuestAddress(0), mem_ref, Self::QUEUE_SIZE);
            let txq = VirtQueue::new(
                rxq.end().unchecked_align_up(VirtqDesc::ALIGNMENT),
                mem_ref,
                Self::QUEUE_SIZE,
            );
            assign_queues(&mut net, rxq.create_queue(), txq.create_queue());

            let net = Arc::new(Mutex::new(net));
            let subscriber_id = event_manager.add_subscriber(net.clone());

            Self {
                event_manager,
                subscriber_id,
                net,
                mem,
                rxq,
                txq,
            }
        }

        pub fn net(&mut self) -> MutexGuard<Net> {
            self.net.lock().unwrap()
        }

        pub fn activate_net(&mut self) {
            self.net.lock().unwrap().activate(self.mem.clone()).unwrap();
            // Process the activate event.
            let ev_count = self.event_manager.run_with_timeout(100).unwrap();
            assert_eq!(ev_count, 1);
        }

        pub fn simulate_event(&mut self, event: NetEvent) {
            match event {
                NetEvent::RxQueue => self.net().process_rx_queue_event(),
                NetEvent::RxRateLimiter => self.net().process_rx_rate_limiter_event(),
                NetEvent::Tap => self.net().process_tap_rx_event(),
                NetEvent::TxQueue => self.net().process_tx_queue_event(),
                NetEvent::TxRateLimiter => self.net().process_tx_rate_limiter_event(),
            };
        }

        pub fn data_addr(&self) -> u64 {
            self.txq.end().raw_value()
        }

        pub fn add_desc_chain(
            &mut self,
            queue: NetQueue,
            addr_offset: u64,
            desc_list: &[(u16, u32, u16)],
        ) {
            // Get queue and event_fd.
            let net = self.net.lock().unwrap();
            let (queue, event_fd) = match queue {
                NetQueue::Rx => (&self.rxq, &net.queue_evts[RX_INDEX]),
                NetQueue::Tx => (&self.txq, &net.queue_evts[TX_INDEX]),
            };

            // Create the descriptor chain.
            let mut iter = desc_list.iter().peekable();
            let mut addr = self.data_addr() + addr_offset;
            while let Some(&(index, len, flags)) = iter.next() {
                let desc = &queue.dtable[index as usize];
                desc.set(addr, len, flags, 0);
                if let Some(&&(next_index, _, _)) = iter.peek() {
                    desc.flags.set(flags | VIRTQ_DESC_F_NEXT);
                    desc.next.set(next_index);
                }

                addr += u64::from(len);
                // Add small random gaps between descriptor addresses in order to make sure we
                // don't blindly read contiguous memory.
                addr += u64::from(utils::rand::xor_pseudo_rng_u32()) % 10;
            }

            // Mark the chain as available.
            if let Some(&(index, _, _)) = desc_list.first() {
                let ring_index = queue.avail.idx.get();
                queue.avail.ring[ring_index as usize].set(index);
                queue.avail.idx.set(ring_index + 1);
            }
            event_fd.write(1).unwrap();
        }

        /// Generate a tap frame of `frame_len` and check that it is deferred
        pub fn check_rx_deferred_frame(&mut self, frame_len: usize) -> Vec<u8> {
            self.net().tap.mocks.set_read_tap(ReadTapMock::TapFrame);
            let used_idx = self.rxq.used.idx.get();

            // Inject frame to tap and run epoll.
            let frame = inject_tap_tx_frame(&self.net(), frame_len);
            check_metric_after_block!(
                self.net().metrics.rx_packets_count,
                0,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the frame has been deferred.
            assert!(self.net().rx_deferred_frame);
            // Check that the descriptor chain has been discarded.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            assert!(&self.net().irq_trigger.has_pending_irq(IrqType::Vring));

            frame
        }

        /// Check that after adding a valid Rx queue descriptor chain a previously deferred frame
        /// is eventually received by the guest
        pub fn check_rx_queue_resume(&mut self, expected_frame: &[u8]) {
            let used_idx = self.rxq.used.idx.get();
            // Add a valid Rx avail descriptor chain and run epoll.
            self.add_desc_chain(
                NetQueue::Rx,
                0,
                &[(
                    0,
                    u32::try_from(expected_frame.len()).unwrap(),
                    VIRTQ_DESC_F_WRITE,
                )],
            );
            check_metric_after_block!(
                self.net().metrics.rx_packets_count,
                1,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the expected frame was sent to the Rx queue eventually.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            assert!(&self.net().irq_trigger.has_pending_irq(IrqType::Vring));
            self.rxq
                .check_used_elem(used_idx, 0, expected_frame.len().try_into().unwrap());
            self.rxq.dtable[0].check_data(expected_frame);
        }

        // Generates a frame of `frame_len` and writes it to the provided descriptor chain.
        // Doesn't generate an error if the descriptor chain is longer than `frame_len`.
        pub fn write_tx_frame(&self, desc_list: &[(u16, u32, u16)], frame_len: usize) -> Vec<u8> {
            let mut frame = utils::rand::rand_alphanumerics(frame_len)
                .as_bytes()
                .to_vec();
            let prefix_len = vnet_hdr_len() + ETH_HLEN as usize;
            frame.splice(..prefix_len, vec![0; prefix_len]);

            let mut frame_slice = frame.as_slice();
            for &(index, len, _) in desc_list {
                let chunk_size = cmp::min(frame_slice.len(), len as usize);
                self.mem
                    .write_slice(
                        &frame_slice[..chunk_size],
                        GuestAddress::new(self.txq.dtable[index as usize].addr.get()),
                    )
                    .unwrap();
                frame_slice = &frame_slice[chunk_size..];
            }

            frame
        }
    }
}
