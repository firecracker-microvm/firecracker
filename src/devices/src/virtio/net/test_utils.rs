// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::raw::c_ulong;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{mem, result};

#[cfg(test)]
use crate::virtio::net::device::vnet_hdr_len;
use crate::virtio::net::tap::{Error, IfReqBuilder, Tap};
use crate::virtio::test_utils::VirtQueue;
use crate::virtio::{Net, Queue, QueueError};

use rate_limiter::RateLimiter;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use utils::net::mac::MacAddr;

use crate::Error as DeviceError;

pub type Result<T> = ::std::result::Result<T, Error>;

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

pub fn default_net() -> Net {
    let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
    let tap_dev_name = format!("net-device{}", next_tap);

    let guest_mac = default_guest_mac();

    let net = Net::new_with_tap(
        format!("net-device{}", next_tap),
        tap_dev_name,
        Some(&guest_mac),
        RateLimiter::default(),
        RateLimiter::default(),
        true,
    )
    .unwrap();
    enable(&net.tap);

    net
}

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

// Used to simulate tap read fails in tests.
pub struct Mocks {
    pub(crate) read_tap: ReadTapMock,
}

impl Mocks {
    pub fn set_read_tap(&mut self, read_tap: ReadTapMock) {
        self.read_tap = read_tap;
    }
}

impl Default for Mocks {
    fn default() -> Mocks {
        Mocks {
            read_tap: ReadTapMock::MockFrame(
                utils::rand::rand_alphanumerics(1234).as_bytes().to_vec(),
            ),
        }
    }
}

pub enum NetQueue {
    Rx,
    Tx,
}

pub enum NetEvent {
    Custom(i32),
    RxQueue,
    RxRateLimiter,
    Tap,
    TxQueue,
    TxRateLimiter,
}

pub struct TapTrafficSimulator {
    socket: File,
    send_addr: libc::sockaddr_ll,
}

impl TapTrafficSimulator {
    pub fn new(tap_index: i32) -> Self {
        // Create sockaddr_ll struct.
        let send_addr_ptr = &unsafe { mem::zeroed() } as *const libc::sockaddr_storage;
        unsafe {
            let sock_addr: *mut libc::sockaddr_ll = send_addr_ptr as *mut libc::sockaddr_ll;
            (*sock_addr).sll_family = libc::AF_PACKET as libc::sa_family_t;
            (*sock_addr).sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            (*sock_addr).sll_halen = libc::ETH_ALEN as u8;
            (*sock_addr).sll_ifindex = tap_index;
        }

        // Bind socket to tap interface.
        let socket = create_socket();
        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                send_addr_ptr as *const _,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret == -1 {
            panic!("Can't create TapChannel");
        }

        // Enable nonblocking
        let ret = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if ret == -1 {
            panic!("Couldn't make TapChannel non-blocking");
        }

        Self {
            socket,
            send_addr: unsafe { *(send_addr_ptr as *const _) },
        }
    }

    pub fn push_tx_packet(&self, buf: &[u8]) {
        let res = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                buf.as_ptr() as *const _,
                buf.len(),
                0,
                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if res == -1 {
            panic!("Can't inject tx_packet");
        }
    }

    pub fn pop_rx_packet(&self, buf: &mut [u8]) -> bool {
        let ret = unsafe {
            libc::recvfrom(
                self.socket.as_raw_fd(),
                buf.as_ptr() as *mut _,
                buf.len(),
                0,
                (&mut mem::zeroed() as *mut libc::sockaddr_storage) as *mut _,
                &mut (mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t),
            )
        };
        if ret == -1 {
            return false;
        }
        true
    }
}

pub fn create_socket() -> File {
    // This is safe since we check the return value.
    let socket = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::ETH_P_ALL.to_be() as i32,
        )
    };
    if socket < 0 {
        panic!("Unable to create tap socket");
    }

    // This is safe; nothing else will use or hold onto the raw socket fd.
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
        .execute(&sock, c_ulong::from(net_gen::sockios::SIOCGIFINDEX))
        .unwrap();

    unsafe { *ifreq.ifr_ifru.ifru_ivalue.as_ref() }
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
            (net_gen::net_device_flags_IFF_UP
                | net_gen::net_device_flags_IFF_RUNNING
                | net_gen::net_device_flags_IFF_NOARP) as i16,
        )
        .execute(&sock, c_ulong::from(net_gen::sockios::SIOCSIFFLAGS))
        .unwrap();
}

// Check that the used queue event has been generated `count` times.
pub fn check_used_queue_signal(net: &Net, count: u64) {
    // Leave at least one event here so that reading it later won't block.
    net.interrupt_evt.write(1).unwrap();
    assert_eq!(net.interrupt_evt.read().unwrap(), count + 1);
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

pub fn write_element_in_queue(net: &Net, idx: usize, val: u64) -> result::Result<(), DeviceError> {
    if idx > net.queue_evts.len() {
        return Err(DeviceError::QueueError(QueueError::DescIndexOutOfBounds(
            idx as u16,
        )));
    }
    net.queue_evts[idx].write(val).unwrap();
    Ok(())
}

pub fn get_element_from_queue(net: &Net, idx: usize) -> result::Result<u64, DeviceError> {
    if idx > net.queue_evts.len() {
        return Err(DeviceError::QueueError(QueueError::DescIndexOutOfBounds(
            idx as u16,
        )));
    }
    Ok(net.queue_evts[idx].as_raw_fd() as u64)
}

pub fn default_guest_mac() -> MacAddr {
    MacAddr::parse_str("11:22:33:44:55:66").unwrap()
}

pub fn default_guest_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
}

pub fn set_mac(net: &mut Net, mac: MacAddr) {
    net.guest_mac = Some(mac);
    net.config_space.guest_mac.copy_from_slice(mac.get_bytes());
}

// Assigns "guest virtio driver" activated queues to the net device.
pub fn assign_queues(net: &mut Net, rxq: Queue, txq: Queue) {
    net.queues.clear();
    net.queues.push(rxq);
    net.queues.push(txq);
}

#[cfg(test)]
pub mod test {
    use crate::check_metric_after_block;
    use crate::virtio::net::device::vnet_hdr_len;
    use crate::virtio::net::test_utils::{
        assign_queues, check_used_queue_signal, default_net, inject_tap_tx_frame, NetEvent,
        NetQueue, ReadTapMock,
    };
    use crate::virtio::test_utils::{VirtQueue, VirtqDesc};
    use crate::virtio::{
        Net, VirtioDevice, MAX_BUFFER_SIZE, RX_INDEX, TX_INDEX, VIRTQ_DESC_F_NEXT,
        VIRTQ_DESC_F_WRITE,
    };
    use logger::{IncMetric, METRICS};
    use net_gen::ETH_HLEN;
    use polly::event_manager::{EventManager, Subscriber};
    use std::cmp;
    use std::mem;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Mutex, MutexGuard};
    use utils::epoll::{EpollEvent, EventSet};
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

    pub struct TestHelper<'a> {
        pub event_manager: EventManager,
        pub net: Arc<Mutex<Net>>,
        pub mem: GuestMemoryMmap,
        pub rxq: VirtQueue<'a>,
        pub txq: VirtQueue<'a>,
    }

    impl<'a> TestHelper<'a> {
        const QUEUE_SIZE: u16 = 16;

        pub fn default() -> TestHelper<'a> {
            let mut event_manager = EventManager::new().unwrap();
            let mut net = default_net();
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MAX_BUFFER_SIZE)]).unwrap();
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
            event_manager.add_subscriber(net.clone()).unwrap();

            Self {
                event_manager,
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
            let event_fd = match event {
                NetEvent::Custom(event_fd) => event_fd,
                NetEvent::RxQueue => self.net().queue_evts[RX_INDEX].as_raw_fd(),
                NetEvent::RxRateLimiter => self.net().rx_rate_limiter.as_raw_fd(),
                NetEvent::Tap => self.net().tap.as_raw_fd(),
                NetEvent::TxQueue => self.net().queue_evts[TX_INDEX].as_raw_fd(),
                NetEvent::TxRateLimiter => self.net().tx_rate_limiter.as_raw_fd(),
            };
            self.net.lock().unwrap().process(
                &EpollEvent::new(EventSet::IN, event_fd as u64),
                &mut self.event_manager,
            );
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

                addr += len as u64;
                // Add small random gaps between descriptor addresses in order to make sure we
                // don't blindly read contiguous memory.
                addr += utils::rand::xor_psuedo_rng_u32() as u64 % 10;
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
            self.net().mocks.set_read_tap(ReadTapMock::TapFrame);
            let used_idx = self.rxq.used.idx.get();

            // Inject frame to tap and run epoll.
            let frame = inject_tap_tx_frame(&self.net(), frame_len);
            check_metric_after_block!(
                METRICS.net.rx_packets_count,
                0,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the frame has been deferred.
            assert!(self.net().rx_deferred_frame);
            // Check that the descriptor chain has been discarded.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            check_used_queue_signal(&self.net(), 1);

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
                &[(0, expected_frame.len() as u32, VIRTQ_DESC_F_WRITE)],
            );
            check_metric_after_block!(
                METRICS.net.rx_packets_count,
                1,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the expected frame was sent to the Rx queue eventually.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            check_used_queue_signal(&self.net(), 1);
            self.rxq
                .check_used_elem(used_idx, 0, expected_frame.len() as u32);
            self.rxq.dtable[0].check_data(&expected_frame);
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
