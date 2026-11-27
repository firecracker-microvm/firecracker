// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target, "vsock_fuzz");

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target, "vsock_fuzz");

/// Module containing a fuzzer for the vsock device
///
/// Unlike the net and block devices, the vsock device cannot be effectively fuzzed by just putting
/// randomly generated descriptors into the tx queue. This is because vsock is connection oriented,
/// and every packet (with the exception of connection requests) needs to be mapped to an
/// established connection. This is done via a combination of 4 fields in the virtio_vsock_hdr
/// structure, which has to be the first part of every tx descriptor chain processed by the device.
/// As the probability of the fuzzer generating the same 4-tuple (a total of 128 bytes!) multiple
/// times is vanishingly small, it needs some help.
///
/// Additionally, host-initiated connections cannot be established by only interacting with the
/// virtio queues. For these connections, specific bytes need to be written to unix domain sockets,
/// in addition to interacting with both tx and rx queues. Guest-initiated connections on the other
/// hand need the fuzzer to have a UnixListener open on a specific file. Therefore, this module has
/// routines to guide the fuzzer through successful connection establishment.
///
/// In short this means that for every connection, the fuzzer opens a UnixStream to read/write a
/// unix domain socket. The other end of this socket is inside of the device. Data written into this
/// socket by the fuzzer is translated into rx queue packages. Data written into this socket by the
/// device originated from tx queue descriptors.
///
/// Lastly, the vsock device has a component called the "tx_buf" for each connection, which buffers
/// additional data if the device's socket's buffer runs full (which happens if the fuzzer does not
/// read from its own end fast enough/at all).
/// However, this buffer has size ~212kb, which is more data than the fuzzer will ever reasonably
/// generate. For this reason, we send almost 212kb of dummy data not generated from fuzz input
/// through every newly established connection, to get the connection into a state where the fuzzer
/// could potentially trigger a scenario where the tx_buf needs to be used.
pub mod fuzzing {
    use std::borrow::Cow;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::Arc;

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::devices::virtio::vsock::{Vsock, VsockUnixBackend};
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::memory::test_utils::into_region_ext;
    use vmm::vstate::memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap, anonymous};
    use vmm_sys_util::epoll::EventSet;

    // redefinition of constants from virtio spec - they are not publically exported from
    // firecracker :(
    const VIRTIO_VSOCK_OP_REQUEST: u16 = 1;
    const VIRTIO_VSOCK_OP_RESPONSE: u16 = 2;

    const VIRTIO_VSOCK_TYPE_STREAM: u16 = 1;

    // firecracker doesnt publically export its version of this :(
    /// Vsock packet header, as defined in 5.10.6 of https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf
    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    #[allow(dead_code)]
    // struct is transmuted to bytes, so technically some fields are never accessed from rustc's POV
    pub struct VirtioVsockHdr {
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        len: u32,
        type_: u16,
        op: u16,
        flags: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    }

    impl Default for VirtioVsockHdr {
        fn default() -> Self {
            VirtioVsockHdr {
                src_cid: 0,
                // hard coded in firecracker (uapi::VSOCK_HOST_CID)
                dst_cid: 2,
                src_port: 0,
                dst_port: 0,
                len: 0,
                // according to 5.10.6.2 this is the only valid value for this field
                type_: VIRTIO_VSOCK_TYPE_STREAM,
                op: 0,
                flags: 0,
                buf_alloc: 0,
                fwd_cnt: 0,
            }
        }
    }

    // SAFETY: repr(packed) struct (e.g. POD)
    unsafe impl ByteValued for VirtioVsockHdr {}

    #[rustfmt::skip]
    fn virtio_vsock_hdr_descriptor(write_only: bool) -> [u8; 8 + 44] {
        [
            0x1, // single descriptor
            0x0, // put at index 0 into the descriptor table
            0x0,
            0x40,                         // with payload stored at address 0x4000,
            0x1 + (write_only as u8 * 2), /* with VIRTQ_DESC_F_NEXT set, in addition to maybe
                                           * being write-only */
            0x0, // descriptor chain loops, as we don't have a body
            44, 0x0, // length of body is size of VirtioVsockHdr

            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]
    }

    /// (host side port, host-side unix stream, guest side port)
    pub type Connection = (u32, UnixStream, u32);

    #[allow(dead_code)]
    pub struct VsockFuzzer<'a> {
        device: Vsock<VsockUnixBackend>,

        txq: VirtQueue<'a>,
        rxq: VirtQueue<'a>,

        guest_cid: u32,
    }

    impl<'a> VsockFuzzer<'a> {
        pub fn new<'b>(
            gm: &'a GuestMemoryMmap,
            input: &mut impl FuzzData<'b>,
            work_dir_path: &Path,
        ) -> Result<Self, InsufficientData> {
            // The guest_cid field is u64 in the virtio_vsock_hdr struct, but the upper 32 bits are
            // reserved and zeroed.
            let guest_cid = input.take_u32()?;
            let features = input.take_u64()?;

            // We fuzz the queue size, as it is possible that a driver sets up a queue smaller than
            // the device's default queue size. For the vsock device, the default queue size is 256
            // bytes, so there is no point in setting up queues larger than that (and the fuzzer
            // uses u8 to index into the descriptor table, so it could not make use of larger queues
            // anyway).
            // Note that queue size has to be a power of two. This is verified via assert! by
            // VirtQueue::new.
            let txq_size = (input.take_u8()? as u16).next_power_of_two();
            let rxq_size = (input.take_u8()? as u16).next_power_of_two();

            let uds_path = work_dir_path.join("v.sock");

            // data flowing from guest to host
            let txq = VirtQueue::new(GuestAddress(0x0), gm, txq_size);
            // data flowing from host to guest
            let rxq = VirtQueue::new(GuestAddress(0x1000), gm, rxq_size);
            // event queue, unused by fuzzer (so no need to fuzz its size either)
            let evq = VirtQueue::new(GuestAddress(0x2000), gm, 256);

            let backend =
                VsockUnixBackend::new(guest_cid as u64, uds_path.to_str().unwrap().to_string())
                    .unwrap();
            let mut vsock = Vsock::with_queues(
                guest_cid as u64,
                backend,
                vec![rxq.create_queue(), txq.create_queue(), evq.create_queue()],
            )
            .unwrap();

            let irq = Arc::new(IrqTrigger::new());
            vsock.set_acked_features(vsock.avail_features() & features);
            vsock.activate(gm.clone(), irq).unwrap();

            Ok(VsockFuzzer {
                device: vsock,
                txq,
                rxq,
                guest_cid,
            })
        }

        pub fn establish_host_to_guest_connection(
            &mut self,
            guest_port: u32,
        ) -> Option<Connection> {
            // Go through the flow os initiating a vsock connection from the host:
            // 1. connect to the UDS which we passed to the vsock device upon creation
            let mut stream = UnixStream::connect(self.device.backend().host_sock_path()).ok()?;
            // We don't want the fuzzer to hang on reads/writes on this stream
            stream.set_nonblocking(true).ok()?;

            // 2. manually drive the event loop once, so that the device calls
            // `UnixListener::accept`.
            // It doesn't matter what we pass here, the backend ignores the argument.
            self.device.notify_backend(EventSet::IN).ok()?;

            // 3. Write the 'CONNECT <port>'  request to tell the device with which guest-facing
            // port we want to connect
            stream
                .write_all(format!("CONNECT {guest_port}\n").as_bytes())
                .ok()?;

            // 4. manually drive the event loop again to make the device process the bytes we just
            // wrote to the socket
            self.device.notify_backend(EventSet::IN).ok()?;

            // At this point, usually the guest would call `accept` on the AF_VSOCK socket it is
            // listening on. Here we fake our way around this by writing a VIRTIO_VSOCK_OP_RESPONSE
            // to the tx queue. However, to write the VIRTIO_VSOCK_OP_RESPONSE packet, we need to
            // know what host-side port was assigned for this connection. This is generated by
            // handle_event in the muxer, and communicated to the guest in a VIRTIO_VSOCK_OP_REQUEST
            // packet (and since this is a host -> guest packet, the port is in the src_port field).
            // The only thing we can do to get hold of this packet is to call process_rx.
            let host_port = self.clear_rx_queue()?.src_port;

            let mut virtio_vsock_op_response = VirtioVsockHdr::default();
            virtio_vsock_op_response.src_cid = self.guest_cid as u64;
            virtio_vsock_op_response.src_port = guest_port;
            virtio_vsock_op_response.dst_port = host_port;
            virtio_vsock_op_response.op = VIRTIO_VSOCK_OP_RESPONSE;

            // Lastly, the guest has to "accept" the connection - we write a
            // VIRTIO_VSOCK_OP_RESPONSE to the tx queue
            let mut input = virtio_vsock_hdr_descriptor(false);
            input[8..].copy_from_slice(virtio_vsock_op_response.as_slice());

            let _ = input
                .as_ref()
                .fill_virt_queue(&mut self.txq, fuzz_data_descriptor, false);

            self.device.process_tx().ok()?;

            Some((host_port, stream, guest_port))
        }

        pub fn establish_guest_to_host_connection(
            &mut self,
            host_port: u32,
            guest_port: u32,
        ) -> Option<Connection> {
            // If we want the guest to connect to port "host_port", then the host needs to listen on
            // a UDS at the following path.
            let host_socket_path =
                format!("{}_{host_port}", self.device.backend().host_sock_path());

            // Go through the flow of initiating a vsock connection from within the guest:
            // 1. Have the host listen on v.sock_<port> to give the guest an endpoint to connect to
            let host_listener = UnixListener::bind(&host_socket_path).ok()?;

            // 2. The guest initiates the connection by opening a AF_VSOCK socket. This is
            // translated into a VIRTIO_VSOCK_OP_REQUEST descriptor the driver places into the
            // device's TX queue
            let mut virtio_op_request = VirtioVsockHdr::default();
            virtio_op_request.src_cid = self.guest_cid as u64;
            virtio_op_request.src_port = guest_port;
            virtio_op_request.dst_port = host_port;
            virtio_op_request.op = VIRTIO_VSOCK_OP_REQUEST;

            let mut input = virtio_vsock_hdr_descriptor(false);
            input[8..].copy_from_slice(virtio_op_request.as_slice());
            let _ = input
                .as_ref()
                .fill_virt_queue(&mut self.txq, fuzz_data_descriptor, false);

            self.device.process_tx().ok()?;

            // 3. After the driver processed the VIRTO_VSOCK_OP_REQUEST descriptor, it will open a
            // connection with our v.sock_<port> socket, meaning we can accept a new connection
            // there - the connection is now established.
            // There is now a VIRTIO_VSOCK_OP_RESPONSE in the rx queue which would usually indicate
            // to the guest that the host has accepted the connection.

            // Make sure we don't hang if someone goes wrong
            host_listener.set_nonblocking(true).ok()?;

            let stream = host_listener.accept().ok()?.0;
            // we don't want the fuzzer to hang on reads/writes from this socket
            stream.set_nonblocking(true).ok()?;

            // To move the internal connection state to ConnState::Established, the
            // VIRTIO_VSOCK_OP_RESPONSE packet needs to actually be processed.
            self.clear_rx_queue();

            Some((host_port, stream, guest_port))
        }

        /// Processing all descriptors that are pending to be written to the RX queue by the device
        ///
        /// This is needed because
        /// * host-to-guest connection establishment code needs to read the guest-side port from the
        ///   header of an rx queue package
        /// * guest-to-host connection establishment code needs the VIRTIO_VSOCK_OP_RESPONSE packet
        ///   to be written to the rx queue to have the connection move to `ConnState::Established`.
        ///
        /// This code is very inefficient at clearing the queue: All data is written to guest
        /// address 0x4000 in chunks of at most 44 bytes (the size of a virtio_vsock_header).
        fn clear_rx_queue(&mut self) -> Option<VirtioVsockHdr> {
            loop {
                // This is not really the header of the last rx packet, as if the packet had a
                // body, then the first 44 bytes of the body would be written to 0x4000 instead.
                // However, VIRTIO_VSOCK_OP_RESPONSE packets don't have a body, and we only need
                // this code to handle those correctly.
                let last_header = self
                    .rxq
                    .memory()
                    .read_obj::<VirtioVsockHdr>(GuestAddress(0x4000));
                let input = virtio_vsock_hdr_descriptor(true);
                let _ = input
                    .as_ref()
                    .fill_virt_queue(&mut self.rxq, fuzz_data_descriptor, false);
                if let Ok(true) = self.device.process_rx() {
                    break last_header.ok();
                }
            }
        }

        /// Fills the given connections internal buffer with dummy data
        ///
        /// To be able to trigger usage of the tx_buf module, the device-owned UnixStream's send
        /// buffer needs to be filled up (the unconfigurable default is 212992 bytes, see
        /// https://unix.stackexchange.com/questions/424380/what-values-may-linux-use-for-the-default-unix-socket-buffer-size).
        /// We do this by writing a few very large buffers filled with zeros to the TX queue
        fn fill_connection_buffer(&mut self, connection: &Connection) {
            // 212992 = 3 * 65536 + 16384
            // We'll put 5 descriptor chains (because the maximal payload for a single chain is
            // 65536, see MAX_PKT_BUF_SIZE in firecracker)
            let mut remaining_payload = 212980u32;

            while remaining_payload > 0 {
                let payload_len = remaining_payload.min(65535) as u16;
                remaining_payload -= payload_len as u32;

                let mut input = vec![
                    0x2, // two descriptors
                    0x0, // byte used to determine index at which first descriptor will be placed
                    0x0, 0x30, // address at which descriptor will be put in guest memory
                    0x1,  // descriptor flags, here VIRTQ_DESC_F_NEXT
                    0x1,  // index at which the next descriptor in the chain will be placed
                    44, 0x0, // length of descriptor buffer (size_of(virtio_vsock_hdr) == 44)
                ];

                let mut header = VirtioVsockHdr::default();
                header.src_cid;
                header.src_port = connection.2;
                header.dst_port = connection.0;
                header.len = payload_len as u32;
                header.op = 5; // VIRTIO_VSOCK_OP_RW
                input.extend(header.as_slice());

                input.extend([
                    1, // byte used to determine index at which first descriptor will be placed
                    0x0, 0x40, // address at which descriptor will be put in guest memory
                    0x0,  // descriptor flags
                    0x0,  // index at which the next descriptor in the chain will be placed
                ]);
                input.extend(payload_len.to_le_bytes());
                input.extend(vec![0u8; payload_len as usize]);

                let input = &mut &input[..];
                let _ = input.fill_virt_queue(&mut self.txq, fuzz_data_descriptor, false);
                _ = self.device.process_tx();
            }
        }
    }

    pub fn target(mut data: &[u8], work_dir_path: &Path) -> Result<(), InsufficientData> {
        const MEMORY_64K: usize = 0x10000;
        const MEMORY_8M: usize = 0x800000;

        let input = &mut data;

        let [huge_pages, ..] = input.take_bools()?;

        let guest_port_1 = input.take_u32()?;
        let guest_port_2 = input.take_u32()?;
        let host_port = input.take_u32()?;

        // Filling up the buffer on a UDS incurs a performance penalty, so we don't want to always
        // do it.
        // Particularly, once AFL++ determines there is nothing more to discover in the "buffer
        // full" scenario it should switch to the faster "don't fill buffer" path. Note that even
        // if this variable is true, only a single connection will have its buffer filled (the guest
        // initiated one) to minimize performance degradation.
        let fill_connection_buffer = input.take_bool()?;

        // sadly, we cannot allocate the guest memory in VsockFuzzer::new, as then we'd have a
        // self-referential struct
        let (huge_page_config, mem_size) = match huge_pages {
            true => {
                // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
                // would fail with SIGBUS.
                if !check_hugepages_available(MEMORY_8M) {
                    return Ok(());
                }
                (HugePageConfig::Hugetlbfs2M, MEMORY_8M)
            }
            false => (HugePageConfig::None, MEMORY_64K),
        };

        // Make sure to only allocate after all early returns (via '?'), otherwise we'll not free
        // the memory and go OOM.
        let regions = anonymous(&[(GuestAddress(0), mem_size)], false, huge_page_config)
            .expect("Cannot initialize memory");

        let gm = into_region_ext(regions);

        let mut connections = Vec::new();
        let mut fuzzer = VsockFuzzer::new(&gm, input, work_dir_path)?;

        if let Some(conn) = fuzzer.establish_host_to_guest_connection(guest_port_1) {
            connections.push(conn);
        }

        if let Some(conn) = fuzzer.establish_guest_to_host_connection(host_port, guest_port_2) {
            if fill_connection_buffer {
                fuzzer.fill_connection_buffer(&conn);
            }
            connections.push(conn);
        }

        let guest_cid = fuzzer.guest_cid;

        while let Ok(()) = input.fill_virt_queue(
            &mut fuzzer.txq,
            |input| fuzz_vsock_hdr(input, guest_cid, &connections),
            false,
        ) {
            // process as much tx as we can
            while let Ok(true) = fuzzer.device.process_tx() {}

            // Make some space for incomming packets in the rx queue: Put some random empty
            // descriptors in there
            let _ = input.fill_virt_queue(
                &mut fuzzer.rxq,
                |input| {
                    let len = input.take_u16()? as usize;

                    Ok(Cow::Owned(vec![0; len]))
                },
                false,
            );

            // Write some data to the host side of some connection, to exercise rx code paths.
            // Read from host side of stream to go through code responsible for draining tx_bufs
            // when space is the socket buffer opens up.
            // Even though we trust the host, there might be device states that are unreachable if
            // we never generate rx packages.
            if let (Ok(idx), Ok(len)) = (input.take_u8(), input.take_u16()) {
                let idx = idx as usize % connections.len();

                let stream = &mut connections[idx].1;

                // .unwrap() cannot panic, min(remaining, len) will always be less than or equal to
                // the number of bytes remaining in our fuzz input.
                let data = input
                    .take_slice(input.remaining().min(len as usize))
                    .unwrap();

                let _ = stream.write(data);
                let _ = stream.read(&mut vec![0; len as usize]);

                // Notify the device that data can be read from some connection
                _ = fuzzer.device.notify_backend(EventSet::IN);
            }

            // process as much rx as we can
            while let Ok(true) = fuzzer.device.process_rx() {}
        }

        Ok(())
    }

    fn fuzz_vsock_hdr<'a>(
        input: &mut impl FuzzData<'a>,
        guest_cid: u32,
        connections: &[Connection],
    ) -> Result<Cow<'a, [u8]>, InsufficientData> {
        if input.remaining() >= 17 && input.take_bool()? {
            let (host_port, _, guest_port) =
                connections[input.take_u8()? as usize % connections.len()];

            let mut header = VirtioVsockHdr::default();
            header.src_cid = guest_cid as u64;
            header.src_port = guest_port;
            header.dst_port = host_port;
            header.len = input.take_u16()? as u32;
            // Only valid types are 0 through 7
            header.op = (input.take_u8()? % 8) as u16;
            header.flags = input.take_u32()?;
            header.buf_alloc = input.take_u32()?;
            header.fwd_cnt = input.take_u32()?;

            Ok(Cow::Owned(header.as_slice().to_owned()))
        } else {
            fuzz_data_descriptor(input)
        }
    }
}

#[cfg(test)]
mod seed_gen {
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    #[rustfmt::skip]
    fn generate_seed() {
        let seed = vec![
            0b00000000, // byte interpreted as 8 booleans. Only least significant bit is used to determine whether to use hugepages.
            0x0, 0x0, 0x0, 0x1, // guest port of host -> guest connection used by fuzzer
            0x0, 0x0, 0x0, 0x2, // guest port of guest -> host connection used by fuzzer
            0x0, 0x0, 0x0, 0x3, // host port of guest -> host connection used by fuzzer
            0x0, /* Byte used to determine whether the harness should fill up a connection's
                  * socket's buffer. An even value means 'yes'. */
            0x0, 0x0, 0x0, 0x4, // Guest CID
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // acknowledged features
            0x10, // TXQ size
            0x10, // RXQ size
            // fill virt queue first time
            0x2, /* byte used to determine how many descriptors to write to queue. The
                  * firecracker vsock implementation expects header and payload in different
                  * descriptors, so 2 */
            // first descriptor header
            0x4, // byte used to determine index at which first descriptor will be placed
            0x0, 0x30, // address at which descriptor will be put in guest memory
            0x1,  // descriptor flags, here VIRTQ_DESC_F_NEXT
            0x9,  // index at which the next descriptor in the chain will be placed
            // first descriptor buffer (vsock header)
            // The fuzzer only uses 17 bytes to fill the 44 byte structure, as some of the fields
            // take on pre-determined values
            0x0, /* boolean used to determine whether we should build a structurally valid
                  * header, or fill the descriptor with fuzz data. 0 = build structurally valid
                  * vsock header */
            0x1, // Index into Vec containing all valid connections
            0x10, 0x0, // length of buffer (16 bytes)
            0x5, // op: VIRTIO_VSOCK_OP_RW, e.g. a payload
            0x0, 0x0, 0x0, 0x0, // flags,
            0x0, 0x0, 0x0, 0x0, // buf_alloc
            0x0, 0x0, 0x0, 0x0, // fwd_cnt
            // second descriptor header
            0x9, // byte used to determine index at which first descriptor will be placed
            0x0, 0x40, // address at which descriptor will be put in guest memory
            0x0,  // descriptor flags, here none (last descriptor in chain)
            0x0,  // index at which the next descriptor in the chain will be placed
            // second descriptor buffer (vsock payload)
            0x1, /* boolean used to determine whether this descriptor should be filled with a
                  * structurually valid vsock header, or with fuzz input. 1 = put fuzz data in
                  * the descriptor */
            0x10,
            0x0, /* How much fuzz data to put into descriptor - 16 bytes as that's what we set
                  * the len field of the vsock header to */
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, // payload
        ];

        let _ = std::fs::create_dir_all("in/vsock");
        let mut seed_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open("in/vsock/sample_request.in")
            .unwrap();

        seed_file.write_all(&seed).unwrap();
    }
}
