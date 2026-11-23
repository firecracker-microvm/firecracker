// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;
use vmm::devices::virtio::net::Tap;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target[tap: Tap]);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target[tap: Tap]);

pub mod fuzzing {
    use std::borrow::Cow;
    use std::sync::{Arc, Mutex};

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::generated::virtio_net::VIRTIO_NET_F_GUEST_CSUM;
    use vmm::devices::virtio::net::test_utils::{assign_queues, default_guest_mac, default_net};
    use vmm::devices::virtio::net::{Net, Tap};
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::mmds::data_store::Mmds;
    use vmm::mmds::ns::MmdsNetworkStack;
    use vmm::rate_limiter::RateLimiter;
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::memory::test_utils::into_region_ext;
    use vmm::vstate::memory::{GuestAddress, anonymous};

    pub fn target(mut data: &[u8], tap: &mut Option<Tap>) -> Result<(), InsufficientData> {
        const MEMORY_64K: usize = 0x10000;
        const MEMORY_8M: usize = 0x800000;

        let input = &mut data;
        let [huge_pages, mtu_present, ..] = input.take_bools()?;
        let mtu_value = input.take_u16()?;
        // MTU must be between 68..65535. Upper bound enforced by u16::MAX
        let mtu = mtu_present.then_some(mtu_value.max(68));

        let mut net_device = match tap.take() {
            None => default_net(),
            Some(tap) => {
                let mut net = Net::new_with_tap(
                    "tap-device".to_string(),
                    tap,
                    Some(default_guest_mac()),
                    RateLimiter::default(),
                    RateLimiter::default(),
                    mtu,
                )
                .unwrap();
                net.configure_mmds_network_stack(
                    MmdsNetworkStack::default_ipv4_addr(),
                    Arc::new(Mutex::new(Mmds::default())),
                );
                net
            }
        };

        let features = input.take_u64()?;
        // We know that setting TAP features will fail if VIRTIO_NET_F_GUEST_CSUM
        // is not present. So return early in this case.
        if features & (1 << VIRTIO_NET_F_GUEST_CSUM) == 0 {
            return Ok(());
        }

        // We fuzz the queue size, as it is possible that a driver sets up a queue smaller than the
        // device's default queue size. For the net device, the default queue size is 512 bytes,
        // so there is no point in setting up queues larger than that (and the fuzzer uses u8 to
        // index into the descriptor table, so it could not make use of larger queues anyway).
        // Note that queue size has to be a power of two. This is verified via assert! by
        // VirtQueue::new
        let rxq_size = (input.take_u16()? % 512).next_power_of_two();
        let txq_size = (input.take_u16()? % 512).next_power_of_two();

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
        let irq = Arc::new(IrqTrigger::new());

        // These could overlap, but I can't find any code in the virtio stack that would prevent us
        // from initializing a device with overlapping queues, so lets go for it.
        let mut rxq = VirtQueue::new(GuestAddress(0), &gm, rxq_size);
        let mut txq = VirtQueue::new(GuestAddress(0x1000), &gm, txq_size);

        assign_queues(&mut net_device, rxq.create_queue(), txq.create_queue());

        net_device.set_acked_features(net_device.avail_features() & features);
        net_device.activate(gm.clone(), irq).unwrap();

        while let Ok(()) = input.fill_virt_queue(&mut txq, fuzz_data_descriptor, false) {
            // Make some space for incomming packets in the rx queue: Put some random empty
            // descriptors in there.
            let _ = input.fill_virt_queue(
                &mut rxq,
                |input| {
                    let len = input.take_u16()? as usize;

                    Ok(Cow::Owned(vec![0; len]))
                },
                false,
            );

            // The only source of rx packets is MMDS in this fuzzer. The process_tx path will call
            // process_rx for us if there are incoming packets from mmds
            // ignore return value, we totally expect the fuzzer to configure the queue
            // in such a way that firecracker thinks its a DoS
            _ = net_device.process_virtio_queues();
        }

        // put back the tap :)
        *tap = Some(net_device.tap);

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    use std::fs::OpenOptions;
    use std::io::Write;

    const MMDS_IP: [u8; 4] = [169, 254, 169, 254];
    const SRC_IP: [u8; 4] = [10, 0, 0, 1];

    fn seed_init_header() -> Vec<u8> {
        vec![
            0b00000001, // booleans: hugepages=true (need 8MB guest mem for 65K+
            // RX buffers), mtu_present=false
            0xDC, 0x05, // mtu_value = 1500 (little-endian), only used if mtu_present
            0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // features (VIRTIO_NET_F_GUEST_CSUM)
            0x02, 0x00, 0x00, 0x00, // queue sizes: rxq=2 (need >=65562 RX capacity), txq=1
        ]
    }

    /// Build a TX descriptor: num_descs count byte, descriptor table index, guest addr, then
    /// the payload. Flags=0 (readonly, no NEXT).
    /// Includes 2 trailing bytes for the used_event that fill_virt_queue always reads.
    fn tx_desc(num_descs: u8, idx: u8, addr: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![num_descs, idx];
        v.extend_from_slice(&addr.to_le_bytes());
        v.push(0x0); // flags
        v.push(0x0); // next
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0x0, 0x0]); // used_event padding
        v
    }

    /// Build RX fill entries: 2 writable descriptors to provide >= 65562 bytes total
    /// capacity (required by NET_MAX_BUFFER_SIZE). With rxq_size=2, both slots are filled.
    /// Includes 2 trailing bytes for the used_event that fill_virt_queue always reads.
    fn rx_fill() -> Vec<u8> {
        let mut v = vec![];
        // num_descriptors byte: fill_virt_queue reads take_u8() % queue_size + 1
        // With queue_size=2: 0x01 % 2 + 1 = 2 descriptors
        v.push(0x01);
        // Descriptor 0: 65535 bytes at addr 0x2000
        v.push(0x00); // idx=0
        v.extend_from_slice(&0x2000u16.to_le_bytes());
        v.push(0x02); // flags = VIRTQ_DESC_F_WRITE
        v.push(0x00); // next
        v.extend_from_slice(&0xFFFFu16.to_le_bytes()); // 65535 bytes
        // Descriptor 1: 65535 bytes at addr 0x2000 (overlapping is fine for capacity)
        v.push(0x01); // idx=1
        v.extend_from_slice(&0x2000u16.to_le_bytes());
        v.push(0x02); // flags = VIRTQ_DESC_F_WRITE
        v.push(0x00); // next
        v.extend_from_slice(&0xFFFFu16.to_le_bytes()); // 65535 bytes
        // used_event padding
        v.extend_from_slice(&[0x0, 0x0]);
        v
    }

    /// Build a raw ethernet+IPv4+TCP frame (no options) with given parameters.
    fn eth_ipv4_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let ip_len = (40 + payload.len() as u16).to_be_bytes();
        let sp = src_port.to_be_bytes();
        let dp = dst_port.to_be_bytes();
        let sq = seq.to_be_bytes();
        let ak = ack.to_be_bytes();
        let wn = window.to_be_bytes();

        let mut f = Vec::new();
        f.extend_from_slice(&[0u8; 12]); // vnet_hdr
        f.extend_from_slice(&[0u8; 12]); // dst+src MAC
        f.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
        // IPv4 header (20 bytes)
        f.extend_from_slice(&[0x45, 0x00, ip_len[0], ip_len[1]]);
        f.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // TTL=64, proto=TCP
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        // TCP header (20 bytes)
        f.extend_from_slice(&[sp[0], sp[1], dp[0], dp[1]]);
        f.extend_from_slice(&[sq[0], sq[1], sq[2], sq[3]]);
        f.extend_from_slice(&[ak[0], ak[1], ak[2], ak[3]]);
        f.extend_from_slice(&[0x50, flags, wn[0], wn[1]]); // data_offset=5 (20 bytes)
        f.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum, urgent
        f.extend_from_slice(payload);
        f
    }

    fn write_seed(name: &str, data: &[u8]) {
        let _ = std::fs::create_dir_all("in/net");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("in/net/{name}"))
            .unwrap()
            .write_all(data)
            .unwrap();
    }

    #[test]
    fn generate_mmds_arp_seed() {
        #[rustfmt::skip]
        let arp_frame = [
            // vnet_hdr (12 bytes)
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            // ethernet header (14 bytes, last two = ARP ethertype)
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08, 0x06,
            // ARP packet (28 bytes): HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1(request)
            0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // SHA
            0x0, 0x0, 0x0, 0x0,             // SPA
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // THA
            169, 254, 169, 254,             // TPA = MMDS IP
        ];

        let mut seed = seed_init_header();
        seed.extend_from_slice(&tx_desc(1, 0, 0xd00, &arp_frame));
        write_seed("mmds_arp.in", &seed);
    }

    /// TCP SYN with MSS option → passive_open, MSS parsing (connection.rs, tcp.rs)
    #[test]
    fn generate_tcp_syn_mss_seed() {
        let ip_len = 44u16.to_be_bytes(); // 20 IP + 24 TCP (20 hdr + 4 MSS opt)
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 12]); // vnet_hdr
        frame.extend_from_slice(&[0u8; 12]); // MACs
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0x45, 0x00, ip_len[0], ip_len[1]]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
        frame.extend_from_slice(&SRC_IP);
        frame.extend_from_slice(&MMDS_IP);
        // TCP SYN with MSS option (header_len=24 → data_offset=6)
        #[rustfmt::skip]
        frame.extend_from_slice(&[
            0x10, 0x00, 0x00, 80,       // ports
            0x00, 0x00, 0x10, 0x00,     // seq=4096
            0x00, 0x00, 0x00, 0x00,     // ack=0
            0x60, 0x02, 0x20, 0x00,     // data_offset=6, SYN, window=8192
            0x00, 0x00, 0x00, 0x00,     // checksum, urgent
            0x02, 0x04, 0x05, 0xb4,     // MSS option: kind=2, len=4, value=1460
        ]);

        let mut seed = seed_init_header();
        seed.extend_from_slice(&tx_desc(1, 0, 0xd00, &frame));
        seed.extend_from_slice(&rx_fill());
        write_seed("tcp_syn_mss.in", &seed);
    }

    // The vmm `fuzzing` feature makes the dumbo ISN deterministic: 0x12345678.
    // ACK number for completing the handshake is therefore ISN+1 = 0x12345679.
    const SERVER_ISN_PLUS_1: u32 = 0x12345679;

    /// TCP handshake + HTTP GET → connection establishment, endpoint HTTP parsing,
    /// response generation, handler write path (connection.rs, endpoint.rs, handler.rs)
    #[test]
    fn generate_tcp_handshake_http_seed() {
        let syn = eth_ipv4_tcp(SRC_IP, MMDS_IP, 4096, 80, 0x1000, 0, 0x02, 8192, &[]);
        // ACK completing handshake with deterministic ISN
        let ack = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            0x1001,
            SERVER_ISN_PLUS_1,
            0x10,
            8192,
            &[],
        );
        // PSH+ACK with HTTP GET
        let http = b"GET / HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let psh = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            0x1001,
            SERVER_ISN_PLUS_1,
            0x18,
            8192,
            http,
        );

        let mut seed = seed_init_header();
        seed.extend_from_slice(&tx_desc(1, 0, 0xd00, &syn));
        seed.extend_from_slice(&rx_fill());
        seed.extend_from_slice(&tx_desc(1, 1, 0xe00, &ack));
        seed.extend_from_slice(&rx_fill());
        seed.extend_from_slice(&tx_desc(1, 2, 0xf00, &psh));
        seed.extend_from_slice(&rx_fill());
        write_seed("tcp_handshake_http.in", &seed);
    }

    /// Non-MMDS destination → tap write path (device.rs)
    #[test]
    fn generate_non_mmds_seed() {
        let frame = eth_ipv4_tcp(SRC_IP, [10, 0, 0, 2], 4096, 80, 0x1000, 0, 0x02, 8192, &[]);
        let mut seed = seed_init_header();
        seed.extend_from_slice(&tx_desc(1, 0, 0xd00, &frame));
        write_seed("non_mmds_tcp.in", &seed);
    }

    /// Helper: SYN + RX fill + ACK → established connection, returns (seed, next_seq)
    fn handshake_prefix() -> (Vec<u8>, u32) {
        let syn = eth_ipv4_tcp(SRC_IP, MMDS_IP, 4096, 80, 0x1000, 0, 0x02, 8192, &[]);
        let ack = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            0x1001,
            SERVER_ISN_PLUS_1,
            0x10,
            8192,
            &[],
        );

        let mut seed = seed_init_header();
        seed.extend_from_slice(&tx_desc(1, 0, 0xd00, &syn));
        seed.extend_from_slice(&rx_fill());
        seed.extend_from_slice(&tx_desc(1, 1, 0xe00, &ack));
        seed.extend_from_slice(&rx_fill());
        // Next guest sequence number after SYN(1) + ACK(0) = 0x1001
        (seed, 0x1001)
    }

    /// Full HTTP GET with response read-back → endpoint receive_segment, parse_request_bytes,
    /// response generation, connection write_next_segment, handler write_next_packet
    /// (endpoint.rs, handler.rs, connection.rs write path)
    #[test]
    fn generate_http_get_response_seed() {
        let (mut seed, seq) = handshake_prefix();
        let http = b"GET / HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let psh = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            seq,
            SERVER_ISN_PLUS_1,
            0x18,
            8192,
            http,
        );
        seed.extend_from_slice(&tx_desc(1, 2, 0xf00, &psh));
        // Multiple RX fills so the response segments can be written back
        for _ in 0..4 {
            seed.extend_from_slice(&rx_fill());
        }
        write_seed("http_get_response.in", &seed);
    }

    /// FIN teardown after HTTP exchange → connection close, endpoint is_done, handler
    /// endpoint removal (connection.rs close/fin path, endpoint.rs fin handling)
    #[test]
    fn generate_http_fin_seed() {
        let (mut seed, seq) = handshake_prefix();
        let http = b"GET / HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let psh = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            seq,
            SERVER_ISN_PLUS_1,
            0x18,
            8192,
            http,
        );
        let next_seq = seq + http.len() as u32;
        seed.extend_from_slice(&tx_desc(1, 2, 0xf00, &psh));
        for _ in 0..4 {
            seed.extend_from_slice(&rx_fill());
        }
        // FIN+ACK to close the connection
        let fin = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            next_seq,
            SERVER_ISN_PLUS_1,
            0x11,
            8192,
            &[],
        );
        seed.extend_from_slice(&tx_desc(1, 3, 0x1100, &fin));
        seed.extend_from_slice(&rx_fill());
        write_seed("http_fin.in", &seed);
    }

    /// Multiple HTTP requests on same connection → endpoint receive_buf recycling,
    /// response_seq advancement (endpoint.rs response completion + re-request path)
    #[test]
    fn generate_http_pipelined_seed() {
        let (mut seed, seq) = handshake_prefix();

        let req1 = b"GET / HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let psh1 = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            seq,
            SERVER_ISN_PLUS_1,
            0x18,
            8192,
            req1,
        );
        let seq2 = seq + req1.len() as u32;

        seed.extend_from_slice(&tx_desc(1, 2, 0xf00, &psh1));
        for _ in 0..4 {
            seed.extend_from_slice(&rx_fill());
        }

        // Second request on same connection
        let req2 = b"GET /latest HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let psh2 = eth_ipv4_tcp(
            SRC_IP,
            MMDS_IP,
            4096,
            80,
            seq2,
            SERVER_ISN_PLUS_1,
            0x18,
            8192,
            req2,
        );
        seed.extend_from_slice(&tx_desc(1, 4, 0x1200, &psh2));
        for _ in 0..4 {
            seed.extend_from_slice(&rx_fill());
        }

        write_seed("http_pipelined.in", &seed);
    }
}
