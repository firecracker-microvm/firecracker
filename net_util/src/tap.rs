// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::net::UdpSocket;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc;

use net_gen;
use sys_util::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};

// As defined in the Linux UAPI:
// https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/if.h#L33
const IFACE_NAME_MAX_LEN: usize = 16;

/// List of errors the tap implementation can throw.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a socket.
    CreateSocket(IoError),
    /// Unable to create tap interface.
    CreateTap(IoError),
    /// Invalid interface name.
    InvalidIfname,
    /// ioctl failed.
    IoctlError(IoError),
    /// Couldn't open /dev/net/tun.
    OpenTun(IoError),
}

pub type Result<T> = ::std::result::Result<T, Error>;

const TUNTAP: ::std::os::raw::c_uint = 84;
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: [u8; IFACE_NAME_MAX_LEN],
}

impl PartialEq for Tap {
    fn eq(&self, other: &Tap) -> bool {
        self.if_name == other.if_name
    }
}

fn create_socket() -> Result<UdpSocket> {
    // This is safe since we check the return value.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::CreateSocket(IoError::last_os_error()));
    }

    // This is safe; nothing else will use or hold onto the raw sock fd.
    Ok(unsafe { UdpSocket::from_raw_fd(sock) })
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<[u8; IFACE_NAME_MAX_LEN]> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let if_name = if_name.as_bytes();

    if if_name.len() >= IFACE_NAME_MAX_LEN {
        return Err(Error::InvalidIfname);
    }

    let mut terminated_if_name = [b'\0'; IFACE_NAME_MAX_LEN];
    terminated_if_name[..if_name.len()].copy_from_slice(if_name);

    Ok(terminated_if_name)
}

impl Tap {
    /// Create a TUN/TAP device given the interface name.
    /// # Arguments
    ///
    /// * `if_name` - the name of the interface.
    /// # Example
    ///
    /// ```
    /// extern crate net_util;
    ///
    /// use self::net_util::Tap;
    /// Tap::open_named("doc-test-tap").unwrap();
    /// ```
    pub fn open_named(if_name: &str) -> Result<Tap> {
        let terminated_if_name = build_terminated_if_name(if_name)?;

        let fd = unsafe {
            // Open calls are safe because we give a constant null-terminated
            // string and verify the result.
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::OpenTun(IoError::last_os_error()));
        }

        // We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_fd(fd) };

        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: net_gen::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.copy_from_slice(terminated_if_name.as_ref());
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            *ifru_flags =
                (net_gen::IFF_TAP | net_gen::IFF_NO_PI | net_gen::IFF_VNET_HDR) as c_short;
        }

        // ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, TUNSETIFF(), &mut ifreq) };

        if ret < 0 {
            return Err(Error::CreateTap(IoError::last_os_error()));
        }

        // Safe since only the name is accessed, and it's cloned out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { *ifreq.ifr_ifrn.ifrn_name.as_ref() },
        })
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe { ioctl_with_val(&self.tap_file, TUNSETOFFLOAD(), c_ulong::from(flags)) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Enable the tap interface.
    pub fn enable(&self) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            *ifru_flags =
                (net_gen::net_device_flags_IFF_UP | net_gen::net_device_flags_IFF_RUNNING) as i16;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, c_ulong::from(net_gen::sockios::SIOCSIFFLAGS), &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.tap_file, TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    fn get_ifreq(&self) -> net_gen::ifreq {
        let mut ifreq: net_gen::ifreq = Default::default();

        // This sets the name of the interface, which is the only entry
        // in a single-field union.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.clone_from_slice(&self.if_name);
        }

        ifreq
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(&buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    extern crate pnet;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::str;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use dumbo::pdu::arp::{EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
    use dumbo::pdu::ethernet::{EthernetFrame, ETHERTYPE_ARP, ETHERTYPE_IPV4, PAYLOAD_OFFSET};
    use dumbo::pdu::ipv4::{IPv4Packet, PROTOCOL_UDP};
    use dumbo::pdu::udp::{UdpDatagram, UDP_HEADER_SIZE};
    use dumbo::MacAddr;

    use super::*;

    const DATA_STRING: &str = "test for tap";
    const SUBNET_MASK: &str = "255.255.255.0";

    const TAP_IP_PREFIX: &str = "192.168.241.";
    static NEXT_IP: AtomicUsize = AtomicUsize::new(1);

    // Create a sockaddr_in from an IPv4 address, and expose it as
    // an opaque sockaddr suitable for usage by socket ioctls.
    fn create_sockaddr(ip_addr: Ipv4Addr) -> net_gen::sockaddr {
        // IPv4 addresses big-endian (network order), but Ipv4Addr will give us
        // a view of those bytes directly so we can avoid any endian trickiness.
        let addr_in = net_gen::sockaddr_in {
            sin_family: net_gen::AF_INET as u16,
            sin_port: 0,
            sin_addr: unsafe { mem::transmute(ip_addr.octets()) },
            __pad: [0; 8usize],
        };

        unsafe { mem::transmute(addr_in) }
    }
    impl Tap {
        // We do not run unit tests in parallel so we should have no problem
        // assigning the same IP.

        /// Create a new tap interface.
        pub fn new() -> Result<Tap> {
            // The name of the tap should be {module_name}{index} so that
            // we make sure it stays different when tests are run concurrently.
            let next_ip = NEXT_IP.fetch_add(1, Ordering::SeqCst);
            Self::open_named(&format!("tap{}", next_ip))
        }

        // Set the host-side IP address for the tap interface.
        pub fn set_ip_addr(&self, ip_addr: Ipv4Addr) -> Result<()> {
            let sock = create_socket()?;
            let addr = create_sockaddr(ip_addr);

            let mut ifreq = self.get_ifreq();

            // We only access one field of the ifru union, hence this is safe.
            unsafe {
                let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
                *ifru_addr = addr;
            }

            // ioctl is safe. Called with a valid sock fd, and we check the return.
            let ret = unsafe {
                ioctl_with_ref(&sock, c_ulong::from(net_gen::sockios::SIOCSIFADDR), &ifreq)
            };
            if ret < 0 {
                return Err(Error::IoctlError(IoError::last_os_error()));
            }

            Ok(())
        }

        // Set the netmask for the subnet that the tap interface will exist on.
        pub fn set_netmask(&self, netmask: Ipv4Addr) -> Result<()> {
            let sock = create_socket()?;
            let addr = create_sockaddr(netmask);

            let mut ifreq = self.get_ifreq();

            // We only access one field of the ifru union, hence this is safe.
            unsafe {
                let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
                *ifru_addr = addr;
            }

            // ioctl is safe. Called with a valid sock fd, and we check the return.
            let ret = unsafe {
                ioctl_with_ref(
                    &sock,
                    c_ulong::from(net_gen::sockios::SIOCSIFNETMASK),
                    &ifreq,
                )
            };
            if ret < 0 {
                return Err(Error::IoctlError(IoError::last_os_error()));
            }

            Ok(())
        }
    }

    // Describes the outcomes we are currently interested in when parsing a packet (we use
    // an UDP packet for testing).
    struct ParsedPkt<'a> {
        eth: EthernetFrame<'a, &'a [u8]>,
        ipv4: Option<IPv4Packet<'a, &'a [u8]>>,
        udp: Option<UdpDatagram<'a, &'a [u8]>>,
    }

    impl<'a> ParsedPkt<'a> {
        fn new(buf: &'a [u8]) -> Self {
            let eth = EthernetFrame::from_bytes(buf).unwrap();
            let mut ipv4 = None;
            let mut udp = None;

            if eth.ethertype() == ETHERTYPE_IPV4 {
                let ipv4_start = 14;
                ipv4 = Some(IPv4Packet::from_bytes(&buf[ipv4_start..], false).unwrap());

                // Hiding the old ipv4 variable for the rest of this block.
                let ipv4 = IPv4Packet::from_bytes(eth.payload(), false).unwrap();
                let (_, header_length) = ipv4.version_and_header_len();

                if ipv4.protocol() == PROTOCOL_UDP {
                    let udp_start = ipv4_start + header_length;
                    udp = Some(UdpDatagram::from_bytes(&buf[udp_start..], None).unwrap());
                }
            }

            ParsedPkt { eth, ipv4, udp }
        }

        fn print(&self) {
            print!(
                "{} {} {} ",
                self.eth.src_mac().to_string(),
                self.eth.dst_mac().to_string(),
                self.eth.ethertype()
            );
            if let Some(ref ipv4) = self.ipv4 {
                print!(
                    "{} {} {} ",
                    ipv4.source_address(),
                    ipv4.destination_address(),
                    ipv4.protocol()
                );
            }
            if let Some(ref udp) = self.udp {
                print!(
                    "{} {} {}",
                    udp.source_port(),
                    udp.destination_port(),
                    str::from_utf8(udp.payload()).unwrap()
                );
            }
            println!();
        }
    }

    fn tap_name_to_string(tap: &Tap) -> String {
        let null_pos = tap.if_name.iter().position(|x| *x == 0).unwrap();
        str::from_utf8(&tap.if_name[..null_pos])
            .unwrap()
            .to_string()
    }

    // Given a buffer of appropriate size, this fills in the relevant fields based on the
    // provided information. Payload refers to the UDP payload.
    fn pnet_build_packet(buf: &mut [u8], dst_mac: MacAddr, payload: &[u8]) {
        // Make a new vector that can accommodate the header (buf) and data (payload)
        // we can't escape the copy here, because from_bytes consumes buf
        // unless we change the ether API in dumbo
        let mut v = vec![0u8; buf.len()];
        let mut eth = EthernetFrame::from_bytes(v.as_mut_slice()).unwrap();

        let src_mac = MacAddr::from_bytes(&[0x06, 0, 0, 0, 0, 0]).unwrap();
        eth.set_src_mac(src_mac);
        eth.set_dst_mac(dst_mac);
        eth.set_ethertype(ETHERTYPE_IPV4);

        // Because we're borrowing eth as mutable
        {
            let mut ipv4 = IPv4Packet::from_bytes_unchecked(eth.payload_mut());
            let ip_header_len_bytes = 20;
            ipv4.set_version_and_header_len(IPV4_VERSION, ip_header_len_bytes);
            ipv4.set_total_len((ip_header_len_bytes + UDP_HEADER_SIZE + payload.len()) as u16);
            ipv4.set_ttl(DEFAULT_TTL);
            ipv4.set_protocol(PROTOCOL_UDP);
            ipv4.set_source_address(Ipv4Addr::new(192, 168, 241, 1));
            ipv4.set_destination_address(Ipv4Addr::new(192, 168, 241, 2));

            let mut udp = UdpDatagram::from_bytes(ipv4.payload_mut(), None).unwrap();
            udp.set_source_port(1000);
            udp.set_destination_port(1001);
            udp.set_len((UDP_HEADER_SIZE + payload.len()) as u16);
            udp.set_payload(payload);
        }

        buf.copy_from_slice(eth.as_raw()); // Copy the raw data by the buf of pnet
    }

    // Sends a test packet on the interface named "ifname".
    fn pnet_send_packet(ifname: String) {
        let payload = DATA_STRING.as_bytes();

        // eth hdr + ip hdr + udp hdr + payload len
        let buf_size = 14 + 20 + 8 + payload.len();

        let (mac, mut tx, _) = pnet_get_mac_tx_rx(ifname);

        let res = tx.build_and_send(1, buf_size, &mut |buf| {
            pnet_build_packet(buf, mac, payload);
        });
        // Make sure build_and_send() -> Option<io::Result<()>> succeeds.
        res.unwrap().unwrap();
    }

    // For a given interface name, this returns a tuple that contains the MAC address of the
    // interface, an object that can be used to send Ethernet frames, and a receiver of
    // Ethernet frames arriving at the specified interface.
    fn pnet_get_mac_tx_rx(
        ifname: String,
    ) -> (MacAddr, Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
        let interface_name_matches = |iface: &NetworkInterface| iface.name == ifname;

        // Find the network interface with the provided name.
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter().find(interface_name_matches).unwrap();

        if let Ok(Ethernet(tx, rx)) = datalink::channel(&interface, Default::default()) {
            let mac_addr = interface.mac_address();
            // TODO: replace pnet interfaces
            let mut mac_bytes = [0u8; 6];
            mac_bytes[0] = mac_addr.0;
            mac_bytes[1] = mac_addr.1;
            mac_bytes[2] = mac_addr.2;
            mac_bytes[3] = mac_addr.3;
            mac_bytes[4] = mac_addr.4;
            mac_bytes[5] = mac_addr.5;
            let mac = MacAddr::from_bytes(mac_bytes.as_mut()).unwrap();
            (mac, tx, rx)
        } else {
            panic!("datalink channel error or unhandled channel type");
        }
    }

    #[test]
    fn test_tap_name() {
        // Sanity check that the assumed max iface name length is correct.
        assert_eq!(
            IFACE_NAME_MAX_LEN,
            net_gen::ifreq__bindgen_ty_1::default()
                .bindgen_union_field
                .len()
        );

        // 16 characters - too long.
        let name = "a123456789abcdef";
        match Tap::open_named(name) {
            Err(Error::InvalidIfname) => (),
            _ => panic!("Expected Error::InvalidIfname"),
        };

        // 15 characters - OK.
        let name = "a123456789abcde";
        let tap = Tap::open_named(name).unwrap();
        assert_eq!(
            name,
            std::str::from_utf8(&tap.if_name[0..(IFACE_NAME_MAX_LEN - 1)]).unwrap()
        );
    }

    #[test]
    fn test_tap_partial_eq() {
        assert_ne!(Tap::new().unwrap(), Tap::new().unwrap());
    }

    #[test]
    fn test_tap_configure() {
        // `fetch_add` adds to the current value, returning the previous value.
        let next_ip = NEXT_IP.fetch_add(1, Ordering::SeqCst);

        let tap = Tap::new().unwrap();
        let ip_addr: Ipv4Addr = format!("{}{}", TAP_IP_PREFIX, next_ip).parse().unwrap();
        let netmask: Ipv4Addr = SUBNET_MASK.parse().unwrap();

        let ret = tap.set_ip_addr(ip_addr);
        assert!(ret.is_ok());
        let ret = tap.set_netmask(netmask);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_set_options() {
        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::new().unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();

        let faulty_tap = Tap {
            tap_file: unsafe { File::from_raw_fd(-1) },
            if_name: [0x01; 16],
        };
        assert!(faulty_tap.set_vnet_hdr_size(16).is_err());
        assert!(faulty_tap.set_offload(0).is_err());
    }

    #[test]
    fn test_tap_enable() {
        let tap = Tap::new().unwrap();
        let ret = tap.enable();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_tap_get_ifreq() {
        let tap = Tap::new().unwrap();
        let ret = tap.get_ifreq();
        assert_eq!(
            "__BindgenUnionField",
            format!("{:?}", ret.ifr_ifrn.ifrn_name)
        );
    }

    #[test]
    fn test_raw_fd() {
        let tap = Tap::new().unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    #[test]
    fn test_read() {
        // `fetch_add` adds to the current value, returning the previous value.
        let next_ip = NEXT_IP.fetch_add(1, Ordering::SeqCst);

        let mut tap = Tap::new().unwrap();
        let ip_addr = format!("{}{}", TAP_IP_PREFIX, next_ip).parse().unwrap();

        tap.set_ip_addr(ip_addr).unwrap();
        tap.set_netmask(SUBNET_MASK.parse().unwrap()).unwrap();
        tap.enable().unwrap();

        // Send a packet to the interface. We expect to be able to receive it on the associated fd.
        pnet_send_packet(tap_name_to_string(&tap));

        let mut buf = [0u8; 4096];

        let mut found_packet_sz = None;

        // In theory, this could actually loop forever if something keeps sending data through the
        // tap interface, but it's highly unlikely.
        while found_packet_sz.is_none() {
            let result = tap.read(&mut buf);
            assert!(result.is_ok());

            let size = result.unwrap();

            // We skip the first 10 bytes because the IFF_VNET_HDR flag is set when the interface
            // is created, and the legacy header is 10 bytes long without a certain flag which
            // is not set in Tap::new().
            let eth_bytes = &buf[10..size];
            let packet = EthernetFrame::from_bytes(eth_bytes).unwrap();
            if packet.ethertype() != ETHERTYPE_IPV4 {
                // not an IPv4 packet
                continue;
            }

            let ipv4_bytes = &eth_bytes[14..];
            let packet = IPv4Packet::from_bytes(ipv4_bytes, false).unwrap();

            // Our packet should carry an UDP payload, and not contain IP options.
            if packet.protocol() != PROTOCOL_UDP && packet.header_len() != 5 {
                continue;
            }

            let ipv4_data_start = 20;
            let udp_bytes = &ipv4_bytes[ipv4_data_start..];

            let udp_len = UdpDatagram::from_bytes(udp_bytes, None).unwrap().len() as usize;

            // Skip the header bytes.
            let inner_string = str::from_utf8(&udp_bytes[UDP_HEADER_SIZE..udp_len]).unwrap();

            if inner_string.eq(DATA_STRING) {
                found_packet_sz = Some(size);
                break;
            }
        }

        assert!(found_packet_sz.is_some());
    }

    #[test]
    fn test_write() {
        // `fetch_add` adds to the current value, returning the previous value.
        let next_ip = NEXT_IP.fetch_add(1, Ordering::SeqCst);

        let mut tap = Tap::new().unwrap();
        let ip_addr = format!("{}{}", TAP_IP_PREFIX, next_ip).parse().unwrap();

        tap.set_ip_addr(ip_addr).unwrap();

        tap.set_netmask(SUBNET_MASK.parse().unwrap()).unwrap();
        tap.enable().unwrap();

        let (mac, _, mut rx) = pnet_get_mac_tx_rx(tap_name_to_string(&tap));

        let payload = DATA_STRING.as_bytes();

        // vnet hdr + eth hdr + ip hdr + udp hdr + payload len
        let buf_size = 10 + 14 + 20 + 8 + payload.len();

        let mut buf = vec![0u8; buf_size];
        // leave the vnet hdr as is
        pnet_build_packet(&mut buf[10..], mac, payload);

        assert!(tap.write(&buf[..]).is_ok());
        assert!(tap.flush().is_ok());

        let (channel_tx, channel_rx) = mpsc::channel();

        // We use a separate thread to wait for the test packet because the API exposed by pnet is
        // blocking. This thread will be killed when the main thread exits.
        let _handle = thread::spawn(move || loop {
            let buf = rx.next().unwrap();
            let p = ParsedPkt::new(buf);
            p.print();

            if let Some(ref udp) = p.udp {
                if payload == udp.payload() {
                    channel_tx.send(true).unwrap();
                    break;
                }
            }
        });

        // We wait for at most SLEEP_MILLIS * SLEEP_ITERS milliseconds for the reception of the
        // test packet to be detected.
        static SLEEP_MILLIS: u64 = 500;
        static SLEEP_ITERS: u32 = 6;

        let mut found_test_packet = false;

        for _ in 0..SLEEP_ITERS {
            thread::sleep(Duration::from_millis(SLEEP_MILLIS));
            if let Ok(true) = channel_rx.try_recv() {
                found_test_packet = true;
                break;
            }
        }

        assert!(found_test_packet);
    }
}
