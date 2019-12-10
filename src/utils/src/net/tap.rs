// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use libc;
use net_gen;
use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::net::UdpSocket;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};

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
    /// extern crate utils;
    ///
    /// use utils::net::Tap;
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
    extern crate dumbo;

    use std::io::Read;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::process::Command;
    use std::str;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use self::dumbo::{
        EthIPv4ArpFrame, EthernetFrame, IPv4Packet, MacAddr, UdpDatagram, ETHERNET_PAYLOAD_OFFSET,
        ETHERTYPE_ARP, ETHERTYPE_IPV4, ETH_IPV4_FRAME_LEN, PROTOCOL_UDP, UDP_HEADER_SIZE,
    };

    use super::*;

    const DATA_STRING: &str = "test for tap";
    const SUBNET_MASK: &str = "255.255.255.0";
    const TAP_IP_PREFIX: &str = "192.168.241.";
    const FAKE_MAC: &str = "12:34:56:78:9a:bc";

    // We skip the first 10 bytes because the IFF_VNET_HDR flag is set when the interface
    // is created, and the legacy header is 10 bytes long without a certain flag which
    // is not set in Tap::new().
    const VETH_OFFSET: usize = 10;
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

    fn tap_name_to_string(tap: &Tap) -> String {
        let null_pos = tap.if_name.iter().position(|x| *x == 0).unwrap();
        str::from_utf8(&tap.if_name[..null_pos])
            .unwrap()
            .to_string()
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

    fn construct_arp_reply<'a>(
        buf: &'a mut [u8],
        arp_frame: &EthernetFrame<&[u8]>,
    ) -> EthernetFrame<'a, &'a mut [u8]> {
        let arp_bytes = arp_frame.payload();
        let arp_request = EthIPv4ArpFrame::request_from_bytes(arp_bytes).unwrap();
        let mac_addr = MacAddr::parse_str(FAKE_MAC).unwrap();
        let mut reply_frame =
            EthernetFrame::write_incomplete(buf, arp_frame.src_mac(), mac_addr, ETHERTYPE_ARP)
                .unwrap();
        let sha = arp_request.sha();
        let spa = arp_request.spa();
        let tpa = arp_request.tpa();

        EthIPv4ArpFrame::write_reply(
            reply_frame.inner_mut().payload_mut(),
            mac_addr,
            tpa,
            sha,
            spa,
        )
        .unwrap();
        reply_frame.with_payload_len_unchecked(ETH_IPV4_FRAME_LEN)
    }

    fn make_tap(tap_ip: Ipv4Addr) -> Tap {
        let tap = Tap::new().unwrap();
        tap.set_ip_addr(tap_ip).unwrap();
        tap.set_netmask(SUBNET_MASK.parse().unwrap()).unwrap();
        tap.enable().unwrap();
        tap
    }

    #[test]
    fn test_read() {
        // `fetch_add` adds to the current value, returning the previous value.
        // reserve 2 fake IPs, one for the tap and the other for the virtual host
        let next_ip = NEXT_IP.fetch_add(2, Ordering::SeqCst);
        let tap_ip: Ipv4Addr = format!("{}{}", TAP_IP_PREFIX, next_ip).parse().unwrap();
        let mut tap = make_tap(tap_ip);

        // Now we want to set the target address to something that's near the IP address
        // of the TAP (within its subnet) so the OS will think that the TAP is the next hop
        // and forward the Udp packet through the TAP, where we can read it.
        let dst_ip = format!("{}{}", TAP_IP_PREFIX, next_ip + 1).parse().unwrap();
        let dst_port = 44445;
        let dst_addr = SocketAddrV4::new(dst_ip, dst_port);

        let src_port = 44444;
        let src_addr = SocketAddrV4::new(tap_ip, src_port);
        let socket = UdpSocket::bind(src_addr).expect("Failed to bind UDP socket");
        socket.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
        socket.send_to(DATA_STRING.as_bytes(), dst_addr).unwrap();

        let mut found_packet_sz = None;

        while found_packet_sz.is_none() {
            let mut buf = [0u8; 1024];
            let result = tap.read(&mut buf);
            assert!(result.is_ok());

            let size = result.unwrap();
            let eth_bytes = &buf[VETH_OFFSET..size];

            let packet = EthernetFrame::from_bytes(eth_bytes).unwrap();
            if packet.ethertype() == ETHERTYPE_ARP {
                // Veth header + ARP reply
                let reply_buf =
                    &mut [0u8; VETH_OFFSET + ETHERNET_PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN];
                construct_arp_reply(&mut reply_buf[VETH_OFFSET..], &packet);

                assert!(tap.write(reply_buf).is_ok());
                assert!(tap.flush().is_ok());
                continue;
            }

            if packet.ethertype() != ETHERTYPE_IPV4 {
                // not an IPv4 packet
                continue;
            }

            let ipv4_bytes = packet.payload();
            let packet = IPv4Packet::from_bytes(ipv4_bytes, false).unwrap();

            // Our packet should carry an UDP payload
            if packet.protocol() != PROTOCOL_UDP {
                continue;
            }

            let udp_bytes = packet.payload();
            let packet = UdpDatagram::from_bytes(udp_bytes, None).unwrap();
            // Avoid parsing any unwanted packets
            if packet.destination_port() != dst_port && packet.source_port() != src_port {
                continue;
            }

            let payload_bytes = packet.payload();
            let inner_string = str::from_utf8(payload_bytes).unwrap();

            if inner_string.eq(DATA_STRING) {
                found_packet_sz = Some(size);
                break;
            } else {
                panic!("Received a corrupted payload [{}]", inner_string);
            }
        }

        assert!(found_packet_sz.is_some());
    }

    // Given a buffer of appropriate size, this fills in the relevant fields based on the
    // provided information. Payload refers to the UDP payload.
    fn build_packet(
        buf: &mut [u8],
        src_mac: MacAddr,
        dst_mac: MacAddr,
        payload: &[u8],
        src_addr: &SocketAddrV4,
        dst_addr: &SocketAddrV4,
    ) {
        let mut eth = EthernetFrame::from_bytes(buf).unwrap();

        eth.set_src_mac(src_mac)
            .set_dst_mac(dst_mac)
            .set_ethertype(ETHERTYPE_IPV4);

        let ip_header_len_bytes = 20; // 20 bytes for header (min length)
        let mut ipv4 = IPv4Packet::write_header(
            eth.payload_mut(),
            PROTOCOL_UDP,
            *src_addr.ip(),
            *dst_addr.ip(),
        )
        .unwrap()
        .with_header_and_payload_len_unchecked(
            ip_header_len_bytes,             // IHL = 5
            UDP_HEADER_SIZE + payload.len(), // Udp packet
            true,
        );

        let udp = UdpDatagram::write_incomplete_datagram(ipv4.payload_mut(), payload).unwrap();
        udp.finalize(
            src_addr.port(),
            dst_addr.port(),
            Some((*src_addr.ip(), *dst_addr.ip())),
        );
    }

    /// Set the TAP's MAC to the given address
    fn set_tap_mac(tap: &Tap, mac_addr: &str) {
        let tap_name = tap_name_to_string(&tap);
        Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(tap_name)
            .arg("address")
            .arg(mac_addr)
            .status()
            .expect("Failed to execute ip link");
    }

    #[test]
    fn test_write() {
        // `fetch_add` adds to the current value, returning the previous value.
        // reserve 2 IPs one for the tap and the other for the UdpSocket
        let next_ip = NEXT_IP.fetch_add(2, Ordering::SeqCst);

        let tap_ip: Ipv4Addr = format!("{}{}", TAP_IP_PREFIX, next_ip).parse().unwrap();
        let mut tap = make_tap(tap_ip);
        let tap_mac = "12:34:56:78:9a:bd";
        set_tap_mac(&tap, tap_mac);

        let payload = DATA_STRING.as_bytes();

        let src_ip: Ipv4Addr = format!("{}{}", TAP_IP_PREFIX, next_ip + 1).parse().unwrap();
        let src_port = 44444;
        let src_addr = SocketAddrV4::new(src_ip, src_port);
        let src_mac = MacAddr::parse_str(FAKE_MAC).unwrap();

        let dst_port = 44448;
        let dst_addr = SocketAddrV4::new(tap_ip, dst_port);
        let dst_mac = MacAddr::parse_str(tap_mac).unwrap();

        let socket = UdpSocket::bind(dst_addr).expect("Failed to bind UDP socket");
        socket.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

        // vnet hdr + eth hdr + ip hdr + udp hdr + payload len
        let buf_size = VETH_OFFSET + 14 + 20 + UDP_HEADER_SIZE + payload.len();
        let mut buf = vec![0u8; buf_size];
        // leave the vnet hdr as is
        build_packet(
            &mut buf[VETH_OFFSET..],
            src_mac,
            dst_mac,
            payload,
            &src_addr,
            &dst_addr,
        );
        assert!(tap.write(&buf[..]).is_ok());
        assert!(tap.flush().is_ok());

        let mut buf = [0u8; 256];
        let recv_result = socket.recv_from(&mut buf);
        assert!(recv_result.is_ok());

        let size = recv_result.unwrap().0;
        let data = str::from_utf8(&buf[..size]).unwrap();
        assert_eq!(data, DATA_STRING);
    }
}
