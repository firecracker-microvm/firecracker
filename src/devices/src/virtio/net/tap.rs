// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use net_gen::ifreq;
use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use utils::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use utils::{ioctl_expr, ioctl_ioc_nr, ioctl_iow_nr};

// As defined in the Linux UAPI:
// https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/if.h#L33
const IFACE_NAME_MAX_LEN: usize = 16;

/// List of errors the tap implementation can throw.
#[derive(Debug)]
pub enum Error {
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

struct IfReqBuilder(ifreq);

impl IfReqBuilder {
    fn new() -> Self {
        Self(Default::default())
    }

    fn if_name(mut self, if_name: &[u8; IFACE_NAME_MAX_LEN]) -> Self {
        // Since we don't call as_mut on the same union field more than once, this block is safe.
        let ifrn_name = unsafe { self.0.ifr_ifrn.ifrn_name.as_mut() };
        ifrn_name.copy_from_slice(if_name.as_ref());

        self
    }

    fn flags(mut self, flags: i16) -> Self {
        // Since we don't call as_mut on the same union field more than once, this block is safe.
        let ifru_flags = unsafe { self.0.ifr_ifru.ifru_flags.as_mut() };
        *ifru_flags = flags;

        self
    }

    fn execute<F: AsRawFd>(mut self, socket: &F, ioctl: u64) -> Result<ifreq> {
        // ioctl is safe. Called with a valid socket fd, and we check the return.
        let ret = unsafe { ioctl_with_mut_ref(socket, ioctl, &mut self.0) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(self.0)
    }
}

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

        let ifreq = IfReqBuilder::new()
            .if_name(&terminated_if_name)
            .flags((net_gen::IFF_TAP | net_gen::IFF_NO_PI | net_gen::IFF_VNET_HDR) as i16)
            .execute(&tuntap, TUNSETIFF())?;

        // Safe since only the name is accessed, and it's cloned out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { *ifreq.ifr_ifrn.ifrn_name.as_ref() },
        })
    }

    pub fn if_name_as_str(&self) -> &str {
        let len = self
            .if_name
            .iter()
            .position(|x| *x == 0)
            .unwrap_or(IFACE_NAME_MAX_LEN);
        std::str::from_utf8(&self.if_name[..len]).unwrap_or("")
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

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.tap_file, TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
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
pub mod tests {

    use std::mem;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    use super::*;
    use net_gen::ETH_HLEN;

    // The size of the virtio net header
    const VNET_HDR_SIZE: usize = 10;

    const PAYLOAD_SIZE: usize = 512;
    const PACKET_SIZE: usize = 1024;

    fn create_socket() -> File {
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

    impl Tap {
        pub fn if_index(&self) -> i32 {
            let sock = create_socket();
            let ifreq = IfReqBuilder::new()
                .if_name(&self.if_name)
                .execute(&sock, c_ulong::from(net_gen::sockios::SIOCGIFINDEX))
                .unwrap();

            unsafe { *ifreq.ifr_ifru.ifru_ivalue.as_ref() }
        }

        /// Enable the tap interface.
        pub fn enable(&self) {
            // Disable IPv6 router advertisment requests
            Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra",
                    self.if_name_as_str()
                ))
                .output()
                .unwrap();

            let sock = create_socket();
            IfReqBuilder::new()
                .if_name(&self.if_name)
                .flags(
                    (net_gen::net_device_flags_IFF_UP
                        | net_gen::net_device_flags_IFF_RUNNING
                        | net_gen::net_device_flags_IFF_NOARP) as i16,
                )
                .execute(&sock, c_ulong::from(net_gen::sockios::SIOCSIFFLAGS))
                .unwrap();
        }
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

    #[test]
    fn test_tap_name() {
        // Sanity check that the assumed max iface name length is correct.
        assert_eq!(
            IFACE_NAME_MAX_LEN,
            net_gen::ifreq__bindgen_ty_1::default()
                .bindgen_union_field
                .len()
        );

        // Empty name - The tap should be named "tap0" by default
        let tap = Tap::open_named("").unwrap();
        assert_eq!(b"tap0\0\0\0\0\0\0\0\0\0\0\0\0", &tap.if_name);
        assert_eq!("tap0", tap.if_name_as_str());

        // 16 characters - too long.
        let name = "a123456789abcdef";
        match Tap::open_named(name) {
            Err(Error::InvalidIfname) => (),
            _ => panic!("Expected Error::InvalidIfname"),
        };

        // 15 characters - OK.
        let name = "a123456789abcde";
        let tap = Tap::open_named(name).unwrap();
        assert_eq!(&format!("{}\0", name).as_bytes(), &tap.if_name);
        assert_eq!(name, tap.if_name_as_str());
    }

    #[test]
    fn test_tap_exclusive_open() {
        let _tap1 = Tap::open_named("exclusivetap").unwrap();
        // Opening same tap device a second time should not be permitted.
        Tap::open_named("exclusivetap").unwrap_err();
    }

    #[test]
    fn test_set_options() {
        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::open_named("").unwrap();
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
    fn test_raw_fd() {
        let tap = Tap::open_named("").unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    #[test]
    fn test_read() {
        let mut tap = Tap::open_named("").unwrap();
        tap.enable();
        let tap_traffic_simulator = TapTrafficSimulator::new(tap.if_index());

        let packet = utils::rand::rand_alphanumerics(PAYLOAD_SIZE);
        tap_traffic_simulator.push_tx_packet(packet.as_bytes());

        let mut buf = [0u8; PACKET_SIZE];
        assert!(tap.read(&mut buf).is_ok());
        assert_eq!(
            &buf[VNET_HDR_SIZE..packet.len() + VNET_HDR_SIZE],
            packet.as_bytes()
        );
    }

    #[test]
    fn test_write() {
        let mut tap = Tap::open_named("").unwrap();
        tap.enable();
        let tap_traffic_simulator = TapTrafficSimulator::new(tap.if_index());

        let mut packet = [0u8; PACKET_SIZE];
        let payload = utils::rand::rand_alphanumerics(PAYLOAD_SIZE);
        packet[ETH_HLEN as usize..payload.len() + ETH_HLEN as usize]
            .copy_from_slice(payload.as_bytes());
        assert!(tap.write(&packet).is_ok());

        let mut read_buf = [0u8; PACKET_SIZE];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut read_buf));
        assert_eq!(
            &read_buf[..PACKET_SIZE - VNET_HDR_SIZE],
            &packet[VNET_HDR_SIZE..]
        );
    }
}
