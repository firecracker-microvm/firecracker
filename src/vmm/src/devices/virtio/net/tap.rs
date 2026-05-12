// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::{self, Debug};
use std::fs::File;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::ioctl_iow_nr;

use crate::devices::virtio::iovec::IoVecBuffer;
use crate::devices::virtio::net::device::vnet_hdr_len;
use crate::devices::virtio::net::generated;

// As defined in the Linux UAPI:
// https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/if.h#L33
const IFACE_NAME_MAX_LEN: usize = 16;

/// List of errors the tap implementation can throw.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum TapError {
    /// Couldn't open /dev/net/tun: {0}
    OpenTun(IoError),
    /// Invalid interface name
    InvalidIfname,
    /// Error while creating ifreq structure: {0}. Invalid TUN/TAP Backend provided by {1}. Check our documentation on setting up the network devices.
    IfreqExecuteError(IoError, String),
    /// Error while setting the offload flags: {0}
    SetOffloadFlags(IoError),
    /// Error while setting size of the vnet header: {0}
    SetSizeOfVnetHdr(IoError),
}

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
    pub(crate) if_name: [u8; IFACE_NAME_MAX_LEN],
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<[u8; IFACE_NAME_MAX_LEN], TapError> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let if_name = if_name.as_bytes();

    if if_name.len() >= IFACE_NAME_MAX_LEN {
        return Err(TapError::InvalidIfname);
    }

    let mut terminated_if_name = [b'\0'; IFACE_NAME_MAX_LEN];
    terminated_if_name[..if_name.len()].copy_from_slice(if_name);

    Ok(terminated_if_name)
}

#[derive(Copy, Clone)]
pub struct IfReqBuilder(generated::ifreq);

impl fmt::Debug for IfReqBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IfReqBuilder {{ .. }}")
    }
}

impl IfReqBuilder {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn if_name(mut self, if_name: &[u8; IFACE_NAME_MAX_LEN]) -> Self {
        // SAFETY: Since we don't call as_mut on the same union field more than once, this block is
        // safe.
        let ifrn_name = unsafe { self.0.ifr_ifrn.ifrn_name.as_mut() };
        ifrn_name.copy_from_slice(if_name.as_ref());

        self
    }

    pub(crate) fn flags(mut self, flags: i16) -> Self {
        self.0.ifr_ifru.ifru_flags = flags;
        self
    }

    pub(crate) fn execute<F: AsRawFd + Debug>(
        mut self,
        socket: &F,
        ioctl: u64,
    ) -> std::io::Result<generated::ifreq> {
        // SAFETY: ioctl is safe. Called with a valid socket fd, and we check the return.
        if unsafe { ioctl_with_mut_ref(socket, ioctl, &mut self.0) } < 0 {
            return Err(IoError::last_os_error());
        }

        Ok(self.0)
    }
}

#[derive(Debug)]
pub enum NetDevBackend {
    Passt(PasstBackend),
    Tap(Tap),
}

impl AsRawFd for NetDevBackend {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            NetDevBackend::Passt(passt) => passt.as_raw_fd(),
            NetDevBackend::Tap(tap) => tap.as_raw_fd(),
        }
    }
}

impl NetDevBackend {
    pub fn identifier(&self) -> String {
        match self {
            NetDevBackend::Passt(passt) => passt.identifier(),
            NetDevBackend::Tap(tap) => tap.identifier(),
        }
    }

    pub fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> Result<usize, IoError> {
        match self {
            NetDevBackend::Passt(passt) => passt.read_iovec(buffer),
            NetDevBackend::Tap(tap) => tap.read_iovec(buffer),
        }
    }

    pub fn write_iovec(&mut self, buffer: &IoVecBuffer) -> Result<usize, IoError> {
        match self {
            NetDevBackend::Passt(passt) => passt.write_iovec(buffer),
            NetDevBackend::Tap(tap) => tap.write_iovec(buffer),
        }
    }
}

#[derive(Debug)]
pub struct PasstBackend {
    fd: UnixStream,
    hdr_size: c_int,
    path: PathBuf,
}

impl PasstBackend {
    pub fn new(path: String) -> Result<Self, IoError> {
        // open a socket and set its path to path
        let stream = UnixStream::connect(path.clone())?;
        stream.set_nonblocking(true)?;
        Ok(PasstBackend {
            fd: stream,
            hdr_size: 0,
            path: PathBuf::from(&path),
        })
    }

    fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> Result<usize, IoError> {
        let iov = buffer.as_mut_ptr();
        let iovcnt = buffer.len().try_into().unwrap();

        // SAFETY: Dereferencing a pointer underlying a slice can never be null as guaranteed by the compiler.
        unsafe {
            if (*iov).iov_len < 12 && iovcnt == 1 {
                // we don't have enough iovs to receive 12 bytes
                if iovcnt == 1 {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        "The buffers allocated for the packet don't contain the minimum capacity to receive",
                    ));
                }
            }
        }

        // the guest expects the vnet header to be populated, which passt won't provide.
        // write the header length bytes into the iov at the start.
        // SAFETY: We just checked that the iov is atleast 12 bytes in length.
        unsafe { std::ptr::write_bytes((*iov).iov_base.cast::<u8>(), 0, vnet_hdr_len()) };

        // read the length of the incoming packet which passt adds to discard it as we have no use for it.
        // SAFETY: `read` is being called with a valid file descriptor and the error is being handled.
        let mut len_buf = [0u8; 4];
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                len_buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                4,
            )
        };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }

        // SAFETY: We checked that there are atleast 12 bytes in the first iov and there is more
        // than 1 and we are calling `readv` with a valid file descriptor.
        let ret = unsafe {
            // store the original base of the which contains the vnet header bytes we wrote
            let original_base = (*iov).iov_base;
            // add vnet_hdr_len bytes to the base so when we call readv on the fd it writes vnet_hdr_len
            // bytes into the iov
            (*iov).iov_base = ((*iov).iov_base.cast::<u8>()).add(vnet_hdr_len()).cast();
            let ret = libc::readv(self.fd.as_raw_fd(), iov, iovcnt);
            // revert the iov base back to the original base so the guest would see [vnet_header][ethernet_frame]
            (*iov).iov_base = original_base;
            ret
        };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }

        Ok(usize::try_from(ret + vnet_hdr_len().cast_signed()).unwrap())
    }

    fn write_iovec(&mut self, buffer: &IoVecBuffer) -> Result<usize, IoError> {
        // get the count of iovs from the buffer
        let iovcnt = buffer.iovec_count();

        // the guest didn't put a vnet header into the packet
        if buffer.len() as usize <= vnet_hdr_len() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "Packet sent by the guest isn't the minimum needed size",
            ));
        };

        // the guest will have set the length to how many bytes were in the frame + vnet_hdr_len
        let msglen =
            ((buffer.len() - u32::try_from(vnet_hdr_len()).unwrap()) as libc::c_uint).to_be();

        // Copy the first iov into a new iov.
        // SAFETY: IoVecBuffer is a safe wrapper that contains a vector, dereferencing the
        // pointer can never be null. We already checked the iov length is atleast 12 bytes
        // and we are writing a valid value to iov_base.
        let mut iov = unsafe {
            let mut i = *buffer.as_iovec_ptr();
            // add 12 bytes to its base to ignore the vnet header. we will use the last 4 bytes
            // of the space allocated to the vnet header to write the size
            i.iov_base = (i.iov_base.cast::<u8>()).add(vnet_hdr_len() - 4).cast();

            // copy msglen into this new base
            std::ptr::write_unaligned(i.iov_base.cast::<u32>(), msglen);
            i
        };

        // set the length to 4 (the size before the ethernet header)
        iov.iov_len = 4;

        // build a new iovec buffer, with one extra iov because we split the first into 2.
        let mut iovs: Vec<libc::iovec> = {
            let mut new_buf = Vec::with_capacity(iovcnt + 1);
            // push the 4 bytes iov we just created to it
            new_buf.push(iov);
            // push the spliced iov (the rest of the original)
            // SAFETY: We previously checked that the first iov has atleast 12 bytes.
            unsafe {
                new_buf.push(libc::iovec {
                    iov_base: (iov.iov_base.cast::<u8>())
                        .add(4)
                        .cast::<core::ffi::c_void>(),
                    iov_len: buffer.len() as usize - vnet_hdr_len(), // the original message length
                });
            }
            let mut curr_iov = buffer.as_iovec_ptr();
            // SAFETY: We are iterating on a valid array of iovec's up to iovcnt and creating
            // immutable pointers from it.
            unsafe {
                for _ in 1..iovcnt {
                    // add 1 will add the size of an iovec to that address
                    curr_iov = curr_iov.add(1);
                    new_buf.push(*curr_iov);
                }
            }

            new_buf
        };

        // SAFETY: calling `writev` with a valid file descriptor and handling the error.
        let ret = unsafe {
            libc::writev(
                self.fd.as_raw_fd(),
                iovs.as_ptr(),
                i32::try_from(iovs.len()).unwrap(),
            )
        };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(usize::try_from(ret).unwrap())
    }

    pub fn identifier(&self) -> String {
        self.path.display().to_string()
    }
}

impl AsRawFd for PasstBackend {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Tap {
    /// Create a TUN/TAP device given the interface name.
    /// # Arguments
    ///
    /// * `if_name` - the name of the interface.
    pub fn open_named(if_name: &str) -> Result<Tap, TapError> {
        // SAFETY: Open calls are safe because we give a constant null-terminated
        // string and verify the result.
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(TapError::OpenTun(IoError::last_os_error()));
        }

        // SAFETY: We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_fd(fd) };

        let terminated_if_name = build_terminated_if_name(if_name)?;
        let ifreq = IfReqBuilder::new()
            .if_name(&terminated_if_name)
            .flags(
                i16::try_from(generated::IFF_TAP | generated::IFF_NO_PI | generated::IFF_VNET_HDR)
                    .unwrap(),
            )
            .execute(&tuntap, TUNSETIFF())
            .map_err(|io_error| TapError::IfreqExecuteError(io_error, if_name.to_owned()))?;

        Ok(Tap {
            tap_file: tuntap,
            // SAFETY: Safe since only the name is accessed, and it's cloned out.
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name },
        })
    }

    /// Retrieve the interface's name as a str.
    pub fn if_name_as_str(&self) -> &str {
        let len = self
            .if_name
            .iter()
            .position(|x| *x == 0)
            .unwrap_or(IFACE_NAME_MAX_LEN);
        std::str::from_utf8(&self.if_name[..len]).unwrap_or("")
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_val(&self.tap_file, TUNSETOFFLOAD(), c_ulong::from(flags)) } < 0 {
            return Err(TapError::SetOffloadFlags(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_ref(&self.tap_file, TUNSETVNETHDRSZ(), &size) } < 0 {
            return Err(TapError::SetSizeOfVnetHdr(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Write an `IoVecBuffer` to tap
    pub(crate) fn write_iovec(&mut self, buffer: &IoVecBuffer) -> Result<usize, IoError> {
        let iovcnt = i32::try_from(buffer.iovec_count()).unwrap();
        let iov = buffer.as_iovec_ptr();
        // SAFETY: `writev` is safe. Called with a valid tap fd, the iovec pointer and length
        // is provide by the `IoVecBuffer` implementation and we check the return value.
        let ret = unsafe { libc::writev(self.tap_file.as_raw_fd(), iov, iovcnt) };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(usize::try_from(ret).unwrap())
    }

    /// Read from tap to an `IoVecBufferMut`
    pub(crate) fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> Result<usize, IoError> {
        let iov = buffer.as_mut_ptr();
        let iovcnt = buffer.len().try_into().unwrap();

        // SAFETY: `readv` is safe. Called with a valid tap fd, the iovec pointer and length
        // is provide by the `IoVecBufferMut` implementation and we check the return value.
        let ret = unsafe { libc::readv(self.tap_file.as_raw_fd(), iov, iovcnt) };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(usize::try_from(ret).unwrap())
    }

    pub fn identifier(&self) -> String {
        self.if_name_as_str().to_string()
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::devices::virtio::net::generated;
    use crate::devices::virtio::net::test_utils::{TapTrafficSimulator, enable, if_index};

    // Redefine `IoVecBufferMut` with specific length. Otherwise
    // Rust will not know what to do.
    type IoVecBufferMut = crate::devices::virtio::iovec::IoVecBufferMut<256>;

    // The size of the virtio net header
    const VNET_HDR_SIZE: usize = 10;

    const PAYLOAD_SIZE: usize = 512;

    #[test]
    fn test_tap_name() {
        // Sanity check that the assumed max iface name length is correct.
        assert_eq!(IFACE_NAME_MAX_LEN, unsafe {
            generated::ifreq__bindgen_ty_1::default().ifrn_name.len()
        });

        // Empty name - The tap should be named "tapN" by default, where N is some number
        // assigned by the kernel (e.g. "tap0", "tap1", etc.). We cannot assert a specific
        // number because other tests running in parallel may have already created tap devices.
        let tap = Tap::open_named("").unwrap();
        let name = tap.if_name_as_str();
        assert!(
            name.starts_with("tap")
                && name.len() > 3
                && name[3..].chars().all(|c| c.is_ascii_digit()),
            "Expected tap name matching 'tapN', got '{name}'"
        );

        // Test using '%d' to have the kernel assign an unused name,
        // and that we correctly copy back that generated name
        let tap = Tap::open_named("tap%d").unwrap();
        // '%d' should be replaced with _some_ number, although we don't know what was the next
        // available one. Just assert that '%d' definitely isn't there anymore.
        assert_ne!(b"tap%d", &tap.if_name[..5]);

        // 16 characters - too long.
        let name = "a123456789abcdef";
        match Tap::open_named(name) {
            Err(TapError::InvalidIfname) => (),
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
    }

    #[test]
    fn test_raw_fd() {
        let tap = Tap::open_named("").unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    #[test]
    fn test_write_iovec() {
        let mut tap = Tap::open_named("").unwrap();
        enable(&tap);
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&tap));

        let mut fragment1 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        fragment1.as_mut_slice()[..generated::ETH_HLEN as usize]
            .copy_from_slice(&[0; generated::ETH_HLEN as usize]);
        let fragment2 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        let fragment3 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);

        let scattered = IoVecBuffer::from(vec![
            fragment1.as_slice(),
            fragment2.as_slice(),
            fragment3.as_slice(),
        ]);

        let num_bytes = tap.write_iovec(&scattered).unwrap();
        assert_eq!(num_bytes, scattered.len() as usize);

        let mut read_buf = vec![0u8; scattered.len() as usize];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut read_buf));
        assert_eq!(
            &read_buf[..PAYLOAD_SIZE - VNET_HDR_SIZE],
            &fragment1[VNET_HDR_SIZE..]
        );
        assert_eq!(
            &read_buf[PAYLOAD_SIZE - VNET_HDR_SIZE..2 * PAYLOAD_SIZE - VNET_HDR_SIZE],
            fragment2
        );
        assert_eq!(
            &read_buf[2 * PAYLOAD_SIZE - VNET_HDR_SIZE..3 * PAYLOAD_SIZE - VNET_HDR_SIZE],
            fragment3
        );
    }

    #[test]
    fn test_read_iovec() {
        let mut tap = Tap::open_named("").unwrap();
        enable(&tap);
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&tap));

        let mut buff1 = vec![0; PAYLOAD_SIZE + VNET_HDR_SIZE];
        let mut buff2 = vec![0; 2 * PAYLOAD_SIZE];

        let mut rx_buffers = IoVecBufferMut::from(vec![buff1.as_mut_slice(), buff2.as_mut_slice()]);

        let packet = vmm_sys_util::rand::rand_alphanumerics(2 * PAYLOAD_SIZE);
        tap_traffic_simulator.push_tx_packet(packet.as_bytes());
        assert_eq!(
            tap.read_iovec(rx_buffers.as_iovec_mut_slice()).unwrap(),
            2 * PAYLOAD_SIZE + VNET_HDR_SIZE
        );
        assert_eq!(&buff1[VNET_HDR_SIZE..], &packet.as_bytes()[..PAYLOAD_SIZE]);
        assert_eq!(&buff2[..PAYLOAD_SIZE], &packet.as_bytes()[PAYLOAD_SIZE..]);
        assert_eq!(&buff2[PAYLOAD_SIZE..], &vec![0; PAYLOAD_SIZE])
    }
}
