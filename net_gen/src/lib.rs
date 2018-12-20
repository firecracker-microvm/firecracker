// Copyright TUNTAP, 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate sys_util;

// generated with bindgen /usr/include/linux/if.h --no-unstable-rust
// --constified-enum '*' --with-derive-default -- -D __UAPI_DEF_IF_IFNAMSIZ -D
// __UAPI_DEF_IF_NET_DEVICE_FLAGS -D __UAPI_DEF_IF_IFREQ -D __UAPI_DEF_IF_IFMAP
// Name is "iff" to avoid conflicting with "if" keyword.
// Generated against Linux 4.11 to include fix "uapi: fix linux/if.h userspace
// compilation errors".
// Manual fixup of ifrn_name to be of type c_uchar instead of c_char.
pub mod iff;
// generated with bindgen /usr/include/linux/if_tun.h --no-unstable-rust
// --constified-enum '*' --with-derive-default
pub mod if_tun;
// generated with bindgen /usr/include/linux/in.h --no-unstable-rust
// --constified-enum '*' --with-derive-default
// Name is "inn" to avoid conflicting with "in" keyword.
pub mod inn;
// generated with bindgen /usr/include/linux/sockios.h --no-unstable-rust
// --constified-enum '*' --with-derive-default
pub mod sockios;
pub use if_tun::*;
pub use iff::*;
pub use inn::*;
pub use sockios::*;

pub const TUNTAP: ::std::os::raw::c_uint = 84;

ioctl_iow_nr!(TUNSETNOCSUM, TUNTAP, 200, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETDEBUG, TUNTAP, 201, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETPERSIST, TUNTAP, 203, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOWNER, TUNTAP, 204, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETLINK, TUNTAP, 205, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETGROUP, TUNTAP, 206, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 207, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETTXFILTER, TUNTAP, 209, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETIFF, TUNTAP, 210, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETSNDBUF, TUNTAP, 211, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETSNDBUF, TUNTAP, 212, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNATTACHFILTER, TUNTAP, 213, sock_fprog);
ioctl_iow_nr!(TUNDETACHFILTER, TUNTAP, 214, sock_fprog);
ioctl_ior_nr!(TUNGETVNETHDRSZ, TUNTAP, 215, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 217, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFINDEX, TUNTAP, 218, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETFILTER, TUNTAP, 219, sock_fprog);
ioctl_iow_nr!(TUNSETVNETLE, TUNTAP, 220, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETLE, TUNTAP, 221, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETBE, TUNTAP, 222, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETBE, TUNTAP, 223, ::std::os::raw::c_int);
