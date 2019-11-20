// Copyright TUNTAP, 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![allow(clippy::all)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

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
