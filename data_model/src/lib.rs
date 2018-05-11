extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate fc_util;

pub mod device_config;
pub mod vm;

use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT};

// ATOMIC_BOOL_INIT = false
pub static FIRECRACKER_IS_JAILED: AtomicBool = ATOMIC_BOOL_INIT;
