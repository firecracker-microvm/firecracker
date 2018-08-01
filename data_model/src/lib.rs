extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate json_patch;
extern crate serde_json;

extern crate fc_util;

pub mod mmds;
pub mod vm;

use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT};

// ATOMIC_BOOL_INIT = false
pub static FIRECRACKER_IS_JAILED: AtomicBool = ATOMIC_BOOL_INIT;
