extern crate json_patch;
#[macro_use]
extern crate lazy_static;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate fc_util;

pub mod mmds;
pub mod vm;

use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT};

// ATOMIC_BOOL_INIT = false
pub static FIRECRACKER_IS_JAILED: AtomicBool = ATOMIC_BOOL_INIT;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerContext {
    pub id: String,
    pub jailed: bool,
    pub seccomp_level: u32,
    pub start_time_ms: u64,
}
