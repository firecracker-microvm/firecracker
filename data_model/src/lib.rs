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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerContext {
    pub id: String,
    pub jailed: bool,
    pub seccomp_level: u32,
    pub start_time_us: u64,
    pub start_time_cpu_us: u64,
}
