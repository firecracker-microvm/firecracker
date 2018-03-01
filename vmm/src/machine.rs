/// Machine configuration specifics

use std::net::Ipv4Addr;
use std::path::PathBuf;

pub const DEFAULT_SUBNET_MASK: &str = "255.255.255.0";

pub struct MachineCfg {
    pub root_blk_file: Option<PathBuf>,
    pub host_ip: Option<Ipv4Addr>,
    pub subnet_mask: Ipv4Addr, //has default value
    pub vsock_guest_cid: Option<u64>,
}

impl Default for MachineCfg {
    fn default() -> Self {
        MachineCfg {
            root_blk_file: None,
            host_ip: None,
            subnet_mask: DEFAULT_SUBNET_MASK.parse().unwrap(),
            vsock_guest_cid: None,
        }
    }
}

impl MachineCfg {
    pub fn new(
        root_blk_file: Option<PathBuf>,
        host_ip: Option<Ipv4Addr>,
        subnet_mask: Ipv4Addr,
        vsock_guest_cid: Option<u64>,
    ) -> Self {
        MachineCfg {
            root_blk_file,
            host_ip,
            subnet_mask,
            vsock_guest_cid,
        }
    }
}
