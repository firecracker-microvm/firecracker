use std::collections::linked_list::{self, LinkedList};
use std::mem;
use std::rc::Rc;
use std::result::Result;

use api_server::request::sync::{Error, OkStatus};
use api_server::request::VsockJsonBody;

pub struct VsockDeviceConfig {
    body: VsockJsonBody,
    // Will come in handy if/when the id will placed in all sorts of maps and such.
    id: Rc<String>,
}

impl From<VsockJsonBody> for VsockDeviceConfig {
    fn from(mut body: VsockJsonBody) -> Self {
        let id = Rc::new(mem::replace(&mut body.vsock_id, String::new()));
        VsockDeviceConfig { body, id }
    }
}

impl VsockDeviceConfig {
    pub fn get_guest_cid(&self) -> u32 {
        return self.body.guest_cid;
    }

    pub fn get_id(&self) -> &str {
        self.id.as_str()
    }
}

// TODO: have a more efficient implementation at some point
pub struct VsockDeviceConfigs {
    configs: LinkedList<VsockDeviceConfig>,
}

impl VsockDeviceConfigs {
    pub fn new() -> Self {
        VsockDeviceConfigs {
            configs: LinkedList::new(),
        }
    }

    fn contains_cid(&self, cid: u32) -> bool {
        for cfg in self.configs.iter() {
            if cfg.get_guest_cid() == cid {
                return true;
            }
        }
        false
    }

    pub fn put(&mut self, body: VsockJsonBody) -> Result<OkStatus, Error> {
        let cfg = VsockDeviceConfig::from(body);

        for x in self.configs.iter() {
            if cfg.get_id() == x.get_id() {
                return Err(Error::UpdateNotImplemented);
            }
        }

        if self.contains_cid(cfg.get_guest_cid()) {
            return Err(Error::GuestCIDAlreadyInUse);
        }

        self.configs.push_back(cfg);
        Ok(OkStatus::Created)
    }

    pub fn iter(&self) -> linked_list::Iter<VsockDeviceConfig> {
        self.configs.iter()
    }
}
