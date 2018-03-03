use std::collections::linked_list::{self, LinkedList};
use std::mem;
use std::rc::Rc;
use std::result;

use api_server::request::sync::{Error as SyncError, NetworkInterfaceBody, OkStatus as SyncOkStatus};
use net_util::{MacAddr, Tap, TapError};

pub struct NetworkInterfaceConfig {
    // The request body received from the API side.
    body: NetworkInterfaceBody,
    // We extract the id from the body and hold it as a reference counted String. This should
    // come in handy later on, when we'll need the id to appear in a number of data structures
    // to implement efficient lookup, update, deletion, etc.
    id: Rc<String>,
    // We open the tap that will be associated with the virtual device as soon as the PUT request
    // arrives from the API. We want to see if there are any errors associated with the operation,
    // and if so, we want to report the failure back to the API caller immediately. This is an
    // option, because the inner value will be moved to the actual virtio net device before boot.
    pub tap: Option<Tap>,
}

impl NetworkInterfaceConfig {
    pub fn try_from_body(mut body: NetworkInterfaceBody) -> result::Result<Self, TapError> {
        let id = Rc::new(mem::replace(&mut body.iface_id, String::new()));

        // TODO: rework net_util stuff such that references would suffice here, instead
        // of having to move things around.
        let tap = Tap::open_named(body.host_dev_name.as_str())?;

        Ok(NetworkInterfaceConfig {
            body,
            id,
            tap: Some(tap),
        })
    }

    pub fn id_as_str(&self) -> &str {
        self.id.as_str()
    }

    pub fn take_tap(&mut self) -> Option<Tap> {
        self.tap.take()
    }

    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.body.guest_mac.as_ref()
    }
}

pub struct NetworkInterfaceConfigs {
    // We use just a list for now, since we only add interfaces as this point.
    if_list: LinkedList<NetworkInterfaceConfig>,
}

impl NetworkInterfaceConfigs {
    pub fn new() -> Self {
        NetworkInterfaceConfigs {
            if_list: LinkedList::new(),
        }
    }

    pub fn put(&mut self, body: NetworkInterfaceBody) -> result::Result<SyncOkStatus, SyncError> {
        let cfg = NetworkInterfaceConfig::try_from_body(body).map_err(SyncError::OpenTap)?;
        for x in self.if_list.iter() {
            if x.id_as_str() == cfg.id_as_str() {
                return Err(SyncError::UpdateNotImplemented);
            }
            if x.guest_mac() == cfg.guest_mac() {
                return Err(SyncError::GuestMacAddressInUse);
            }
        }
        self.if_list.push_back(cfg);
        Ok(SyncOkStatus::Created)
    }

    pub fn iter_mut(&mut self) -> linked_list::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }
}
