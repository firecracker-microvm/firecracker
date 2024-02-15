use event_manager::{EventOps, Events};
use log::{error, warn};
use utils::epoll::EventSet;

use super::device::VhostNet;
use crate::devices::virtio::device::VirtioDevice;

impl VhostNet {
    const PROCESS_ACTIVATE: u32 = 0;
    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_evt.read() {
            error!("Failed to consume net activate event: {:?}", err);
        }
        if let Err(err) = ops.remove(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to register activate event: {}", err);
        }
    }

    pub(crate) fn init(&mut self, ops: &mut EventOps) {
        if !self.is_activated() {
            self.register_activate_event(ops);
        }
    }

    pub(crate) fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();

        if self.is_activated() {
            match source {
                Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
                _ => {
                    warn!("Net: Spurious event received: {:?}", source);
                }
            }
        }
    }
}
