extern crate futures;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_uds;

extern crate data_model;
extern crate fc_util;
extern crate jailer;
#[macro_use]
extern crate logger;
extern crate net_util;
extern crate sys_util;

mod http_service;
pub mod request;

use std::cell::RefCell;
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};

use futures::{Future, Stream};
use hyper::server::Http;
use tokio_core::reactor::Core;
use tokio_uds::UnixListener;

use data_model::mmds::Mmds;
use fc_util::LriHashMap;
use http_service::ApiServerHttpService;
use request::actions::ActionBody;
use request::instance_info::InstanceInfo;
pub use request::ApiRequest;
use sys_util::EventFd;

// When information is requested about an async action, it can still be waiting to be processed
// by the VMM, or we already know the outcome, which is recorded directly into response form,
// because it's inherently static at this point.
pub enum ActionMapValue {
    Pending(ActionBody),
    // The response status code, and the response json body.
    JsonResponse(hyper::StatusCode, String),
}

// A map that holds information about currently pending, and previous async actions.
pub type ActionMap = LriHashMap<String, ActionMapValue>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Eventfd(sys_util::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ApiServer {
    // MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    // VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    // Sender which allows passing messages to the VMM.
    api_request_sender: Rc<mpsc::Sender<Box<ApiRequest>>>,
    max_previous_actions: usize,
    efd: Rc<EventFd>,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<Box<ApiRequest>>,
        max_previous_actions: usize,
    ) -> Result<Self> {
        Ok(ApiServer {
            mmds_info,
            vmm_shared_info,
            api_request_sender: Rc::new(api_request_sender),
            max_previous_actions,
            efd: Rc::new(EventFd::new().map_err(Error::Eventfd)?),
        })
    }

    // TODO: does tokio_uds also support abstract domain sockets?
    pub fn bind_and_run<P: AsRef<Path>>(&self, uds_path: P) -> Result<()> {
        let mut core = Core::new().map_err(Error::Io)?;
        let handle = Rc::new(core.handle());

        let listener = if data_model::FIRECRACKER_IS_JAILED
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // This is a UnixListener of the tokio_uds variety. Using fd inherited from the jailer.
            UnixListener::from_listener(
                unsafe { std::os::unix::net::UnixListener::from_raw_fd(jailer::LISTENER_FD) },
                &handle,
            ).map_err(Error::Io)?
        } else {
            UnixListener::bind(uds_path, &handle).map_err(Error::Io)?
        };

        let http: Http<hyper::Chunk> = Http::new();

        let action_map = Rc::new(RefCell::new(LriHashMap::<String, ActionMapValue>::new(
            self.max_previous_actions,
        )));

        let f = listener
            .incoming()
            .for_each(|(stream, _)| {
                // For the sake of clarity: when we use self.efd.clone(), the intent is to
                // clone the wrapping Rc, not the EventFd itself.
                let service = ApiServerHttpService::new(
                    self.mmds_info.clone(),
                    self.vmm_shared_info.clone(),
                    self.api_request_sender.clone(),
                    self.efd.clone(),
                    action_map.clone(),
                    handle.clone(),
                );
                let connection = http.serve_connection(stream, service);
                // todo: is spawn() any better/worse than execute()?
                // We have to adjust the future item and error, to fit spawn()'s definition.
                handle.spawn(connection.map(|_| ()).map_err(|_| ()));
                Ok(())
            })
            .map_err(Error::Io);

        // This runs forever, unless an error is returned somewhere within f (but nothing happens
        // for errors which might arise inside the connections we spawn from f, unless we explicitly
        // do something in their future chain). When this returns, ongoing connections will be
        // interrupted, and other futures will not complete, as the event loop stops working.
        core.run(f)
    }

    pub fn get_event_fd_clone(&self) -> Result<EventFd> {
        self.efd.try_clone().map_err(Error::Eventfd)
    }
}
