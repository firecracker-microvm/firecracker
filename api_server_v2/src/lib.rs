extern crate futures;
extern crate hyper;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;

extern crate fc_util;
extern crate sys_util;

mod http_service;
pub mod request;

use std::cell::RefCell;
use std::rc::Rc;

use fc_util::LriHashMap;
use request::AsyncRequestBody;

// When information is requested about an async action, it can still be waiting to be processed
// by the VMM, or we already know the outcome, which is recorded directly into response form,
// because it's inherently static at this point.
pub enum ActionMapValue {
    Pending(AsyncRequestBody),
    Response(hyper::Response),
}

// A map that holds information about currently pending, and previous async actions.
pub type ActionMap = LriHashMap<String, ActionMapValue>;
