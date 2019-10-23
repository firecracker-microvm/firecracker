// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// use std::result;

// use futures::sync::oneshot;
// use hyper::Method;

// use request::{IntoParsedRequest, ParsedRequest};
// use super::{VmmAction, VmmRequest};

// use super::super::VmmAction;
// use request::{Body, Error, ParsedRequest};
// use vmm::vmm_config::vsock::VsockDeviceConfig;

use super::super::VmmAction;
use request::{checked_id, Body, Error, ParsedRequest, StatusCode};
use vmm::vmm_config::vtfs::VtfsDeviceConfig;

pub fn parse_put_vtfs(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    let vtfs = serde_json::from_slice::<VtfsDeviceConfig>(body.raw()).map_err(|e| {
        Error::SerdeJson(e)
    })?;
    if id != vtfs.drive_id.as_str() {
        return Err(Error::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::Sync(VmmAction::InsertVtfsDevice(vtfs)))
}

// impl IntoParsedRequest for VtfsDeviceConfig {
//     fn into_parsed_request(
//         self,
//         id_from_path: Option<String>,
//         _: Method,
//     ) -> result::Result<ParsedRequest, String> {
//         let id_from_path = id_from_path.unwrap_or_default();
//         if id_from_path != self.drive_id.as_str() {
//             return Err(String::from(
//                 "The id from the path does not match the id from the body!",
//             ));
//         }

//         let (sender, receiver) = oneshot::channel();
//         Ok(ParsedRequest::Sync(
//             VmmRequest::new(
//             VmmAction::InsertVtfsDevice(self), sender),
//             receiver,
//         ))
//     }
// }

#[cfg(test)]
mod tests {

}
