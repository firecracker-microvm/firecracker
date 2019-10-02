// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use logger::{Metric, METRICS};
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use request::actions::ActionBody;
use request::drive::PatchDrivePayload;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::logger::LoggerConfig;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};
use vmm::{VmmAction, VmmData, VmmRequestOutcome};
use ApiServer;

#[allow(clippy::large_enum_variant)]
pub enum ParsedRequest {
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(VmmAction),
}

impl ParsedRequest {
    pub fn try_from_request(request: &Request) -> Result<ParsedRequest, Error> {
        let request_uri = request.uri().get_abs_path().to_string();
        match (
            request.method(),
            request_uri.as_str(),
            request.body.as_ref(),
        ) {
            (Method::Get, "/", None) => {
                log_received_api_request(describe(Method::Get, "/", None));
                METRICS.get_api_requests.instance_info_count.inc();
                Ok(ParsedRequest::GetInstanceInfo)
            }
            (Method::Get, "/machine-config", None) => {
                log_received_api_request(describe(Method::Get, "/machine-config", None));
                METRICS.get_api_requests.machine_cfg_count.inc();
                Ok(ParsedRequest::Sync(VmmAction::GetVmConfiguration))
            }
            (Method::Get, "/mmds", None) => {
                log_received_api_request(describe(Method::Get, "/mmds", None));
                Ok(ParsedRequest::GetMMDS)
            }
            (Method::Put, "/actions", Some(body)) => {
                log_received_api_request(describe(Method::Put, "/actions", Some(&body)));
                METRICS.put_api_requests.actions_count.inc();
                Ok(serde_json::from_slice::<ActionBody>(body.raw())
                    .map_err(|e| {
                        METRICS.put_api_requests.actions_fails.inc();
                        Error::SerdeJson(e)
                    })?
                    .into_parsed_request()
                    .map_err(|msg| {
                        METRICS.put_api_requests.actions_fails.inc();
                        Error::Generic(StatusCode::BadRequest, msg)
                    })?)
            }
            (Method::Put, "/boot-source", Some(body)) => {
                log_received_api_request(describe(Method::Put, "/boot-source", Some(&body)));
                METRICS.put_api_requests.boot_source_count.inc();
                Ok(ParsedRequest::Sync(VmmAction::ConfigureBootSource(
                    serde_json::from_slice::<BootSourceConfig>(body.raw()).map_err(|e| {
                        METRICS.put_api_requests.boot_source_fails.inc();
                        Error::SerdeJson(e)
                    })?,
                )))
            }
            (Method::Put, "/machine-config", maybe_body) => {
                log_received_api_request(describe(Method::Put, "/machine-config", maybe_body));
                METRICS.put_api_requests.machine_cfg_count.inc();
                match maybe_body {
                    Some(body) => {
                        let vm_config =
                            serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
                                METRICS.put_api_requests.machine_cfg_fails.inc();
                                Error::SerdeJson(e)
                            })?;
                        if vm_config.vcpu_count.is_none()
                            || vm_config.mem_size_mib.is_none()
                            || vm_config.ht_enabled.is_none()
                        {
                            return Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Missing mandatory fields.".to_string(),
                            ));
                        }
                        Ok(ParsedRequest::Sync(VmmAction::SetVmConfiguration(
                            vm_config,
                        )))
                    }
                    None => Err(Error::Generic(
                        StatusCode::BadRequest,
                        "Missing mandatory fields.".to_string(),
                    )),
                }
            }
            (Method::Put, "/logger", Some(body)) => {
                log_received_api_request(describe(Method::Put, "/logger", Some(&body)));
                METRICS.put_api_requests.logger_count.inc();
                Ok(ParsedRequest::Sync(VmmAction::ConfigureLogger(
                    serde_json::from_slice::<LoggerConfig>(body.raw()).map_err(|e| {
                        METRICS.put_api_requests.logger_fails.inc();
                        Error::SerdeJson(e)
                    })?,
                )))
            }
            (Method::Put, "/vsock", Some(body)) => {
                log_received_api_request(describe(Method::Put, "/vsock", Some(&body)));
                Ok(ParsedRequest::Sync(VmmAction::SetVsockDevice(
                    serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
                )))
            }
            (Method::Put, "/mmds", Some(body)) => {
                log_received_api_request(describe(Method::Put, "/mmds", None));
                Ok(ParsedRequest::PutMMDS(
                    serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
                ))
            }
            (Method::Put, uri, maybe_body) => {
                log_received_api_request(describe(Method::Put, uri, maybe_body));
                let path_tokens: Vec<&str> = uri[1..].split_terminator('/').collect();
                match path_tokens[0] {
                    "drives" => {
                        METRICS.put_api_requests.drive_count.inc();
                        let id_from_path = if path_tokens.len() > 1 {
                            checked_id(path_tokens[1])?
                        } else {
                            return Err(Error::EmptyID);
                        };

                        if path_tokens.len() != 2 {
                            return Err(Error::InvalidPathMethod(uri.to_string(), Method::Put));
                        }

                        if let Some(body) = maybe_body {
                            let device_cfg = serde_json::from_slice::<BlockDeviceConfig>(
                                body.raw(),
                            )
                            .map_err(|e| {
                                METRICS.put_api_requests.drive_fails.inc();
                                Error::SerdeJson(e)
                            })?;

                            if id_from_path != device_cfg.drive_id {
                                METRICS.put_api_requests.drive_fails.inc();
                                Err(Error::Generic(
                                    StatusCode::BadRequest,
                                    "The id from the path does not match the id from the body!"
                                        .to_string(),
                                ))
                            } else {
                                Ok(ParsedRequest::Sync(VmmAction::InsertBlockDevice(
                                    device_cfg,
                                )))
                            }
                        } else {
                            Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Empty PUT request.".to_string(),
                            ))
                        }
                    }
                    "network-interfaces" => {
                        METRICS.put_api_requests.network_count.inc();
                        let id_from_path = if path_tokens.len() > 1 {
                            checked_id(path_tokens[1])?
                        } else {
                            return Err(Error::EmptyID);
                        };

                        if path_tokens.len() != 2 {
                            return Err(Error::InvalidPathMethod(uri.to_string(), Method::Put));
                        }

                        if let Some(body) = maybe_body {
                            let netif =
                                serde_json::from_slice::<NetworkInterfaceConfig>(body.raw())
                                    .map_err(|e| {
                                        METRICS.put_api_requests.network_fails.inc();
                                        Error::SerdeJson(e)
                                    })?;
                            if id_from_path != netif.iface_id {
                                return Err(Error::Generic(
                                    StatusCode::BadRequest,
                                    "The id from the path does not match the id from the body!"
                                        .to_string(),
                                ));
                            }
                            Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(netif)))
                        } else {
                            Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Empty PUT request.".to_string(),
                            ))
                        }
                    }
                    unknown_str => Err(Error::InvalidPathMethod(
                        unknown_str.to_string(),
                        Method::Put,
                    )),
                }
            }
            (Method::Patch, "/machine-config", maybe_body) => {
                log_received_api_request(describe(Method::Patch, "/machine-config", maybe_body));
                METRICS.patch_api_requests.machine_cfg_count.inc();
                match maybe_body {
                    Some(body) => {
                        let vm_config =
                            serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
                                METRICS.patch_api_requests.machine_cfg_fails.inc();
                                Error::SerdeJson(e)
                            })?;
                        if vm_config.vcpu_count.is_none()
                            && vm_config.mem_size_mib.is_none()
                            && vm_config.cpu_template.is_none()
                            && vm_config.ht_enabled.is_none()
                        {
                            return Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Empty PATCH request.".to_string(),
                            ));
                        }
                        Ok(ParsedRequest::Sync(VmmAction::SetVmConfiguration(
                            vm_config,
                        )))
                    }
                    None => Err(Error::Generic(
                        StatusCode::BadRequest,
                        "Empty PATCH request.".to_string(),
                    )),
                }
            }
            (Method::Patch, "/mmds", Some(body)) => {
                log_received_api_request(describe(Method::Patch, "/mmds", None));
                Ok(ParsedRequest::PatchMMDS(
                    serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
                ))
            }
            (Method::Patch, uri, maybe_body) => {
                log_received_api_request(describe(Method::Patch, uri, maybe_body));
                let path_tokens: Vec<&str> = uri[1..].split_terminator('/').collect();
                match path_tokens[0] {
                    "drives" => {
                        METRICS.patch_api_requests.drive_count.inc();
                        let id_from_path = if path_tokens.len() > 1 {
                            checked_id(path_tokens[1])?
                        } else {
                            return Err(Error::EmptyID);
                        };

                        if path_tokens.len() != 2 {
                            return Err(Error::InvalidPathMethod(uri.to_string(), Method::Patch));
                        }

                        if let Some(body) = maybe_body {
                            METRICS.patch_api_requests.drive_count.inc();

                            Ok(PatchDrivePayload {
                                fields: serde_json::from_slice(body.raw()).map_err(|e| {
                                    METRICS.patch_api_requests.drive_fails.inc();
                                    Error::SerdeJson(e)
                                })?,
                            }
                            .into_parsed_request(id_from_path.to_string())
                            .map_err(|s| {
                                METRICS.patch_api_requests.drive_fails.inc();
                                Error::Generic(StatusCode::BadRequest, s)
                            })?)
                        } else {
                            Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Empty PUT request.".to_string(),
                            ))
                        }
                    }
                    "network-interfaces" => {
                        METRICS.patch_api_requests.network_count.inc();
                        let id_from_path = if path_tokens.len() > 1 {
                            checked_id(path_tokens[1])?
                        } else {
                            return Err(Error::EmptyID);
                        };

                        if path_tokens.len() != 2 {
                            return Err(Error::InvalidPathMethod(uri.to_string(), Method::Patch));
                        }

                        if let Some(body) = maybe_body {
                            let netif =
                                serde_json::from_slice::<NetworkInterfaceUpdateConfig>(body.raw())
                                    .map_err(|e| {
                                        METRICS.patch_api_requests.network_fails.inc();
                                        Error::SerdeJson(e)
                                    })?;
                            if id_from_path != netif.iface_id {
                                return Err(Error::Generic(
                                    StatusCode::BadRequest,
                                    "The id from the path does not match the id from the body!"
                                        .to_string(),
                                ));
                            }
                            Ok(ParsedRequest::Sync(VmmAction::UpdateNetworkInterface(
                                netif,
                            )))
                        } else {
                            Err(Error::Generic(
                                StatusCode::BadRequest,
                                "Empty PATCH request.".to_string(),
                            ))
                        }
                    }
                    unknown_str => Err(Error::InvalidPathMethod(
                        unknown_str.to_string(),
                        Method::Patch,
                    )),
                }
            }
            (method, unknown_uri, maybe_body) => {
                log_received_api_request(describe(method, unknown_uri, maybe_body));
                Err(Error::InvalidPathMethod(unknown_uri.to_string(), method))
            }
        }
    }

    pub fn convert_to_response(request_outcome: VmmRequestOutcome) -> Response {
        match request_outcome {
            Ok(vmm_data) => match vmm_data {
                VmmData::Empty => Response::new(Version::Http11, StatusCode::NoContent),
                VmmData::MachineConfiguration(vm_config) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    response.set_body(Body::new(vm_config.to_string()));
                    response
                }
            },
            Err(vmm_action_error) => {
                let mut response = Response::new(Version::Http11, StatusCode::BadRequest);
                response.set_body(Body::new(vmm_action_error.to_string()));
                response
            }
        }
    }
}

/// Helper function for writing the received API requests to the log.
///
/// The `info` macro is used for logging.
#[inline]
fn log_received_api_request(api_description: String) {
    info!("The API server received a {}.", api_description);
}

/// Helper function for metric-logging purposes on API requests.
///
/// # Arguments
///
/// * `method` - one of `GET`, `PATCH`, `PUT`
/// * `path` - path of the API request
/// * `body` - body of the API request
///
fn describe(method: Method, path: &str, body: Option<&Body>) -> String {
    match body {
        Some(value) => format!(
            "synchronous {:?} request on {:?} with body {:?}",
            method,
            path,
            std::str::from_utf8(value.body.as_slice())
                .unwrap_or("inconvertible to UTF-8")
                .to_string()
        ),
        None => format!("synchronous {:?} request on {:?}", method, path),
    }
}

pub enum Error {
    // A generic error, with a given status code and message to be turned into a fault message.
    Generic(StatusCode, String),
    // The resource ID is empty.
    EmptyID,
    // The resource ID must only contain alphanumeric characters and '_'.
    InvalidID,
    // The HTTP method & request path combination is not valid.
    InvalidPathMethod(String, Method),
    // An error occurred when deserializing the json body of a request.
    SerdeJson(serde_json::Error),
}

// It's convenient to turn errors into HTTP responses directly.
impl Into<Response> for Error {
    fn into(self) -> Response {
        match self {
            Error::Generic(status, msg) => {
                ApiServer::json_response(status, ApiServer::json_fault_message(msg))
            }
            Error::EmptyID => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message("The ID cannot be empty."),
            ),
            Error::InvalidID => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(
                    "API Resource IDs can only contain alphanumeric characters and underscores.",
                ),
            ),
            Error::InvalidPathMethod(path, method) => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(format!(
                    "Invalid request method and/or path: {} {}",
                    std::str::from_utf8(method.raw()).unwrap(),
                    path
                )),
            ),
            Error::SerdeJson(e) => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(e.to_string()),
            ),
        }
    }
}

// This function is supposed to do id validation for requests.
fn checked_id(id: &str) -> Result<&str, Error> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    // check: ensure string is not empty
    if id.is_empty() {
        return Err(Error::EmptyID);
    }
    // check: ensure string is alphanumeric
    if !id.chars().all(|c| c == '_' || c.is_alphanumeric()) {
        return Err(Error::InvalidID);
    }
    Ok(id)
}
