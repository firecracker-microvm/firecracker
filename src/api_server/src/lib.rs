// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! Implements the interface for intercepting API requests, forwarding them to the VMM
//! and responding to the user.
//! It is constructed on top of an HTTP Server that uses Unix Domain Sockets and `EPOLL` to
//! handle multiple connections on the same thread.
mod parsed_request;
mod request;

use std::convert::Infallible;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::mpsc;

use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use hyperlocal::UnixServerExt;
use logger::{error, info, update_metric_with_elapsed_time, ProcessTimeReporter, METRICS};
use seccompiler::BpfProgramRef;
use utils::eventfd::EventFd;
use vmm::rpc_interface::{VmmAction, VmmActionError, VmmData};
use vmm::vmm_config::snapshot::{CreateSnapshotParams, SnapshotType};

use crate::parsed_request::{ParsedRequest, RequestAction};

/// Shorthand type for a request containing a boxed VmmAction.
pub type ApiRequest = Box<VmmAction>;
/// Shorthand type for a response containing a boxed Result.
pub type ApiResponse = Box<std::result::Result<VmmData, VmmActionError>>;

async fn handle(req: Request<Body>) -> Result<Response<hyper::Body>, Infallible> {
    let request_processing_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

    let (head, body) = req.into_parts();
    let uri = head.uri;
    info!("uri: {uri}");
    let path = uri.path();
    let method = head.method;

    let bytes = hyper::body::to_bytes(body).await.unwrap();
    let body = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();

    // log_received_api_request -> describe
    match path {
        "/mmds" => info!("{method:?} request on {path:?}"),
        "/cpu-config" if !log::log_enabled!(log::Level::Debug) => info!(
            "{method:?} request on {path:?}. To view the CPU template received by the API, \
             configure log-level to DEBUG"
        ),
        // describe_with_body
        _ => info!("{method:?} request on {path:?} with body {body}"),
    }

    let mut tokens = path.split('/');
    let root = tokens.next().unwrap_or("");
    let res = match (method, root) {
        (Method::GET, "") => request::instance_info::parse_get_instance_info(),
        (Method::GET, "balloon") => request::balloon::parse_get_balloon(tokens.next()),
        (Method::GET, "version") => request::version::parse_get_version(),
        (Method::GET, "vm") if tokens.next() == Some("config") => {
            Ok(ParsedRequest::new_sync(VmmAction::GetFullVmConfig))
        }
        (Method::GET, "machine-config") => {
            request::machine_configuration::parse_get_machine_config()
        }
        (Method::GET, "mmds") => request::mmds::parse_get_mmds(),
        (Method::GET, _) => crate::parsed_request::method_to_error(Method::GET),
        (Method::PUT, "actions") => request::actions::parse_put_actions(body),
        (Method::PUT, "balloon") => request::balloon::parse_put_balloon(body),
        (Method::PUT, "boot-source") => request::boot_source::parse_put_boot_source(body),
        (Method::PUT, "cpu-config") => request::cpu_configuration::parse_put_cpu_config(body),
        (Method::PUT, "drives") => request::drive::parse_put_drive(body, tokens.next()),
        (Method::PUT, "logger") => request::logger::parse_put_logger(body),
        (Method::PUT, "machine-config") => {
            request::machine_configuration::parse_put_machine_config(body)
        }
        (Method::PUT, "metrics") => request::metrics::parse_put_metrics(body),
        (Method::PUT, "mmds") => request::mmds::parse_put_mmds(body, tokens.next()),
        (Method::PUT, "network-interfaces") => request::net::parse_put_net(body, tokens.next()),
        (Method::PUT, "shutdown-internal") => {
            Ok(ParsedRequest::new(RequestAction::ShutdownInternal))
        }
        (Method::PUT, "snapshot") => request::snapshot::parse_put_snapshot(body, tokens.next()),
        (Method::PUT, "vsock") => request::vsock::parse_put_vsock(body),
        (Method::PUT, "entropy") => request::entropy::parse_put_entropy(body),
        (Method::PUT, _) => crate::parsed_request::method_to_error(Method::PUT),
        (Method::PATCH, "balloon") => request::balloon::parse_patch_balloon(body, tokens.next()),
        (Method::PATCH, "drives") => request::drive::parse_patch_drive(body, tokens.next()),
        (Method::PATCH, "machine-config") => {
            request::machine_configuration::parse_patch_machine_config(body)
        }
        (Method::PATCH, "mmds") => request::mmds::parse_patch_mmds(body),
        (Method::PATCH, "network-interfaces") => request::net::parse_patch_net(body, tokens.next()),
        (Method::PATCH, "vm") => request::snapshot::parse_patch_vm_state(body),
        (Method::PATCH, _) => crate::parsed_request::method_to_error(Method::PATCH),
        (method, unknown) => Err(parsed_request::Error::InvalidPathMethod(
            String::from(unknown),
            method,
        )),
    };

    match res.map(|r| r.into_parts()) {
        Ok((req_action, _parsing_info)) => {
            // TODO Include deprecation message
            let response = match req_action {
                RequestAction::Sync(vmm_action) => {
                    let metric_action = match &*vmm_action {
                        VmmAction::CreateSnapshot(CreateSnapshotParams {
                            snapshot_type: SnapshotType::Full,
                            ..
                        }) => Some((
                            &METRICS.latencies_us.full_create_snapshot,
                            "create full snapshot",
                        )),
                        VmmAction::CreateSnapshot(CreateSnapshotParams {
                            snapshot_type: SnapshotType::Diff,
                            ..
                        }) => Some((
                            &METRICS.latencies_us.diff_create_snapshot,
                            "create diff snapshot",
                        )),
                        VmmAction::LoadSnapshot(_) => {
                            Some((&METRICS.latencies_us.load_snapshot, "load snapshot"))
                        }
                        VmmAction::Pause => Some((&METRICS.latencies_us.pause_vm, "pause vm")),
                        VmmAction::Resume => Some((&METRICS.latencies_us.resume_vm, "resume vm")),
                        _ => None,
                    };

                    DATA.lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .0
                        .send(vmm_action)
                        .expect("Failed to send VMM message");
                    DATA.lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .2
                        .write(1)
                        .expect("Cannot update send VMM fd");
                    let vmm_outcome: Result<VmmData, VmmActionError> = *(DATA
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .1
                        .recv()
                        .expect("VMM disconnected"));

                    if let Some((metric, action)) = metric_action {
                        let elapsed_time_us =
                            update_metric_with_elapsed_time(metric, request_processing_start_us);
                        info!("'{action}' API request took {elapsed_time_us} us.");
                    }

                    let response = match vmm_outcome {
                        Ok(ok) => match ok {
                            VmmData::Empty => {
                                info!(
                                    "The request was executed successfully. Status code: 204 No \
                                     Content."
                                );
                                Response::builder()
                                    .version(hyper::Version::HTTP_11)
                                    .status(StatusCode::NO_CONTENT)
                                    .body(hyper::Body::empty())
                            }
                            VmmData::MachineConfiguration(vm_config) => {
                                success_response_with_data(vm_config)
                            }
                            VmmData::MmdsValue(value) => {
                                info!(
                                    "The request was executed successfully. Status code: 200 OK."
                                );
                                Response::builder()
                                    .version(hyper::Version::HTTP_11)
                                    .status(StatusCode::OK)
                                    .body(Body::from(value.to_string()))
                            }
                            VmmData::BalloonConfig(balloon_config) => {
                                success_response_with_data(balloon_config)
                            }
                            VmmData::BalloonStats(stats) => success_response_with_data(stats),
                            VmmData::InstanceInformation(info) => success_response_with_data(info),
                            VmmData::VmmVersion(version) => success_response_with_data(
                                serde_json::json!({ "firecracker_version": version.as_str() }),
                            ),
                            VmmData::FullVmConfig(config) => success_response_with_data(config),
                        },
                        Err(err) => return Ok(Response::try_from(err).unwrap()),
                    }
                    .unwrap();

                    Ok(response)
                }
                RequestAction::ShutdownInternal => {
                    // DATA.lock().unwrap().unwrap().shutdown_flag = true;
                    Ok(Response::builder()
                        .version(hyper::Version::HTTP_11)
                        .status(hyper::StatusCode::NO_CONTENT)
                        .body(hyper::Body::empty())
                        .unwrap())
                }
            };
            response
        }
        Err(err) => {
            error!("{err:?}");
            Ok(Response::builder()
                .version(hyper::Version::HTTP_11)
                .status(hyper::StatusCode::NO_CONTENT)
                .body(hyper::Body::empty())
                .unwrap())
        }
    }
}

use std::sync::Mutex;

// TODO Pass the data to the service, avoiding this static.
#[allow(clippy::type_complexity)]
static DATA: Mutex<
    Option<(
        mpsc::Sender<ApiRequest>,
        mpsc::Receiver<ApiResponse>,
        EventFd,
    )>,
> = Mutex::new(None);

/// Error type for [`bind_and_run`].
#[derive(Debug, thiserror::Error)]
pub enum BindAndRunError {
    /// Failed to bind.
    #[error("Failed to bind {0}")]
    Bind(std::io::Error),
    /// Failed to serve.
    #[error("Failed to serve {0}")]
    Serve(hyper::Error),
    /// No one to signal that the socket path is ready!
    #[error("No one to signal that the socket path is ready!")]
    Socket(std::sync::mpsc::SendError<bool>),
    /// Failed to set the requested seccomp filters on the API thread.
    #[error("Failed to set the requested seccomp filters on the API thread: {0}")]
    Seccomp(seccompiler::InstallationError),
}

/// Starts the HTTP Server by binding to the socket path provided as
/// an argument.
pub async fn bind_and_run(
    api_request_sender: mpsc::Sender<ApiRequest>,
    vmm_response_receiver: mpsc::Receiver<ApiResponse>,
    to_vmm_fd: EventFd,
    path: &PathBuf,
    process_time_reporter: ProcessTimeReporter,
    seccomp_filter: BpfProgramRef<'_>,
    socket_ready: mpsc::Sender<bool>,
) -> Result<(), BindAndRunError> {
    *DATA.lock().unwrap() = Some((api_request_sender, vmm_response_receiver, to_vmm_fd));

    let make_service = make_service_fn(move |_| async { Ok::<_, Infallible>(service_fn(handle)) });

    Server::bind_unix(path)
        .map_err(BindAndRunError::Bind)?
        .serve(make_service)
        .await
        .map_err(BindAndRunError::Serve)?;

    // Announce main thread that the socket path was created.
    // As per the doc, "A send operation can only fail if the receiving end of a channel is
    // disconnected". so this means that the main thread has exited.
    socket_ready.send(true).map_err(BindAndRunError::Socket)?;

    // Store process start time metric.
    process_time_reporter.report_start_time();
    // Store process CPU start time metric.
    process_time_reporter.report_cpu_start_time();

    // Load seccomp filters on the API thread.
    // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
    // altogether is the desired behaviour.
    seccompiler::apply_filter(seccomp_filter).map_err(BindAndRunError::Seccomp)
}

/// Returns a response containing the given body serialized to JSON.
pub fn success_response_with_data<T: serde::Serialize + Debug>(
    body: T,
) -> Result<Response<hyper::Body>, http::Error> {
    info!("The request was executed successfully. Status code: 200 OK.");
    Response::builder()
        .version(hyper::Version::HTTP_11)
        .status(StatusCode::OK)
        .body(hyper::Body::from(serde_json::to_string(&body).unwrap()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::channel;

    use utils::tempfile::TempFile;
    use vmm::seccomp_filters::get_empty_filters;
    use vmm::vmm_config::instance_info::InstanceInfo;

    use super::*;
    use crate::request::cpu_configuration::parse_put_cpu_config;

    /// Test unescaped CPU template in JSON format.
    /// Newlines injected into a field's value to
    /// test deserialization and logging.
    #[cfg(target_arch = "x86_64")]
    const TEST_UNESCAPED_JSON_TEMPLATE: &str = r#"{
      "msr_modifiers": [
        {
          "addr": "0x0\n\n\n\nTEST\n\n\n\n",
          "bitmap": "0b00"
        }
      ]
    }"#;
    #[cfg(target_arch = "aarch64")]
    pub const TEST_UNESCAPED_JSON_TEMPLATE: &str = r#"{
      "reg_modifiers": [
        {
          "addr": "0x0\n\n\n\nTEST\n\n\n\n",
          "bitmap": "0b00"
        }
      ]
    }"#;

    #[test]
    fn test_handle_request_logging() {
        let value = serde_json::to_value(TEST_UNESCAPED_JSON_TEMPLATE).unwrap();
        let result = parse_put_cpu_config(value);
        assert!(result.is_err());
        let result_error = result.unwrap_err();
        let err_msg = format!("{}", result_error);
        assert_ne!(
            1,
            err_msg.lines().count(),
            "Error Body response:\n{}",
            err_msg
        );

        let err_msg_with_debug = format!("{:?}", result_error);
        // Check the loglines are on one line.
        assert_eq!(
            1,
            err_msg_with_debug.lines().count(),
            "Error Body response:\n{}",
            err_msg_with_debug
        );
    }

    #[test]
    fn test_bind_and_run() {
        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
        let api_thread_path_to_socket = path_to_socket.clone();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_empty_filters();
        let (socket_ready_sender, socket_ready_receiver) = channel();

        let _handle = tokio::task::spawn(async move {
            bind_and_run(
                api_request_sender,
                vmm_response_receiver,
                to_vmm_fd,
                &PathBuf::from(api_thread_path_to_socket),
                ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                seccomp_filters.get("api").unwrap(),
                socket_ready_sender,
            )
            .await
            .unwrap();
        });

        // Wait for the server to set itself up.
        socket_ready_receiver.recv().unwrap();
        to_api
            .send(Box::new(Ok(VmmData::InstanceInformation(
                InstanceInfo::default(),
            ))))
            .unwrap();
        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket)).unwrap();

        // Send a GET InstanceInfo request.
        assert!(sock.write_all(b"GET / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);

        // Send an erroneous request.
        assert!(sock.write_all(b"OPTIONS / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);
    }

    #[test]
    fn test_bind_and_run_with_limit() {
        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
        let api_thread_path_to_socket = path_to_socket.clone();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_empty_filters();
        let (socket_ready_sender, socket_ready_receiver) = channel();

        let _handle = tokio::task::spawn(async move {
            bind_and_run(
                api_request_sender,
                vmm_response_receiver,
                to_vmm_fd,
                &PathBuf::from(&api_thread_path_to_socket),
                ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                seccomp_filters.get("api").unwrap(),
                socket_ready_sender,
            )
            .await
            .unwrap();
        });

        // Wait for the server to set itself up.
        socket_ready_receiver.recv().unwrap();
        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket)).unwrap();

        // Send a GET mmds request.
        assert!(sock
            .write_all(
                b"PUT http://localhost/home HTTP/1.1\r\n\
                  Content-Length: 50000\r\n\r\naaaaaa"
            )
            .is_ok());
        let mut buf: [u8; 265] = [0; 265];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);
        let error_message = b"HTTP/1.1 400 \r\n\
                              Server: Firecracker API\r\n\
                              Connection: keep-alive\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 146\r\n\r\n{ \"error\": \"\
                              Request payload with size 50000 is larger than \
                              the limit of 50 allowed by server.\nAll previous \
                              unanswered requests will be dropped.\" }";
        assert_eq!(&buf[..], &error_message[..]);
    }
}
