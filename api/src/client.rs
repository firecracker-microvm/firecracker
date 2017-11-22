#![allow(unused_extern_crates)]
extern crate hyper_openssl;
extern crate chrono;



use hyper;
use hyper::client::IntoUrl;
use hyper::mime;
use hyper::header::{Headers, ContentType};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::Url;
use self::hyper_openssl::openssl;
use futures;
use futures::{Future, Stream};
use futures::{future, stream};
use std::borrow::Cow;
use std::io::{Read, Error};
use std::error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::str;

use mimetypes;

use serde_json;


#[allow(unused_imports)]
use std::collections::{HashMap, BTreeMap};
#[allow(unused_imports)]
use swagger;

use swagger::{Context, ApiError, XSpanId};

use {Api,
     ApplyLimiterToDriveResponse,
     ApplyLimiterToNetworkInterfaceResponse,
     ApplyLimiterToVsockResponse,
     CreateInstanceActionResponse,
     DeleteGuestDriveByIDResponse,
     DeleteGuestNetworkInterfaceByIDResponse,
     DeleteGuestVsockByIDResponse,
     DeleteLimiterResponse,
     DescribeInstanceResponse,
     DescribeInstanceActionResponse,
     DescribeLimiterResponse,
     GetGuestBootSourceResponse,
     GetGuestDriveByIDResponse,
     GetGuestDrivesResponse,
     GetGuestNetworkInterfaceByIDResponse,
     GetGuestNetworkInterfacesResponse,
     GetGuestVsockByIDResponse,
     GetGuestVsocksResponse,
     GetLimitersForGuestDriveResponse,
     GetLimitersForGuestNetworkInterfaceResponse,
     GetLimitersForGuestVsockResponse,
     GetMetadataResponse,
     ListInstanceActionsResponse,
     ListLimitersResponse,
     PutGuestBootSourceResponse,
     PutGuestDriveByIDResponse,
     PutGuestNetworkInterfaceByIDResponse,
     PutGuestVsockByIDResponse,
     UpdateLimiterResponse
     };
use models;

/// Convert input into a base path, e.g. "http://example:123". Also checks the scheme as it goes.
fn into_base_path<T: IntoUrl>(input: T, correct_scheme: Option<&'static str>) -> Result<String, ClientInitError> {
    // First convert to Url, since a base path is a subset of Url.
    let url = input.into_url()?;

    let scheme = url.scheme();

    // Check the scheme if necessary
    if let Some(correct_scheme) = correct_scheme {
        if scheme != correct_scheme {
            return Err(ClientInitError::InvalidScheme);
        }
    }

    let host = url.host().ok_or_else(|| ClientInitError::MissingHost)?;
    let port = url.port().map(|x| format!(":{}", x)).unwrap_or_default();
    Ok(format!("{}://{}{}", scheme, host, port))
}

/// A client that implements the API by making HTTP calls out to a server.
#[derive(Clone)]
pub struct Client {
    base_path: String,
    hyper_client: Arc<Fn() -> hyper::client::Client + Sync + Send>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client {{ base_path: {} }}", self.base_path)
    }
}

impl Client {
    pub fn try_new_http<T>(base_path: T) -> Result<Client, ClientInitError>
        where T: IntoUrl
    {
        Ok(Client {
            base_path: into_base_path(base_path, Some("http"))?,
            hyper_client: Arc::new(hyper::client::Client::new),
        })
    }

    pub fn try_new_https<T, CA>(base_path: T,
                                ca_certificate: CA)
                            -> Result<Client, ClientInitError>
        where T: IntoUrl,
              CA: AsRef<Path>
    {
        let ca_certificate = ca_certificate.as_ref().to_owned();

        let https_hyper_client = move || {
            // SSL implementation
            let mut ssl = openssl::ssl::SslConnectorBuilder::new(openssl::ssl::SslMethod::tls()).unwrap();

            // Server authentication
            ssl.builder_mut().set_ca_file(ca_certificate.clone()).unwrap();

            let ssl = hyper_openssl::OpensslClient::from(ssl.build());
            let connector = hyper::net::HttpsConnector::new(ssl);
            hyper::client::Client::with_connector(connector)
        };

        Ok(Client {
                base_path: into_base_path(base_path, Some("https"))?,
                hyper_client: Arc::new(https_hyper_client),
            })
    }

    pub fn try_new_https_mutual<T, CA, K, C>(base_path: T,
                                             ca_certificate: CA,
                                             client_key: K,
                                             client_certificate: C)
                                             -> Result<Client, ClientInitError>
        where T: IntoUrl,
              CA: AsRef<Path>,
              K: AsRef<Path>,
              C: AsRef<Path>
    {
        let ca_certificate = ca_certificate.as_ref().to_owned();
        let client_key = client_key.as_ref().to_owned();
        let client_certificate = client_certificate.as_ref().to_owned();

        let https_mutual_hyper_client = move || {
            // SSL implementation
            let mut ssl = openssl::ssl::SslConnectorBuilder::new(openssl::ssl::SslMethod::tls()).unwrap();

            // Server authentication
            ssl.builder_mut().set_ca_file(ca_certificate.clone()).unwrap();

            // Client authentication
            ssl.builder_mut().set_private_key_file(client_key.clone(), openssl::x509::X509_FILETYPE_PEM).unwrap();
            ssl.builder_mut().set_certificate_chain_file(client_certificate.clone()).unwrap();
            ssl.builder_mut().check_private_key().unwrap();

            let ssl = hyper_openssl::OpensslClient::from(ssl.build());
            let connector = hyper::net::HttpsConnector::new(ssl);
            hyper::client::Client::with_connector(connector)
        };

        Ok(Client {
                base_path: into_base_path(base_path, Some("https"))?,
                hyper_client: Arc::new(https_mutual_hyper_client)
            })
    }

    /// Constructor for creating a `Client` by passing in a pre-made `hyper` client.
    ///
    /// One should avoid relying on this function if possible, since it adds a dependency on the underlying transport
    /// implementation, which it would be better to abstract away. Therefore, using this function may lead to a loss of
    /// code generality, which may make it harder to move the application to a serverless environment, for example.
    ///
    /// The reason for this function's existence is to support legacy test code, which did mocking at the hyper layer.
    /// This is not a recommended way to write new tests. If other reasons are found for using this function, they
    /// should be mentioned here.
    pub fn try_new_with_hyper_client<T>(base_path: T,
                                    hyper_client: Arc<Fn() -> hyper::client::Client + Sync + Send>)
                                    -> Result<Client, ClientInitError>
        where T: IntoUrl
    {
        Ok(Client {
            base_path: into_base_path(base_path, None)?,
            hyper_client: hyper_client
        })
    }
}

impl Api for Client {

    fn apply_limiter_to_drive(&self, param_drive_id: String, param_limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToDriveResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives/{drive_id}/limiters/{limiter_id}?", self.base_path, drive_id=param_drive_id.to_string(), limiter_id=param_limiter_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<ApplyLimiterToDriveResponse, ApiError> {
            match response.status.to_u16() {
                200 => {


                    Ok(ApplyLimiterToDriveResponse::LimiterApplied)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToDriveResponse::LimiterCannotBeAppliedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToDriveResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn apply_limiter_to_network_interface(&self, param_iface_id: String, param_limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToNetworkInterfaceResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces/{iface_id}/limiters/{limiter_id}?", self.base_path, iface_id=param_iface_id.to_string(), limiter_id=param_limiter_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<ApplyLimiterToNetworkInterfaceResponse, ApiError> {
            match response.status.to_u16() {
                200 => {


                    Ok(ApplyLimiterToNetworkInterfaceResponse::LimiterApplied)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToNetworkInterfaceResponse::LimiterCannotBeAppliedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToNetworkInterfaceResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn apply_limiter_to_vsock(&self, param_vsock_id: String, param_limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToVsockResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks/{vsock_id}/limiters/{limiter_id}?", self.base_path, vsock_id=param_vsock_id.to_string(), limiter_id=param_limiter_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<ApplyLimiterToVsockResponse, ApiError> {
            match response.status.to_u16() {
                200 => {


                    Ok(ApplyLimiterToVsockResponse::LimiterApplied)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToVsockResponse::LimiterCannotBeAppliedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ApplyLimiterToVsockResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn create_instance_action(&self, param_action_id: String, param_info: models::InstanceActionInfo, context: &Context) -> Box<Future<Item=CreateInstanceActionResponse, Error=ApiError> + Send> {


        let url = format!("{}//action/{action_id}?", self.base_path, action_id=param_action_id.to_string());


        let body = serde_json::to_string(&param_info).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::CREATE_INSTANCE_ACTION.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<CreateInstanceActionResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(CreateInstanceActionResponse::NoPreviousActionExistedSoANewOneWasCreated)
                },
                204 => {


                    Ok(CreateInstanceActionResponse::ActionUpdated)
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(CreateInstanceActionResponse::UnexpectedError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn delete_guest_drive_by_id(&self, param_drive_id: String, context: &Context) -> Box<Future<Item=DeleteGuestDriveByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives/{drive_id}?", self.base_path, drive_id=param_drive_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Delete, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DeleteGuestDriveByIDResponse, ApiError> {
            match response.status.to_u16() {
                202 => {


                    Ok(DeleteGuestDriveByIDResponse::DriveDeleted)
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DeleteGuestDriveByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn delete_guest_network_interface_by_id(&self, param_iface_id: String, context: &Context) -> Box<Future<Item=DeleteGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces/{iface_id}?", self.base_path, iface_id=param_iface_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Delete, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DeleteGuestNetworkInterfaceByIDResponse, ApiError> {
            match response.status.to_u16() {
                202 => {


                    Ok(DeleteGuestNetworkInterfaceByIDResponse::NetworkInterfaceDeleted)
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DeleteGuestNetworkInterfaceByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn delete_guest_vsock_by_id(&self, param_vsock_id: String, context: &Context) -> Box<Future<Item=DeleteGuestVsockByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks/{vsock_id}?", self.base_path, vsock_id=param_vsock_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Delete, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DeleteGuestVsockByIDResponse, ApiError> {
            match response.status.to_u16() {
                202 => {


                    Ok(DeleteGuestVsockByIDResponse::VsockDeleted)
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DeleteGuestVsockByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn delete_limiter(&self, param_limiter_id: String, context: &Context) -> Box<Future<Item=DeleteLimiterResponse, Error=ApiError> + Send> {


        let url = format!("{}//limiters/{limiter_id}?", self.base_path, limiter_id=param_limiter_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Delete, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DeleteLimiterResponse, ApiError> {
            match response.status.to_u16() {
                202 => {


                    Ok(DeleteLimiterResponse::LimiterDeleted)
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DeleteLimiterResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn describe_instance(&self, context: &Context) -> Box<Future<Item=DescribeInstanceResponse, Error=ApiError> + Send> {


        let url = format!("{}//?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DescribeInstanceResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::InstanceInfo>(&buf)?;



                    Ok(DescribeInstanceResponse::TheInstanceInformation(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DescribeInstanceResponse::UnexpectedError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn describe_instance_action(&self, param_action_id: String, context: &Context) -> Box<Future<Item=DescribeInstanceActionResponse, Error=ApiError> + Send> {


        let url = format!("{}//action/{action_id}?", self.base_path, action_id=param_action_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DescribeInstanceActionResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::InstanceActionInfo>(&buf)?;



                    Ok(DescribeInstanceActionResponse::TheInstanceActionInformation(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DescribeInstanceActionResponse::UnexpectedError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn describe_limiter(&self, param_limiter_id: String, context: &Context) -> Box<Future<Item=DescribeLimiterResponse, Error=ApiError> + Send> {


        let url = format!("{}//limiters/{limiter_id}?", self.base_path, limiter_id=param_limiter_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<DescribeLimiterResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Limiter>(&buf)?;



                    Ok(DescribeLimiterResponse::SpecifiedLimiter(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DescribeLimiterResponse::LimiterDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(DescribeLimiterResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_boot_source(&self, context: &Context) -> Box<Future<Item=GetGuestBootSourceResponse, Error=ApiError> + Send> {


        let url = format!("{}//boot/source?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestBootSourceResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::BootSource>(&buf)?;



                    Ok(GetGuestBootSourceResponse::SpecifiedBootSource(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestBootSourceResponse::BootSourceDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestBootSourceResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_drive_by_id(&self, param_drive_id: String, context: &Context) -> Box<Future<Item=GetGuestDriveByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives/{drive_id}?", self.base_path, drive_id=param_drive_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestDriveByIDResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Drive>(&buf)?;



                    Ok(GetGuestDriveByIDResponse::SpecifiedDrive(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestDriveByIDResponse::DriveDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestDriveByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_drives(&self, context: &Context) -> Box<Future<Item=GetGuestDrivesResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestDrivesResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<models::Drive>>(&buf)?;



                    Ok(GetGuestDrivesResponse::ListOfGuestDrives(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestDrivesResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_network_interface_by_id(&self, param_iface_id: String, context: &Context) -> Box<Future<Item=GetGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces/{iface_id}?", self.base_path, iface_id=param_iface_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestNetworkInterfaceByIDResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::NetworkInterface>(&buf)?;



                    Ok(GetGuestNetworkInterfaceByIDResponse::SpecifiedNetworkInterface(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestNetworkInterfaceByIDResponse::NetworkInterfaceDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestNetworkInterfaceByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_network_interfaces(&self, context: &Context) -> Box<Future<Item=GetGuestNetworkInterfacesResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestNetworkInterfacesResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<models::NetworkInterface>>(&buf)?;



                    Ok(GetGuestNetworkInterfacesResponse::ListOfGuestNetworkInterfaces(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestNetworkInterfacesResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_vsock_by_id(&self, param_vsock_id: String, context: &Context) -> Box<Future<Item=GetGuestVsockByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks/{vsock_id}?", self.base_path, vsock_id=param_vsock_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestVsockByIDResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Vsock>(&buf)?;



                    Ok(GetGuestVsockByIDResponse::SpecifiedVsock(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestVsockByIDResponse::VsockDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestVsockByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_guest_vsocks(&self, context: &Context) -> Box<Future<Item=GetGuestVsocksResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetGuestVsocksResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<models::Vsock>>(&buf)?;



                    Ok(GetGuestVsocksResponse::ListOfGuestVsocks(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetGuestVsocksResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_limiters_for_guest_drive(&self, param_drive_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestDriveResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives/{drive_id}/limiters?", self.base_path, drive_id=param_drive_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetLimitersForGuestDriveResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<i32>>(&buf)?;



                    Ok(GetLimitersForGuestDriveResponse::ListOfLimitersIDsCurrentlyAppliedToThisDrive(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestDriveResponse::DriveDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestDriveResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_limiters_for_guest_network_interface(&self, param_iface_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestNetworkInterfaceResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces/{iface_id}/limiters?", self.base_path, iface_id=param_iface_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetLimitersForGuestNetworkInterfaceResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<i32>>(&buf)?;



                    Ok(GetLimitersForGuestNetworkInterfaceResponse::ListOfLimitersIDsCurrentlyAppliedToThisNetworkInterface(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestNetworkInterfaceResponse::NetworkInterfaceDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestNetworkInterfaceResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_limiters_for_guest_vsock(&self, param_vsock_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestVsockResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks/{vsock_id}/limiters?", self.base_path, vsock_id=param_vsock_id.to_string());


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetLimitersForGuestVsockResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<i32>>(&buf)?;



                    Ok(GetLimitersForGuestVsockResponse::ListOfLimitersIDsCurrentlyAppliedToThisVsock(body))
                },
                404 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestVsockResponse::VsockDoesNotExist(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetLimitersForGuestVsockResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn get_metadata(&self, context: &Context) -> Box<Future<Item=GetMetadataResponse, Error=ApiError> + Send> {


        let url = format!("{}//metadata?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<GetMetadataResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::InstanceMetadata>(&buf)?;



                    Ok(GetMetadataResponse::TheInstanceMetadata(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(GetMetadataResponse::UnexpectedError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn list_instance_actions(&self, context: &Context) -> Box<Future<Item=ListInstanceActionsResponse, Error=ApiError> + Send> {


        let url = format!("{}//actions?", self.base_path);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<ListInstanceActionsResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<Vec<String>>(&buf)?;



                    Ok(ListInstanceActionsResponse::The_(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ListInstanceActionsResponse::UnexpectedError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn list_limiters(&self, param_next_token: Option<String>, context: &Context) -> Box<Future<Item=ListLimitersResponse, Error=ApiError> + Send> {

        // Query parameters
        let query_next_token = param_next_token.map_or_else(String::new, |query| format!("next_token={next_token}&", next_token=query.to_string()));


        let url = format!("{}//limiters?{next_token}", self.base_path, next_token=query_next_token);


        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Get, &url);
        let mut custom_headers = hyper::header::Headers::new();

        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<ListLimitersResponse, ApiError> {
            match response.status.to_u16() {
                200 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::LimiterList>(&buf)?;



                    Ok(ListLimitersResponse::ListOfLimiters(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(ListLimitersResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn put_guest_boot_source(&self, param_body: models::BootSource, context: &Context) -> Box<Future<Item=PutGuestBootSourceResponse, Error=ApiError> + Send> {


        let url = format!("{}//boot/source?", self.base_path);


        let body = serde_json::to_string(&param_body).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::PUT_GUEST_BOOT_SOURCE.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<PutGuestBootSourceResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(PutGuestBootSourceResponse::BootSourceCreated)
                },
                204 => {


                    Ok(PutGuestBootSourceResponse::BootSourceUpdated)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestBootSourceResponse::BootSourceCannotBeCreatedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestBootSourceResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn put_guest_drive_by_id(&self, param_drive_id: String, param_body: models::Drive, context: &Context) -> Box<Future<Item=PutGuestDriveByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//drives/{drive_id}?", self.base_path, drive_id=param_drive_id.to_string());


        let body = serde_json::to_string(&param_body).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::PUT_GUEST_DRIVE_BY_ID.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<PutGuestDriveByIDResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(PutGuestDriveByIDResponse::DriveCreated)
                },
                204 => {


                    Ok(PutGuestDriveByIDResponse::DriveUpdated)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestDriveByIDResponse::DriveCannotBeCreatedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestDriveByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn put_guest_network_interface_by_id(&self, param_iface_id: String, param_body: models::NetworkInterface, context: &Context) -> Box<Future<Item=PutGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//network-interfaces/{iface_id}?", self.base_path, iface_id=param_iface_id.to_string());


        let body = serde_json::to_string(&param_body).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::PUT_GUEST_NETWORK_INTERFACE_BY_ID.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<PutGuestNetworkInterfaceByIDResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceCreated)
                },
                204 => {


                    Ok(PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceUpdated)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceCannotBeCreatedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestNetworkInterfaceByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn put_guest_vsock_by_id(&self, param_vsock_id: String, param_body: models::Vsock, context: &Context) -> Box<Future<Item=PutGuestVsockByIDResponse, Error=ApiError> + Send> {


        let url = format!("{}//vsocks/{vsock_id}?", self.base_path, vsock_id=param_vsock_id.to_string());


        let body = serde_json::to_string(&param_body).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::PUT_GUEST_VSOCK_BY_ID.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<PutGuestVsockByIDResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(PutGuestVsockByIDResponse::VsockCreated)
                },
                204 => {


                    Ok(PutGuestVsockByIDResponse::VsockUpdated)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestVsockByIDResponse::VsockCannotBeCreatedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(PutGuestVsockByIDResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

    fn update_limiter(&self, param_limiter_id: String, param_limiter: models::Limiter, context: &Context) -> Box<Future<Item=UpdateLimiterResponse, Error=ApiError> + Send> {


        let url = format!("{}//limiters/{limiter_id}?", self.base_path, limiter_id=param_limiter_id.to_string());


        let body = serde_json::to_string(&param_limiter).expect("impossible to fail to serialize");

        let hyper_client = (self.hyper_client)();
        let request = hyper_client.request(hyper::method::Method::Put, &url);
        let mut custom_headers = hyper::header::Headers::new();

        let request = request.body(&body);

        custom_headers.set(ContentType(mimetypes::requests::UPDATE_LIMITER.clone()));
        context.x_span_id.as_ref().map(|header| custom_headers.set(XSpanId(header.clone())));


        let request = request.headers(custom_headers);

        // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
        fn parse_response(mut response: hyper::client::response::Response) -> Result<UpdateLimiterResponse, ApiError> {
            match response.status.to_u16() {
                201 => {


                    Ok(UpdateLimiterResponse::LimiterCreated)
                },
                204 => {


                    Ok(UpdateLimiterResponse::LimiterUpdated)
                },
                400 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(UpdateLimiterResponse::LimiterCannotBeCreatedDueToBadInput(body))
                },
                0 => {
                    let mut buf = String::new();
                    response.read_to_string(&mut buf).map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                    let body = serde_json::from_str::<models::Error>(&buf)?;



                    Ok(UpdateLimiterResponse::InternalServerError(body))
                },
                code => {
                    let mut buf = [0; 100];
                    let debug_body = match response.read(&mut buf) {
                        Ok(len) => match str::from_utf8(&buf[..len]) {
                            Ok(body) => Cow::from(body),
                            Err(_) => Cow::from(format!("<Body was not UTF8: {:?}>", &buf[..len].to_vec())),
                        },
                        Err(e) => Cow::from(format!("<Failed to read body: {}>", e)),
                    };
                    Err(ApiError(format!("Unexpected response code {}:\n{:?}\n\n{}",
                                         code,
                                         response.headers,
                                         debug_body)))
                }
            }
        }

        let result = request.send().map_err(|e| ApiError(format!("No response received: {}", e))).and_then(parse_response);
        Box::new(futures::done(result))
    }

}

#[derive(Debug)]
pub enum ClientInitError {
    InvalidScheme,
    InvalidUrl(hyper::error::ParseError),
    MissingHost,
    SslError(openssl::error::ErrorStack)
}

impl From<hyper::error::ParseError> for ClientInitError {
    fn from(err: hyper::error::ParseError) -> ClientInitError {
        ClientInitError::InvalidUrl(err)
    }
}

impl From<openssl::error::ErrorStack> for ClientInitError {
    fn from(err: openssl::error::ErrorStack) -> ClientInitError {
        ClientInitError::SslError(err)
    }
}

impl fmt::Display for ClientInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Debug).fmt(f)
    }
}

impl error::Error for ClientInitError {
    fn description(&self) -> &str {
        "Failed to produce a hyper client."
    }
}
