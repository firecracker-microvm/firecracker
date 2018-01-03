/// SWAGGER codegen auto generated file
///
/// Do NOT manually modify!
///

extern crate serde_ignored;
extern crate iron;
extern crate router;
extern crate bodyparser;
extern crate urlencoded;
extern crate uuid;


use futures::Future;
use hyper::header::ContentType;
use self::iron::prelude::*;
use self::iron::status;
use self::iron::url::percent_encoding::percent_decode;
use self::router::Router;
use self::urlencoded::UrlEncodedQuery;
use mimetypes;


use serde_json;

use swagger::auth::{Authorization, AuthData};
use swagger::{Context, XSpanId};

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

header! { (Warning, "Warning") => [String] }

/// Create a new router for `Api`
pub fn router<T>(api: T) -> Router where T: Api + Send + Sync + Clone + 'static {
    let mut router = Router::new();
    add_routes(&mut router, api);
    router
}

/// Add routes for `Api` to a provided router.
///
/// Note that these routes are added straight onto the router. This means that if the router
/// already has a route for an endpoint which clashes with those provided by this API, then the
/// old route will be lost.
///
/// It is generally a bad idea to add routes in this way to an existing router, which may have
/// routes on it for other APIs. Distinct APIs should be behind distinct paths to encourage
/// separation of interfaces, which this function does not enforce. APIs should not overlap.
///
/// Alternative approaches include:
///
/// - generate an `iron::middleware::Handler` (usually a `router::Router` or
///   `iron::middleware::chain`) for each interface, and add those handlers inside an existing
///   router, mounted at different paths - so the interfaces are separated by path
/// - use a different instance of `iron::Iron` for each interface - so the interfaces are
///   separated by the address/port they listen on
///
/// This function exists to allow legacy code, which doesn't separate its APIs properly, to make
/// use of this crate.
#[deprecated(note="APIs should not overlap - only for use in legacy code.")]
pub fn route<T>(router: &mut Router, api: T) where T: Api + Send + Sync + Clone + 'static {
    add_routes(router, api)
}

/// Add routes for `Api` to a provided router
fn add_routes<T>(router: &mut Router, api: T) where T: Api + Send + Sync + Clone + 'static {

    let api_clone = api.clone();
    router.put(
        "/drives/:drive_id/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_drive_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("drive_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter drive_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter drive_id: {}", e))))?
                };
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };



                match api.apply_limiter_to_drive(param_drive_id, param_limiter_id, context).wait() {
                    Ok(rsp) => match rsp {
                        ApplyLimiterToDriveResponse::LimiterApplied => {


                            let mut response = Response::with((status::Status::from_u16(200)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToDriveResponse::LimiterCannotBeAppliedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_DRIVE_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToDriveResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_DRIVE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "ApplyLimiterToDrive");

    let api_clone = api.clone();
    router.put(
        "/network-interfaces/:iface_id/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_iface_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("iface_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter iface_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter iface_id: {}", e))))?
                };
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };



                match api.apply_limiter_to_network_interface(param_iface_id, param_limiter_id, context).wait() {
                    Ok(rsp) => match rsp {
                        ApplyLimiterToNetworkInterfaceResponse::LimiterApplied => {


                            let mut response = Response::with((status::Status::from_u16(200)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToNetworkInterfaceResponse::LimiterCannotBeAppliedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_NETWORK_INTERFACE_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToNetworkInterfaceResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_NETWORK_INTERFACE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "ApplyLimiterToNetworkInterface");

    let api_clone = api.clone();
    router.put(
        "/vsocks/:vsock_id/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_vsock_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("vsock_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter vsock_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter vsock_id: {}", e))))?
                };
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };



                match api.apply_limiter_to_vsock(param_vsock_id, param_limiter_id, context).wait() {
                    Ok(rsp) => match rsp {
                        ApplyLimiterToVsockResponse::LimiterApplied => {


                            let mut response = Response::with((status::Status::from_u16(200)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToVsockResponse::LimiterCannotBeAppliedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_VSOCK_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ApplyLimiterToVsockResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::APPLY_LIMITER_TO_VSOCK_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "ApplyLimiterToVsock");

    let api_clone = api.clone();
    router.put(
        "/action/:action_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_action_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("action_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter action_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter action_id: {}", e))))?
                };


                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_info_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter info - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_info = if let Some(param_info_raw) = param_info_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_info_raw);

                    let param_info: Option<models::InstanceActionInfo> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter info - doesn't match schema: {}", e))))?;

                    param_info
                } else {
                    None
                };
                let param_info = param_info.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter info".to_string())))?;


                match api.create_instance_action(param_action_id, param_info, context).wait() {
                    Ok(rsp) => match rsp {
                        CreateInstanceActionResponse::NoPreviousActionExistedSoANewOneWasCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        CreateInstanceActionResponse::ActionUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        CreateInstanceActionResponse::UnexpectedError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::CREATE_INSTANCE_ACTION_UNEXPECTED_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "CreateInstanceAction");

    let api_clone = api.clone();
    router.delete(
        "/drives/:drive_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_drive_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("drive_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter drive_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter drive_id: {}", e))))?
                };



                match api.delete_guest_drive_by_id(param_drive_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DeleteGuestDriveByIDResponse::DriveDeleted => {


                            let mut response = Response::with((status::Status::from_u16(202)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DeleteGuestDriveByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DELETE_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DeleteGuestDriveByID");

    let api_clone = api.clone();
    router.delete(
        "/network-interfaces/:iface_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_iface_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("iface_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter iface_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter iface_id: {}", e))))?
                };



                match api.delete_guest_network_interface_by_id(param_iface_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DeleteGuestNetworkInterfaceByIDResponse::NetworkInterfaceDeleted => {


                            let mut response = Response::with((status::Status::from_u16(202)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DeleteGuestNetworkInterfaceByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DELETE_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DeleteGuestNetworkInterfaceByID");

    let api_clone = api.clone();
    router.delete(
        "/vsocks/:vsock_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_vsock_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("vsock_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter vsock_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter vsock_id: {}", e))))?
                };



                match api.delete_guest_vsock_by_id(param_vsock_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DeleteGuestVsockByIDResponse::VsockDeleted => {


                            let mut response = Response::with((status::Status::from_u16(202)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DeleteGuestVsockByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DELETE_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DeleteGuestVsockByID");

    let api_clone = api.clone();
    router.delete(
        "/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };



                match api.delete_limiter(param_limiter_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DeleteLimiterResponse::LimiterDeleted => {


                            let mut response = Response::with((status::Status::from_u16(202)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DeleteLimiterResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DELETE_LIMITER_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DeleteLimiter");

    let api_clone = api.clone();
    router.get(
        "/",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                match api.describe_instance(context).wait() {
                    Ok(rsp) => match rsp {
                        DescribeInstanceResponse::TheInstanceInformation(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_INSTANCE_THE_INSTANCE_INFORMATION.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DescribeInstanceResponse::UnexpectedError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_INSTANCE_UNEXPECTED_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DescribeInstance");

    let api_clone = api.clone();
    router.get(
        "/action/:action_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_action_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("action_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter action_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter action_id: {}", e))))?
                };



                match api.describe_instance_action(param_action_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DescribeInstanceActionResponse::TheInstanceActionInformation(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_INSTANCE_ACTION_THE_INSTANCE_ACTION_INFORMATION.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DescribeInstanceActionResponse::UnexpectedError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_INSTANCE_ACTION_UNEXPECTED_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DescribeInstanceAction");

    let api_clone = api.clone();
    router.get(
        "/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };



                match api.describe_limiter(param_limiter_id, context).wait() {
                    Ok(rsp) => match rsp {
                        DescribeLimiterResponse::SpecifiedLimiter(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_LIMITER_SPECIFIED_LIMITER.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DescribeLimiterResponse::LimiterDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_LIMITER_LIMITER_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        DescribeLimiterResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::DESCRIBE_LIMITER_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "DescribeLimiter");

    let api_clone = api.clone();
    router.get(
        "/boot/source",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.get_guest_boot_source(context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestBootSourceResponse::SpecifiedBootSource(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_BOOT_SOURCE_SPECIFIED_BOOT_SOURCE.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestBootSourceResponse::BootSourceDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_BOOT_SOURCE_BOOT_SOURCE_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestBootSourceResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_BOOT_SOURCE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestBootSource");

    let api_clone = api.clone();
    router.get(
        "/drives/:drive_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_drive_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("drive_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter drive_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter drive_id: {}", e))))?
                };



                match api.get_guest_drive_by_id(param_drive_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestDriveByIDResponse::SpecifiedDrive(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_DRIVE_BY_ID_SPECIFIED_DRIVE.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestDriveByIDResponse::DriveDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_DRIVE_BY_ID_DRIVE_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestDriveByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestDriveByID");

    let api_clone = api.clone();
    router.get(
        "/drives",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.get_guest_drives(context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestDrivesResponse::ListOfGuestDrives(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_DRIVES_LIST_OF_GUEST_DRIVES.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestDrivesResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_DRIVES_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestDrives");

    let api_clone = api.clone();
    router.get(
        "/network-interfaces/:iface_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_iface_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("iface_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter iface_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter iface_id: {}", e))))?
                };



                match api.get_guest_network_interface_by_id(param_iface_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestNetworkInterfaceByIDResponse::SpecifiedNetworkInterface(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_NETWORK_INTERFACE_BY_ID_SPECIFIED_NETWORK_INTERFACE.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestNetworkInterfaceByIDResponse::NetworkInterfaceDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_NETWORK_INTERFACE_BY_ID_NETWORK_INTERFACE_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestNetworkInterfaceByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestNetworkInterfaceByID");

    let api_clone = api.clone();
    router.get(
        "/network-interfaces",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.get_guest_network_interfaces(context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestNetworkInterfacesResponse::ListOfGuestNetworkInterfaces(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_NETWORK_INTERFACES_LIST_OF_GUEST_NETWORK_INTERFACES.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestNetworkInterfacesResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_NETWORK_INTERFACES_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestNetworkInterfaces");

    let api_clone = api.clone();
    router.get(
        "/vsocks/:vsock_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_vsock_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("vsock_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter vsock_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter vsock_id: {}", e))))?
                };



                match api.get_guest_vsock_by_id(param_vsock_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestVsockByIDResponse::SpecifiedVsock(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_VSOCK_BY_ID_SPECIFIED_VSOCK.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestVsockByIDResponse::VsockDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_VSOCK_BY_ID_VSOCK_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestVsockByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestVsockByID");

    let api_clone = api.clone();
    router.get(
        "/vsocks",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.get_guest_vsocks(context).wait() {
                    Ok(rsp) => match rsp {
                        GetGuestVsocksResponse::ListOfGuestVsocks(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_VSOCKS_LIST_OF_GUEST_VSOCKS.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetGuestVsocksResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_GUEST_VSOCKS_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetGuestVsocks");

    let api_clone = api.clone();
    router.get(
        "/drives/:drive_id/limiters",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_drive_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("drive_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter drive_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter drive_id: {}", e))))?
                };



                match api.get_limiters_for_guest_drive(param_drive_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetLimitersForGuestDriveResponse::ListOfLimitersIDsCurrentlyAppliedToThisDrive(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_DRIVE_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_DRIVE.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestDriveResponse::DriveDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_DRIVE_DRIVE_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestDriveResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_DRIVE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetLimitersForGuestDrive");

    let api_clone = api.clone();
    router.get(
        "/network-interfaces/:iface_id/limiters",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_iface_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("iface_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter iface_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter iface_id: {}", e))))?
                };



                match api.get_limiters_for_guest_network_interface(param_iface_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetLimitersForGuestNetworkInterfaceResponse::ListOfLimitersIDsCurrentlyAppliedToThisNetworkInterface(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_NETWORK_INTERFACE.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestNetworkInterfaceResponse::NetworkInterfaceDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_NETWORK_INTERFACE_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestNetworkInterfaceResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetLimitersForGuestNetworkInterface");

    let api_clone = api.clone();
    router.get(
        "/vsocks/:vsock_id/limiters",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_vsock_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("vsock_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter vsock_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter vsock_id: {}", e))))?
                };



                match api.get_limiters_for_guest_vsock(param_vsock_id, context).wait() {
                    Ok(rsp) => match rsp {
                        GetLimitersForGuestVsockResponse::ListOfLimitersIDsCurrentlyAppliedToThisVsock(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_VSOCK_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_VSOCK.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestVsockResponse::VsockDoesNotExist(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(404), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_VSOCK_VSOCK_DOES_NOT_EXIST.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetLimitersForGuestVsockResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_LIMITERS_FOR_GUEST_VSOCK_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetLimitersForGuestVsock");

    let api_clone = api.clone();
    router.get(
        "/metadata",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.get_metadata(context).wait() {
                    Ok(rsp) => match rsp {
                        GetMetadataResponse::TheInstanceMetadata(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_METADATA_THE_INSTANCE_METADATA.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        GetMetadataResponse::UnexpectedError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::GET_METADATA_UNEXPECTED_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "GetMetadata");

    let api_clone = api.clone();
    router.get(
        "/actions",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();





                match api.list_instance_actions(context).wait() {
                    Ok(rsp) => match rsp {
                        ListInstanceActionsResponse::The_(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::LIST_INSTANCE_ACTIONS_THE_.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ListInstanceActionsResponse::UnexpectedError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::LIST_INSTANCE_ACTIONS_UNEXPECTED_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "ListInstanceActions");

    let api_clone = api.clone();
    router.get(
        "/limiters",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();




                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = req.get::<UrlEncodedQuery>().unwrap_or_default();
                let param_next_token = query_params.get("next_token")
                    .and_then(|list| list.first()).and_then(|x| x.parse::<String>().ok());


                match api.list_limiters(param_next_token, context).wait() {
                    Ok(rsp) => match rsp {
                        ListLimitersResponse::ListOfLimiters(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(200), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::LIST_LIMITERS_LIST_OF_LIMITERS.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                        ListLimitersResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::LIST_LIMITERS_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));

                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "ListLimiters");

    let api_clone = api.clone();
    router.put(
        "/boot/source",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();




                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_body_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_body = if let Some(param_body_raw) = param_body_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_body_raw);

                    let param_body: Option<models::BootSource> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - doesn't match schema: {}", e))))?;

                    param_body
                } else {
                    None
                };
                let param_body = param_body.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter body".to_string())))?;


                match api.put_guest_boot_source(param_body, context).wait() {
                    Ok(rsp) => match rsp {
                        PutGuestBootSourceResponse::BootSourceCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestBootSourceResponse::BootSourceUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestBootSourceResponse::BootSourceCannotBeCreatedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_BOOT_SOURCE_BOOT_SOURCE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestBootSourceResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_BOOT_SOURCE_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "PutGuestBootSource");

    let api_clone = api.clone();
    router.put(
        "/drives/:drive_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_drive_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("drive_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter drive_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter drive_id: {}", e))))?
                };


                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_body_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_body = if let Some(param_body_raw) = param_body_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_body_raw);

                    let param_body: Option<models::Drive> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - doesn't match schema: {}", e))))?;

                    param_body
                } else {
                    None
                };
                let param_body = param_body.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter body".to_string())))?;


                match api.put_guest_drive_by_id(param_drive_id, param_body, context).wait() {
                    Ok(rsp) => match rsp {
                        PutGuestDriveByIDResponse::DriveCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestDriveByIDResponse::DriveUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestDriveByIDResponse::DriveCannotBeCreatedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_DRIVE_BY_ID_DRIVE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestDriveByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "PutGuestDriveByID");

    let api_clone = api.clone();
    router.put(
        "/network-interfaces/:iface_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_iface_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("iface_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter iface_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter iface_id: {}", e))))?
                };


                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_body_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_body = if let Some(param_body_raw) = param_body_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_body_raw);

                    let param_body: Option<models::NetworkInterface> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - doesn't match schema: {}", e))))?;

                    param_body
                } else {
                    None
                };
                let param_body = param_body.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter body".to_string())))?;


                match api.put_guest_network_interface_by_id(param_iface_id, param_body, context).wait() {
                    Ok(rsp) => match rsp {
                        PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestNetworkInterfaceByIDResponse::NetworkInterfaceCannotBeCreatedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_NETWORK_INTERFACE_BY_ID_NETWORK_INTERFACE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestNetworkInterfaceByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "PutGuestNetworkInterfaceByID");

    let api_clone = api.clone();
    router.put(
        "/vsocks/:vsock_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_vsock_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("vsock_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter vsock_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter vsock_id: {}", e))))?
                };


                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_body_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_body = if let Some(param_body_raw) = param_body_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_body_raw);

                    let param_body: Option<models::Vsock> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter body - doesn't match schema: {}", e))))?;

                    param_body
                } else {
                    None
                };
                let param_body = param_body.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter body".to_string())))?;


                match api.put_guest_vsock_by_id(param_vsock_id, param_body, context).wait() {
                    Ok(rsp) => match rsp {
                        PutGuestVsockByIDResponse::VsockCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestVsockByIDResponse::VsockUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestVsockByIDResponse::VsockCannotBeCreatedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_VSOCK_BY_ID_VSOCK_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        PutGuestVsockByIDResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::PUT_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "PutGuestVsockByID");

    let api_clone = api.clone();
    router.put(
        "/limiters/:limiter_id",
        move |req: &mut Request| {
            let mut context = Context::default();

            // Helper function to provide a code block to use `?` in (to be replaced by the `catch` block when it exists).
            fn handle_request<T>(req: &mut Request, api: &T, context: &mut Context) -> Result<Response, Response> where T: Api {

                context.x_span_id = Some(req.headers.get::<XSpanId>().map(XSpanId::to_string).unwrap_or_else(|| self::uuid::Uuid::new_v4().to_string()));
                context.auth_data = req.extensions.remove::<AuthData>();
                context.authorization = req.extensions.remove::<Authorization>();



                // Path parameters
                let param_limiter_id = {
                    let param = req.extensions.get::<Router>().ok_or_else(|| Response::with((status::InternalServerError, "An internal error occurred".to_string())))?
                        .find("limiter_id").ok_or_else(|| Response::with((status::BadRequest, "Missing path parameter limiter_id".to_string())))?;
                    percent_decode(param.as_bytes()).decode_utf8()
                        .map_err(|_| Response::with((status::BadRequest, format!("Couldn't percent-decode path parameter as UTF-8: {}", param))))?
                        .parse().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse path parameter limiter_id: {}", e))))?
                };


                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.

                let param_limiter_raw = req.get::<bodyparser::Raw>().map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter limiter - not valid UTF-8: {}", e))))?;
                let mut unused_elements = Vec::new();

                let param_limiter = if let Some(param_limiter_raw) = param_limiter_raw { 
                    let deserializer = &mut serde_json::Deserializer::from_str(&param_limiter_raw);

                    let param_limiter: Option<models::Limiter> = serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }).map_err(|e| Response::with((status::BadRequest, format!("Couldn't parse body parameter limiter - doesn't match schema: {}", e))))?;

                    param_limiter
                } else {
                    None
                };
                let param_limiter = param_limiter.ok_or_else(|| Response::with((status::BadRequest, "Missing required body parameter limiter".to_string())))?;


                match api.update_limiter(param_limiter_id, param_limiter, context).wait() {
                    Ok(rsp) => match rsp {
                        UpdateLimiterResponse::LimiterCreated => {


                            let mut response = Response::with((status::Status::from_u16(201)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        UpdateLimiterResponse::LimiterUpdated => {


                            let mut response = Response::with((status::Status::from_u16(204)));    


                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        UpdateLimiterResponse::LimiterCannotBeCreatedDueToBadInput(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(400), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::UPDATE_LIMITER_LIMITER_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                        UpdateLimiterResponse::InternalServerError(body) => {

                            let body_string = serde_json::to_string(&body).expect("impossible to fail to serialize");

                            let mut response = Response::with((status::Status::from_u16(0), body_string));    
                            response.headers.set(ContentType(mimetypes::responses::UPDATE_LIMITER_INTERNAL_SERVER_ERROR.clone()));

                            context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                            if !unused_elements.is_empty() {
                                response.headers.set(Warning(format!("Ignoring unknown fields in body: {:?}", unused_elements)));
                            }
                            Ok(response)
                        },
                    },
                    Err(_) => {
                        // Application code returned an error. This should not happen, as the implementation should
                        // return a valid response.
                        Err(Response::with((status::InternalServerError, "An internal error occurred".to_string())))
                    }
                }
            }

            handle_request(req, &api_clone, &mut context).or_else(|mut response| {
                context.x_span_id.as_ref().map(|header| response.headers.set(XSpanId(header.clone())));
                Ok(response)
            })
        },
        "UpdateLimiter");

}
