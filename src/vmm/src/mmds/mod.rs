// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// MMDS data store
pub mod data_store;
/// MMDS network stack
pub mod ns;
/// Defines the structures needed for saving/restoring MmdsNetworkStack.
pub mod persist;
mod token;
/// MMDS token headers
pub mod token_headers;

use std::sync::{Arc, Mutex};

use micro_http::{
    Body, HttpHeaderError, MediaType, Method, Request, RequestError, Response, StatusCode, Version,
};
use serde_json::{Map, Value};
use token_headers::TokenHeaders;

use crate::mmds::data_store::{Mmds, MmdsDatastoreError as MmdsError, MmdsVersion, OutputFormat};
use crate::mmds::token::PATH_TO_TOKEN;
use crate::mmds::token_headers::REJECTED_HEADER;

#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// MMDS token errors
pub enum VmmMmdsError {
    /// MMDS token not valid.
    InvalidToken,
    /// Invalid URI.
    InvalidURI,
    /// Not allowed HTTP method.
    MethodNotAllowed,
    /// No MMDS token provided. Use `X-metadata-token` header to specify the session token.
    NoTokenProvided,
    /// Token time to live value not found. Use `X-metadata-token-ttl-seconds` header to specify the token's lifetime.
    NoTtlProvided,
    /// Resource not found: {0}.
    ResourceNotFound(String),
}

impl From<MediaType> for OutputFormat {
    fn from(media_type: MediaType) -> Self {
        match media_type {
            MediaType::ApplicationJson => OutputFormat::Json,
            MediaType::PlainText => OutputFormat::Imds,
        }
    }
}

// Builds the `micro_http::Response` with a given HTTP version, status code, and body.
fn build_response(http_version: Version, status_code: StatusCode, body: Body) -> Response {
    let mut response = Response::new(http_version, status_code);
    response.set_body(body);
    response
}

/// Patch provided JSON document (given as `serde_json::Value`) in-place with JSON Merge Patch
/// [RFC 7396](https://tools.ietf.org/html/rfc7396).
pub fn json_patch(target: &mut Value, patch: &Value) {
    if patch.is_object() {
        if !target.is_object() {
            // Replace target with a serde_json object so we can recursively copy patch values.
            *target = Value::Object(Map::new());
        }

        // This is safe since we make sure patch and target are objects beforehand.
        let doc = target.as_object_mut().unwrap();
        for (key, value) in patch.as_object().unwrap() {
            if value.is_null() {
                // If the value in the patch is null we remove the entry.
                doc.remove(key.as_str());
            } else {
                // Recursive call to update target document.
                // If `key` is not in the target document (it's a new field defined in `patch`)
                // insert a null placeholder and pass it as the new target
                // so we can insert new values recursively.
                json_patch(doc.entry(key.as_str()).or_insert(Value::Null), value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

// Make the URI a correct JSON pointer value.
fn sanitize_uri(mut uri: String) -> String {
    let mut len = u32::MAX as usize;
    // Loop while the deduping decreases the sanitized len.
    // Each iteration will attempt to dedup "//".
    while uri.len() < len {
        len = uri.len();
        uri = uri.replace("//", "/");
    }

    uri
}

/// Build a response for `request` and return response based on MMDS version
pub fn convert_to_response(mmds: Arc<Mutex<Mmds>>, request: Request) -> Response {
    let uri = request.uri().get_abs_path();
    if uri.is_empty() {
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            Body::new(VmmMmdsError::InvalidURI.to_string()),
        );
    }

    let mut mmds_guard = mmds.lock().expect("Poisoned lock");

    match mmds_guard.version() {
        MmdsVersion::V1 => respond_to_request_mmdsv1(&mmds_guard, request),
        MmdsVersion::V2 => respond_to_request_mmdsv2(&mut mmds_guard, request),
    }
}

fn respond_to_request_mmdsv1(mmds: &Mmds, request: Request) -> Response {
    // Allow only GET requests.
    match request.method() {
        Method::Get => respond_to_get_request_unchecked(mmds, request),
        _ => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::MethodNotAllowed,
                Body::new(VmmMmdsError::MethodNotAllowed.to_string()),
            );
            response.allow_method(Method::Get);
            response
        }
    }
}

fn respond_to_request_mmdsv2(mmds: &mut Mmds, request: Request) -> Response {
    // Fetch custom headers from request.
    let token_headers = match TokenHeaders::try_from(request.headers.custom_entries()) {
        Ok(token_headers) => token_headers,
        Err(err) => {
            return build_response(
                request.http_version(),
                StatusCode::BadRequest,
                Body::new(err.to_string()),
            );
        }
    };

    // Allow only GET and PUT requests.
    match request.method() {
        Method::Get => respond_to_get_request_checked(mmds, request, token_headers),
        Method::Put => respond_to_put_request(mmds, request, token_headers),
        _ => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::MethodNotAllowed,
                Body::new(VmmMmdsError::MethodNotAllowed.to_string()),
            );
            response.allow_method(Method::Get);
            response.allow_method(Method::Put);
            response
        }
    }
}

fn respond_to_get_request_checked(
    mmds: &Mmds,
    request: Request,
    token_headers: TokenHeaders,
) -> Response {
    // Get MMDS token from custom headers.
    let token = match token_headers.x_metadata_token() {
        Some(token) => token,
        None => {
            let error_msg = VmmMmdsError::NoTokenProvided.to_string();
            return build_response(
                request.http_version(),
                StatusCode::Unauthorized,
                Body::new(error_msg),
            );
        }
    };

    // Validate MMDS token.
    match mmds.is_valid_token(token) {
        Ok(true) => respond_to_get_request_unchecked(mmds, request),
        Ok(false) => build_response(
            request.http_version(),
            StatusCode::Unauthorized,
            Body::new(VmmMmdsError::InvalidToken.to_string()),
        ),
        Err(_) => unreachable!(),
    }
}

fn respond_to_get_request_unchecked(mmds: &Mmds, request: Request) -> Response {
    let uri = request.uri().get_abs_path();

    // The data store expects a strict json path, so we need to
    // sanitize the URI.
    let json_path = sanitize_uri(uri.to_string());

    match mmds.get_value(json_path, request.headers.accept().into()) {
        Ok(response_body) => build_response(
            request.http_version(),
            StatusCode::OK,
            Body::new(response_body),
        ),
        Err(err) => match err {
            MmdsError::NotFound => {
                let error_msg = VmmMmdsError::ResourceNotFound(String::from(uri)).to_string();
                build_response(
                    request.http_version(),
                    StatusCode::NotFound,
                    Body::new(error_msg),
                )
            }
            MmdsError::UnsupportedValueType => build_response(
                request.http_version(),
                StatusCode::NotImplemented,
                Body::new(err.to_string()),
            ),
            MmdsError::DataStoreLimitExceeded => build_response(
                request.http_version(),
                StatusCode::PayloadTooLarge,
                Body::new(err.to_string()),
            ),
            _ => unreachable!(),
        },
    }
}

fn respond_to_put_request(
    mmds: &mut Mmds,
    request: Request,
    token_headers: TokenHeaders,
) -> Response {
    // Reject `PUT` requests that contain `X-Forwarded-For` header.
    if request
        .headers
        .custom_entries()
        .contains_key(REJECTED_HEADER)
    {
        let error_msg = RequestError::HeaderError(HttpHeaderError::UnsupportedName(
            REJECTED_HEADER.to_string(),
        ))
        .to_string();
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            Body::new(error_msg),
        );
    }

    let uri = request.uri().get_abs_path();
    // Sanitize the URI into a strict json path.
    let json_path = sanitize_uri(uri.to_string());

    // Only accept PUT requests towards TOKEN_PATH.
    if json_path != PATH_TO_TOKEN {
        let error_msg = VmmMmdsError::ResourceNotFound(String::from(uri)).to_string();
        return build_response(
            request.http_version(),
            StatusCode::NotFound,
            Body::new(error_msg),
        );
    }

    // Get token lifetime value.
    let ttl_seconds = match token_headers.x_metadata_token_ttl_seconds() {
        Some(ttl_seconds) => ttl_seconds,
        None => {
            return build_response(
                request.http_version(),
                StatusCode::BadRequest,
                Body::new(VmmMmdsError::NoTtlProvided.to_string()),
            );
        }
    };

    // Generate token.
    let result = mmds.generate_token(ttl_seconds);
    match result {
        Ok(token) => {
            let mut response =
                build_response(request.http_version(), StatusCode::OK, Body::new(token));
            response.set_content_type(MediaType::PlainText);
            response
        }
        Err(err) => build_response(
            request.http_version(),
            StatusCode::BadRequest,
            Body::new(err.to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::mmds::token::{MAX_TOKEN_TTL_SECONDS, MIN_TOKEN_TTL_SECONDS};

    fn populate_mmds() -> Arc<Mutex<Mmds>> {
        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": 43,
            "phones": {
                "home": {
                    "RO": "+401234567",
                    "UK": "+441234567"
                },
                "mobile": "+442345678"
            }
        }"#;
        let mmds = Arc::new(Mutex::new(Mmds::default()));
        mmds.lock()
            .expect("Poisoned lock")
            .put_data(serde_json::from_str(data).unwrap())
            .unwrap();

        mmds
    }

    fn get_json_data() -> &'static str {
        r#"{
            "age": 43,
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "phones": {
                "home": {
                    "RO": "+401234567",
                    "UK": "+441234567"
                },
                "mobile": "+442345678"
            }
        }"#
    }

    #[test]
    fn test_sanitize_uri() {
        let sanitized = "/a/b/c/d";
        assert_eq!(sanitize_uri("/a/b/c/d".to_owned()), sanitized);
        assert_eq!(sanitize_uri("/a////b/c//d".to_owned()), sanitized);
        assert_eq!(sanitize_uri("/a///b/c///d".to_owned()), sanitized);
        assert_eq!(sanitize_uri("/a//b/c////d".to_owned()), sanitized);
        assert_eq!(sanitize_uri("///////a//b///c//d".to_owned()), sanitized);
        assert_eq!(sanitize_uri("a".to_owned()), "a");
        assert_eq!(sanitize_uri("a/".to_owned()), "a/");
        assert_eq!(sanitize_uri("aa//".to_owned()), "aa/");
        assert_eq!(sanitize_uri("aa".to_owned()), "aa");
        assert_eq!(sanitize_uri("/".to_owned()), "/");
        assert_eq!(sanitize_uri("".to_owned()), "");
        assert_eq!(sanitize_uri("////".to_owned()), "/");
        assert_eq!(sanitize_uri("aa//bb///cc//d".to_owned()), "aa/bb/cc/d");
        assert_eq!(sanitize_uri("//aa//bb///cc//d".to_owned()), "/aa/bb/cc/d");
    }

    #[test]
    fn test_respond_to_request_mmdsv1() {
        // Populate MMDS with data.
        let mmds = populate_mmds();

        // Set version to V1.
        mmds.lock()
            .expect("Poisoned lock")
            .set_version(MmdsVersion::V1)
            .unwrap();
        assert_eq!(
            mmds.lock().expect("Poisoned lock").version(),
            MmdsVersion::V1
        );

        // Test resource not found.
        let request_bytes = b"GET http://169.254.169.254/invalid HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new(
            VmmMmdsError::ResourceNotFound(String::from("/invalid")).to_string(),
        ));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test NotImplemented.
        let request_bytes = b"GET /age HTTP/1.1\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        let body = "Cannot retrieve value. The value has an unsupported type.".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test not allowed HTTP Method.
        let not_allowed_methods = ["PUT", "PATCH"];
        for method in not_allowed_methods.iter() {
            let request_bytes = format!("{} http://169.254.169.255/ HTTP/1.0\r\n\r\n", method);
            let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
            let mut expected_response =
                Response::new(Version::Http10, StatusCode::MethodNotAllowed);
            expected_response.set_body(Body::new(VmmMmdsError::MethodNotAllowed.to_string()));
            expected_response.allow_method(Method::Get);
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
        }

        // Test invalid (empty absolute path) URI.
        let request_bytes = b"GET http:// HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new(VmmMmdsError::InvalidURI.to_string()));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test invalid custom header value is ignored when V1 is configured.
        let request_bytes = b"GET http://169.254.169.254/name/first HTTP/1.0\r\n\
                                    Accept: application/json\r\n
                                    X-metadata-token-ttl-seconds: application/json\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::OK);
        expected_response.set_body(Body::new("\"John\""));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test Ok path.
        let request_bytes = b"GET http://169.254.169.254/ HTTP/1.0\r\n\
                                    Accept: application/json\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::OK);
        let mut body = get_json_data().to_string();
        body.retain(|c| !c.is_whitespace());
        expected_response.set_body(Body::new(body));
        let actual_response = convert_to_response(mmds, request);
        assert_eq!(actual_response, expected_response);
    }

    #[test]
    fn test_respond_to_request_mmdsv2() {
        // Populate MMDS with data.
        let mmds = populate_mmds();

        // Set version to V2.
        mmds.lock()
            .expect("Poisoned lock")
            .set_version(MmdsVersion::V2)
            .unwrap();
        assert_eq!(
            mmds.lock().expect("Poisoned lock").version(),
            MmdsVersion::V2
        );

        // Test not allowed PATCH HTTP Method.
        let request_bytes = b"PATCH http://169.254.169.255/ HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::MethodNotAllowed);
        expected_response.set_body(Body::new(VmmMmdsError::MethodNotAllowed.to_string()));
        expected_response.allow_method(Method::Get);
        expected_response.allow_method(Method::Put);
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test invalid value for custom header.
        let request_bytes = b"GET http://169.254.169.254/ HTTP/1.0\r\n\
                                    Accept: application/json\r\n
                                    X-metadata-token-ttl-seconds: application/json\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new(
            "Invalid header. Reason: Invalid value. Key:X-metadata-token-ttl-seconds; \
             Value:application/json"
                .to_string(),
        ));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test PUT requests.
        // Unsupported `X-Forwarded-For` header present.
        let request_bytes = b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                                    X-Forwarded-For: 203.0.113.195\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new(
            "Invalid header. Reason: Unsupported header name. Key: X-Forwarded-For".to_string(),
        ));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test invalid path.
        let request_bytes = b"PUT http://169.254.169.254/token HTTP/1.0\r\n\
                                    X-metadata-token-ttl-seconds: 60\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new(
            VmmMmdsError::ResourceNotFound(String::from("/token")).to_string(),
        ));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test invalid lifetime values for token.
        let invalid_values = [MIN_TOKEN_TTL_SECONDS - 1, MAX_TOKEN_TTL_SECONDS + 1];
        for invalid_value in invalid_values.iter() {
            let request_bytes = format!(
                "PUT http://169.254.169.254/latest/api/token \
                 HTTP/1.0\r\nX-metadata-token-ttl-seconds: {}\r\n\r\n",
                invalid_value
            );
            let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
            let error_msg = format!(
                "Invalid time to live value provided for token: {}. Please provide a value \
                 between {} and {}.",
                invalid_value, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            );
            expected_response.set_body(Body::new(error_msg));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
        }

        // Test no lifetime value provided for token.
        let request_bytes = b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new(VmmMmdsError::NoTtlProvided.to_string()));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test valid PUT.
        let request_bytes = b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                                    X-metadata-token-ttl-seconds: 60\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response.status(), StatusCode::OK);
        assert_eq!(actual_response.content_type(), MediaType::PlainText);

        // Test valid GET.
        let valid_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();
        let request_bytes = format!(
            "GET http://169.254.169.254/ HTTP/1.0\r\nAccept: \
             application/json\r\nX-metadata-token: {}\r\n\r\n",
            valid_token
        );
        let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::OK);
        let mut body = get_json_data().to_string();
        body.retain(|c| !c.is_whitespace());
        expected_response.set_body(Body::new(body));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test GET request towards unsupported value type.
        let request_bytes = format!(
            "GET /age HTTP/1.1\r\nX-metadata-token: {}\r\n\r\n",
            valid_token
        );
        let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        let body = "Cannot retrieve value. The value has an unsupported type.".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test GET request towards invalid resource.
        let request_bytes = format!(
            "GET http://169.254.169.254/invalid HTTP/1.0\r\nX-metadata-token: {}\r\n\r\n",
            valid_token
        );
        let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new(
            VmmMmdsError::ResourceNotFound(String::from("/invalid")).to_string(),
        ));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test GET request without token should return Unauthorized status code.
        let request_bytes = b"GET http://169.254.169.254/ HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::Unauthorized);
        expected_response.set_body(Body::new(VmmMmdsError::NoTokenProvided.to_string()));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Test GET request with invalid token should return Unauthorized status code.
        let request_bytes = b"GET http://169.254.169.254/ HTTP/1.0\r\n\
                                    X-metadata-token: foo\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::Unauthorized);
        expected_response.set_body(Body::new(VmmMmdsError::InvalidToken.to_string()));
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);

        // Create a new MMDS token that expires in one second.
        let request_bytes = b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                                    X-metadata-token-ttl-seconds: 1\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response.status(), StatusCode::OK);
        assert_eq!(actual_response.content_type(), MediaType::PlainText);

        // Test GET request with invalid tokens.
        // `valid_token` will become invalid after one second, when it expires.
        let valid_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();
        let invalid_token = "a".repeat(58);
        let tokens = [invalid_token, valid_token];
        for token in tokens.iter() {
            let request_bytes = format!(
                "GET http://169.254.169.254/ HTTP/1.0\r\nX-metadata-token: {}\r\n\r\n",
                token
            );
            let request = Request::try_from(request_bytes.as_bytes(), None).unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::Unauthorized);
            expected_response.set_body(Body::new(VmmMmdsError::InvalidToken.to_string()));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Wait for the second token to expire.
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn test_json_patch() {
        let mut data = serde_json::json!({
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": "43",
            "phones": {
                "home": {
                    "RO": "+40 1234567",
                    "UK": "+44 1234567"
                },
                "mobile": "+44 2345678"
            }
        });

        let patch = serde_json::json!({
            "name": {
                "second": null,
                "last": "Kennedy"
            },
            "age": "44",
            "phones": {
                "home": "+44 1234567",
                "mobile": {
                    "RO": "+40 2345678",
                    "UK": "+44 2345678"
                }
            }
        });
        json_patch(&mut data, &patch);

        // Test value replacement in target document.
        assert_eq!(data["age"], patch["age"]);

        // Test null value removal from target document.
        assert_eq!(data["name"]["second"], Value::Null);

        // Test add value to target document.
        assert_eq!(data["name"]["last"], patch["name"]["last"]);
        assert!(!data["phones"]["home"].is_object());
        assert_eq!(data["phones"]["home"], patch["phones"]["home"]);
        assert!(data["phones"]["mobile"].is_object());
        assert_eq!(
            data["phones"]["mobile"]["RO"],
            patch["phones"]["mobile"]["RO"]
        );
        assert_eq!(
            data["phones"]["mobile"]["UK"],
            patch["phones"]["mobile"]["UK"]
        );
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            VmmMmdsError::InvalidToken.to_string(),
            "MMDS token not valid."
        );

        assert_eq!(VmmMmdsError::InvalidURI.to_string(), "Invalid URI.");

        assert_eq!(
            VmmMmdsError::MethodNotAllowed.to_string(),
            "Not allowed HTTP method."
        );

        assert_eq!(
            VmmMmdsError::NoTokenProvided.to_string(),
            "No MMDS token provided. Use `X-metadata-token` header to specify the session token."
        );

        assert_eq!(
            VmmMmdsError::NoTtlProvided.to_string(),
            "Token time to live value not found. Use `X-metadata-token-ttl-seconds` header to \
             specify the token's lifetime."
        );

        assert_eq!(
            VmmMmdsError::ResourceNotFound(String::from("invalid/")).to_string(),
            "Resource not found: invalid/."
        )
    }
}
