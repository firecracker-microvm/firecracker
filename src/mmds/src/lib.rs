// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate lazy_static;
extern crate serde_json;

extern crate micro_http;

pub mod data_store;

use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};

use data_store::{Error as MmdsError, Mmds, OutputFormat};
use micro_http::{Body, MediaType, Method, Request, RequestError, Response, StatusCode, Version};

lazy_static! {
    // A static reference to a global Mmds instance. We currently use this for ease of access during
    // prototyping. We'll consider something like passing Arc<Mutex<Mmds>> references to the
    // appropriate threads in the future.
    pub static ref MMDS: Arc<Mutex<Mmds>> = Arc::new(Mutex::new(Mmds::default()));
}

impl Into<OutputFormat> for MediaType {
    fn into(self) -> OutputFormat {
        match self {
            MediaType::ApplicationJson => OutputFormat::Json,
            MediaType::PlainText => OutputFormat::Imds,
        }
    }
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

fn build_response(http_version: Version, status_code: StatusCode, body: Body) -> Response {
    let mut response = Response::new(http_version, status_code);
    response.set_body(body);
    response
}

pub fn parse_request(request_bytes: &[u8]) -> Response {
    let request = Request::try_from(request_bytes);
    match request {
        Ok(request) => {
            let uri = request.uri().get_abs_path();
            if uri.is_empty() {
                return build_response(
                    request.http_version(),
                    StatusCode::BadRequest,
                    Body::new("Invalid URI.".to_string()),
                );
            }

            if request.method() != Method::Get {
                let mut response = build_response(
                    request.http_version(),
                    StatusCode::MethodNotAllowed,
                    Body::new("Not allowed HTTP method."),
                );
                response.allow_method(Method::Get);
                return response;
            }

            // The lock can be held by one thread only, so it is safe to unwrap.
            // If another thread poisoned the lock, we abort the execution.
            let response = MMDS
                .lock()
                .expect("Failed to build MMDS response due to poisoned lock")
                .get_value(uri.to_string(), request.headers.accept().into());

            match response {
                Ok(response_body) => build_response(
                    request.http_version(),
                    StatusCode::OK,
                    Body::new(response_body),
                ),
                Err(e) => match e {
                    MmdsError::NotFound => {
                        let error_msg = format!("Resource not found: {}.", uri);
                        build_response(
                            request.http_version(),
                            StatusCode::NotFound,
                            Body::new(error_msg),
                        )
                    }
                    MmdsError::UnsupportedValueType => build_response(
                        request.http_version(),
                        StatusCode::NotImplemented,
                        Body::new(e.to_string()),
                    ),
                    MmdsError::NotInitialized => unreachable!(),
                },
            }
        }
        Err(e) => match e {
            RequestError::InvalidHttpVersion(err_msg) => build_response(
                Version::default(),
                StatusCode::NotImplemented,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidUri(err_msg) => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidHttpMethod(err_msg) => build_response(
                Version::default(),
                StatusCode::NotImplemented,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidRequest => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new("Invalid request.".to_string()),
            ),
            RequestError::InvalidHeader => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new("Invalid headers.".to_string()),
            ),
            // `micro-http` supports a predefined list of HTTP headers.
            // It shouldn't reach this point, because it ignores the
            // HTTP unsupported headers.
            RequestError::UnsupportedHeader => unreachable!(),
        },
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::*;

    fn check_http_method_failure(method: String, status: StatusCode, err_msg: String) {
        let request = format!("{} http://169.254.169.254/ HTTP/1.1\r\n\r\n", method);
        let mut expected_response = Response::new(Version::Http11, status);
        expected_response.set_body(Body::new(err_msg));
        let actual_response = parse_request(request.as_bytes());
        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
    }

    #[test]
    fn test_parse_request() {
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
        MMDS.lock()
            .unwrap()
            .put_data(serde_json::from_str(data).unwrap())
            .unwrap();

        // Test invalid request.
        let request = b"HTTP/1.1";
        let dummy_response = Response::new(Version::Http11, StatusCode::BadRequest);
        assert!(parse_request(request).status() == dummy_response.status());

        // Test unsupported HTTP version.
        let request = b"GET http://169.254.169.255/ HTTP/2.0\r\n\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        expected_response.set_body(Body::new("Unsupported HTTP version.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test invalid (empty absolute path) URI.
        let request = b"GET http:// HTTP/1.0\r\n\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Invalid URI.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test invalid HTTP format.
        let request = b"GET / HTTP/1.1\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Invalid request.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test resource not found.
        let request = b"GET http://169.254.169.254/invalid HTTP/1.0\r\n\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new("Resource not found: /invalid.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test Ok path.
        let request = b"GET http://169.254.169.254/ HTTP/1.0\r\n\
                                    Accept: application/json\r\n\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::OK);
        let mut body = r#"{
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
        .to_string();
        body.retain(|c| !c.is_whitespace());
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        let request = b"GET /age HTTP/1.1\r\n\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        let body = "Cannot retrieve value. The value has an unsupported type.".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());
    }

    #[test]
    fn test_unsupported_http_method() {
        check_http_method_failure(
            "PUT".to_string(),
            StatusCode::MethodNotAllowed,
            "Not allowed HTTP method.".to_string(),
        );
        check_http_method_failure(
            "PATCH".to_string(),
            StatusCode::MethodNotAllowed,
            "Not allowed HTTP method.".to_string(),
        );
        check_http_method_failure(
            "POST".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "DELETE".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "POST".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "HEAD".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "CONNECT".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "OPTIONS".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "TRACE".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
        check_http_method_failure(
            "NOMETHOD".to_string(),
            StatusCode::NotImplemented,
            "Unsupported HTTP method.".to_string(),
        );
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
}
