// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate lazy_static;
extern crate serde_json;

extern crate dumbo;
extern crate logger;
extern crate micro_http;
extern crate snapshot;
extern crate utils;
extern crate versionize;
extern crate versionize_derive;

pub mod data_store;
pub mod ns;
pub mod persist;

use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};

use data_store::{Error as MmdsError, Mmds, OutputFormat};
use micro_http::{Body, MediaType, Method, Request, Response, StatusCode, Version};

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

/// Builds the `micro_http::Response` with a given HTTP version, status code, and body.
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

fn convert_to_response(request: Request) -> Response {
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

    // The data store expects a strict json path, so we need to
    // sanitize the URI.
    let json_pointer = sanitize_uri(uri.to_string());

    // The lock can be held by one thread only, so it is safe to unwrap.
    // If another thread poisoned the lock, we abort the execution.
    let response = MMDS
        .lock()
        .expect("Poisoned lock")
        .get_value(json_pointer, request.headers.accept().into());

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

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

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
    fn test_convert_to_response() {
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

        // Test resource not found.
        let request_bytes = b"GET http://169.254.169.254/invalid HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new("Resource not found: /invalid.".to_string()));
        let actual_response = convert_to_response(request);
        assert_eq!(actual_response, expected_response);

        // Test NotImplemented.
        let request_bytes = b"GET /age HTTP/1.1\r\n\r\n";
        let request = Request::try_from(request_bytes).unwrap();
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        let body = "Cannot retrieve value. The value has an unsupported type.".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = convert_to_response(request);
        assert_eq!(actual_response, expected_response);

        // Test not allowed HTTP Method.
        let not_allowed_methods = ["PUT", "PATCH"];
        for method in not_allowed_methods.iter() {
            let request_bytes = format!("{} http://169.254.169.255/ HTTP/1.0\r\n\r\n", method);
            let request = Request::try_from(request_bytes.as_bytes()).unwrap();
            let mut expected_response =
                Response::new(Version::Http10, StatusCode::MethodNotAllowed);
            expected_response.set_body(Body::new("Not allowed HTTP method.".to_string()));
            expected_response.allow_method(Method::Get);
            let actual_response = convert_to_response(request);
            assert_eq!(actual_response, expected_response);
        }

        // Test invalid (empty absolute path) URI.
        let request_bytes = b"GET http:// HTTP/1.0\r\n\r\n";
        let request = Request::try_from(request_bytes).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Invalid URI.".to_string()));
        let actual_response = convert_to_response(request);
        assert_eq!(actual_response, expected_response);

        // Test Ok path.
        let request_bytes = b"GET http://169.254.169.254/ HTTP/1.0\r\n\
                                    Accept: application/json\r\n\r\n";
        let request = Request::try_from(request_bytes).unwrap();
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
        let actual_response = convert_to_response(request);
        assert_eq!(actual_response, expected_response);
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
