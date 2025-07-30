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

use crate::logger::{IncMetric, METRICS};
use crate::mmds::data_store::{Mmds, MmdsDatastoreError as MmdsError, MmdsVersion, OutputFormat};
use crate::mmds::token::PATH_TO_TOKEN;
use crate::mmds::token_headers::{
    X_AWS_EC2_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER,
    X_FORWARDED_FOR_HEADER, X_METADATA_TOKEN_HEADER, X_METADATA_TOKEN_TTL_SECONDS_HEADER,
    get_header_value_pair,
};

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
    /// No MMDS token provided. Use `X-metadata-token` or `X-aws-ec2-metadata-token` header to specify the session token.
    NoTokenProvided,
    /// Token time to live value not found. Use `X-metadata-token-ttl-seconds` or `X-aws-ec2-metadata-token-ttl-seconds` header to specify the token's lifetime.
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
fn build_response(
    http_version: Version,
    status_code: StatusCode,
    content_type: MediaType,
    body: Body,
) -> Response {
    let mut response = Response::new(http_version, status_code);
    response.set_content_type(content_type);
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
    // Check URI is not empty
    let uri = request.uri().get_abs_path();
    if uri.is_empty() {
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
            Body::new(VmmMmdsError::InvalidURI.to_string()),
        );
    }

    let mut mmds_guard = mmds.lock().expect("Poisoned lock");

    // Allow only GET and PUT requests
    match request.method() {
        Method::Get => match mmds_guard.version() {
            MmdsVersion::V1 => respond_to_get_request_v1(&mmds_guard, request),
            MmdsVersion::V2 => respond_to_get_request_v2(&mmds_guard, request),
        },
        Method::Put => respond_to_put_request(&mut mmds_guard, request),
        _ => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::MethodNotAllowed,
                MediaType::PlainText,
                Body::new(VmmMmdsError::MethodNotAllowed.to_string()),
            );
            response.allow_method(Method::Get);
            response.allow_method(Method::Put);
            response
        }
    }
}

fn respond_to_get_request_v1(mmds: &Mmds, request: Request) -> Response {
    match get_header_value_pair(
        request.headers.custom_entries(),
        &[X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER],
    ) {
        Some((_, token)) => {
            if !mmds.is_valid_token(token) {
                METRICS.mmds.rx_invalid_token.inc();
            }
        }
        None => {
            METRICS.mmds.rx_no_token.inc();
        }
    }

    respond_to_get_request(mmds, request)
}

fn respond_to_get_request_v2(mmds: &Mmds, request: Request) -> Response {
    // Check whether a token exists.
    let token = match get_header_value_pair(
        request.headers.custom_entries(),
        &[X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER],
    ) {
        Some((_, token)) => token,
        None => {
            METRICS.mmds.rx_no_token.inc();
            let error_msg = VmmMmdsError::NoTokenProvided.to_string();
            return build_response(
                request.http_version(),
                StatusCode::Unauthorized,
                MediaType::PlainText,
                Body::new(error_msg),
            );
        }
    };

    // Validate the token.
    match mmds.is_valid_token(token) {
        true => respond_to_get_request(mmds, request),
        false => {
            METRICS.mmds.rx_invalid_token.inc();
            build_response(
                request.http_version(),
                StatusCode::Unauthorized,
                MediaType::PlainText,
                Body::new(VmmMmdsError::InvalidToken.to_string()),
            )
        }
    }
}

fn respond_to_get_request(mmds: &Mmds, request: Request) -> Response {
    let uri = request.uri().get_abs_path();

    // The data store expects a strict json path, so we need to
    // sanitize the URI.
    let json_path = sanitize_uri(uri.to_string());

    let content_type = request.headers.accept();

    match mmds.get_value(json_path, content_type.into()) {
        Ok(response_body) => build_response(
            request.http_version(),
            StatusCode::OK,
            content_type,
            Body::new(response_body),
        ),
        Err(err) => match err {
            MmdsError::NotFound => {
                let error_msg = VmmMmdsError::ResourceNotFound(String::from(uri)).to_string();
                build_response(
                    request.http_version(),
                    StatusCode::NotFound,
                    MediaType::PlainText,
                    Body::new(error_msg),
                )
            }
            MmdsError::UnsupportedValueType => build_response(
                request.http_version(),
                StatusCode::NotImplemented,
                MediaType::PlainText,
                Body::new(err.to_string()),
            ),
            MmdsError::DataStoreLimitExceeded => build_response(
                request.http_version(),
                StatusCode::PayloadTooLarge,
                MediaType::PlainText,
                Body::new(err.to_string()),
            ),
            _ => unreachable!(),
        },
    }
}

fn respond_to_put_request(mmds: &mut Mmds, request: Request) -> Response {
    let custom_headers = request.headers.custom_entries();

    // Reject `PUT` requests that contain `X-Forwarded-For` header.
    if let Some((header, _)) = get_header_value_pair(custom_headers, &[X_FORWARDED_FOR_HEADER]) {
        let error_msg =
            RequestError::HeaderError(HttpHeaderError::UnsupportedName(header.to_string()))
                .to_string();
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
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
            MediaType::PlainText,
            Body::new(error_msg),
        );
    }

    // Get token lifetime value.
    let (header, ttl_seconds) = match get_header_value_pair(
        custom_headers,
        &[
            X_METADATA_TOKEN_TTL_SECONDS_HEADER,
            X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER,
        ],
    ) {
        // Header found
        Some((header, value)) => match value.parse::<u32>() {
            Ok(ttl_seconds) => (header, ttl_seconds),
            Err(_) => {
                return build_response(
                    request.http_version(),
                    StatusCode::BadRequest,
                    MediaType::PlainText,
                    Body::new(
                        RequestError::HeaderError(HttpHeaderError::InvalidValue(
                            header.into(),
                            value.into(),
                        ))
                        .to_string(),
                    ),
                );
            }
        },
        // Header not found
        None => {
            return build_response(
                request.http_version(),
                StatusCode::BadRequest,
                MediaType::PlainText,
                Body::new(VmmMmdsError::NoTtlProvided.to_string()),
            );
        }
    };

    // Generate token.
    let result = mmds.generate_token(ttl_seconds);
    match result {
        Ok(token) => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::OK,
                MediaType::PlainText,
                Body::new(token),
            );
            let custom_headers = [(header.into(), ttl_seconds.to_string())].into();
            // Safe to unwrap because the header name and the value are valid as US-ASCII.
            // - `header` is either `X_METADATA_TOKEN_TTL_SECONDS_HEADER` or
            //   `X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER`.
            // - `ttl_seconds` is a decimal number between `MIN_TOKEN_TTL_SECONDS` and
            //   `MAX_TOKEN_TTL_SECONDS`.
            response.set_custom_headers(&custom_headers).unwrap();
            response
        }
        Err(err) => build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
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

    fn get_plain_text_data() -> &'static str {
        "age\nname/\nphones/"
    }

    fn generate_request_and_expected_response(
        request_bytes: &[u8],
        media_type: MediaType,
    ) -> (Request, Response) {
        let request = Request::try_from(request_bytes, None).unwrap();

        let mut response = Response::new(Version::Http10, StatusCode::OK);
        response.set_content_type(media_type);
        let body = match media_type {
            MediaType::ApplicationJson => {
                let mut body = get_json_data().to_string();
                body.retain(|c| !c.is_whitespace());
                body
            }
            MediaType::PlainText => get_plain_text_data().to_string(),
        };
        response.set_body(Body::new(body));

        (request, response)
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
    fn test_request_accept_header() {
        // This test validates the response `Content-Type` header and the response content for
        // various request `Accept` headers.

        // Populate MMDS with data.
        let mmds = populate_mmds();

        // Test without `Accept` header. micro-http defaults to `Accept: text/plain`.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\r\n",
            MediaType::PlainText,
        );
        assert_eq!(
            convert_to_response(mmds.clone(), request),
            expected_response
        );

        // Test with empty `Accept` header. micro-http defaults to `Accept: text/plain`.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\"
              Accept:\r\n\r\n",
            MediaType::PlainText,
        );
        assert_eq!(
            convert_to_response(mmds.clone(), request),
            expected_response
        );

        // Test with `Accept: */*` header.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\"
              Accept: */*\r\n\r\n",
            MediaType::PlainText,
        );
        assert_eq!(
            convert_to_response(mmds.clone(), request),
            expected_response
        );

        // Test with `Accept: text/plain`.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\
              Accept: text/plain\r\n\r\n",
            MediaType::PlainText,
        );
        assert_eq!(
            convert_to_response(mmds.clone(), request),
            expected_response
        );

        // Test with `Accept: application/json`.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\
              Accept: application/json\r\n\r\n",
            MediaType::ApplicationJson,
        );
        assert_eq!(convert_to_response(mmds, request), expected_response);
    }

    // Test the version-independent error paths of `convert_to_response()`.
    #[test]
    fn test_convert_to_response_negative() {
        for version in [MmdsVersion::V1, MmdsVersion::V2] {
            let mmds = populate_mmds();
            mmds.lock().expect("Poisoned lock").set_version(version);

            // Test InvalidURI (empty absolute path).
            let request = Request::try_from(b"GET http:// HTTP/1.0\r\n\r\n", None).unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(VmmMmdsError::InvalidURI.to_string()));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Test MethodNotAllowed (PATCH method).
            let request =
                Request::try_from(b"PATCH http://169.254.169.255/ HTTP/1.0\r\n\r\n", None).unwrap();
            let mut expected_response =
                Response::new(Version::Http10, StatusCode::MethodNotAllowed);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(VmmMmdsError::MethodNotAllowed.to_string()));
            expected_response.allow_method(Method::Get);
            expected_response.allow_method(Method::Put);
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
        }
    }

    #[test]
    fn test_respond_to_request_mmdsv1() {
        let mmds = populate_mmds();
        mmds.lock()
            .expect("Poisoned lock")
            .set_version(MmdsVersion::V1);

        // Test valid v1 GET request.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\
              Accept: application/json\r\n\r\n",
            MediaType::ApplicationJson,
        );
        let prev_rx_invalid_token = METRICS.mmds.rx_invalid_token.count();
        let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);
        assert_eq!(prev_rx_invalid_token, METRICS.mmds.rx_invalid_token.count());
        assert_eq!(prev_rx_no_token + 1, METRICS.mmds.rx_no_token.count());

        // Test valid PUT request to generate a valid token.
        let request = Request::try_from(
            b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
              X-metadata-token-ttl-seconds: 60\r\n\r\n",
            None,
        )
        .unwrap();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response.status(), StatusCode::OK);
        assert_eq!(actual_response.content_type(), MediaType::PlainText);
        let valid_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();

        // Test valid v2 GET request.
        #[rustfmt::skip]
        let (request, expected_response) = generate_request_and_expected_response(
            format!(
                "GET http://169.254.169.254/ HTTP/1.0\r\n\
                 Accept: application/json\r\n\
                 X-metadata-token: {valid_token}\r\n\r\n",
            )
            .as_bytes(),
            MediaType::ApplicationJson,
        );
        let prev_rx_invalid_token = METRICS.mmds.rx_invalid_token.count();
        let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);
        assert_eq!(prev_rx_invalid_token, METRICS.mmds.rx_invalid_token.count());
        assert_eq!(prev_rx_no_token, METRICS.mmds.rx_no_token.count());

        // Test GET request with invalid token is accepted when v1 is configured.
        let (request, expected_response) = generate_request_and_expected_response(
            b"GET http://169.254.169.254/ HTTP/1.0\r\n\
              Accept: application/json\r\n\
              X-metadata-token: INVALID_TOKEN\r\n\r\n",
            MediaType::ApplicationJson,
        );
        let prev_rx_invalid_token = METRICS.mmds.rx_invalid_token.count();
        let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
        let actual_response = convert_to_response(mmds, request);
        assert_eq!(actual_response, expected_response);
        assert_eq!(
            prev_rx_invalid_token + 1,
            METRICS.mmds.rx_invalid_token.count()
        );
        assert_eq!(prev_rx_no_token, METRICS.mmds.rx_no_token.count());
    }

    #[test]
    fn test_respond_to_request_mmdsv2() {
        let mmds = populate_mmds();
        mmds.lock()
            .expect("Poisoned lock")
            .set_version(MmdsVersion::V2);

        // Test valid PUT to generate a valid token.
        let request = Request::try_from(
            b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
              X-metadata-token-ttl-seconds: 60\r\n\r\n",
            None,
        )
        .unwrap();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response.status(), StatusCode::OK);
        assert_eq!(actual_response.content_type(), MediaType::PlainText);
        let valid_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();

        // Test valid GET.
        #[rustfmt::skip]
        let (request, expected_response) = generate_request_and_expected_response(
            format!(
                "GET http://169.254.169.254/ HTTP/1.0\r\n\
                 Accept: application/json\r\n\
                 X-metadata-token: {valid_token}\r\n\r\n",
            )
            .as_bytes(),
            MediaType::ApplicationJson,
        );
        let prev_rx_invalid_token = METRICS.mmds.rx_invalid_token.count();
        let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);
        assert_eq!(prev_rx_invalid_token, METRICS.mmds.rx_invalid_token.count());
        assert_eq!(prev_rx_no_token, METRICS.mmds.rx_no_token.count());

        // Test GET request without token should return Unauthorized status code.
        let request =
            Request::try_from(b"GET http://169.254.169.254/ HTTP/1.0\r\n\r\n", None).unwrap();
        let mut expected_response = Response::new(Version::Http10, StatusCode::Unauthorized);
        expected_response.set_content_type(MediaType::PlainText);
        expected_response.set_body(Body::new(VmmMmdsError::NoTokenProvided.to_string()));
        let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response, expected_response);
        assert_eq!(prev_rx_no_token + 1, METRICS.mmds.rx_no_token.count());

        // Create an expired token.
        let request = Request::try_from(
            b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
              X-metadata-token-ttl-seconds: 1\r\n\r\n",
            None,
        )
        .unwrap();
        let actual_response = convert_to_response(mmds.clone(), request);
        assert_eq!(actual_response.status(), StatusCode::OK);
        assert_eq!(actual_response.content_type(), MediaType::PlainText);
        let expired_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();
        std::thread::sleep(Duration::from_secs(1));

        // Test GET request with invalid tokens.
        let tokens = ["INVALID_TOKEN", &expired_token];
        for token in tokens.iter() {
            #[rustfmt::skip]
            let request = Request::try_from(
                format!(
                    "GET http://169.254.169.254/ HTTP/1.0\r\n\
                     X-metadata-token: {token}\r\n\r\n",
                )
                .as_bytes(),
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::Unauthorized);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(VmmMmdsError::InvalidToken.to_string()));
            let prev_rx_invalid_token = METRICS.mmds.rx_invalid_token.count();
            let prev_rx_no_token = METRICS.mmds.rx_no_token.count();
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
            assert_eq!(
                prev_rx_invalid_token + 1,
                METRICS.mmds.rx_invalid_token.count()
            );
            assert_eq!(prev_rx_no_token, METRICS.mmds.rx_no_token.count());
        }
    }

    // Test the version-independent parts of GET request
    #[test]
    fn test_respond_to_get_request() {
        for version in [MmdsVersion::V1, MmdsVersion::V2] {
            let mmds = populate_mmds();
            mmds.lock().expect("Poisoned lock").set_version(version);

            // Generate a token
            let request = Request::try_from(
                b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                  X-metadata-token-ttl-seconds: 60\r\n\r\n",
                None,
            )
            .unwrap();
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response.status(), StatusCode::OK);
            assert_eq!(actual_response.content_type(), MediaType::PlainText);
            let valid_token = String::from_utf8(actual_response.body().unwrap().body).unwrap();

            // Test invalid path
            #[rustfmt::skip]
            let request = Request::try_from(
                format!(
                    "GET http://169.254.169.254/invalid HTTP/1.0\r\n\
                     X-metadata-token: {valid_token}\r\n\r\n",
                )
                .as_bytes(),
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(
                VmmMmdsError::ResourceNotFound(String::from("/invalid")).to_string(),
            ));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Test unsupported type
            #[rustfmt::skip]
            let request = Request::try_from(
                format!(
                    "GET /age HTTP/1.1\r\n\
                     X-metadata-token: {valid_token}\r\n\r\n",
                )
                .as_bytes(),
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
            expected_response.set_content_type(MediaType::PlainText);
            let body = "Cannot retrieve value. The value has an unsupported type.".to_string();
            expected_response.set_body(Body::new(body));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Test invalid `X-metadata-token-ttl-seconds` value is ignored if not PUT request.
            #[rustfmt::skip]
            let (request, expected_response) = generate_request_and_expected_response(
                format!(
                    "GET http://169.254.169.254/ HTTP/1.0\r\n\
                     X-metadata-token: {valid_token}\r\n\
                     X-metadata-token-ttl-seconds: application/json\r\n\r\n",
                )
                .as_bytes(),
                MediaType::PlainText,
            );
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
        }
    }

    // Test PUT request (version-independent)
    #[test]
    fn test_respond_to_put_request() {
        for version in [MmdsVersion::V1, MmdsVersion::V2] {
            let mmds = populate_mmds();
            mmds.lock().expect("Poisoned lock").set_version(version);

            // Test valid PUT
            let request = Request::try_from(
                b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                  X-metadata-token-ttl-seconds: 60\r\n\r\n",
                None,
            )
            .unwrap();
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response.status(), StatusCode::OK);
            assert_eq!(actual_response.content_type(), MediaType::PlainText);
            assert_eq!(
                actual_response
                    .custom_headers()
                    .get("X-metadata-token-ttl-seconds")
                    .unwrap(),
                "60"
            );

            // Test unsupported `X-Forwarded-For` header
            for header in ["X-Forwarded-For", "x-forwarded-for", "X-fOrWaRdEd-FoR"] {
                #[rustfmt::skip]
                let request = Request::try_from(
                    format!(
                        "PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                         {header}: 203.0.113.195\r\n\r\n"
                    )
                    .as_bytes(),
                    None,
                )
                .unwrap();
                let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
                expected_response.set_content_type(MediaType::PlainText);
                expected_response.set_body(Body::new(format!(
                    "Invalid header. Reason: Unsupported header name. Key: {header}"
                )));
                let actual_response = convert_to_response(mmds.clone(), request);
                assert_eq!(actual_response, expected_response);
            }

            // Test invalid path
            let request = Request::try_from(
                b"PUT http://169.254.169.254/token HTTP/1.0\r\n\
                  X-metadata-token-ttl-seconds: 60\r\n\r\n",
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(
                VmmMmdsError::ResourceNotFound(String::from("/token")).to_string(),
            ));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Test non-numeric `X-metadata-token-ttl-seconds` value
            let request = Request::try_from(
                b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                  X-metadata-token-ttl-seconds: application/json\r\n\r\n",
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
            expected_response.set_content_type(MediaType::PlainText);
            #[rustfmt::skip]
            expected_response.set_body(Body::new(
                "Invalid header. Reason: Invalid value. \
                 Key:X-metadata-token-ttl-seconds; Value:application/json"
                    .to_string(),
            ));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);

            // Test out-of-range `X-metadata-token-ttl-seconds` value
            let invalid_values = [MIN_TOKEN_TTL_SECONDS - 1, MAX_TOKEN_TTL_SECONDS + 1];
            for invalid_value in invalid_values.iter() {
                #[rustfmt::skip]
                let request = Request::try_from(
                    format!(
                        "PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\
                         X-metadata-token-ttl-seconds: {invalid_value}\r\n\r\n",
                    )
                    .as_bytes(),
                    None,
                )
                .unwrap();
                let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
                expected_response.set_content_type(MediaType::PlainText);
                #[rustfmt::skip]
                let error_msg = format!(
                    "Invalid time to live value provided for token: {invalid_value}. \
                     Please provide a value between {MIN_TOKEN_TTL_SECONDS} and {MAX_TOKEN_TTL_SECONDS}.",
                );
                expected_response.set_body(Body::new(error_msg));
                let actual_response = convert_to_response(mmds.clone(), request);
                assert_eq!(actual_response, expected_response);
            }

            // Test lack of `X-metadata-token-ttl-seconds` header
            let request = Request::try_from(
                b"PUT http://169.254.169.254/latest/api/token HTTP/1.0\r\n\r\n",
                None,
            )
            .unwrap();
            let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
            expected_response.set_content_type(MediaType::PlainText);
            expected_response.set_body(Body::new(VmmMmdsError::NoTtlProvided.to_string()));
            let actual_response = convert_to_response(mmds.clone(), request);
            assert_eq!(actual_response, expected_response);
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
            "No MMDS token provided. Use `X-metadata-token` or `X-aws-ec2-metadata-token` header \
             to specify the session token."
        );

        assert_eq!(
            VmmMmdsError::NoTtlProvided.to_string(),
            "Token time to live value not found. Use `X-metadata-token-ttl-seconds` or \
             `X-aws-ec2-metadata-token-ttl-seconds` header to specify the token's lifetime."
        );

        assert_eq!(
            VmmMmdsError::ResourceNotFound(String::from("invalid/")).to_string(),
            "Resource not found: invalid/."
        )
    }
}
