extern crate data_model;
extern crate micro_http;

use data_model::mmds::{Error as MmdsError, MMDS};
use micro_http::{Body, Request, RequestError, Response, StatusCode, Version};

use std::str::from_utf8;

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
            if uri.len() == 0 {
                return build_response(
                    request.http_version(),
                    StatusCode::BadRequest,
                    Body::new("Invalid URI.".to_string()),
                );
            }

            // We ensure that the URI is UTF-8 when creating the request.
            let uri_utf8 = from_utf8(uri).unwrap();

            // The lock can be held by one thread only, so it is safe to unwrap.
            // If another thread poisened the lock, we abort the execution.
            let response = MMDS.lock().unwrap().get_value(uri_utf8.to_string());
            match response {
                Ok(response) => {
                    let response_body = response.join("\n");
                    build_response(
                        request.http_version(),
                        StatusCode::OK,
                        Body::new(response_body),
                    )
                }
                Err(e) => {
                    match e {
                        MmdsError::NotFound => {
                            // NotFound
                            let error_msg = format!("Resource not found: {}.", uri_utf8);
                            return build_response(
                                request.http_version(),
                                StatusCode::NotFound,
                                Body::new(error_msg),
                            );
                        }
                        MmdsError::UnsupportedValueType => {
                            // InternalServerError
                            let error_msg = format!(
                                "The resource {} has an invalid format.",
                                uri_utf8.to_string()
                            );
                            return build_response(
                                request.http_version(),
                                StatusCode::InternalServerError,
                                Body::new(error_msg),
                            );
                        }
                    }
                }
            }
        }
        Err(e) => match e {
            RequestError::InvalidHttpVersion(err_msg) => build_response(
                Version::default(),
                StatusCode::NotImplemented,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidUri(err_msg) | RequestError::InvalidHttpMethod(err_msg) => {
                build_response(
                    Version::default(),
                    StatusCode::BadRequest,
                    Body::new(err_msg.to_string()),
                )
            }
            RequestError::InvalidRequest => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new("Invalid request.".to_string()),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::*;

    #[test]
    fn test_parse_request() {
        let data = r#"{
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
        }"#;
        MMDS.lock()
            .unwrap()
            .put_data(serde_json::from_str(data).unwrap());

        // Test invalid request.
        let request = b"HTTP/1.1";
        let dummy_response = Response::new(Version::Http11, StatusCode::BadRequest);
        assert!(parse_request(request).status() == dummy_response.status());

        // Test unsupported HTTP version.
        let request = b"GET http://169.254.169.255/ HTTP/2.0\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        expected_response.set_body(Body::new("Unsupported HTTP version.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test invalid HTTP Method.
        let request = b"PUT http://169.254.169.255/ HTTP/1.0\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Unsupported HTTP method.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test invalid (empty absolute path) URI.
        let request = b"GET http:// HTTP/1.0\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Invalid URI.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test resource not found.
        let request = b"GET http://169.254.169.254/invalid HTTP/1.0\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::NotFound);
        expected_response.set_body(Body::new("Resource not found: /invalid.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test Ok path.
        let request = b"GET http://169.254.169.254/ HTTP/1.0\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::OK);
        let body = "age\nname/\nphones/".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        let request = b"GET /age HTTP/1.1\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::OK);
        let body = "43".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());

        // Test Internal Server Error.
        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": 43
        }"#;
        MMDS.lock()
            .unwrap()
            .put_data(serde_json::from_str(data).unwrap());

        let request = b"GET http://169.254.169.254/age HTTP/1.0\r\n";
        let mut expected_response = Response::new(Version::Http10, StatusCode::InternalServerError);
        let body = format!("The resource /age has an invalid format.");
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);
        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
        assert!(expected_response.http_version() == actual_response.http_version());
    }
}
