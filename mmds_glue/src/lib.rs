extern crate data_model;
extern crate micro_http;

use data_model::mmds::{Error as MmdsError, MMDS};
use micro_http::{Body, Request, Response, StatusCode};

fn build_response(status_code: StatusCode, body: Body) -> Response {
    let mut response = Response::new(status_code);
    response.set_body(body);
    response
}

pub fn parse_request(request_bytes: &[u8]) -> Response {
    let request = Request::try_from(request_bytes);
    match request {
        Ok(request) => {
            let uri = request.get_uri();
            // Only accept URI that start with uri_prefix.
            // The instance metadata is available at the following uri, as specified in the
            // official documentation:
            // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
            let uri_prefix = "http://169.254.169.254";
            if !uri.starts_with(uri_prefix) {
                let error_msg = format!("Invalid URI: {}", uri);
                return build_response(StatusCode::BadRequest, Body::new(error_msg));
            }

            let mmds_uri = &uri[uri_prefix.len()..];
            // The lock can be held by one thread only, so it is safe to unwrap.
            let response = MMDS.lock().unwrap().get_value(mmds_uri.to_string());
            match response {
                Ok(response) => {
                    let response_body = response.join("\n");
                    build_response(StatusCode::OK, Body::new(response_body))
                }
                Err(e) => {
                    match e {
                        MmdsError::NotFound => {
                            // NotFound
                            let error_msg = format!("Resource not found: {}.", mmds_uri);
                            return build_response(StatusCode::NotFound, Body::new(error_msg));
                        }
                        MmdsError::UnsupportedValueType => {
                            // InternalServerError
                            let error_msg = format!(
                                "The resource {} has an invalid format.",
                                mmds_uri.to_string()
                            );
                            return build_response(
                                StatusCode::InternalServerError,
                                Body::new(error_msg),
                            );
                        }
                    }
                }
            }
        }
        Err(_) => {
            // All errors that come from parsing the request are BadRequest.
            // We will probably need to separate the errors in errors that map to BadRequest (400)
            // and to Internal Server Error (500).
            build_response(
                StatusCode::BadRequest,
                Body::new("Invalid request.".to_string()),
            )
        }
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
        let dummy_response = Response::new(StatusCode::BadRequest);
        assert!(parse_request(request).status() == dummy_response.status());

        // Test invalid URI.
        let request = b"GET http://169.254.169.255/ HTTP/1.0\r\n";
        let mut expected_response = Response::new(StatusCode::BadRequest);
        expected_response.set_body(Body::new(
            "Invalid URI: http://169.254.169.255/".to_string(),
        ));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());

        // Test resource not found.
        let request = b"GET http://169.254.169.254/invalid HTTP/1.0\r\n";
        let mut expected_response = Response::new(StatusCode::NotFound);
        expected_response.set_body(Body::new("Resource not found: /invalid.".to_string()));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());

        // Test Ok path.
        let request = b"GET http://169.254.169.254/ HTTP/1.0\r\n";
        let mut expected_response = Response::new(StatusCode::OK);
        let body = "age\nname/\nphones/".to_string();
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);

        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());

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
        let mut expected_response = Response::new(StatusCode::InternalServerError);
        let body = format!("The resource /age has an invalid format.");
        expected_response.set_body(Body::new(body));
        let actual_response = parse_request(request);
        assert!(expected_response.status() == actual_response.status());
        assert!(expected_response.body().unwrap() == actual_response.body().unwrap());
    }
}
