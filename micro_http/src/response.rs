// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error as WriteError, Write};

use ascii::{CR, LF, SP};
use common::{Body, Version};
use headers::{Header, Headers, MediaType};

/// Wrapper over a response status code.
///
/// The status code is defined as specified in the
/// [RFC](https://tools.ietf.org/html/rfc7231#section-6).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
pub enum StatusCode {
    /// 100, OK
    OK,
    /// 400, Bad Request
    BadRequest,
    /// 404, Not Found
    NotFound,
    /// 500, Internal Server Error
    InternalServerError,
    /// 501, Not Implemented
    NotImplemented,
}

impl StatusCode {
    fn raw(&self) -> &'static [u8; 3] {
        match self {
            StatusCode::OK => b"200",
            StatusCode::BadRequest => b"400",
            StatusCode::NotFound => b"404",
            StatusCode::InternalServerError => b"500",
            StatusCode::NotImplemented => b"501",
        }
    }
}

struct StatusLine {
    http_version: Version,
    status_code: StatusCode,
}

impl StatusLine {
    fn new(http_version: Version, status_code: StatusCode) -> Self {
        return StatusLine {
            http_version,
            status_code,
        };
    }

    fn write_all<T: Write>(&self, mut buf: T) -> Result<(), WriteError> {
        buf.write_all(self.http_version.raw())?;
        buf.write_all(&[SP])?;
        buf.write_all(self.status_code.raw())?;
        buf.write_all(&[SP, CR, LF])?;

        Ok(())
    }
}

/// Wrapper over an HTTP Response.
///
/// The Response is created using a `Version` and a `StatusCode`. When creating a Response object,
/// the body is initialize to `None`. The body can be updated with a call to `set_body`.
pub struct Response {
    status_line: StatusLine,
    headers: Headers,
    body: Option<Body>,
}

impl Response {
    /// Creates a new HTTP `Response` with an empty body.
    pub fn new(http_version: Version, status_code: StatusCode) -> Response {
        return Response {
            status_line: StatusLine::new(http_version, status_code),
            headers: Headers::default(),
            body: None,
        };
    }

    /// Updates the body of the `Response`.
    ///
    /// This function has side effects because it also updates the headers:
    /// - `ContentLength`: this is set to the length of the specified body.
    /// - `MediaType`: this is set to "text/plain".
    pub fn set_body(&mut self, body: Body) {
        self.headers
            .add(Header::ContentLength, body.len().to_string());
        self.headers.add(
            Header::ContentType,
            String::from(MediaType::PlainText.as_str()),
        );
        self.body = Some(body);
    }

    fn write_body<T: Write>(&self, mut buf: T) -> Result<(), WriteError> {
        if let Some(ref body) = self.body {
            buf.write_all(body.raw())?;
        }
        Ok(())
    }

    /// Writes the content of the `Response` to the specified `buf`.
    ///
    /// # Errors
    /// Returns an error when the buffer is not large enough.
    pub fn write_all<T: Write>(&self, mut buf: &mut T) -> Result<(), WriteError> {
        self.status_line.write_all(&mut buf)?;
        self.headers.write_all(&mut buf)?;
        self.write_body(&mut buf)?;

        Ok(())
    }

    /// Returns the Status Code of the Response.
    pub fn status(&self) -> StatusCode {
        self.status_line.status_code
    }

    /// Returns the Body of the response. If the response does not have a body,
    /// it returns None.
    pub fn body(&self) -> Option<Body> {
        self.body.clone()
    }

    /// Returns the HTTP Version of the response.
    pub fn http_version(&self) -> Version {
        self.status_line.http_version.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_response() {
        let mut response = Response::new(Version::Http10, StatusCode::OK);
        let body = "This is a test";
        response.set_body(Body::new(body));

        assert!(response.status() == StatusCode::OK);
        assert_eq!(response.body().unwrap(), Body::new(body));
        assert_eq!(response.http_version(), Version::Http10);

        // Headers can be in either order.
        let expected_response_1: &'static [u8] = b"HTTP/1.0 200 \r\n\
            Content-Type: text/plain\r\n\
            Content-Length: 14\r\n\r\n\
            This is a test";

        let expected_response_2: &'static [u8] = b"HTTP/1.0 200 \r\n\
            Content-Length: 14\r\n\
            Content-Type: text/plain\r\n\r\n\
            This is a test";

        let mut response_buf: [u8; 77] = [0; 77];
        assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
        assert!(
            response_buf.as_ref() == expected_response_1
                || response_buf.as_ref() == expected_response_2
        );

        // Test write failed.
        let mut response_buf: [u8; 1] = [0; 1];
        assert!(response.write_all(&mut response_buf.as_mut()).is_err());
    }

    #[test]
    fn test_status_code() {
        assert_eq!(StatusCode::OK.raw(), b"200");
        assert_eq!(StatusCode::BadRequest.raw(), b"400");
        assert_eq!(StatusCode::NotFound.raw(), b"404");
        assert_eq!(StatusCode::InternalServerError.raw(), b"500");
        assert_eq!(StatusCode::NotImplemented.raw(), b"501");
    }
}
