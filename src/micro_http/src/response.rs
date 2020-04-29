// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error as WriteError, Write};

use ascii::{COLON, CR, LF, SP};
use common::{Body, Version};
use headers::{Header, MediaType};
use Method;

/// Wrapper over a response status code.
///
/// The status code is defined as specified in the
/// [RFC](https://tools.ietf.org/html/rfc7231#section-6).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StatusCode {
    /// 100, Continue
    Continue,
    /// 200, OK
    OK,
    /// 204, No Content
    NoContent,
    /// 400, Bad Request
    BadRequest,
    /// 404, Not Found
    NotFound,
    /// 405, Method Not Allowed
    MethodNotAllowed,
    /// 500, Internal Server Error
    InternalServerError,
    /// 501, Not Implemented
    NotImplemented,
}

impl StatusCode {
    /// Returns the status code as bytes.
    pub fn raw(self) -> &'static [u8; 3] {
        match self {
            Self::Continue => b"100",
            Self::OK => b"200",
            Self::NoContent => b"204",
            Self::BadRequest => b"400",
            Self::NotFound => b"404",
            Self::MethodNotAllowed => b"405",
            Self::InternalServerError => b"500",
            Self::NotImplemented => b"501",
        }
    }
}

struct StatusLine {
    http_version: Version,
    status_code: StatusCode,
}

impl StatusLine {
    fn new(http_version: Version, status_code: StatusCode) -> Self {
        Self {
            http_version,
            status_code,
        }
    }

    fn write_all<T: Write>(&self, mut buf: T) -> Result<(), WriteError> {
        buf.write_all(self.http_version.raw())?;
        buf.write_all(&[SP])?;
        buf.write_all(self.status_code.raw())?;
        buf.write_all(&[SP, CR, LF])?;

        Ok(())
    }
}

/// Wrapper over the list of headers associated with a HTTP Response.
/// When creating a ResponseHeaders object, the content type is initialized to `text/plain`.
/// The content type can be updated with a call to `set_content_type`.
pub struct ResponseHeaders {
    content_length: i32,
    content_type: MediaType,
    server: String,
    allow: Vec<Method>,
}

impl Default for ResponseHeaders {
    fn default() -> Self {
        Self {
            content_length: Default::default(),
            content_type: Default::default(),
            server: String::from("Firecracker API"),
            allow: Vec::new(),
        }
    }
}

impl ResponseHeaders {
    // The logic pertaining to `Allow` header writing.
    fn write_allow_header<T: Write>(&self, buf: &mut T) -> Result<(), WriteError> {
        if self.allow.is_empty() {
            return Ok(());
        }

        buf.write_all(b"Allow: ")?;

        let delimitator = b", ";
        for (idx, method) in self.allow.iter().enumerate() {
            buf.write_all(method.raw())?;
            if idx < self.allow.len() - 1 {
                buf.write_all(delimitator)?;
            }
        }

        buf.write_all(&[CR, LF])
    }

    /// Writes the headers to `buf` using the HTTP specification.
    pub fn write_all<T: Write>(&self, buf: &mut T) -> Result<(), WriteError> {
        buf.write_all(Header::Server.raw())?;
        buf.write_all(&[COLON, SP])?;
        buf.write_all(self.server.as_bytes())?;

        buf.write_all(&[CR, LF])?;
        buf.write_all(b"Connection: keep-alive")?;
        buf.write_all(&[CR, LF])?;

        self.write_allow_header(buf)?;

        if self.content_length != 0 {
            buf.write_all(Header::ContentType.raw())?;
            buf.write_all(&[COLON, SP])?;
            buf.write_all(self.content_type.as_str().as_bytes())?;
            buf.write_all(&[CR, LF])?;

            buf.write_all(Header::ContentLength.raw())?;
            buf.write_all(&[COLON, SP])?;
            buf.write_all(self.content_length.to_string().as_bytes())?;
            buf.write_all(&[CR, LF])?;
        }

        buf.write_all(&[CR, LF])
    }

    // Sets the content length to be written in the HTTP response.
    fn set_content_length(&mut self, content_length: i32) {
        self.content_length = content_length;
    }

    /// Sets the HTTP response header server.
    pub fn set_server(&mut self, server: &str) {
        self.server = String::from(server);
    }

    /// Sets the content type to be written in the HTTP response.
    #[allow(unused)]
    pub fn set_content_type(&mut self, content_type: MediaType) {
        self.content_type = content_type;
    }
}

/// Wrapper over an HTTP Response.
///
/// The Response is created using a `Version` and a `StatusCode`. When creating a Response object,
/// the body is initialized to `None` and the header is initialized with the `default` value. The body
/// can be updated with a call to `set_body`. The header can be updated with `set_content_type` and
/// `set_server`.
pub struct Response {
    status_line: StatusLine,
    headers: ResponseHeaders,
    body: Option<Body>,
}

impl Response {
    /// Creates a new HTTP `Response` with an empty body.
    pub fn new(http_version: Version, status_code: StatusCode) -> Self {
        Self {
            status_line: StatusLine::new(http_version, status_code),
            headers: ResponseHeaders::default(),
            body: Default::default(),
        }
    }

    /// Updates the body of the `Response`.
    ///
    /// This function has side effects because it also updates the headers:
    /// - `ContentLength`: this is set to the length of the specified body.
    pub fn set_body(&mut self, body: Body) {
        self.headers.set_content_length(body.len() as i32);
        self.body = Some(body);
    }

    /// Updates the content type of the `Response`.
    pub fn set_content_type(&mut self, content_type: MediaType) {
        self.headers.set_content_type(content_type);
    }

    /// Sets the HTTP response server.
    pub fn set_server(&mut self, server: &str) {
        self.headers.set_server(server);
    }

    /// Sets the HTTP allowed methods.
    pub fn set_allow(&mut self, methods: Vec<Method>) {
        self.headers.allow = methods;
    }

    /// Allows a specific HTTP method.
    pub fn allow_method(&mut self, method: Method) {
        self.headers.allow.push(method);
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
    pub fn content_length(&self) -> i32 {
        self.headers.content_length
    }

    /// Returns the HTTP Version of the response.
    pub fn content_type(&self) -> MediaType {
        self.headers.content_type
    }

    /// Returns the HTTP Version of the response.
    pub fn http_version(&self) -> Version {
        self.status_line.http_version
    }

    /// Returns the allowed HTTP methods.
    pub fn allow(&self) -> Vec<Method> {
        self.headers.allow.clone()
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
        response.set_content_type(MediaType::PlainText);

        assert!(response.status() == StatusCode::OK);
        assert_eq!(response.body().unwrap(), Body::new(body));
        assert_eq!(response.http_version(), Version::Http10);
        assert_eq!(response.content_length(), 14);
        assert_eq!(response.content_type(), MediaType::PlainText);

        let expected_response: &'static [u8] = b"HTTP/1.0 200 \r\n\
            Server: Firecracker API\r\n\
            Connection: keep-alive\r\n\
            Content-Type: text/plain\r\n\
            Content-Length: 14\r\n\r\n\
            This is a test";

        let mut response_buf: [u8; 126] = [0; 126];
        assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
        assert!(response_buf.as_ref() == expected_response);

        // Test response `Allow` header.
        let mut response = Response::new(Version::Http10, StatusCode::OK);
        let allowed_methods = vec![Method::Get, Method::Patch, Method::Put];
        response.set_allow(allowed_methods.clone());
        assert_eq!(response.allow(), allowed_methods);

        let expected_response: &'static [u8] = b"HTTP/1.0 200 \r\n\
            Server: Firecracker API\r\n\
            Connection: keep-alive\r\n\
            Allow: GET, PATCH, PUT\r\n\r\n";
        let mut response_buf: [u8; 90] = [0; 90];
        assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
        assert_eq!(response_buf.as_ref(), expected_response);

        // Test write failed.
        let mut response_buf: [u8; 1] = [0; 1];
        assert!(response.write_all(&mut response_buf.as_mut()).is_err());
    }

    #[test]
    fn test_set_server() {
        let mut response = Response::new(Version::Http10, StatusCode::OK);
        let body = "This is a test";
        let server = "rust-vmm API";
        response.set_body(Body::new(body));
        response.set_content_type(MediaType::PlainText);
        response.set_server(server);

        assert!(response.status() == StatusCode::OK);
        assert_eq!(response.body().unwrap(), Body::new(body));
        assert_eq!(response.http_version(), Version::Http10);
        assert_eq!(response.content_length(), 14);
        assert_eq!(response.content_type(), MediaType::PlainText);

        let expected_response = format!(
            "HTTP/1.0 200 \r\n\
             Server: {}\r\n\
             Connection: keep-alive\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: 14\r\n\r\n\
             This is a test",
            server
        );

        let mut response_buf: [u8; 123] = [0; 123];
        assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
        assert!(response_buf.as_ref() == expected_response.as_bytes());
    }

    #[test]
    fn test_status_code() {
        assert_eq!(StatusCode::Continue.raw(), b"100");
        assert_eq!(StatusCode::OK.raw(), b"200");
        assert_eq!(StatusCode::NoContent.raw(), b"204");
        assert_eq!(StatusCode::BadRequest.raw(), b"400");
        assert_eq!(StatusCode::NotFound.raw(), b"404");
        assert_eq!(StatusCode::MethodNotAllowed.raw(), b"405");
        assert_eq!(StatusCode::InternalServerError.raw(), b"500");
        assert_eq!(StatusCode::NotImplemented.raw(), b"501");
    }

    #[test]
    fn test_allow_method() {
        let mut response = Response::new(Version::Http10, StatusCode::MethodNotAllowed);
        response.allow_method(Method::Get);
        response.allow_method(Method::Put);
        assert_eq!(response.allow(), vec![Method::Get, Method::Put]);
    }
}
