// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod headers;

pub mod ascii {
    pub const CR: u8 = b'\r';
    pub const COLON: u8 = b':';
    pub const LF: u8 = b'\n';
    pub const SP: u8 = b' ';
}

/// Errors associated with parsing the HTTP Request from a u8 slice.
#[derive(Debug, PartialEq)]
pub enum RequestError {
    /// The HTTP Method is not supported or it is invalid.
    InvalidHttpMethod(&'static str),
    /// Cannot parse the Request Line due to invalid input.
    InvalidRequest,
    /// Request URI is invalid.
    InvalidUri(&'static str),
    /// The HTTP Version in the Request is not supported or it is invalid.
    InvalidHttpVersion(&'static str),
}

/// The Body associated with an HTTP Request or Response.
///
/// ## Examples
/// ```
/// extern crate micro_http;
/// use micro_http::Body;
/// let body = Body::new("This is a test body.".to_string());
/// assert_eq!(body.raw(), b"This is a test body.");
/// assert_eq!(body.len(), 20);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Body {
    body: Vec<u8>,
}

impl Body {
    /// Creates a new `Body` from a `String` input.
    pub fn new<T: Into<Vec<u8>>>(body: T) -> Self {
        Body { body: body.into() }
    }

    /// Returns the body as an `u8 slice`.
    pub fn raw(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Returns the length of the `Body`.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Checks if the body is empty, ie with zero length
    pub fn is_empty(&self) -> bool {
        self.body.len() == 0
    }
}

/// Supported HTTP Methods.
#[derive(Debug, PartialEq)]
pub enum Method {
    /// GET Method.
    Get,
}

impl Method {
    /// Returns a `Method` object if the parsing of `bytes` is successful.
    ///
    /// The method is case sensitive. A call to try_from with the input b"get" will return
    /// an error, but when using the input b"GET", it returns Method::Get.
    ///
    /// # Errors
    /// Returns `RequestError` if the method specified by `bytes` is unsupported.
    pub fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        match bytes {
            b"GET" => Ok(Method::Get),
            _ => Err(RequestError::InvalidHttpMethod("Unsupported HTTP method.")),
        }
    }

    /// Returns an `u8 slice` corresponding to the Method.
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
        }
    }
}

/// Supported HTTP Versions.
///
/// # Examples
/// ```
/// extern crate micro_http;
/// use micro_http::Version;
/// let version = Version::try_from(b"HTTP/1.1");
/// assert!(version.is_ok());
///
/// let version = Version::try_from(b"http/1.1");
/// assert!(version.is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl Version {
    /// HTTP Version as an `u8 slice`.
    pub fn raw(self) -> &'static [u8] {
        match self {
            Version::Http10 => b"HTTP/1.0",
            Version::Http11 => b"HTTP/1.1",
        }
    }

    /// Creates a new HTTP Version from an `u8 slice`.
    ///
    /// The supported versions are HTTP/1.0 and HTTP/1.1.
    /// The version is case sensitive and the accepted input is upper case.
    ///
    /// # Errors
    /// Returns a `RequestError` when the version is not supported.
    ///
    pub fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        match bytes {
            b"HTTP/1.0" => Ok(Version::Http10),
            b"HTTP/1.1" => Ok(Version::Http11),
            _ => Err(RequestError::InvalidHttpVersion(
                "Unsupported HTTP version.",
            )),
        }
    }

    /// Returns the default HTTP version = HTTP/1.1.
    pub fn default() -> Self {
        Version::Http11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // Tests for raw()
        assert_eq!(Version::Http10.raw(), b"HTTP/1.0");
        assert_eq!(Version::Http11.raw(), b"HTTP/1.1");

        // Tests for try_from()
        assert_eq!(Version::try_from(b"HTTP/1.0").unwrap(), Version::Http10);
        assert_eq!(Version::try_from(b"HTTP/1.1").unwrap(), Version::Http11);
        assert_eq!(
            Version::try_from(b"HTTP/2.0").unwrap_err(),
            RequestError::InvalidHttpVersion("Unsupported HTTP version.")
        );

        // Test for default()
        assert_eq!(Version::default(), Version::Http11);
    }

    #[test]
    fn test_method() {
        // Test for raw
        assert_eq!(Method::Get.raw(), b"GET");

        // Tests for try_from
        assert_eq!(Method::try_from(b"GET").unwrap(), Method::Get);
        assert_eq!(
            Method::try_from(b"PUT").unwrap_err(),
            RequestError::InvalidHttpMethod("Unsupported HTTP method.")
        );
    }
}
