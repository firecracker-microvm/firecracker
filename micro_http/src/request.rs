// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::from_utf8;

use common::ascii::{CR, LF, SP};
pub use common::RequestError;
use common::{Body, Method, Version};
use headers::Headers;

// Helper function used for parsing the HTTP Request.
// Splits the bytes in a pair containing the bytes before the separator and after the separator.
// The separator is not included in the return values.
fn split(bytes: &[u8], separator: u8) -> (&[u8], &[u8]) {
    for index in 0..bytes.len() {
        if bytes[index] == separator {
            if index + 1 < bytes.len() {
                return (&bytes[..index], &bytes[index + 1..]);
            } else {
                return (&bytes[..index], &[]);
            }
        }
    }

    return (&[], bytes);
}

/// Wrapper over HTTP URIs.
///
/// The `Uri` can not be used directly and it is only accessible from an HTTP Request.
#[derive(Clone, Debug, PartialEq)]
pub struct Uri<'a> {
    slice: &'a str,
}

impl<'a> Uri<'a> {
    fn new(slice: &'a str) -> Self {
        Uri { slice }
    }

    fn try_from(bytes: &'a [u8]) -> Result<Self, RequestError> {
        if bytes.len() == 0 {
            return Err(RequestError::InvalidUri("Empty URI not allowed."));
        }
        let utf8_slice =
            from_utf8(bytes).map_err(|_| RequestError::InvalidUri("Cannot parse URI as UTF-8."))?;
        Ok(Uri::new(utf8_slice))
    }

    /// Returns the absolute path of the `Uri`.
    ///
    /// URIs can be represented in absolute form or relative form. The absolute form includes
    /// the HTTP scheme, followed by the absolute path as follows:
    /// "http:" "//" host [ ":" port ] [ abs_path ]
    /// The relative URIs can be one of net_path | abs_path | rel_path.
    /// This method only handles absolute URIs and relative URIs specified by abs_path.
    /// The abs_path is expected to start with '/'.
    ///
    /// # Errors
    /// Returns an empty byte array when the host or the path are empty/invalid.
    ///
    pub fn get_abs_path(&self) -> &'a str {
        let http_scheme_prefix = "http://";
        if self.slice.starts_with(http_scheme_prefix) {
            if self.slice.len() == http_scheme_prefix.len() {
                return "";
            }
            // The host in this case includes the port and contains the bytes after http:// up to
            // the next '/'.
            let (host, _) = split(&self.slice.as_bytes()[http_scheme_prefix.len()..], b'/');
            if host.len() == 0 {
                return "";
            }
            let path_start_index = http_scheme_prefix.len() + host.len();
            return &self.slice[path_start_index..];
        } else {
            if self.slice.starts_with("/") {
                return &self.slice;
            }
            return "";
        }
    }
}

#[derive(Debug, PartialEq)]
struct RequestLine<'a> {
    method: Method,
    uri: Uri<'a>,
    http_version: Version,
}

impl<'a> RequestLine<'a> {
    fn remove_trailing_cr(version: &[u8]) -> &[u8] {
        if version.len() > 1 && version[version.len() - 1] == CR {
            return &version[..version.len() - 1];
        }

        version
    }

    fn parse_request_line(request_line: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let (method, remaining_bytes) = split(request_line, SP);
        let (uri, remaining_bytes) = split(remaining_bytes, SP);
        let (mut version, _) = split(remaining_bytes, LF);
        version = RequestLine::remove_trailing_cr(version);

        (method, uri, version)
    }

    fn try_from(request_line: &'a [u8]) -> Result<Self, RequestError> {
        let (method, uri, version) = RequestLine::parse_request_line(request_line);

        Ok(RequestLine {
            method: Method::try_from(method)?,
            uri: Uri::try_from(uri)?,
            http_version: Version::try_from(version)?,
        })
    }

    // Returns the minimum length of a valid request. The request must contain
    // the method (GET), the URI (minmum 1 character), the HTTP method(HTTP/DIGIT.DIGIT) and
    // 3 separators (SP/LF).
    fn min_len() -> usize {
        Method::Get.raw().len() + 1 + Version::Http10.raw().len() + 3
    }
}

/// Wrapper over an HTTP Request.
#[allow(unused)]
#[derive(Debug)]
pub struct Request<'a> {
    request_line: RequestLine<'a>,
    headers: Headers,
    body: Option<Body>,
}

impl<'a> Request<'a> {
    /// Parses a byte slice into a HTTP Request.
    ///
    /// The byte slice is expected to have the following format: </br>
    ///     * Request Line: "GET SP Request-uri SP HTTP/1.0 CRLF" - Mandatory </br>
    ///     * Request Headers "<headers> CRLF"- Optional </br>
    ///     * Entity Body - Optional </br>
    /// The request headers and the entity body is not parsed and None is returned because
    /// these are not used by the MMDS server.
    /// The only supported method is GET and the HTTP protocol is expected to be HTTP/1.0
    /// or HTTP/1.1.
    ///
    /// # Errors
    /// The function returns InvalidRequest when parsing the byte stream fails.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate micro_http;
    /// use micro_http::Request;
    ///
    /// let http_request = Request::try_from(b"GET http://localhost/home HTTP/1.0\r\n");
    /// ```
    pub fn try_from(byte_stream: &'a [u8]) -> Result<Self, RequestError> {
        // The first line of the request is the Request Line. The line ending is LF.
        let (request_line, _) = split(byte_stream, LF);
        if request_line.len() < RequestLine::min_len() {
            return Err(RequestError::InvalidRequest);
        }

        // The Request Line should include the trailing LF.
        let request_line = RequestLine::try_from(&byte_stream[..=request_line.len()])?;
        // We ignore the Headers and Entity body because we don't need them for MMDS requests.
        Ok(Request {
            request_line,
            headers: Headers::default(),
            body: None,
        })
    }

    /// Returns the `Uri` from the parsed `Request`.
    ///
    /// The return value can be used to get the absolute path of the URI.
    pub fn uri(&self) -> &Uri {
        &self.request_line.uri
    }

    /// Returns the HTTP `Version` of the `Request`.
    pub fn http_version(&self) -> Version {
        self.request_line.http_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<'a> PartialEq for Request<'a> {
        fn eq(&self, other: &Request) -> bool {
            // Ignore the other fields of Request for now because they are not used.
            return self.request_line == other.request_line;
        }
    }

    #[test]
    fn test_uri() {
        let uri = Uri::new("http://localhost/home");
        assert_eq!(uri.get_abs_path(), "/home");

        let uri = Uri::new("/home");
        assert_eq!(uri.get_abs_path(), "/home");

        let uri = Uri::new("home");
        assert_eq!(uri.get_abs_path(), "");

        let uri = Uri::new("http://");
        assert_eq!(uri.get_abs_path(), "");

        let uri = Uri::new("http://192.168.0.0");
        assert_eq!(uri.get_abs_path(), "");
    }

    #[test]
    fn test_into_request_line() {
        let expected_request_line = RequestLine {
            http_version: Version::Http10,
            method: Method::Get,
            uri: Uri::new("http://localhost/home"),
        };

        let request_line = b"GET http://localhost/home HTTP/1.0\r\n";
        match RequestLine::try_from(request_line) {
            Ok(request) => assert_eq!(request, expected_request_line),
            Err(_) => assert!(false),
        };

        let expected_request_line = RequestLine {
            http_version: Version::Http11,
            method: Method::Get,
            uri: Uri::new("http://localhost/home"),
        };

        // Happy case with request line ending in CRLF.
        let request_line = b"GET http://localhost/home HTTP/1.1\r\n";
        match RequestLine::try_from(request_line) {
            Ok(request) => assert_eq!(request, expected_request_line),
            Err(_) => assert!(false),
        };

        // Happy case with request line ending in LF instead of CRLF.
        let request_line = b"GET http://localhost/home HTTP/1.1\n";
        match RequestLine::try_from(request_line) {
            Ok(request) => assert_eq!(request, expected_request_line),
            Err(_) => assert!(false),
        };

        // Test for invalid method.
        let request_line = b"PUT http://localhost/home HTTP/1.0\r\n";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidHttpMethod("Unsupported HTTP method.")
        );

        // Test for invalid uri.
        let request_line = b"GET  HTTP/1.0\r\n";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidUri("Empty URI not allowed.")
        );

        // Test for invalid HTTP version.
        let request_line = b"GET http://localhost/home HTTP/2.0\r\n";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidHttpVersion("Unsupported HTTP version.")
        );
    }

    #[test]
    fn test_into_request() {
        let expected_request = Request {
            request_line: RequestLine {
                http_version: Version::Http10,
                method: Method::Get,
                uri: Uri::new("http://localhost/home"),
            },
            body: None,
            headers: Headers::default(),
        };
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n \
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT";
        let request = Request::try_from(request_bytes).unwrap();
        assert!(request == expected_request);
        assert_eq!(request.uri(), &Uri::new("http://localhost/home"));
        assert_eq!(request.http_version(), Version::Http10);

        // Test for invalid Request (length is less than minimum).
        let request_bytes = b"GET";
        assert_eq!(
            Request::try_from(request_bytes).unwrap_err(),
            RequestError::InvalidRequest
        );
    }
}
