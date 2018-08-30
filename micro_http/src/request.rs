use std::str::from_utf8;

use common::ascii::{CR, LF, SP};
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

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidRequest,
}

#[derive(Clone, PartialEq)]
struct Uri<'a> {
    bytes: &'a [u8],
}

impl<'a> Uri<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Uri { bytes }
    }
}

#[derive(PartialEq)]
struct RequestLine<'a> {
    method: Method,
    uri: Uri<'a>,
    http_version: Version,
}

impl<'a> RequestLine<'a> {
    fn try_from(request_line: &'a[u8]) -> Result<Self, Error> {
        let (method, remaining_bytes) = split(request_line, SP);
        if method != Method::Get.raw() {
            return Err(Error::InvalidRequest);
        }

        let (uri, remaining_bytes) = split(remaining_bytes, SP);
        // TODO add some more validation to the URI.
        if uri.len() == 0 {
            return Err(Error::InvalidRequest);
        }
        if from_utf8(uri).is_err() {
            // TODO: return UTF8 error.
            return Err(Error::InvalidRequest);
        }
        // TODO add some more validation to the URI.

        let (mut version, _) = split(remaining_bytes, LF);
        // If the version ends with \r, we need to strip it.
        if version.len() > 1 && version[version.len() - 1] == CR {
            version = &version[..version.len() - 1]
        }
        if version != Version::Http10.raw() {
            return Err(Error::InvalidRequest);
        }

        Ok(RequestLine {
            method: Method::Get,
            uri: Uri::new(uri),
            http_version: Version::Http10,
        })
    }

    // Returns the minimum length of a valid request. The request must contain
    // the method (GET), the URI (minmum 1 character), the HTTP method(HTTP/DIGIT.DIGIT) and
    // 3 separators (SP/LF).
    fn min_len() -> usize {
        Method::Get.raw().len() + 1 + Version::Http10.raw().len() + 3
    }
}

#[allow(unused)]
pub struct Request<'a> {
    request_line: RequestLine<'a>,
    headers: Headers,
    body: Option<Body>,
}

impl<'a> Request<'a> {
    /// Parses a byte slice into a HTTP Request.
    /// The byte slice is expected to have the following format: </br>
    ///     * Request Line: "GET SP Request-uri SP HTTP/1.0 CRLF" - Mandatory </br>
    ///     * Request Headers "<headers> CRLF"- Optional </br>
    ///     * Entity Body - Optional </br>
    /// The request headers and the entity body is not parsed and None is returned because
    /// these are not used by the MMDS server.
    /// The only supported method is GET and the HTTP protocol is expected to be HTTP/1.0.
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
    ///
    pub fn try_from(byte_stream: &'a [u8]) -> Result<Self, Error> {
        // The first line of the request is the Request Line. The line ending is LF.
        let (request_line, _) = split(byte_stream, LF);
        if request_line.len() < RequestLine::min_len() {
            return Err(Error::InvalidRequest);
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

    pub fn get_uri_utf8(&self) -> &str {
        // Safe to unwrap because we validate the URI when creating the Request Line.
        from_utf8(self.request_line.uri.bytes).unwrap()
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
    fn test_into_request_line() {
        let expected_request_line = RequestLine {
            http_version: Version::Http10,
            method: Method::Get,
            uri: Uri::new(b"http://localhost/home"),
        };

        let request_line = b"GET http://localhost/home HTTP/1.0\r\n";
        match RequestLine::try_from(request_line) {
            Ok(request) => assert!(request == expected_request_line),
            Err(_) => assert!(false),
        };

        // Test for invalid method.
        let request_line = b"PUT http://localhost/home HTTP/1.0\r\n";
        assert!(RequestLine::try_from(request_line).is_err());

        // Test for invalid uri.
        let request_line = b"GET  HTTP/1.0\r\n";
        assert!(RequestLine::try_from(request_line).is_err());

        // Test for invalid HTTP version.
        let request_line = b"GET http://localhost/home HTTP/2.0\r\n";
        assert!(RequestLine::try_from(request_line).is_err());
    }

    #[test]
    fn test_into_request() {
        let expected_request = Request {
            request_line: RequestLine {
                http_version: Version::Http10,
                method: Method::Get,
                uri: Uri::new(b"http://localhost/home"),
            },
            body: None,
            headers: Headers::default(),
        };
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n \
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT";
        assert!(Request::try_from(request_bytes) == Ok(expected_request));
    }
}
