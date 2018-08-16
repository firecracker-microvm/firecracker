use common::{Body, Method, Version};
use headers::Headers;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidRequest,
}

#[derive(PartialEq)]
struct RequestLine {
    method: Method,
    uri: String,
    http_version: Version,
}

impl RequestLine {
    fn try_from(byte_stream: &[u8]) -> Result<Self, Error> {
        let method_len = helpers::request_line::check_method(byte_stream)?;
        let version_len = helpers::request_line::check_http_version(byte_stream)?;

        let request_uri =
            helpers::request_line::get_request_uri(byte_stream, method_len, version_len)?;

        Ok(RequestLine {
            http_version: Version::Http10,
            method: Method::Get,
            uri: request_uri,
        })
    }
}

#[allow(unused)]
pub struct Request {
    request_line: RequestLine,
    headers: Headers,
    body: Option<Body>,
}

impl Request {
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
    pub fn try_from(byte_stream: &[u8]) -> Result<Self, Error> {
        // The first line of the request is the Request Line. The line ending is LF.
        let lf_pos = helpers::request::get_first_lf(byte_stream)?;

        // The Request Line should include the trailing LF.
        let request_line = RequestLine::try_from(&byte_stream[0..=lf_pos])?;
        // We ignore the Headers and Entity body because we don't need them for MMDS requests.
        Ok(Request {
            request_line,
            headers: Headers::default(),
            body: None,
        })
    }

    pub fn get_uri(&self) -> String {
        self.request_line.uri.clone()
    }
}

mod helpers {
    use super::{Error, Method, Version};
    use ascii::{CRLF, LF, SP};

    // Module used for grouping functions that parse a Request.
    pub mod request {
        use super::*;

        // Helper function that returns the first position of the LF character in a u8 slice.
        // Returns Error::InvalidRequest if LF is not found.
        pub fn get_first_lf(byte_stream: &[u8]) -> Result<usize, Error> {
            for i in 0..byte_stream.len() {
                if byte_stream[i] == LF[0] {
                    return Ok(i);
                }
            }
            return Err(Error::InvalidRequest);
        }
    }

    // Module used for grouping functions that parse a RequestLine.
    pub mod request_line {
        use super::*;
        use std;

        // Checks that the HTTP method is correct (only GET is supported).
        // When the method is correct, returns the length of the method + 1, where the additional 1
        // is the length of SP character.
        pub fn check_method(byte_stream: &[u8]) -> Result<usize, Error> {
            // The first 3 characters from the request line should be the method.
            // We only support GET requests. Check that the first three letters are GET, followed
            // by SP.
            let request_line_prefix = [Method::Get.raw(), SP].concat();

            if byte_stream.starts_with(request_line_prefix.as_slice()) {
                return Ok(request_line_prefix.len());
            }

            return Err(Error::InvalidRequest);
        }

        // Checks that the HTTP version is 1.0. When the version is correct, it returns the length
        // of the suffix defined as "SP HTTP_Version CRLF/LF".
        pub fn check_http_version(byte_stream: &[u8]) -> Result<usize, Error> {
            let http_version = Version::Http10.raw();

            let line_suffix_with_crlf = [SP, http_version.clone(), CRLF].concat();
            let line_suffix_with_lf = [SP, http_version, LF].concat();

            if byte_stream.ends_with(line_suffix_with_crlf.as_slice()) {
                return Ok(line_suffix_with_crlf.len());
            }

            if byte_stream.ends_with(line_suffix_with_lf.as_slice()) {
                return Ok(line_suffix_with_lf.len());
            }

            return Err(Error::InvalidRequest);
        }

        // Returns the request URI.
        // The prefix should be GET SP and the suffix one of SP HTTP/1.0 CRLF or SP HTTP/1.0 LF.
        // TODO: we need some validation of the URI.
        pub fn get_request_uri(
            byte_stream: &[u8],
            prefix_len: usize,
            suffix_len: usize,
        ) -> Result<String, Error> {
            if prefix_len + suffix_len >= byte_stream.len() {
                return Err(Error::InvalidRequest);
            }

            match std::str::from_utf8(&byte_stream[prefix_len..(byte_stream.len() - suffix_len)]) {
                Ok(request_uri) => Ok(String::from(request_uri)),
                Err(_) => Err(Error::InvalidRequest),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::helpers::request_line::{check_http_version, check_method, get_request_uri};
    use super::*;

    impl PartialEq for Request {
        fn eq(&self, other: &Request) -> bool {
            // Ignore the other fields of Request for now because they are not used.
            return self.request_line == other.request_line;
        }
    }

    #[test]
    fn test_check_http_method() {
        let request_line = b"GET http://localhost/home HTTP/1.0\r\n";
        match check_method(request_line) {
            Ok(len) => assert_eq!(len, 4),
            Err(_) => assert!(false),
        };

        let request_line = b"PUT http://localhost/home HTTP/1.0\r\n";
        assert!(check_method(request_line).is_err());

        assert!(check_method(b"").is_err());
    }

    #[test]
    fn test_check_http_version() {
        // Test CRLF ending for Request Line.
        let request_line = b"GET http://localhost/home HTTP/1.0\r\n";
        let expected_http_version = b" HTTP/1.0\r\n";
        match check_http_version(request_line) {
            Ok(val) => assert_eq!(val, expected_http_version.len()),
            Err(_) => assert!(false),
        };

        // Test LF ending for Request Line.
        let request_line = b"GET http://localhost/home HTTP/1.0\n";
        let expected_http_version = b" HTTP/1.0\n";
        match check_http_version(request_line) {
            Ok(val) => assert_eq!(val, expected_http_version.len()),
            Err(_) => assert!(false),
        };

        // Test Invalid HTTP version.
        let request_line = b"GET http://localhost/home HTTP/1.1\n";
        match check_http_version(request_line) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, Error::InvalidRequest),
        };

        assert!(check_http_version(b"").is_err());
    }

    #[test]
    fn test_get_request_uri() {
        let request_line = b"GET http://localhost/home HTTP/1.0\r\n";
        let prefix = b"GET ";
        let suffix = b" HTTP/1.0\r\n";
        let request_uri = String::from("http://localhost/home");

        match get_request_uri(request_line, prefix.len(), suffix.len()) {
            Ok(req_uri) => assert_eq!(req_uri, request_uri),
            Err(_) => assert!(false),
        };

        assert!(get_request_uri(request_line, 50, 50).is_err());
    }

    #[test]
    fn test_into_request_line() {
        let expected_request_line = RequestLine {
            http_version: Version::Http10,
            method: Method::Get,
            uri: String::from("http://localhost/home"),
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
                uri: String::from("http://localhost/home"),
            },
            body: None,
            headers: Headers::default(),
        };
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n \
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT";
        assert!(Request::try_from(request_bytes) == Ok(expected_request));
    }
}
