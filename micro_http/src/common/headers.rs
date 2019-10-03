// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result::Result;

use RequestError;

/// Wrapper over an HTTP Header type.
#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Header {
    /// Header `Content-Length`.
    ContentLength,
    /// Header `Content-Type`.
    ContentType,
    /// Header `Expect`.
    Expect,
    /// Header `Transfer-Encoding`.
    TransferEncoding,
    /// Header `Server`.
    Server,
}

impl Header {
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Header::ContentLength => b"Content-Length",
            Header::ContentType => b"Content-Type",
            Header::Expect => b"Expect",
            Header::TransferEncoding => b"Transfer-Encoding",
            Header::Server => b"Server",
        }
    }

    fn try_from(string: &[u8]) -> Result<Self, RequestError> {
        if let Ok(utf8_string) = String::from_utf8(string.to_vec()) {
            match utf8_string.trim() {
                "Content-Length" => Ok(Header::ContentLength),
                "Content-Type" => Ok(Header::ContentType),
                "Expect" => Ok(Header::Expect),
                "Transfer-Encoding" => Ok(Header::TransferEncoding),
                "Server" => Ok(Header::Server),
                _ => Err(RequestError::InvalidHeader),
            }
        } else {
            Err(RequestError::InvalidRequest)
        }
    }
}

/// Wrapper over the list of headers associated with a Request that we need
/// in order to parse the request correctly and be able to respond to it.
///
/// The only `Content-Type`s supported are `text/plain` and `application/json`, which are both
/// in plain text actually and don't influence our parsing process.
///
/// All the other possible header fields are not necessary in order to serve this connection
/// and, thus, are not of interest to us. However, we still look for header fields that might
/// invalidate our request as we don't support the full set of HTTP/1.1 specification.
/// Such header entries are "Transfer-Encoding: identity; q=0", which means a compression
/// algorithm is applied to the body of the request, or "Expect: 103-checkpoint".
#[derive(Debug)]
pub struct Headers {
    /// The `Content-Length` header field tells us how many bytes we need to receive
    /// from the source after the headers.
    content_length: i32,
    /// The `Expect` header field is set when the headers contain the entry "Expect: 100-continue".
    /// This means that, per HTTP/1.1 specifications, we must send a response with the status code
    /// 100 after we have received the headers in order to receive the body of the request. This
    /// field should be known immediately after parsing the headers.
    expect: bool,
    /// `Chunked` is a possible value of the `Transfer-Encoding` header field and every HTTP/1.1
    /// server must support it. It is useful only when receiving the body of the request and should
    /// be known immediately after parsing the headers.
    chunked: bool,
}

impl Headers {
    /// By default Requests are created with no headers.
    pub fn default() -> Headers {
        Headers {
            content_length: 0,
            expect: false,
            chunked: false,
        }
    }

    /// Expects one header line and parses it, updating the header structure or returning an
    /// error if the header is invalid.
    ///
    /// # Errors
    /// `UnsupportedHeader` is returned when the parsed header line is not of interest
    /// to us or when it is unrecognizable.
    /// `InvalidHeader` is returned when the parsed header is formatted incorrectly or suggests
    /// that the client is using HTTP features that we do not support in this implementation,
    /// which invalidates the request.
    pub fn parse_header_line(&mut self, header_line: &[u8]) -> Result<(), RequestError> {
        // Headers must be ASCII, so also UTF-8 valid.
        match std::str::from_utf8(header_line) {
            Ok(headers_str) => {
                let entry = headers_str.split(": ").collect::<Vec<&str>>();
                if entry.len() != 2 {
                    return Err(RequestError::InvalidHeader);
                }
                if let Ok(head) = Header::try_from(entry[0].as_bytes()) {
                    match head {
                        Header::ContentLength => {
                            let try_numeric: Result<i32, std::num::ParseIntError> =
                                std::str::FromStr::from_str(entry[1].trim());
                            if let Ok(content_length) = try_numeric {
                                self.content_length = content_length;
                                Ok(())
                            } else {
                                Err(RequestError::InvalidHeader)
                            }
                        }
                        Header::ContentType => {
                            match MediaType::try_from(entry[1].trim().as_bytes()) {
                                Ok(_) => Ok(()),
                                Err(_) => Err(RequestError::InvalidHeader),
                            }
                        }
                        Header::TransferEncoding => match entry[1].trim() {
                            "chunked" => {
                                self.chunked = true;
                                Ok(())
                            }
                            "identity; q=0" => Err(RequestError::InvalidHeader),
                            _ => Err(RequestError::UnsupportedHeader),
                        },
                        Header::Expect => match entry[1].trim() {
                            "100-continue" => {
                                self.expect = true;
                                Ok(())
                            }
                            _ => Err(RequestError::InvalidHeader),
                        },
                        Header::Server => Ok(()),
                    }
                } else {
                    Err(RequestError::UnsupportedHeader)
                }
            }
            _ => Err(RequestError::InvalidHeader),
        }
    }

    /// Returns the content length of the body.
    pub fn content_length(&self) -> i32 {
        self.content_length
    }

    /// Returns `true` if the transfer encoding is chunked.
    #[allow(unused)]
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// Returns `true` if the client is expecting the code 100.
    #[allow(unused)]
    pub fn expect(&self) -> bool {
        self.expect
    }

    #[cfg(test)]
    pub fn new(content_length: i32, expect: bool, chunked: bool) -> Self {
        Headers {
            content_length,
            expect,
            chunked,
        }
    }

    /// Parses a byte slice into a Headers structure for a HTTP request.
    ///
    /// The byte slice is expected to have the following format: </br>
    ///     * Request Header Lines "<header_line> CRLF"- Optional </br>
    /// There can be any number of request headers, including none, followed by
    /// an extra sequence of Carriage Return and Line Feed.
    /// All header fields are parsed. However, only the ones present in the
    /// [`Headers`](struct.Headers.html) struct are relevant to us and stored
    /// for future use.
    ///
    /// # Errors
    /// The function returns `InvalidHeader` when parsing the byte stream fails.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate micro_http;
    /// use micro_http::Headers;
    ///
    /// let request_headers = Headers::try_from(b"Content-Length: 55\r\n\r\n");
    /// ```
    pub fn try_from(bytes: &[u8]) -> Result<Headers, RequestError> {
        // Headers must be ASCII, so also UTF-8 valid.
        if let Ok(text) = std::str::from_utf8(bytes) {
            let mut headers = Headers::default();

            let header_lines = text.split("\r\n");
            for header_line in header_lines {
                if header_line.is_empty() {
                    break;
                }
                match headers.parse_header_line(header_line.as_bytes()) {
                    Ok(_) | Err(RequestError::UnsupportedHeader) => continue,
                    Err(e) => return Err(e),
                };
            }
            return Ok(headers);
        }
        Err(RequestError::InvalidRequest)
    }
}

/// Wrapper over supported Media Types.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MediaType {
    /// Media Type: "text/plain".
    PlainText,
    /// Media Type: "application/json".
    ApplicationJson,
}

impl Default for MediaType {
    fn default() -> Self {
        MediaType::PlainText
    }
}

impl MediaType {
    fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.is_empty() {
            return Err(RequestError::InvalidRequest);
        }
        let utf8_slice =
            String::from_utf8(bytes.to_vec()).map_err(|_| RequestError::InvalidRequest)?;
        match utf8_slice.as_str() {
            "text/plain" => Ok(MediaType::PlainText),
            "application/json" => Ok(MediaType::ApplicationJson),
            _ => Err(RequestError::InvalidRequest),
        }
    }

    /// Returns a static string representation of the object.
    pub fn as_str(self) -> &'static str {
        match self {
            MediaType::PlainText => "text/plain",
            MediaType::ApplicationJson => "application/json",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let headers = Headers::default();
        assert_eq!(headers.content_length(), 0);
        assert_eq!(headers.chunked(), false);
        assert_eq!(headers.expect(), false);
    }

    #[test]
    fn test_try_from_media() {
        assert_eq!(
            MediaType::try_from(b"application/json").unwrap(),
            MediaType::ApplicationJson
        );

        assert_eq!(
            MediaType::try_from(b"text/plain").unwrap(),
            MediaType::PlainText
        );

        assert_eq!(
            MediaType::try_from(b"").unwrap_err(),
            RequestError::InvalidRequest
        );

        assert_eq!(
            MediaType::try_from(b"application/json-patch").unwrap_err(),
            RequestError::InvalidRequest
        );
    }

    #[test]
    fn test_media_as_str() {
        let media_type = MediaType::ApplicationJson;
        assert_eq!(media_type.as_str(), "application/json");

        let media_type = MediaType::PlainText;
        assert_eq!(media_type.as_str(), "text/plain");
    }

    #[test]
    fn test_try_from_headers() {
        // Valid headers.
        assert_eq!(
            Headers::try_from(
                b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nContent-Length: 55\r\n\r\n"
            )
            .unwrap()
            .content_length,
            55
        );

        let bytes: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        // Invalid headers.
        assert!(Headers::try_from(&bytes[..]).is_err());
    }

    #[test]
    fn test_parse_header_line() {
        let mut header = Headers::default();

        // Invalid header syntax.
        assert_eq!(
            header.parse_header_line(b"Expect"),
            Err(RequestError::InvalidHeader)
        );

        // Invalid content length.
        assert_eq!(
            header.parse_header_line(b"Content-Length: five"),
            Err(RequestError::InvalidHeader)
        );

        // Invalid transfer encoding.
        assert_eq!(
            header.parse_header_line(b"Transfer-Encoding: gzip"),
            Err(RequestError::UnsupportedHeader)
        );

        // Invalid expect.
        assert_eq!(
            header
                .parse_header_line(b"Expect: 102-processing")
                .unwrap_err(),
            RequestError::InvalidHeader
        );

        // Invalid media type.
        assert_eq!(
            header
                .parse_header_line(b"Content-Type: application/json-patch")
                .unwrap_err(),
            RequestError::InvalidHeader
        );

        // Invalid input format.
        let input: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        assert_eq!(
            header.parse_header_line(&input[..]).unwrap_err(),
            RequestError::InvalidHeader
        );

        // Test valid transfer encoding.
        assert!(header
            .parse_header_line(b"Transfer-Encoding: chunked")
            .is_ok());
        assert!(header.chunked());

        // Test valid expect.
        assert!(header.parse_header_line(b"Expect: 100-continue").is_ok());
        assert!(header.expect());

        // Test valid media type.
        assert!(header
            .parse_header_line(b"Content-Type: application/json")
            .is_ok());
    }

    #[test]
    fn test_header_try_from() {
        // Bad header.
        assert_eq!(
            Header::try_from(b"Encoding").unwrap_err(),
            RequestError::InvalidHeader
        );

        // Invalid encoding.
        let input: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        assert_eq!(
            Header::try_from(&input[..]).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test valid headers.
        let header = Header::try_from(b"Expect").unwrap();
        assert_eq!(header.raw(), b"Expect");

        let header = Header::try_from(b"Transfer-Encoding").unwrap();
        assert_eq!(header.raw(), b"Transfer-Encoding");
    }
}
