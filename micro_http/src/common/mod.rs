// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod headers;

pub mod ascii {
    pub const CR: u8 = b'\r';
    pub const COLON: u8 = b':';
    pub const LF: u8 = b'\n';
    pub const SP: u8 = b' ';
}

#[derive(Debug, PartialEq)]
pub enum RequestError {
    InvalidHttpMethod(&'static str),
    InvalidRequest,
    InvalidUri(&'static str),
    InvalidHttpVersion(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Body {
    body: Vec<u8>,
}

impl Body {
    pub fn new(body: String) -> Self {
        Body {
            body: body.into_bytes(),
        }
    }

    pub fn raw(&self) -> &[u8] {
        return self.body.as_slice();
    }

    pub fn len(&self) -> usize {
        return self.body.len();
    }
}

#[derive(Debug, PartialEq)]
pub enum Method {
    Get,
}

impl Method {
    pub fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        match bytes {
            b"GET" => Ok(Method::Get),
            _ => Err(RequestError::InvalidHttpMethod("Unsupported HTTP method.")),
        }
    }

    pub fn raw(&self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Version {
    Http10,
    Http11,
}

impl Version {
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Version::Http10 => b"HTTP/1.0",
            Version::Http11 => b"HTTP/1.1",
        }
    }

    pub fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        match bytes {
            b"HTTP/1.0" => Ok(Version::Http10),
            b"HTTP/1.1" => Ok(Version::Http11),
            _ => Err(RequestError::InvalidHttpVersion(
                "Unsupported HTTP version.",
            )),
        }
    }

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
