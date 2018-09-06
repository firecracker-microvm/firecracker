pub mod headers;

pub mod ascii {
    pub const CR: u8 = b'\r';
    pub const COLON: u8 = b':';
    pub const LF: u8 = b'\n';
    pub const SP: u8 = b' ';
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidHttpMethod(&'static str),
    InvalidRequest,
    InvalidUri(&'static str),
    InvalidHttpVersion(&'static str),
}

#[derive(Clone, PartialEq)]
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

#[derive(PartialEq)]
pub enum Method {
    Get,
}

impl Method {
    pub fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            b"GET" => Ok(Method::Get),
            _ => Err(Error::InvalidHttpMethod("Unsupported HTTP method.")),
        }
    }

    pub fn raw(&self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
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

    pub fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            b"HTTP/1.0" => Ok(Version::Http10),
            b"HTTP/1.1" => Ok(Version::Http11),
            _ => Err(Error::InvalidHttpVersion("Unsupported HTTP version.")),
        }
    }

    pub fn default() -> Self {
        Version::Http11
    }
}
