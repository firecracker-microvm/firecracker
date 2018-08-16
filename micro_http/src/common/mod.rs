pub mod headers;

pub mod ascii {
    pub const CRLF: &[u8] = b"\r\n";
    pub const COLON: &[u8] = b":";
    pub const LF: &[u8] = b"\n";
    pub const SP: &[u8] = b" ";
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
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
        }
    }
}

#[derive(PartialEq)]
pub enum Version {
    Http10,
}

impl Version {
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Version::Http10 => b"HTTP/1.0",
        }
    }
}
