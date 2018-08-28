use std::collections::HashMap;

use ascii::{COLON, CRLF, SP};

#[derive(Eq, Hash, PartialEq)]
pub enum Header {
    ContentLength,
    ContentType,
}

impl Header {
    fn raw(&self) -> &'static [u8] {
        match self {
            Header::ContentLength => b"Content-Length",
            Header::ContentType => b"Content-Type",
        }
    }
}

pub struct Headers {
    headers: HashMap<Header, String>,
}

impl Headers {
    pub fn default() -> Headers {
        return Headers {
            headers: HashMap::new(),
        };
    }

    pub fn add(&mut self, header: Header, value: String) {
        self.headers.insert(header, value);
    }

    pub fn raw(&self) -> Vec<u8> {
        let mut response = Vec::new();

        for (key, val) in &self.headers {
            let header = [key.raw(), COLON, SP, val.clone().as_bytes(), CRLF].concat();
            response = [response, header].concat();
        }

        // The header section ends with a CRLF.
        response = [response, CRLF.to_owned()].concat();

        return response;
    }
}

pub enum MediaType {
    PlainText,
}

impl MediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::PlainText => "text/plain",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        assert!(Headers::default().headers == HashMap::new());
    }

    #[test]
    fn test_add_headers() {
        let mut headers = Headers::default();

        headers.add(Header::ContentType, "text/plain".to_string());
        headers.add(Header::ContentLength, "120".to_string());

        assert!(headers.headers.contains_key(&Header::ContentType));
        assert_eq!(
            headers.headers.get(&Header::ContentType).unwrap(),
            &"text/plain".to_string()
        );
        assert!(headers.headers.contains_key(&Header::ContentLength));
        assert_eq!(
            headers.headers.get(&Header::ContentLength).unwrap(),
            &"120".to_string()
        );

        // Test that adding a Header with the same key, updates the value.
        headers.add(Header::ContentLength, "130".to_string());
        assert_eq!(
            headers.headers.get(&Header::ContentLength).unwrap(),
            &"130".to_string()
        );
    }
}
