use ascii::SP;
use common::{Body, Version};
use headers::{Header, Headers, MediaType};

#[allow(dead_code)]
pub enum StatusCode {
    OK,
    BadRequest,
    NotFound,
    InternalServerError,
    NotImplemented,
}

impl StatusCode {
    fn raw(&self) -> &'static [u8] {
        match self {
            StatusCode::OK => b"200",
            StatusCode::BadRequest => b"400",
            StatusCode::NotFound => b"404",
            StatusCode::InternalServerError => b"500",
            StatusCode::NotImplemented => b"501",
        }
    }
}

struct StatusLine {
    http_version: Version,
    status_code: StatusCode,
}

impl StatusLine {
    fn new(status_code: StatusCode) -> Self {
        return StatusLine {
            http_version: Version::Http10,
            status_code,
        };
    }

    fn raw(&mut self) -> Vec<u8> {
        let http_version = self.http_version.raw();
        let status_code = self.status_code.raw();

        return [http_version, SP, status_code, SP].concat();
    }
}

pub struct Response {
    status_line: StatusLine,
    headers: Headers,
    body: Option<Body>,
}

impl Response {
    pub fn new(status_code: StatusCode) -> Response {
        return Response {
            status_line: StatusLine::new(status_code),
            headers: Headers::default(),
            body: None,
        };
    }

    pub fn set_body(&mut self, body: Body) {
        self.headers
            .add(Header::ContentLength, body.len().to_string());
        self.headers.add(
            Header::ContentType,
            String::from(MediaType::PlainText.as_str()),
        );
        self.body = Some(body);
    }

    fn body_raw(&self) -> &[u8] {
        match self.body {
            Some(ref body) => body.raw(),
            None => &[],
        }
    }

    pub fn raw(&mut self) -> Vec<u8> {
        let status_line = self.status_line.raw();
        let headers = self.headers.raw();
        let body = self.body_raw();

        let response = [status_line, headers, body.to_owned()].concat();

        return response;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw() {
        let mut response = Response::new(StatusCode::OK);
        let body = String::from("This is a test");
        response.set_body(Body::new(body.clone()));

        // Headers can be in either order.
        let content_type = "Content-Type: text/plain\r\n";
        let content_length = format!("Content-Length: {}\r\n", body.len());

        let expected_response_1 = format!(
            "HTTP/1.0 200 {}{}This is a test",
            content_length, content_type
        );
        let expected_response_2 = format!(
            "HTTP/1.0 200 {}{}This is a test",
            content_type, content_length
        );

        assert!(
            response.raw() == expected_response_1.into_bytes()
                || response.raw() == expected_response_2.into_bytes()
        );
    }
}
