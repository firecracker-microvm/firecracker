// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::{Read, Write};

use crate::common::ascii::{CR, CRLF_LEN, LF};
use crate::common::Body;
pub use crate::common::{ConnectionError, HttpHeaderError, RequestError};
use crate::headers::Headers;
use crate::request::{find, Request, RequestLine};
use crate::response::{Response, StatusCode};

const BUFFER_SIZE: usize = 1024;

/// Describes the state machine of an HTTP connection.
enum ConnectionState {
    WaitingForRequestLine,
    WaitingForHeaders,
    WaitingForBody,
    RequestReady,
}

/// A wrapper over a HTTP Connection.
pub struct HttpConnection<T> {
    /// A partial request that is still being received.
    pending_request: Option<Request>,
    /// Stream implementing `Read` and `Write`, capable of sending and
    /// receiving bytes.
    stream: T,
    /// The state of the connection regarding the current request that
    /// is being processed.
    state: ConnectionState,
    /// Buffer where we store the bytes we read from the stream.
    buffer: [u8; BUFFER_SIZE],
    /// The index in the buffer from where we have to start reading in
    /// the next `try_read` call.
    read_cursor: usize,
    /// Contains all bytes pertaining to the body of the request that
    /// is currently being processed.
    body_vec: Vec<u8>,
    /// Represents how many bytes from the body of the request are still
    /// to be read.
    body_bytes_to_be_read: u32,
    /// A queue of all requests that have been fully received and parsed.
    parsed_requests: VecDeque<Request>,
    /// A queue of requests that are waiting to be sent.
    response_queue: VecDeque<Response>,
    /// A buffer containing the bytes of a response that is currently
    /// being sent.
    response_buffer: Option<Vec<u8>>,
}

impl<T: Read + Write> HttpConnection<T> {
    /// Creates an empty connection.
    pub fn new(stream: T) -> Self {
        Self {
            pending_request: None,
            stream,
            state: ConnectionState::WaitingForRequestLine,
            buffer: [0; BUFFER_SIZE],
            read_cursor: 0,
            body_vec: vec![],
            body_bytes_to_be_read: 0,
            parsed_requests: VecDeque::new(),
            response_queue: VecDeque::new(),
            response_buffer: None,
        }
    }

    /// Tries to read new bytes from the stream and automatically update the request.
    /// Meant to be used only with non-blocking streams and an `EPOLL` structure.
    /// Should be called whenever an `EPOLLIN` event is signaled.
    ///
    /// # Errors
    /// `StreamError` is returned when an IO operation fails.
    /// `ConnectionClosed` is returned when a client prematurely closes the connection.
    /// `ParseError` is returned when a parsing operation fails.
    pub fn try_read(&mut self) -> Result<(), ConnectionError> {
        // Read some bytes from the stream, which will be appended to what is already
        // present in the buffer from a previous call of `try_read`. There are already
        // `read_cursor` bytes present in the buffer.
        let end_cursor = self.read_bytes()?;

        let mut line_start_index = 0;
        loop {
            match self.state {
                ConnectionState::WaitingForRequestLine => {
                    if !self.parse_request_line(&mut line_start_index, end_cursor)? {
                        return Ok(());
                    }
                }
                ConnectionState::WaitingForHeaders => {
                    if !self.parse_headers(&mut line_start_index, end_cursor)? {
                        return Ok(());
                    }
                }
                ConnectionState::WaitingForBody => {
                    if !self.parse_body(&mut line_start_index, end_cursor)? {
                        return Ok(());
                    }
                }
                ConnectionState::RequestReady => {
                    // This request is ready to be passed for handling.
                    // Update the state machine to expect a new request and push this request into
                    // the `parsed_requests` queue.
                    self.state = ConnectionState::WaitingForRequestLine;
                    self.body_bytes_to_be_read = 0;
                    self.parsed_requests
                        .push_back(self.pending_request.take().unwrap());
                }
            };
        }
    }

    /// Reads a maximum of 1024 bytes from the stream into `buffer`.
    /// The return value represents the end index of what we have just appended.
    ///
    /// # Errors
    /// `StreamError` is returned if any error occurred while reading the stream.
    /// `ConnectionClosed` is returned if the client closed the connection.
    /// `Overflow` is returned if an arithmetic overflow occurs while parsing the request.
    fn read_bytes(&mut self) -> Result<usize, ConnectionError> {
        if self.read_cursor >= BUFFER_SIZE {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        // Append new bytes to what we already have in the buffer.
        // The slice access is safe, the index is checked above.
        let bytes_read = self
            .stream
            .read(&mut self.buffer[self.read_cursor..])
            .map_err(ConnectionError::StreamError)?;

        // If the read returned 0 then the client has closed the connection.
        if bytes_read == 0 {
            return Err(ConnectionError::ConnectionClosed);
        }
        bytes_read
            .checked_add(self.read_cursor)
            .ok_or(ConnectionError::ParseError(RequestError::Overflow))
    }

    /// Parses bytes in `buffer` for a valid request line.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned if unable to parse request line or line longer than BUFFER_SIZE.
    fn parse_request_line(
        &mut self,
        start: &mut usize,
        end: usize,
    ) -> Result<bool, ConnectionError> {
        if end < *start {
            return Err(ConnectionError::ParseError(RequestError::Underflow));
        }
        if end > self.buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        // The slice access is safe because `end` is checked to be smaller than the buffer size
        // and larger than `start`.
        match find(&self.buffer[*start..end], &[CR, LF]) {
            Some(line_end_index) => {
                // The unchecked addition `start + line_end_index` is safe because `line_end_index`
                // is returned by `find` and thus guaranteed to be in-bounds. This also makes the
                // slice access safe.
                let line = &self.buffer[*start..(*start + line_end_index)];

                // The unchecked addition is safe because of the previous `find()`.
                *start = *start + line_end_index + CRLF_LEN;

                // Form the request with a valid request line, which is the bare minimum
                // for a valid request.
                self.pending_request = Some(Request {
                    request_line: RequestLine::try_from(line)
                        .map_err(ConnectionError::ParseError)?,
                    headers: Headers::default(),
                    body: None,
                });
                self.state = ConnectionState::WaitingForHeaders;
                Ok(true)
            }
            None => {
                // The request line is longer than BUFFER_SIZE bytes, so the request is invalid.
                if end == BUFFER_SIZE && *start == 0 {
                    return Err(ConnectionError::ParseError(RequestError::InvalidRequest));
                } else {
                    // Move the incomplete request line to the beginning of the buffer and wait
                    // for the next `try_read` call to complete it.
                    // This can only happen if another request was sent before this one, as the
                    // limit for the length of a request line in this implementation is 1024 bytes.
                    self.shift_buffer_left(*start, end)
                        .map_err(ConnectionError::ParseError)?;
                }
                Ok(false)
            }
        }
    }

    /// Parses bytes in `buffer` for header fields.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned if unable to parse header or line longer than BUFFER_SIZE.
    fn parse_headers(
        &mut self,
        line_start_index: &mut usize,
        end_cursor: usize,
    ) -> Result<bool, ConnectionError> {
        if end_cursor > self.buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        if end_cursor < *line_start_index {
            return Err(ConnectionError::ParseError(RequestError::Underflow));
        }
        // Safe to access the slice as the bounds are checked above.
        match find(&self.buffer[*line_start_index..end_cursor], &[CR, LF]) {
            // `line_start_index` points to the end of the most recently found CR LF
            // sequence. That means that if we found the next CR LF sequence at this index,
            // they are, in fact, a CR LF CR LF sequence, which marks the end of the header
            // fields, per HTTP specification.

            // We have found the end of the header.
            Some(0) => {
                // The current state is `WaitingForHeaders`, ensuring a valid request formed from a
                // request line.
                let request = self
                    .pending_request
                    .as_mut()
                    .ok_or(ConnectionError::ParseError(
                        RequestError::HeadersWithoutPendingRequest,
                    ))?;
                if request.headers.content_length() == 0 {
                    self.state = ConnectionState::RequestReady;
                } else {
                    if request.headers.expect() {
                        // Send expect.
                        let expect_response =
                            Response::new(request.http_version(), StatusCode::Continue);
                        self.response_queue.push_back(expect_response);
                    }

                    self.body_bytes_to_be_read = request.headers.content_length();
                    request.body = Some(Body::new(vec![]));
                    self.state = ConnectionState::WaitingForBody;
                }

                // Update the index for the next header.
                *line_start_index = line_start_index
                    .checked_add(CRLF_LEN)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
                Ok(true)
            }
            // We have found the end of a header line.
            Some(relative_line_end_index) => {
                let request = self
                    .pending_request
                    .as_mut()
                    .ok_or(ConnectionError::ParseError(
                        RequestError::HeadersWithoutPendingRequest,
                    ))?;
                // The `line_end_index` relative to the whole buffer.
                let line_end_index = relative_line_end_index
                    .checked_add(*line_start_index)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;

                // Get the line slice and parse it.
                // The slice access is safe because `line_end_index` is a sum of `line_end_index`
                // and something else, and `line_end_index` itself is guaranteed to be within
                // `self.buffer`'s bounds by the `find()`.
                let line = &self.buffer[*line_start_index..line_end_index];
                match request.headers.parse_header_line(line) {
                    // If a header is unsupported we ignore it.
                    Ok(_)
                    | Err(RequestError::HeaderError(HttpHeaderError::UnsupportedValue(_, _))) => {}
                    // If parsing the header invalidates the request, we propagate
                    // the error.
                    Err(e) => return Err(ConnectionError::ParseError(e)),
                };

                // Update the `line_start_index` to where we finished parsing.
                *line_start_index = line_end_index
                    .checked_add(CRLF_LEN)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
                Ok(true)
            }
            // If we have an incomplete header line.
            None => {
                // If we have parsed BUFFER_SIZE bytes and still haven't found the header
                // line end sequence.
                if *line_start_index == 0 && end_cursor == BUFFER_SIZE {
                    // Header line is longer than BUFFER_SIZE bytes, so it is invalid.
                    let utf8_string = String::from_utf8_lossy(&self.buffer);
                    return Err(ConnectionError::ParseError(RequestError::HeaderError(
                        HttpHeaderError::SizeLimitExceeded(utf8_string.to_string()),
                    )));
                }
                // Move the incomplete header line from the end of the buffer to
                // the beginning, so that we can append the rest of the line and
                // parse it in the next `try_read` call.
                self.shift_buffer_left(*line_start_index, end_cursor)
                    .map_err(ConnectionError::ParseError)?;
                Ok(false)
            }
        }
    }

    /// Parses bytes in `buffer` to be put into the request body, if there should be one.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned when the body is larger than the specified content-length.
    fn parse_body(
        &mut self,
        line_start_index: &mut usize,
        end_cursor: usize,
    ) -> Result<bool, ConnectionError> {
        // If what we have just read is not enough to complete the request and
        // there are more bytes pertaining to the body of the request.
        if end_cursor > self.buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        let start_to_end = end_cursor
            .checked_sub(*line_start_index)
            .ok_or(ConnectionError::ParseError(RequestError::Underflow))?
            as u32;
        if self.body_bytes_to_be_read > start_to_end {
            // Append everything that we read to our current incomplete body and update
            // `body_bytes_to_be_read`.
            // The slice access is safe, otherwise `checked_sub` would have failed.
            self.body_vec
                .extend_from_slice(&self.buffer[*line_start_index..end_cursor]);
            // Safe to subtract directly as the `if` condition prevents underflow.
            self.body_bytes_to_be_read -= start_to_end;

            // Clear the buffer and reset the starting index.
            for i in 0..BUFFER_SIZE {
                self.buffer[i] = 0;
            }
            self.read_cursor = 0;

            return Ok(false);
        }

        // Append only the remaining necessary bytes to the body of the request.
        let line_end = line_start_index
            .checked_add(self.body_bytes_to_be_read as usize)
            .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
        // The slice access is safe as `line_end` is a sum of `line_start_index` + something else.
        self.body_vec
            .extend_from_slice(&self.buffer[*line_start_index..line_end]);
        *line_start_index = line_end;
        self.body_bytes_to_be_read = 0;

        let request = self
            .pending_request
            .as_mut()
            .ok_or(ConnectionError::ParseError(
                RequestError::BodyWithoutPendingRequest,
            ))?;
        // If there are no more bytes to be read for this request.
        // Assign the body of the request.
        let placeholder: Vec<_> = self
            .body_vec
            .drain(..request.headers.content_length() as usize)
            .collect();
        request.body = Some(Body::new(placeholder));

        // If we read more bytes than we should have into the body of the request.
        if !self.body_vec.is_empty() {
            return Err(ConnectionError::ParseError(RequestError::InvalidRequest));
        }

        self.state = ConnectionState::RequestReady;
        Ok(true)
    }

    /// Tries to write the first available response to the provided stream.
    /// Meant to be used only with non-blocking streams and an `EPOLL` structure.
    /// Should be called whenever an `EPOLLOUT` event is signaled. If no bytes
    /// were written to the stream or error occurred while trying to write to stream,
    /// we will discard all responses from response_queue because there is no way
    /// to deliver it to client.
    ///
    /// # Errors
    /// `StreamError` is returned when an IO operation fails.
    /// `ConnectionClosed` is returned when trying to write on a closed connection.
    /// `InvalidWrite` is returned when trying to write on a connection with an
    /// empty outgoing buffer.
    pub fn try_write(&mut self) -> Result<(), ConnectionError> {
        if self.response_buffer.is_none() {
            if let Some(response) = self.response_queue.pop_front() {
                let mut response_buffer_vec: Vec<u8> = Vec::new();
                response
                    .write_all(&mut response_buffer_vec)
                    .map_err(ConnectionError::StreamError)?;
                self.response_buffer = Some(response_buffer_vec);
            } else {
                return Err(ConnectionError::InvalidWrite);
            }
        }

        let mut response_fully_written = false;
        let mut connection_closed = false;

        if let Some(response_buffer_vec) = self.response_buffer.as_mut() {
            let bytes_to_be_written = response_buffer_vec.len();
            match self.stream.write(response_buffer_vec.as_slice()) {
                Ok(0) | Err(_) => {
                    connection_closed = true;
                }
                Ok(bytes_written) => {
                    if bytes_written != bytes_to_be_written {
                        response_buffer_vec.drain(..bytes_written);
                    } else {
                        response_fully_written = true;
                    }
                }
            }
        }

        if connection_closed {
            self.clear_write_buffer();
            return Err(ConnectionError::ConnectionClosed);
        } else if response_fully_written {
            self.response_buffer.take();
        }

        Ok(())
    }

    fn clear_write_buffer(&mut self) {
        self.response_queue.clear();
        self.response_buffer.take();
    }

    /// Send a response back to the source of a request.
    pub fn enqueue_response(&mut self, response: Response) {
        self.response_queue.push_back(response);
    }

    fn shift_buffer_left(
        &mut self,
        line_start_index: usize,
        end_cursor: usize,
    ) -> Result<(), RequestError> {
        if end_cursor > self.buffer.len() {
            return Err(RequestError::Overflow);
        }
        // We don't want to shift something that is already at the beginning.
        let delta_bytes = end_cursor
            .checked_sub(line_start_index)
            .ok_or(RequestError::Underflow)?;
        if line_start_index != 0 {
            // Move the bytes from `line_start_index` to the beginning of the buffer.
            for cursor in 0..delta_bytes {
                // The unchecked addition is safe, guaranteed by the result of the substraction
                // above.
                // The slice access is safe, as `line_start_index + cursor` is <= `end_cursor`,
                // checked at the start of the function.
                self.buffer[cursor] = self.buffer[line_start_index + cursor];
            }

            // Clear the rest of the buffer.
            for cursor in delta_bytes..end_cursor {
                self.buffer[cursor] = 0;
            }
        }

        // Update `read_cursor`.
        self.read_cursor = delta_bytes;
        Ok(())
    }

    /// Returns the first parsed request in the queue or `None` if the queue
    /// is empty.
    pub fn pop_parsed_request(&mut self) -> Option<Request> {
        self.parsed_requests.pop_front()
    }

    /// Returns `true` if there are bytes waiting to be written into the stream.
    pub fn pending_write(&self) -> bool {
        self.response_buffer.is_some() || !self.response_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::common::{Method, Version};

    #[test]
    fn test_try_read_expect() {
        // Test request with `Expect` header.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Content-Length: 26\r\n\
                                 Transfer-Encoding: chunked\r\n\r\n",
            )
            .unwrap();
        assert!(conn.try_read().is_ok());

        sender.write_all(b"this is not\n\r\na json \nbody").unwrap();
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();

        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
        };

        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_long_headers() {
        // Long request headers.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: chunked\r\n",
            )
            .unwrap();

        for i in 0..90 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        assert!(conn.try_read().is_ok());
        assert!(conn.try_read().is_ok());
        let request = conn.pop_parsed_request().unwrap();

        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_split_ending() {
        // Long request with '\r\n' on BUFFER_SIZEth and 1025th positions in the request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: chunked\r\n",
            )
            .unwrap();

        for i in 0..32 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Head: aaaaa\r\nContent-Length: 26\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_invalid_request() {
        // Invalid request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: chunked\r\n",
            )
            .unwrap();

        for i in 0..40 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Content-Length: alpha\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        let request_error = conn.try_read().unwrap_err();
        assert_eq!(
            request_error,
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " alpha".to_string()
            )))
        );
    }

    #[test]
    fn test_try_read_long_request_body() {
        // Long request body.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: chunked\r\n\
                                 Content-Length: 1400\r\n\r\n",
            )
            .unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            request_body.write_all(b"This is a test").unwrap();
        }
        sender.write_all(request_body.as_slice()).unwrap();
        assert!(conn.try_read().is_ok());
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(1400, true, true),
            body: Some(Body::new(request_body)),
        };

        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_large_req_line() {
        // Request line longer than BUFFER_SIZE bytes.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender.write_all(b"PATCH http://localhost/home").unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..200 {
            request_body.write_all(b"/home").unwrap();
        }
        sender.write_all(request_body.as_slice()).unwrap();
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );
    }

    #[test]
    fn test_try_read_large_header_line() {
        // Header line longer than BUFFER_SIZE bytes.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(b"PATCH http://localhost/home HTTP/1.1\r\nhead: ")
            .unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1030);
        for _ in 0..86 {
            request_body.write_all(b"abcdefghijkl").unwrap();
        }
        request_body.write_all(b"\r\n\r\n").unwrap();
        sender.write_all(request_body.as_slice()).unwrap();
        assert!(conn.try_read().is_ok());

        let expected_msg = &format!("head: {}", String::from_utf8(request_body).unwrap())[..1024];
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(
                HttpHeaderError::SizeLimitExceeded(expected_msg.to_string())
            ))
        );
    }

    #[test]
    fn test_try_read_no_body_request() {
        // Request without body.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: chunked\r\n\r\n",
            )
            .unwrap();
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_segmented_req_line() {
        // Segmented request line.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender.write_all(b"PATCH http://local").unwrap();
        assert!(conn.try_read().is_ok());

        sender.write_all(b"host/home HTTP/1.1\r\n\r\n").unwrap();

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, false, false),
            body: None,
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_long_req_line_b2b() {
        // Long request line after another request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        // Req line 23 + 10*x + 13 = 36 + 10* x    984 free in first try read
        sender
            .write_all(b"PATCH http://localhost/home HTTP/1.1\r\n\r\nPATCH http://localhost/")
            .unwrap();

        let mut request_line: Vec<u8> = Vec::with_capacity(980);
        for _ in 0..98 {
            request_line.write_all(b"localhost/").unwrap();
        }
        request_line.write_all(b" HTTP/1.1\r\n\r\n").unwrap();
        sender.write_all(request_line.as_slice()).unwrap();

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, false, false),
            body: None,
        };
        assert_eq!(request, expected_request);

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let mut expected_request_as_bytes = Vec::new();
        expected_request_as_bytes
            .write_all(b"http://localhost/")
            .unwrap();
        expected_request_as_bytes.append(request_line.as_mut());
        let expected_request = Request {
            request_line: RequestLine::new(
                Method::Patch,
                std::str::from_utf8(&expected_request_as_bytes[..997]).unwrap(),
                Version::Http11,
            ),
            headers: Headers::new(0, false, false),
            body: None,
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_double_request() {
        // Double request in a single read.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Transfer-Encoding: chunked\r\n\
                                 Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody",
            )
            .unwrap();
        sender
            .write_all(
                b"PUT http://farhost/away HTTP/1.1\r\nContent-Length: 23\r\n\r\nthis is another request",
            )
            .unwrap();

        let expected_request_first = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, false, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
        };

        conn.try_read().unwrap();
        let request_first = conn.pop_parsed_request().unwrap();
        let request_second = conn.pop_parsed_request().unwrap();

        let expected_request_second = Request {
            request_line: RequestLine::new(Method::Put, "http://farhost/away", Version::Http11),
            headers: Headers::new(23, false, false),
            body: Some(Body::new(b"this is another request".to_vec())),
        };
        assert_eq!(request_first, expected_request_first);
        assert_eq!(request_second, expected_request_second);
    }

    #[test]
    fn test_try_read_connection_closed() {
        // Connection abruptly closed.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Transfer-Encoding: chunked\r\n\
                                 Content-Len",
            )
            .unwrap();

        conn.try_read().unwrap();
        sender.shutdown(std::net::Shutdown::Both).unwrap();

        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ConnectionClosed
        );
    }

    #[test]
    fn test_enqueue_response() {
        // Response without body.
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(sender);

        let response = Response::new(Version::Http11, StatusCode::OK);
        let mut expected_response: Vec<u8> = vec![];
        response.write_all(&mut expected_response).unwrap();

        conn.enqueue_response(response);
        assert!(conn.try_write().is_ok());

        let mut response_buffer = vec![0u8; expected_response.len()];
        receiver.read_exact(&mut response_buffer).unwrap();
        assert_eq!(response_buffer, expected_response);

        // Response with body.
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(sender);
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        let mut body: Vec<u8> = vec![];
        body.write_all(br#"{ "json": "body", "hello": "world" }"#)
            .unwrap();
        response.set_body(Body::new(body));
        let mut expected_response: Vec<u8> = vec![];
        response.write_all(&mut expected_response).unwrap();

        conn.enqueue_response(response);
        assert!(conn.try_write().is_ok());

        let mut response_buffer = vec![0u8; expected_response.len()];
        receiver.read_exact(&mut response_buffer).unwrap();
        assert_eq!(response_buffer, expected_response);
    }

    #[test]
    fn test_try_read_negative_content_len() {
        // Request with negative `Content-Length` header.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT http://localhost/home HTTP/1.1\r\n\
                                 Content-Length: -1\r\n\r\n",
            )
            .unwrap();
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " -1".to_string()
            )))
        );
    }

    #[test]
    fn test_read_bytes() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);

        // Cursor positioned at buffer end. Read should fail.
        conn.read_cursor = BUFFER_SIZE;
        sender.write_all(b"hello\0").unwrap();
        assert_eq!(
            conn.read_bytes().unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Cursor positioned before buffer end. Partial read should succeed.
        conn.read_cursor = BUFFER_SIZE - 3;
        sender.write_all(b"hello\0").unwrap();
        assert_eq!(conn.read_bytes(), Ok(BUFFER_SIZE));

        // Read the remaining 9 bytes - 3 left from the first "hello" and the 2nd full "hello".
        conn.read_cursor = 0;
        assert_eq!(conn.read_bytes(), Ok(9));
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            conn.read_bytes().unwrap_err(),
            ConnectionError::ConnectionClosed
        );
    }

    #[test]
    fn test_shift_buffer_left() {
        let (_, receiver) = UnixStream::pair().unwrap();
        let mut conn = HttpConnection::new(receiver);

        assert_eq!(
            conn.shift_buffer_left(0, conn.buffer.len() + 1)
                .unwrap_err(),
            RequestError::Overflow
        );
        assert_eq!(
            conn.shift_buffer_left(1, 0).unwrap_err(),
            RequestError::Underflow
        );
        assert!(conn.shift_buffer_left(1, conn.buffer.len()).is_ok());
    }

    #[test]
    fn test_parse_request_line() {
        let (_, receiver) = UnixStream::pair().unwrap();
        let mut conn = HttpConnection::new(receiver);

        // Error case: end past buffer end.
        assert_eq!(
            conn.parse_request_line(&mut 0, conn.buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: start is past end.
        assert_eq!(
            conn.parse_request_line(&mut 1, 0).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // Error case: the request line is longer than BUFFER_SIZE.
        assert_eq!(
            conn.parse_request_line(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );

        // OK case.
        assert_eq!(conn.parse_request_line(&mut 1, BUFFER_SIZE), Ok(false));

        // Error case: invalid content.
        conn.buffer[0..8].copy_from_slice(b"foo\r\nbar");
        assert_eq!(
            conn.parse_request_line(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );

        // OK case.
        conn.buffer[0..29].copy_from_slice(b"GET http://foo/bar HTTP/1.1\r\n");
        assert_eq!(conn.parse_request_line(&mut 0, BUFFER_SIZE), Ok(true));
    }

    #[test]
    fn test_parse_headers() {
        let (_, receiver) = UnixStream::pair().unwrap();
        let mut conn = HttpConnection::new(receiver);

        // Error case: end_cursor past buffer end.
        assert_eq!(
            conn.parse_headers(&mut 0, conn.buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: line_start_index is past end_cursor.
        assert_eq!(
            conn.parse_headers(&mut 1, 0).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // Error case: no request pending.
        // CRLF can be at the start of the buffer...
        conn.buffer[0] = CR;
        conn.buffer[1] = LF;
        assert_eq!(
            conn.parse_headers(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::HeadersWithoutPendingRequest)
        );
        // ...or somewhere in the middle.
        conn.buffer[0] = 0;
        conn.buffer[1] = CR;
        conn.buffer[2] = LF;
        assert_eq!(
            conn.parse_headers(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::HeadersWithoutPendingRequest)
        );

        // Error case: invalid header.
        conn.pending_request = Some(Request {
            request_line: RequestLine::new(Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
        });
        assert_eq!(
            conn.parse_headers(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidFormat(
                "\0".to_string()
            )))
        );

        // OK case: incomplete header line.
        let hdr = b"Custom-Header-Testing: 1";
        conn.buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(conn.parse_headers(&mut 0, hdr.len()), Ok(false));

        // OK case: complete header line.
        let hdr = b"Custom-Header-Testing: 1\r\n";
        conn.buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(conn.parse_headers(&mut 0, hdr.len()), Ok(true));

        // OK case: complete header line, end of header.
        let hdr = b"\r\n";
        conn.buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(conn.parse_headers(&mut 0, hdr.len()), Ok(true));
    }

    #[test]
    fn test_parse_body() {
        let (_, receiver) = UnixStream::pair().unwrap();
        let mut conn = HttpConnection::new(receiver);

        // Error case: end_cursor past buffer end.
        assert_eq!(
            conn.parse_body(&mut 0usize, conn.buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: line_start_index is past end_cursor.
        assert_eq!(
            conn.parse_body(&mut 1usize, 0usize).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // OK case: consume the buffer.
        conn.body_bytes_to_be_read = 1;
        assert_eq!(conn.parse_body(&mut 0usize, 0usize), Ok(false));

        // Error case: there's more body to be parsed, but no pending request set.
        assert_eq!(
            conn.parse_body(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::BodyWithoutPendingRequest)
        );

        // Error case: read more bytes than we should have into the body of the request.
        conn.pending_request = Some(Request {
            request_line: RequestLine::new(Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
        });
        conn.body_vec = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            conn.parse_body(&mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );

        // OK case.
        conn.body_vec.clear();
        assert_eq!(conn.parse_body(&mut 0, BUFFER_SIZE), Ok(true));
    }
}
