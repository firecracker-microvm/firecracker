// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
//! Minimal implementation of the [HTTP/1.0](https://tools.ietf.org/html/rfc1945)
//! and [HTTP/1.1](https://www.ietf.org/rfc/rfc2616.txt) protocols.
//!
//! HTTP/1.1 has a mandatory header **Host**, but as this crate is only used
//! for parsing MMDS requests, this header (if present) is ignored.
//!
//! This HTTP implementation is stateless thus it does not support chunking or
//! compression.
//!
//! ## Supported Headers
//! The **micro_http** crate has support for parsing the following **Request**
//! headers:
//! - Content-Length
//! - Expect
//! - Transfer-Encoding
//!
//! The **Response** does not have a public interface for adding headers, but whenever
//! a write to the **Body** is made, the headers **ContentLength** and **MediaType**
//! are automatically updated.
//!
//! ### Media Types
//! The supported media types are:
//! - text/plain
//! - application/json
//!
//! ## Supported Methods
//! The supported HTTP Methods are:
//! - GET
//! - PUT
//! - PATCH
//!
//! ## Supported Status Codes
//! The supported status codes are:
//!
//! - Continue - 100
//! - OK - 200
//! - No Content - 204
//! - Bad Request - 400
//! - Not Found - 404
//! - Internal Server Error - 500
//! - Not Implemented - 501
//!
//! ## Example for parsing an HTTP Request from a slice
//! ```
//! extern crate micro_http;
//! use micro_http::{Request, Version};
//!
//! let http_request = Request::try_from(b"GET http://localhost/home HTTP/1.0\r\n\r\n").unwrap();
//! assert_eq!(http_request.http_version(), Version::Http10);
//! assert_eq!(http_request.uri().get_abs_path(), "/home");
//! ```
//!
//! ## Example for creating an HTTP Response
//! ```
//! extern crate micro_http;
//! use micro_http::{Body, Response, StatusCode, Version, MediaType};
//!
//! let mut response = Response::new(Version::Http10, StatusCode::OK);
//! let body = String::from("This is a test");
//! response.set_body(Body::new(body.clone()));
//! response.set_content_type(MediaType::PlainText);
//!
//! assert!(response.status() == StatusCode::OK);
//! assert_eq!(response.body().unwrap(), Body::new(body));
//! assert_eq!(response.http_version(), Version::Http10);
//!
//! let mut response_buf: [u8; 126] = [0; 126];
//! assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
//! ```

mod common;
mod connection;
mod request;
mod response;
mod server;
use common::ascii;
use common::headers;

pub use connection::{ConnectionError, HttpConnection};
pub use request::{Request, RequestError};
pub use response::{Response, StatusCode};
pub use server::{HttpServer, ServerError, ServerRequest, ServerResponse};

pub use common::headers::{Headers, MediaType};
pub use common::{Body, Method, Version};
