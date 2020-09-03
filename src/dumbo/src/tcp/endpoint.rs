// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// When designing the MMDS, we thought about a split in functionality, were we have some basic
// building blocks (such as the simplified TCP implementation, and the micro HTTP server) which can
// even be exported as libraries at some point, and then we have things built on top of those.
// That's why the Connection struct (and the upcoming TcpHandler) do not log things, or increase
// metrics, but rather express status via return values. The Endpoint struct implements our HTTP
// based interaction with the MMDS, making use of the aforementioned building blocks, and is
// totally specific to Firecracker. Ideally, the current crate should only contain the generic
// components, but since the separation/interface is not very well defined yet, we keep the
// Endpoint in here too for the time being.

use std::num::{NonZeroU16, NonZeroU64, Wrapping};

use crate::pdu::{bytes::NetworkBytes, tcp::TcpSegment, Incomplete};
use crate::tcp::{
    connection::{Connection, PassiveOpenError, RecvStatusFlags},
    seq_after, NextSegmentStatus, MAX_WINDOW_SIZE,
};
use logger::{Metric, METRICS};
use micro_http::{Body, Request, RequestError, Response, StatusCode, Version};
use utils::time::timestamp_cycles;

// TODO: These are currently expressed in cycles. Normally, they would be the equivalent of a
// certain duration, depending on the frequency of the CPU, but we still have a bit to go until
// that functionality is available, so we just use some conservative-ish values. Even on a fast
// 4GHz CPU, the first is roughly equal to 10 seconds, and the other is ~300 ms.
const EVICTION_THRESHOLD: u64 = 40_000_000_000;
const CONNECTION_RTO_PERIOD: u64 = 1_200_000_000;
const CONNECTION_RTO_COUNT_MAX: u16 = 15;

// This is one plus the size of the largest bytestream carrying an HTTP request we are willing to
// accept. It's limited in order to have a bound on memory usage. This value should be plenty for
// imaginable regular MMDS requests.
// TODO: Maybe at some point include this in the checks we do when populating the MMDS via the API,
// since it effectively limits the size of the keys (URIs) we're willing to use.
const RCV_BUF_MAX_SIZE: usize = 2500;

// Represents the local endpoint of a HTTP over TCP connection which carries GET requests
// to the MMDS.
pub struct Endpoint {
    // A fixed size buffer used to store bytes received via TCP. If the current request does not
    // fit within, we reset the connection, since we see this as a hard memory bound.
    receive_buf: [u8; RCV_BUF_MAX_SIZE],
    // Represents the next available position in the buffer.
    receive_buf_left: usize,
    // This is filled with the HTTP response bytes after we parse a request and generate the reply.
    response_buf: Vec<u8>,
    // Initial response sequence, used to track if the entire `response_buf` was sent.
    initial_response_seq: Wrapping<u32>,
    // Represents the sequence number associated with the first byte from response_buf.
    response_seq: Wrapping<u32>,
    // The TCP connection that does all the receiving/sending work.
    connection: Connection,
    // Timestamp (in cycles) associated with the most recent reception of a segment.
    last_segment_received_timestamp: u64,
    // These many time units have to pass since receiving the last segment to make the current
    // Endpoint evictable.
    eviction_threshold: u64,
    // We ignore incoming segments when this is set, and that happens when we decide to reset
    // the connection (or it decides to reset itself).
    stop_receiving: bool,
}

// The "contract" for the Endpoint (if it implemented a trait or something) is something along
// these lines:
// - Incoming segments are passed by calling receive_segment().
// - To check whether the Endpoint has something to transmit, we must call write_next_segment()
// (the buf parameter should point to where the TCP segment begins). This function will return
// None if there's nothing to write (or there was an error writing, in which case it also
// increases a metric).
// - After calling either of the previous functions, the user should also call is_done() to see
// if the Endpoint is finished.
// - The is_evictable() function returns true if the Endpoint can be destroyed as far as its
// internal logic is concerned. It's going to be used by the connection handler when trying to
// find a new slot for incoming connections if none are free (when replacing an existing connection
// is the only option).

impl Endpoint {
    pub fn new<T: NetworkBytes>(
        segment: &TcpSegment<T>,
        eviction_threshold: NonZeroU64,
        connection_rto_period: NonZeroU64,
        connection_rto_count_max: NonZeroU16,
    ) -> Result<Self, PassiveOpenError> {
        // TODO: mention this in doc comment for function
        // This simplifies things, and is a very reasonable assumption.
        assert!(RCV_BUF_MAX_SIZE <= MAX_WINDOW_SIZE as usize);

        let connection = Connection::passive_open(
            segment,
            RCV_BUF_MAX_SIZE as u32,
            connection_rto_period,
            connection_rto_count_max,
        )?;

        Ok(Endpoint {
            receive_buf: [0u8; RCV_BUF_MAX_SIZE],
            receive_buf_left: 0,
            response_buf: Vec::new(),
            // TODO: Using first_not_sent() makes sense here because a connection is currently
            // created via passive open only, so this points to the sequence number right after
            // the SYNACK. It might stop working like that if/when the implementation changes.
            response_seq: connection.first_not_sent(),
            initial_response_seq: connection.first_not_sent(),
            connection,
            last_segment_received_timestamp: timestamp_cycles(),
            eviction_threshold: eviction_threshold.get(),
            stop_receiving: false,
        })
    }

    pub fn new_with_defaults<T: NetworkBytes>(
        segment: &TcpSegment<T>,
    ) -> Result<Self, PassiveOpenError> {
        // The unwraps are safe because the constants are greater than 0.
        Self::new(
            segment,
            NonZeroU64::new(EVICTION_THRESHOLD).unwrap(),
            NonZeroU64::new(CONNECTION_RTO_PERIOD).unwrap(),
            NonZeroU16::new(CONNECTION_RTO_COUNT_MAX).unwrap(),
        )
    }

    pub fn receive_segment<T: NetworkBytes>(
        &mut self,
        s: &TcpSegment<T>,
        callback: fn(Request) -> Response,
    ) {
        if self.stop_receiving {
            return;
        }

        let now = timestamp_cycles();

        self.last_segment_received_timestamp = now;

        // As long as new segments arrive, we save data in the buffer. We don't have to worry
        // about writing out of bounds because we set the receive window of the connection to
        // match the size of the buffer. When space frees up, we'll advance the window
        // accordingly.
        let (value, status) = match self.connection.receive_segment(
            &s,
            &mut self.receive_buf[self.receive_buf_left..],
            now,
        ) {
            Ok(pair) => pair,
            Err(_) => {
                METRICS.mmds.rx_accepted_err.inc();
                return;
            }
        };

        if !status.is_empty() {
            METRICS.mmds.rx_accepted_unusual.inc();
            if status.intersects(RecvStatusFlags::CONN_RESETTING) {
                self.stop_receiving = true;
                return;
            }
        }

        // Advance receive_buf_left by how many bytes were actually written.
        if let Some(len) = value {
            self.receive_buf_left += len.get();
        };

        if !self.response_buf.is_empty()
            && self.connection.highest_ack_received()
                == self.initial_response_seq + Wrapping(self.response_buf.len() as u32)
        {
            // If we got here, then we still have some response bytes to send (which are
            // stored in self.response_buf).

            // It seems we just recevied the last ACK we were waiting for, so the entire
            // response has been successfully received. Set the new response_seq and clear
            // the response_buf.
            self.response_seq = self.connection.highest_ack_received();
            self.initial_response_seq = self.response_seq;
            self.response_buf.clear();
        }

        if self.response_buf.is_empty() {
            // There's no pending response currently, so we're back to waiting for a request to be
            // available in self.receive_buf.

            // The following is some ugly but workable code that attempts to find the end of an
            // HTTP 1.x request in receive_buf. We need to do this for now because parse_request_bytes()
            // expects the entire request contents as parameter.
            if self.receive_buf_left > 2 {
                let b = self.receive_buf.as_mut();
                for i in 0..self.receive_buf_left - 1 {
                    // We're basically looking for a double new line, which can only appear at the
                    // end of a valid request.
                    if b[i] == b'\n' {
                        let end = if b[i + 1] == b'\n' {
                            i + 2
                        } else if i + 3 <= self.receive_buf_left && &b[i + 1..i + 3] == b"\r\n" {
                            i + 3
                        } else {
                            continue;
                        };

                        // We found a potential request, let's parse it.
                        let response = parse_request_bytes(&b[..end], callback);

                        // The unwrap is safe because a Vec will allocate more space until all the
                        // writes succeed.
                        response.write_all(&mut self.response_buf).unwrap();

                        // Sanity check because the current logic operates under this assumption.
                        assert!(self.response_buf.len() < u32::max_value() as usize);

                        // We have to remove the bytes up to end from receive_buf, by shifting the
                        // others to the beginning of the buffer, and updating receive_buf_left.
                        // Also, advance the rwnd edge of the inner connection.
                        // TODO: Maximum efficiency.
                        for j in 0..b.len() - end {
                            b[j] = b[j + end];
                        }
                        self.receive_buf_left -= end;
                        self.connection.advance_local_rwnd_edge(end as u32);
                        break;
                    }
                }
            }

            if self.receive_buf_left == self.receive_buf.len() {
                // If we get here the buffer is full, but we still couldn't identify the end of a
                // request, so we reset because we are over the maximum request size.
                self.connection.reset();
                self.stop_receiving = true;
                return;
            }
        }

        // We close the connection after receiving a FIN, and making sure there are no more
        // responses to send.
        if self.connection.fin_received() && self.response_buf.is_empty() {
            self.connection.close();
        }
    }

    pub fn write_next_segment<'a>(
        &mut self,
        buf: &'a mut [u8],
        mss_reserved: u16,
    ) -> Option<Incomplete<TcpSegment<'a, &'a mut [u8]>>> {
        let tcp_payload_src = if !self.response_buf.is_empty() {
            let offset = self.response_seq - self.initial_response_seq;
            Some((
                self.response_buf.split_at(offset.0 as usize).1,
                self.response_seq,
            ))
        } else {
            None
        };

        match self.connection.write_next_segment(
            buf,
            mss_reserved,
            tcp_payload_src,
            timestamp_cycles(),
        ) {
            Ok(write_result) => write_result.map(|segment| {
                self.response_seq += Wrapping(segment.inner().payload_len() as u32);
                segment
            }),
            Err(_) => {
                METRICS.mmds.tx_errors.inc();
                None
            }
        }
    }

    #[inline]
    pub fn is_done(&self) -> bool {
        self.connection.is_done()
    }

    #[inline]
    pub fn is_evictable(&self) -> bool {
        timestamp_cycles().wrapping_sub(self.last_segment_received_timestamp)
            > self.eviction_threshold
    }

    pub fn next_segment_status(&self) -> NextSegmentStatus {
        let can_send_new_data = !self.response_buf.is_empty()
            && seq_after(
                self.connection.remote_rwnd_edge(),
                self.connection.first_not_sent(),
            );

        if can_send_new_data || self.connection.dup_ack_pending() {
            NextSegmentStatus::Available
        } else {
            self.connection.control_segment_or_timeout_status()
        }
    }

    #[inline]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

fn build_response(http_version: Version, status_code: StatusCode, body: Body) -> Response {
    let mut response = Response::new(http_version, status_code);
    response.set_body(body);
    response
}

/// Parses the request bytes and builds a `micro_http::Response` by the given callback function.
fn parse_request_bytes(byte_stream: &[u8], callback: fn(Request) -> Response) -> Response {
    let request = Request::try_from(byte_stream);
    match request {
        Ok(request) => callback(request),
        Err(e) => match e {
            RequestError::BodyWithoutPendingRequest => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(e.to_string()),
            ),
            RequestError::HeadersWithoutPendingRequest => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(e.to_string()),
            ),
            RequestError::InvalidHttpVersion(err_msg) => build_response(
                Version::default(),
                StatusCode::NotImplemented,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidUri(err_msg) => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidHttpMethod(err_msg) => build_response(
                Version::default(),
                StatusCode::NotImplemented,
                Body::new(err_msg.to_string()),
            ),
            RequestError::InvalidRequest => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new("Invalid request.".to_string()),
            ),
            RequestError::HeaderError(err) => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(err.to_string()),
            ),
            RequestError::Overflow => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(e.to_string()),
            ),
            RequestError::Underflow => build_response(
                Version::default(),
                StatusCode::BadRequest,
                Body::new(e.to_string()),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt;
    use std::str::from_utf8;

    use crate::pdu::tcp::Flags as TcpFlags;
    use crate::tcp::connection::tests::ConnectionTester;
    use crate::tcp::tests::mock_callback;

    impl Endpoint {
        pub fn set_eviction_threshold(&mut self, value: u64) {
            self.eviction_threshold = value;
        }
    }

    impl fmt::Debug for Endpoint {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(Endpoint)")
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_endpoint() {
        let mut buf1 = [0u8; 500];
        let mut buf2 = [0u8; 500];

        let mut write_buf = [0u8; RCV_BUF_MAX_SIZE + 100];

        let mut t = ConnectionTester::new();

        let mut syn = t.write_syn(buf1.as_mut());

        // Put another flag on the SYN so it becomes invalid.
        syn.set_flags_after_ns(TcpFlags::ACK);
        assert_eq!(
            Endpoint::new_with_defaults(&syn).unwrap_err(),
            PassiveOpenError::InvalidSyn
        );

        // Fix the SYN and create an endpoint.
        syn.set_flags_after_ns(TcpFlags::SYN);
        let remote_isn = syn.sequence_number();
        let mut e = Endpoint::new_with_defaults(&syn).unwrap();

        // Let's complete the three-way handshake. The next segment sent by the endpoint should
        // be a SYNACK.
        assert_eq!(e.next_segment_status(), NextSegmentStatus::Available);
        let endpoint_isn = {
            // We need this block to delimit the mut borrow of write_buf.
            let s = e
                .write_next_segment(write_buf.as_mut(), t.mss_reserved)
                .unwrap();
            assert_eq!(s.inner().flags_after_ns(), TcpFlags::SYN | TcpFlags::ACK);
            s.inner().sequence_number()
        };

        // A RTO should be pending until the SYNACK is ACKed.
        if let NextSegmentStatus::Timeout(_) = e.next_segment_status() {
            assert_eq!(
                e.next_segment_status(),
                e.connection().control_segment_or_timeout_status()
            );
        } else {
            panic!("missing expected timeout.");
        }

        // And now we ACK the SYNACK.
        let mut ctrl = t.write_ctrl(buf2.as_mut());
        ctrl.set_flags_after_ns(TcpFlags::ACK);
        ctrl.set_ack_number(endpoint_isn.wrapping_add(1));
        assert!(!e.connection.is_established());
        e.receive_segment(&ctrl, mock_callback);
        assert!(e.connection.is_established());

        // Also, there should be nothing to send now anymore, nor any timeout pending.
        assert_eq!(e.next_segment_status(), NextSegmentStatus::Nothing);

        // Incomplete because it's missing the newlines at the end.
        let incomplete_request = b"GET http://169.254.169.255/asdfghjkl HTTP/1.1";
        {
            let mut data = t.write_data(write_buf.as_mut(), incomplete_request.as_ref());
            data.set_flags_after_ns(TcpFlags::ACK);
            data.set_sequence_number(remote_isn.wrapping_add(1));
            data.set_ack_number(endpoint_isn.wrapping_add(1));
            e.receive_segment(&data, mock_callback);
        }

        assert_eq!(e.receive_buf_left, incomplete_request.len());

        // 1 for the SYN.
        let mut remote_first_not_sent =
            remote_isn.wrapping_add(1 + incomplete_request.len() as u32);

        // The endpoint should write an ACK at this point.
        {
            assert_eq!(e.next_segment_status(), NextSegmentStatus::Available);
            let s = e
                .write_next_segment(write_buf.as_mut(), t.mss_reserved)
                .unwrap();
            assert_eq!(s.inner().flags_after_ns(), TcpFlags::ACK);
            assert_eq!(s.inner().ack_number(), remote_first_not_sent);
        }

        // There should be nothing else to send.
        assert_eq!(e.next_segment_status(), NextSegmentStatus::Nothing);

        let rest_of_the_request = b"\r\n\r\n";
        // Let's also send the newlines.
        {
            let mut data = t.write_data(write_buf.as_mut(), rest_of_the_request.as_ref());
            data.set_flags_after_ns(TcpFlags::ACK);
            data.set_sequence_number(remote_first_not_sent);
            data.set_ack_number(endpoint_isn + 1);
            e.receive_segment(&data, mock_callback);
        }

        remote_first_not_sent =
            remote_first_not_sent.wrapping_add(rest_of_the_request.len() as u32);

        let mut endpoint_first_not_sent;

        // We should get a data segment that also ACKs the latest bytes received.
        {
            assert_eq!(e.next_segment_status(), NextSegmentStatus::Available);
            let s = e
                .write_next_segment(write_buf.as_mut(), t.mss_reserved)
                .unwrap();
            assert_eq!(s.inner().flags_after_ns(), TcpFlags::ACK);
            assert_eq!(s.inner().ack_number(), remote_first_not_sent);

            let response = from_utf8(s.inner().payload()).unwrap();
            // The response should contain "200" because the HTTP request is correct.
            assert!(response.contains("200"));

            endpoint_first_not_sent = s
                .inner()
                .sequence_number()
                .wrapping_add(s.inner().payload_len() as u32);
        }

        // Cool, now let's check that even though receive_buf is limited to some value, we can
        // respond to any number of requests, as long as each fits individually inside the buffer.
        // We're going to use the simple approach where we send the same request over and over
        // again, for a relatively large number of iterations.

        let complete_request = b"GET http://169.254.169.255/asdfghjkl HTTP/1.1\r\n\r\n";
        let last_request = b"GET http://169.254.169.255/asdfghjkl HTTP/1.1\r\n\r\n123";

        // Send one request for each byte in receive_buf, just to be sure.
        let max_iter = e.receive_buf.len();
        for i in 1..=max_iter {
            // We want to use last_request for the last request.
            let request = if i == max_iter {
                last_request.as_ref()
            } else {
                complete_request.as_ref()
            };

            // Send request.
            {
                let mut data = t.write_data(write_buf.as_mut(), request);

                data.set_flags_after_ns(TcpFlags::ACK);
                data.set_sequence_number(remote_first_not_sent);
                data.set_ack_number(endpoint_first_not_sent);
                e.receive_segment(&data, mock_callback);
            }

            remote_first_not_sent = remote_first_not_sent.wrapping_add(request.len() as u32);

            // Check response.
            {
                let s = e
                    .write_next_segment(write_buf.as_mut(), t.mss_reserved)
                    .unwrap();
                assert_eq!(s.inner().flags_after_ns(), TcpFlags::ACK);
                assert_eq!(s.inner().ack_number(), remote_first_not_sent);

                let response = from_utf8(s.inner().payload()).unwrap();
                assert!(response.contains("200"));

                endpoint_first_not_sent =
                    endpoint_first_not_sent.wrapping_add(s.inner().payload_len() as u32);
            }
        }

        // The value of receive_buf_left should be 3 right now, because of the trailing chars from
        // last_request.
        assert_eq!(e.receive_buf_left, 3);

        // Unless the machine running the tests is super slow for some reason, we should be nowhere
        // near the expiry of the eviction timer.
        assert!(!e.is_evictable());

        // Let's hack this a bit and change the eviction_threshold to 0.
        e.set_eviction_threshold(0);
        // The endpoint should be evictable now.
        assert!(e.is_evictable());

        // Finally, let's fill self.receive_buf with the following request, and see if we get the
        // reset we expect on the next segment.
        let request_to_fill = vec![0u8; RCV_BUF_MAX_SIZE - e.receive_buf_left];

        {
            // Hack: have to artificially increase t.mss to create this segment which is 2k+.
            t.mss = RCV_BUF_MAX_SIZE as u16;
            let mut data = t.write_data(write_buf.as_mut(), request_to_fill.as_ref());

            data.set_flags_after_ns(TcpFlags::ACK);
            data.set_sequence_number(remote_first_not_sent);
            data.set_ack_number(endpoint_first_not_sent);
            e.receive_segment(&data, mock_callback);
        }

        {
            let s = e
                .write_next_segment(write_buf.as_mut(), t.mss_reserved)
                .unwrap();
            assert_eq!(s.inner().flags_after_ns(), TcpFlags::RST);
        }
    }

    #[test]
    fn test_parse_request_bytes_error() {
        // Test unsupported HTTP version.
        let request_bytes = b"GET http://169.254.169.255/ HTTP/2.0\r\n\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
        expected_response.set_body(Body::new("Unsupported HTTP version.".to_string()));
        let actual_response = parse_request_bytes(request_bytes, mock_callback);
        assert_eq!(actual_response, expected_response);

        // Test invalid URI (empty URI).
        let request_bytes = b"GET   HTTP/1.0\r\n\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Empty URI not allowed.".to_string()));
        let actual_response = parse_request_bytes(request_bytes, mock_callback);
        assert_eq!(actual_response, expected_response);

        // Test invalid HTTP methods.
        let invalid_methods = ["POST", "HEAD", "DELETE", "CONNECT", "OPTIONS", "TRACE"];
        for method in invalid_methods.iter() {
            let request_bytes = format!("{} http://169.254.169.255/ HTTP/1.0\r\n\r\n", method);
            let mut expected_response = Response::new(Version::Http11, StatusCode::NotImplemented);
            expected_response.set_body(Body::new("Unsupported HTTP method.".to_string()));
            let actual_response = parse_request_bytes(request_bytes.as_bytes(), mock_callback);
            assert_eq!(actual_response, expected_response);
        }

        // Test valid methods.
        let valid_methods = ["PUT", "PATCH", "GET"];
        for method in valid_methods.iter() {
            let request_bytes = format!("{} http://169.254.169.255/ HTTP/1.0\r\n\r\n", method);
            let expected_response = Response::new(Version::Http11, StatusCode::OK);
            let actual_response = parse_request_bytes(request_bytes.as_bytes(), mock_callback);
            assert_eq!(actual_response, expected_response);
        }

        // Test invalid HTTP format.
        let request_bytes = b"GET / HTTP/1.1\r\n";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new("Invalid request.".to_string()));
        let actual_response = parse_request_bytes(request_bytes, mock_callback);
        assert_eq!(actual_response, expected_response);

        // Test invalid HTTP headers.
        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: identity; q=0\r\n\
                                 Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody";
        assert!(parse_request_bytes(request_bytes, mock_callback)
            .body()
            .is_none());

        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: identity; q=0\r\n\
                                 Content-Length: alpha\r\n\r\nthis is not\n\r\na json \nbody";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new(
            "Invalid value. Key:Content-Length; Value: alpha".to_string(),
        ));
        let actual_response = parse_request_bytes(request_bytes, mock_callback);
        assert_eq!(actual_response, expected_response);

        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Transfer-Encoding: identity; q=0\r\n\
                                 Content-Length: 67\r\n\
                                 Accept-Encoding: deflate, compress, *;q=0\r\n\r\nthis is not\n\r\na json \nbody";
        let mut expected_response = Response::new(Version::Http11, StatusCode::BadRequest);
        expected_response.set_body(Body::new(
            "Invalid value. Key:Accept-Encoding; Value: *;q=0".to_string(),
        ));
        let actual_response = parse_request_bytes(request_bytes, mock_callback);
        assert_eq!(actual_response, expected_response);
    }
}
