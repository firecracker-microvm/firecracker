// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use micro_http::{HttpServer, Request, Response, ServerError};

use crate::logger::{debug, error};
use crate::mmds::data_store::Mmds;
use crate::vmm_config::mmds::MmdsServerConfigError;

#[derive(Debug)]
pub struct MmdsServer {
    mmds: Arc<Mutex<Mmds>>,
}

impl MmdsServer {
    pub fn new(mmds: Arc<Mutex<Mmds>>) -> Self {
        MmdsServer { mmds }
    }

    pub fn run(self, bind_path: PathBuf) -> Result<(), MmdsServerConfigError> {
        let mut server =
            HttpServer::new(bind_path).map_err(|_| MmdsServerConfigError::InvalidVsockAddr)?;
        server
            .start_server()
            .expect("Cannot start MMDS HTTP server");

        thread::spawn(move || loop {
            let request_vec = match server.requests() {
                Ok(vec) => vec,
                Err(ServerError::ShutdownEvent) => {
                    server.flush_outgoing_writes();
                    debug!("shutdown request received, MMDS server thread ending.");
                    return;
                }
                Err(err) => {
                    // print request error, but keep server running
                    error!("MMDS Server error on retrieving incoming request: {}", err);
                    continue;
                }
            };
            for server_request in request_vec {
                // Use `self.handle_request()` as the processing callback.
                let response = server_request.process(|request| self.handle_request(request));
                if let Err(err) = server.respond(response) {
                    error!("MMDS Server encountered an error on response: {}", err);
                };
            }
        });

        Ok(())
    }

    pub fn handle_request(&self, request: &Request) -> Response {
        crate::mmds::convert_to_response(self.mmds.clone(), request)
    }
}

// TODO: Error if failed or launch more than once
pub fn run(mmds: Arc<Mutex<Mmds>>, bind_path: PathBuf) -> Result<(), MmdsServerConfigError> {
    MmdsServer::new(mmds).run(bind_path)
}
