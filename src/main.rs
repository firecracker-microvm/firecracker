#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate api_server;
extern crate data_model;
#[macro_use]
extern crate logger;
extern crate seccomp;
extern crate vmm;

use clap::{App, Arg};
use std::panic;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock};

use api_server::request::instance_info::{InstanceInfo, InstanceState};
use api_server::ApiServer;
use logger::LOGGER;

const DEFAULT_API_SOCK_PATH: &str = "/tmp/firecracker.socket";
const MAX_STORED_ASYNC_REQS: usize = 100;

fn main() {
    // If the signal handler can't be set, it's OK to panic.
    seccomp::setup_sigsys_handler().unwrap();

    // Start firecracker by setting up a panic hook, which will be called before
    // terminating as we're building with panic = "abort".
    // It's worth noting that the abort is caused by sending a SIG_ABORT signal to the process.
    panic::set_hook(Box::new(move |info| {
        // We're currently using the closure parameter, which is a &PanicInfo, for printing the origin of the panic,
        // including the payload passed to panic! and the source code location from which the panic originated.
        error!("Panic occurred: {:?}", info);

        // Log the metrics before aborting.
        if let Err(e) = LOGGER.log_metrics() {
            error!("Failed to log metrics on abort. {}:?", e);
        }
    }));

    let cmd_arguments = App::new("firecracker")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a microvm.")
        .arg(
            Arg::with_name("api_sock")
                .long("api-sock")
                .help("Path to unix domain socket used by the API")
                .default_value(DEFAULT_API_SOCK_PATH)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jailed")
                .long("jailed")
                .help("Let Firecracker know it's running inside a jail."),
        )
        .get_matches();

    let bind_path = cmd_arguments
        .value_of("api_sock")
        .map(|s| PathBuf::from(s))
        .unwrap();

    if cmd_arguments.is_present("jailed") {
        data_model::FIRECRACKER_IS_JAILED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let shared_info = Arc::new(RwLock::new(InstanceInfo {
        state: InstanceState::Uninitialized,
    }));
    let (to_vmm, from_api) = channel();
    let server = ApiServer::new(shared_info.clone(), to_vmm, MAX_STORED_ASYNC_REQS).unwrap();

    let api_event_fd = server
        .get_event_fd_clone()
        .expect("cannot clone API eventFD");
    let _vmm_thread_handle = vmm::start_vmm_thread(shared_info, api_event_fd, from_api);

    server.bind_and_run(bind_path).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;
    use std::{fs, thread};

    #[test]
    fn test_main() {
        // test will be run iff the socket file does not already exist
        if !Path::new(DEFAULT_API_SOCK_PATH).exists() {
            thread::spawn(|| {
                main();
            });

            const MAX_WAIT_ITERS: u32 = 20;
            let mut iter_count = 0;
            loop {
                thread::sleep(Duration::from_secs(1));
                if Path::new(DEFAULT_API_SOCK_PATH).exists() {
                    break;
                }
                iter_count += 1;
                if iter_count > MAX_WAIT_ITERS {
                    fs::remove_file(DEFAULT_API_SOCK_PATH)
                        .expect("failure in removing socket file");
                    assert!(false);
                }
            }

            fs::remove_file(DEFAULT_API_SOCK_PATH).expect("failure in removing socket file");
        }
    }
}
