#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate api_server;
extern crate sys_util;
extern crate vmm;

use clap::{App, Arg};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock};

use api_server::request::instance_info::{InstanceInfo, InstanceState};
use sys_util::eventfd::EventFd;

const DEFAULT_API_SOCK_PATH: &str = "/tmp/firecracker.socket";
const MAX_STORED_ASYNC_REQS: usize = 100;

fn main() {
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
        .get_matches();

    let bind_path = cmd_arguments
        .value_of("api_sock")
        .map(|s| PathBuf::from(s))
        .unwrap();

    let shared_info = Arc::new(RwLock::new(InstanceInfo {
        state: InstanceState::Uninitialized,
    }));
    let (to_vmm, from_api) = channel();

    let api_event_fd = EventFd::new().expect("Failed to create eventfd");
    let _vmm_thread_handle = vmm::start_vmm_thread(
        shared_info.clone(),
        api_event_fd.try_clone().expect("Failed to clone eventfd"),
        from_api,
    );
    let api_thread_handle = api_server::start_api_thread(
        shared_info,
        to_vmm,
        MAX_STORED_ASYNC_REQS,
        api_event_fd,
        bind_path,
    );

    api_thread_handle
        .join()
        .expect("The API thread has panicked");
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
